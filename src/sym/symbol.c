#include "private.h"
#include "../fileio.h"

#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include <mach-o/nlist.h>
#include <mach-o/loader.h>

static uint64_t read_uleb128(const uint8_t **p) {
    int bit = 0;
    uint64_t result = 0;
    do {
        uint64_t slice = **p & 0x7f;
        result |= (slice << bit);
        bit += 7;
    } while (*(*p)++ & 0x80);
    return result;
}

static uint64_t trie_query(const uint8_t *export, const char *name) {
    // documents in <mach-o/loader.h>
    uint64_t symbol_address = 0;
    uint64_t node_off = 0;
    const char *rest_name = name;
    bool go_child = true;
    while (go_child) {
        const uint8_t *cur_pos = export + node_off;
        uint64_t info_len = read_uleb128(&cur_pos);
        const uint8_t *child_off = cur_pos + info_len;
        if (rest_name[0] == '\0') {
            if (info_len != 0) {
                uint64_t flag = read_uleb128(&cur_pos);
                if (flag == EXPORT_SYMBOL_FLAGS_KIND_REGULAR) {
                    symbol_address = read_uleb128(&cur_pos);
                }
            }
            break;
        }
        else {
            go_child = false;
            cur_pos = child_off;
            uint8_t child_count = *(uint8_t *)cur_pos++;
            for (int i = 0; i < child_count; i++) {
                char *cur_str = (char *)cur_pos;
                size_t cur_len = strlen(cur_str);
                cur_pos += cur_len + 1;
                uint64_t next_off = read_uleb128(&cur_pos);
                if (strncmp(rest_name, cur_str, cur_len) == 0) {
                    /* this edge matched the symbol */
                    go_child = true;
                    rest_name += cur_len;
                    node_off = next_off;
                    break;
                }
            }
        }
    }
    return symbol_address;
}

long solve_symbol(FILE *fp, const macho_symbol_info_t *macho_info, const char* symbol_name) {
    uint64_t symbol_address = 0;
    const long base_offset = macho_info->base_offset;

    if (macho_info->export_off != 0) {
        /* export table search */
        uint8_t *export_trie = read_file_off(fp, macho_info->export_size, base_offset + macho_info->export_off);
        symbol_address = trie_query(export_trie, symbol_name);
        free(export_trie);
        if (symbol_address != 0) {
            /* trie value is the location from mach_header */
            symbol_address += base_offset;
            goto ret;
        }
    }

    /* these tables are both needed for symtab search and symbol stubs search */
    const struct nlist_64* nl_tbl = read_file_off(fp, macho_info->nsyms * sizeof(struct nlist_64), base_offset + macho_info->symoff);
    const char* str_tbl = read_file_off(fp, macho_info->strsize, base_offset + macho_info->stroff);

    if (macho_info->indirectsymoff != 0 && macho_info->stubs_off != 0) {
        /* symbol stubs search */
        uint32_t entry_off = macho_info->indirectsymoff + macho_info->indirectsym_idx * sizeof(uint32_t);
        uint64_t nstubs = macho_info->stubs_size / macho_info->stub_len;
        const uint32_t *indirectsym_entry = read_file_off(fp, nstubs * sizeof(uint32_t), base_offset + entry_off);
        for (int i = 0; i < nstubs; i++) {
            uint32_t nl_idx = indirectsym_entry[i];
            if (nl_idx == INDIRECT_SYMBOL_LOCAL ||
                nl_idx == (INDIRECT_SYMBOL_LOCAL | INDIRECT_SYMBOL_ABS)) {
                continue;
            }
            if (strcmp(symbol_name, str_tbl + nl_tbl[nl_idx].n_un.n_strx) == 0) {
                /* stubs_off is direct file offset */
                symbol_address = base_offset + macho_info->stubs_off + i * (uint64_t)macho_info->stub_len;
                break;
            }
        }
        free((void *)indirectsym_entry);
        if (symbol_address != 0)
            goto sym_ret;
    }

    if (macho_info->symoff != 0) {
        /* symtab search */
        for (int i = 0; i < macho_info->nsyms; i++) {
            if ((nl_tbl[i].n_type & N_TYPE) != N_SECT) 
                continue;
            if (strcmp(symbol_name, str_tbl + nl_tbl[i].n_un.n_strx) == 0) {
                /* n_value in nlist is the offset from vmaddr of the image */
                symbol_address = base_offset + macho_info->vm_slide + nl_tbl[i].n_value;
                goto sym_ret;
            }
        }
    }

sym_ret:
    free((void *)nl_tbl);
    free((void *)str_tbl);

ret:
    return (long)symbol_address;
}
