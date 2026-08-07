#include "private.h"
#include "../fileio.h"

#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include <mach-o/nlist.h>
#include <mach-o/loader.h>
#include <regex.h>


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


/* Depth-first Search (DFS) by Trie to match a substring */
static uint64_t trie_dfs_substring(const uint8_t *export, uint64_t node_off, 
                                   char *buf, size_t buf_len, const char *substr) {
    const uint8_t *cur_pos = export + node_off;
    uint64_t info_len = read_uleb128(&cur_pos);
    const uint8_t *child_off = cur_pos + info_len;

    if (info_len != 0) {
        uint64_t flag = read_uleb128(&cur_pos);
        if (flag == EXPORT_SYMBOL_FLAGS_KIND_REGULAR) {
            uint64_t addr = read_uleb128(&cur_pos);
            if (strstr(buf, substr) != NULL) {
                return addr;
            }
        }
    }

    cur_pos = child_off;
    uint8_t child_count = *cur_pos++;
    for (uint8_t i = 0; i < child_count; i++) {
        const char *edge_str = (const char *)cur_pos;
        size_t edge_len = strlen(edge_str);
        cur_pos += edge_len + 1;
        uint64_t next_off = read_uleb128(&cur_pos);

        if (buf_len + edge_len < 4096) {
            memcpy(buf + buf_len, edge_str, edge_len);
            buf[buf_len + edge_len] = '\0';

            uint64_t found_addr = trie_dfs_substring(export, next_off, buf, buf_len + edge_len, substr);
            if (found_addr != 0) {
                return found_addr;
            }
        }
    }

    buf[buf_len] = '\0'; /* Rolling back the buffer when returning from recursion */
    return 0;
}

static uint64_t trie_query_substring(const uint8_t *export, const char *substr) {
    char buf[4096] = {0};
    return trie_dfs_substring(export, 0, buf, 0, substr);
}

/* Depth-first Search (DFS) by Trie to match a regular expression */
static uint64_t trie_dfs_regexp(const uint8_t *export, uint64_t node_off, 
                                char *buf, size_t buf_len, const regex_t *preg) {
    const uint8_t *cur_pos = export + node_off;
    uint64_t info_len = read_uleb128(&cur_pos);
    const uint8_t *child_off = cur_pos + info_len;

    if (info_len != 0) {
        uint64_t flag = read_uleb128(&cur_pos);
        if (flag == EXPORT_SYMBOL_FLAGS_KIND_REGULAR) {
            uint64_t addr = read_uleb128(&cur_pos);
            if (regexec(preg, buf, 0, NULL, 0) == 0) {
                return addr;
            }
        }
    }

    cur_pos = child_off;
    uint8_t child_count = *cur_pos++;
    for (uint8_t i = 0; i < child_count; i++) {
        const char *edge_str = (const char *)cur_pos;
        size_t edge_len = strlen(edge_str);
        cur_pos += edge_len + 1;
        uint64_t next_off = read_uleb128(&cur_pos);

        if (buf_len + edge_len < 4096) {
            memcpy(buf + buf_len, edge_str, edge_len);
            buf[buf_len + edge_len] = '\0';

            uint64_t found_addr = trie_dfs_regexp(export, next_off, buf, buf_len + edge_len, preg);
            if (found_addr != 0) {
                return found_addr;
            }
        }
    }

    buf[buf_len] = '\0'; /* Rolling back the buffer when returning from recursion */
    return 0;
}

static uint64_t trie_query_regexp(const uint8_t *export, const char *pattern) {
    regex_t preg;
    int ret = regcomp(&preg, pattern, REG_EXTENDED | REG_ENHANCED | REG_NOSUB);
    if (ret != 0) {
        fprintf(stderr, "Could not compile regex\n");
        return 0;
    }

    char buf[4096] = {0};
    uint64_t addr = trie_dfs_regexp(export, 0, buf, 0, &preg);
    regfree(&preg);
    return addr;
}


// Function for checking a string for matching a regular expression
static bool match_regexp(const char *string, const char *pattern) {
    regex_t regex;
    int ret;

    // Compile the regular expression
    /* REG_ENHANCED enable support for \d, \w, \s, \b on macOS */
    ret = regcomp(&regex, pattern, REG_EXTENDED | REG_ENHANCED | REG_NOSUB);
    if (ret) {
        fprintf(stderr, "Could not compile regex\n");
        return false;
    }

    // Execute the regular expression match
    ret = regexec(&regex, string, 0, NULL, 0);
    regfree(&regex);

    if (!ret) {
        // printf("Match found: %s matches %s\n", string, pattern);
        return true;
    } else if (ret == REG_NOMATCH) {
        return false;
    } else {
        char error_msg[100];
        regerror(ret, &regex, error_msg, sizeof(error_msg));
        fprintf(stderr, "Regex match failed: %s\n", error_msg);
        return false;
    }
}


long solve_symbol(FILE *fp, const macho_symbol_info_t *macho_info, const char* symbol_name, search_mode_t search_mode) {
    uint64_t symbol_address = 0;
    const long base_offset = macho_info->base_offset;

    if (macho_info->export.off != 0) {
        /* export table search */
        uint8_t *export_trie = read_file_off(fp, macho_info->export.size, base_offset + macho_info->export.off);

        switch (search_mode) {
        case FULL_STRING_MATCH:
            symbol_address = trie_query(export_trie, symbol_name);
            break;
        case SUBSTRING_MATCH:
            symbol_address = trie_query_substring(export_trie, symbol_name);
            break;
        case REGEXP_MATCH:
            symbol_address = trie_query_regexp(export_trie, symbol_name);
            break;
        default:
            fprintf(stderr, "symp: unknown search mode\n");
            break;
        }

        free(export_trie);
        if (symbol_address != 0) {
            /* trie value is the location from mach_header */
            symbol_address += base_offset;
            goto ret;
        }
    }

    /* these tables are both needed for symtab search and symbol stubs search */
    const struct nlist_64* nl_tbl = read_file_off(fp, macho_info->nsyms * sizeof(struct nlist_64), base_offset + macho_info->symoff);
    const char* str_tbl = read_file_off(fp, macho_info->strtab.size, base_offset + macho_info->strtab.off);

    if (macho_info->indirectsymoff != 0 && macho_info->stubs.off != 0) {
        /* symbol stubs search */
        uint32_t entry_off = macho_info->indirectsymoff + macho_info->indirectsym_idx * sizeof(uint32_t);
        uint64_t nstubs = macho_info->stubs.size / macho_info->stub_len;
        const uint32_t *indirectsym_entry = read_file_off(fp, nstubs * sizeof(uint32_t), base_offset + entry_off);
        for (int i = 0; i < nstubs; i++) {
            uint32_t nl_idx = indirectsym_entry[i];
            if (nl_idx == INDIRECT_SYMBOL_LOCAL ||
                nl_idx == (INDIRECT_SYMBOL_LOCAL | INDIRECT_SYMBOL_ABS)) {
                continue;
            }
            const char *current_symbol = str_tbl + nl_tbl[nl_idx].n_un.n_strx;

            switch (search_mode) {
            case REGEXP_MATCH:
                if (match_regexp(current_symbol, symbol_name)) {
                    /* stubs_off is direct file offset */
                    symbol_address = base_offset + macho_info->stubs.off + i * (uint64_t)macho_info->stub_len;
                }
                break;
            case FULL_STRING_MATCH:
                if (strcmp(symbol_name, current_symbol) == 0) {
                    /* stubs_off is direct file offset */
                    symbol_address = base_offset + macho_info->stubs.off + i * (uint64_t)macho_info->stub_len;
                }
                break;
            case SUBSTRING_MATCH:
                if (strstr(current_symbol, symbol_name) != NULL) {
                    /* stubs_off is direct file offset */
                    symbol_address = base_offset + macho_info->stubs.off + i * (uint64_t)macho_info->stub_len;
                }
                break;
            default:
                fprintf(stderr, "symp: unknown search mode\n");
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
            const char *current_symbol = str_tbl + nl_tbl[i].n_un.n_strx;
            
            switch (search_mode) {
            case REGEXP_MATCH:
                if (match_regexp(current_symbol, symbol_name)) {
                    /* n_value in nlist is the offset from vmaddr of the image */
                    symbol_address = base_offset + macho_info->vm_slide + nl_tbl[i].n_value;
                    goto sym_ret;
                }
                break;
            case FULL_STRING_MATCH:
                if (strcmp(symbol_name, current_symbol) == 0) {
                    /* n_value in nlist is the offset from vmaddr of the image */
                    symbol_address = base_offset + macho_info->vm_slide + nl_tbl[i].n_value;
                    goto sym_ret;
                }
                break;
            case SUBSTRING_MATCH:
                if (strstr(current_symbol, symbol_name) != NULL) {
                    /* n_value in nlist is the offset from vmaddr of the image */
                    symbol_address = base_offset + macho_info->vm_slide + nl_tbl[i].n_value;
                    goto sym_ret;
                }
                break;
            default:
                fprintf(stderr, "symp: unknown search mode\n");
                break;
            }
        }
    }

sym_ret:
    free((void *)nl_tbl);
    free((void *)str_tbl);

ret:
    return (long)symbol_address;
}