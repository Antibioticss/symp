#include "private.h"
#include "../fileio.h"

#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include <mach-o/nlist.h>
#include <mach-o/loader.h>
#include <regex.h>

/**
 * @brief Decodes an Unsigned LEB128 (ULEB128) variable-length integer.
 * 
 * Reads multi-byte variable-length integer values used extensively in Mach-O
 * binary structures (e.g., Export Trie). Advances the input pointer as bytes are consumed.
 * 
 * @param[in,out] p Pointer to the current byte pointer in the ULEB128 stream.
 * @return Decoded 64-bit unsigned integer value.
 */
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

/**
 * @brief Queries the Mach-O Export Trie for an exact symbol match.
 * 
 * Traverses the trie structure edge-by-edge matching against the target symbol name.
 * Supports both case-sensitive and case-insensitive exact comparisons.
 * 
 * @param[in] export Pointer to the Mach-O export trie buffer.
 * @param[in] name Target symbol name to look up.
 * @param[in] search_case Case sensitivity option (SEARCH_CASE_SENSITIVE or SEARCH_CASE_INSENSITIVE).
 * @return The relative symbol address from the Mach header if found; 0 otherwise.
 */
static uint64_t trie_query(const uint8_t *export, const char *name, search_case_t search_case) {
    // Documents in <mach-o/loader.h>
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
                if (search_case == SEARCH_CASE_INSENSITIVE) {
                    if (strncasecmp(rest_name, cur_str, cur_len) == 0) {
                        go_child = true;
                        rest_name += cur_len;
                        node_off = next_off;
                        break;
                    }
                } else if (strncmp(rest_name, cur_str, cur_len) == 0) {
                    /* This edge matched the symbol */
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

/**
 * @brief Performs a Depth-First Search (DFS) on the Export Trie to locate symbols containing a substring.
 * 
 * Reconstructs exported symbol names character-by-character during traversal
 * and tests each symbol terminal node against the target substring.
 * 
 * @param[in] export Pointer to the Mach-O export trie memory buffer.
 * @param[in] node_off Current node offset within the trie data.
 * @param[in,out] buf Scratchpad buffer used to accumulate symbol string segments.
 * @param[in] buf_len Current length of the string in \p buf.
 * @param[in] substr Substring to match against reconstructed symbol names.
 * @param[in] base_offset Image base file offset for address resolution.
 * @param[in] search_case Case-sensitivity mode for substring matching.
 * @param[out] out Match collector container to append found symbols to.
 */
static void trie_dfs_substring(const uint8_t *export, uint64_t node_off,
                               char *buf, size_t buf_len, const char *substr,
                               uint64_t base_offset, search_case_t search_case,
                               symbol_matches_t *out) {
    const uint8_t *cur_pos = export + node_off;
    uint64_t info_len = read_uleb128(&cur_pos);
    const uint8_t *child_off = cur_pos + info_len;

    if (info_len != 0) {
        uint64_t flag = read_uleb128(&cur_pos);
        if (flag == EXPORT_SYMBOL_FLAGS_KIND_REGULAR) {
            uint64_t addr = read_uleb128(&cur_pos);
            if (str_contains(buf, substr, search_case)) {
                symbol_matches_push(out, base_offset + addr, buf);
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

            trie_dfs_substring(export, next_off, buf, buf_len + edge_len, substr, base_offset,
                               search_case, out);
        }
    }

    buf[buf_len] = '\0';
}

/**
 * @brief Performs a Depth-First Search (DFS) on the Export Trie using a POSIX regular expression.
 * 
 * Reconstructs exported symbol names during traversal and matches them against
 * a compiled regular expression pattern.
 * 
 * @param[in] export Pointer to the Mach-O export trie memory buffer.
 * @param[in] node_off Current node offset within the trie data.
 * @param[in,out] buf Scratchpad buffer used to accumulate symbol string segments.
 * @param[in] buf_len Current length of the string in \p buf.
 * @param[in] preg Compiled POSIX regular expression object (`regex_t`).
 * @param[in] base_offset Image base file offset for address resolution.
 * @param[out] out Match collector container to append found symbols to.
 */
static void trie_dfs_regexp(const uint8_t *export, uint64_t node_off,
                            char *buf, size_t buf_len, const regex_t *preg,
                            uint64_t base_offset, symbol_matches_t *out) {
    const uint8_t *cur_pos = export + node_off;
    uint64_t info_len = read_uleb128(&cur_pos);
    const uint8_t *child_off = cur_pos + info_len;

    if (info_len != 0) {
        uint64_t flag = read_uleb128(&cur_pos);
        if (flag == EXPORT_SYMBOL_FLAGS_KIND_REGULAR) {
            uint64_t addr = read_uleb128(&cur_pos);
            if (regexec(preg, buf, 0, NULL, 0) == 0) {
                symbol_matches_push(out, base_offset + addr, buf);
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

            trie_dfs_regexp(export, next_off, buf, buf_len + edge_len, preg, base_offset, out);
        }
    }

    buf[buf_len] = '\0';
}

/**
 * @brief Resolves symbol addresses in a Mach-O binary using specified search mode and criteria.
 * 
 * Searches across three main Mach-O symbol structures:
 * 1. Export Table Trie (via exact lookup or DFS traversal for pattern modes).
 * 2. Symbol Stubs (indirect dynamic symbol entries).
 * 3. Standard Symbol Table (`symtab` / `nlist_64` records).
 * 
 * In `FULL_STRING_MATCH` mode, the search returns immediately on the first match.
 * Pattern-based searches (`SUBSTRING_MATCH`, `REGEXP_MATCH`) collect all matching symbols.
 * 
 * @param[in] fp Open file handle for the Mach-O binary.
 * @param[in] macho_info Parsed Mach-O header and section layout metadata.
 * @param[in] symbol_name Symbol name, substring pattern, or regex string to match.
 * @param[in] search_mode Match strategy (FULL_STRING_MATCH, SUBSTRING_MATCH, or REGEXP_MATCH).
 * @param[in] search_case Case sensitivity mode (SEARCH_CASE_SENSITIVE or SEARCH_CASE_INSENSITIVE).
 * @param[out] out Match collection structure where resolved addresses and names are stored.
 * @return Number of new matches added to \p out during this execution.
 */
size_t solve_symbol(FILE *fp, const macho_symbol_info_t *macho_info, const char *symbol_name,
                    search_mode_t search_mode, search_case_t search_case, symbol_matches_t *out) {
    size_t before = out->count;
    const long base_offset = macho_info->base_offset;

    regex_t preg;
    bool preg_compiled = false;

    if (search_mode == REGEXP_MATCH) {
        if (!compile_regex(&preg, symbol_name, search_case)) {
            fprintf(stderr, "Could not compile regex: %s\n", symbol_name);
            return 0;
        }
        preg_compiled = true;
    }

    /* 1. Search in Export Table Trie */
    if (macho_info->export.off != 0) {
        uint8_t *export_trie = read_file_off(fp, macho_info->export.size, base_offset + macho_info->export.off);

        if (search_mode == FULL_STRING_MATCH) {
            uint64_t addr = trie_query(export_trie, symbol_name, search_case);
            if (addr != 0) {
                symbol_matches_push(out, base_offset + addr, NULL);
                free(export_trie);
                goto ret;
            }
        } else {
            char buf[4096] = {0};
            if (search_mode == SUBSTRING_MATCH) {
                trie_dfs_substring(export_trie, 0, buf, 0, symbol_name, base_offset, search_case, out);
            } else if (search_mode == REGEXP_MATCH) {
                trie_dfs_regexp(export_trie, 0, buf, 0, &preg, base_offset, out);
            }
        }

        free(export_trie);
    }

    /* Load symbol tables required for stubs and symtab searches */
    const struct nlist_64* nl_tbl = read_file_off(fp, macho_info->nsyms * sizeof(struct nlist_64), base_offset + macho_info->symoff);
    const char* str_tbl = read_file_off(fp, macho_info->strtab.size, base_offset + macho_info->strtab.off);

    /* 2. Search in Symbol Stubs */
    if (macho_info->indirectsymoff != 0 && macho_info->stubs.off != 0) {
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

            if (match_symbol(current_symbol, symbol_name, search_mode, search_case, &preg)) {
                uint64_t addr = base_offset + macho_info->stubs.off + i * (uint64_t)macho_info->stub_len;
                if (search_mode == FULL_STRING_MATCH) {
                    symbol_matches_push(out, addr, NULL);
                    free((void *)indirectsym_entry);
                    goto sym_ret;
                }
                symbol_matches_push(out, addr, current_symbol);
            }
        }
        free((void *)indirectsym_entry);
    }

    /* 3. Search in Symtab (Standard Symbol Table) */
    if (macho_info->symoff != 0) {
        for (int i = 0; i < macho_info->nsyms; i++) {
            if ((nl_tbl[i].n_type & N_TYPE) != N_SECT)
                continue;
            const char *current_symbol = str_tbl + nl_tbl[i].n_un.n_strx;

            if (match_symbol(current_symbol, symbol_name, search_mode, search_case, &preg)) {
                uint64_t addr = base_offset + macho_info->vm_slide + nl_tbl[i].n_value;
                if (search_mode == FULL_STRING_MATCH) {
                    symbol_matches_push(out, addr, NULL);
                    goto sym_ret;
                }
                symbol_matches_push(out, addr, current_symbol);
            }
        }
    }

sym_ret:
    free((void *)nl_tbl);
    free((void *)str_tbl);

ret:
    if (preg_compiled) {
        regfree(&preg);
    }

    return out->count - before;
}
