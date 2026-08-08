#include "resolve.h"
#include "private.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

/**
 * @brief Represents the classified type of a symbol input query.
 */
typedef enum {
    HEX_OFFSET,     /**< Direct hexadecimal file/virtual address offset (e.g., "0x100003f20"). */
    REGULAR_SYMBOL, /**< Standard C/C++ symbol name or mangled identifier. */
    OBJC_SYMBOL     /**< Objective-C method signature (e.g., "+[Class selector]" or "-[Class selector]"). */
} symtype_t;

/** Initial capacity allocated for a patch offset dynamic array. */
static const size_t PATCH_OFF_LIST_INIT_CAP = 16;

void patch_off_list_init(patch_off_list_t *list) {
    list->items = NULL;
    list->count = 0;
    list->capacity = 0;
}

void patch_off_list_free(patch_off_list_t *list) {
    for (size_t i = 0; i < list->count; i++)
        free(list->items[i].symbol_name);
    free(list->items);
    patch_off_list_init(list);
}

/**
 * @brief Appends a patch offset entry to the list with deduplication and auto-resizing.
 *
 * Prevents duplicates by matching both cputype and fileoff. Expands internal storage
 * exponentially when capacity is exhausted.
 *
 * @param list Pointer to the target patch offset list.
 * @param poff The patch offset structure to append.
 */
static void patch_off_list_push(patch_off_list_t *list, patch_off_t poff) {
    /* Check for duplicate entries */
    for (size_t i = 0; i < list->count; i++) {
        if (list->items[i].cputype == poff.cputype && list->items[i].fileoff == poff.fileoff)
            return;
    }

    /* Grow capacity if buffer is full */
    if (list->count == list->capacity) {
        size_t new_cap = list->capacity == 0 ? PATCH_OFF_LIST_INIT_CAP : list->capacity * 2;
        patch_off_t *new_items = realloc(list->items, new_cap * sizeof(patch_off_t));
        if (new_items == NULL) {
            fprintf(stderr, "symp: out of memory while collecting patch offsets\n");
            return;
        }
        list->items = new_items;
        list->capacity = new_cap;
    }
    list->items[list->count++] = poff;
}

/**
 * @brief Converts a valid hexadecimal string starting with "0x" or "0X" to a 64-bit integer.
 *
 * Strips leading zeros and manually shifts hex digits into a uint64_t integer.
 *
 * @param str Null-terminated hexadecimal string starting with "0x" or "0X".
 * @return Parsed 64-bit unsigned integer value.
 */
static uint64_t str2uint64(const char* str) {
    int i = 1;
    uint64_t num = 0;
    while (str[++i] == '0'); /* Skip '0' padding after prefix */
    
    /* Parse hex characters */
    for (char c = str[i]; c; c = str[++i]) {
        num <<= 4;
        if (c >= '0' && c <= '9') num |= c - '0';
        else if (c >= 'A' && c <= 'F') num |= c - 'A' + 10;
        else if (c >= 'a' && c <= 'f') num |= c - 'a' + 10;
    }
    return num;
}

/**
 * @brief Determines the input symbol type based on string format heuristics.
 *
 * Checks if the string is a hex offset, an Objective-C method signature, or a regular symbol name.
 * Emits warnings to stderr if syntax formatting anomalies are detected.
 *
 * @param symbol_name Query string representing a symbol name, signature, or address offset.
 * @return The corresponding symtype_t classification.
 */
static symtype_t determine_type(const char *symbol_name) {
    size_t len = strlen(symbol_name);
    
    /* Check for Hexadecimal offset format (0x...) */
    if (symbol_name[0] == '0' &&
        (symbol_name[1] == 'x' || symbol_name[1] == 'X')) {
        int i = 1;
        while (symbol_name[++i] == '0'); /* Skip '0' padding */
        if (len - i <= 16) {
            for (char c = symbol_name[i]; c; c = symbol_name[++i]) {
                if (!(c >= '0' && c <= '9') && !(c >= 'A' && c <= 'F') && !(c >= 'a' && c <= 'f')) {
                    i = -1;
                    fprintf(stderr, "symp: warning, invalid char '%c' in hex number, treated as regular symbol\n", c);
                    break;
                }
            }
            if (i != -1) return HEX_OFFSET;
        }
    }
    
    /* Check for Objective-C method format: +[Class selector] or -[Class selector] */
    if ((symbol_name[0] == '+' || symbol_name[0] == '-') &&
        (symbol_name[1] == '[' && symbol_name[len - 1] == ']')) {
        int space_cnt = 0;
        for (int i = 2; i < len; i++) {
            if (symbol_name[i] == ' ') space_cnt++;
        }
        if (space_cnt == 1) return OBJC_SYMBOL;
        else {
            fprintf(stderr, "symp: warning, objc symbol should use 1 space to seperate cls and sel, treated as regular symbol\n");
        }
    }
    
    return REGULAR_SYMBOL;
}

/**
 * @brief Helper function to construct a patch_off_t record and store it in the output list.
 *
 * @param out Destination patch offset list.
 * @param cputype Target architecture CPU type identifier.
 * @param max_patch_len Maximum patchable length in bytes.
 * @param addr Resolved target address offset.
 * @param symbol_name Symbol string to duplicate and associate with the patch offset (optional).
 * @param module_base Base file offset of the binary image.
 */
static void append_match(patch_off_list_t *out, int32_t cputype, uint32_t max_patch_len,
                         uint64_t addr, const char *symbol_name, long module_base) {
    patch_off_t poff = {
        .cputype = cputype,
        .fileoff = (long)addr,
        .addr = (long)(addr - module_base),
        .maxplen = (int)max_patch_len,
        .symbol_name = symbol_name ? strdup(symbol_name) : NULL,
    };
    patch_off_list_push(out, poff);
}

size_t lookup_symbol_macho(FILE *fp, const char *symbol_name, patch_off_list_t *out,
                           search_mode_t search_mode, search_case_t search_case) {
    size_t before = out->count;
    int32_t cputype = 0;
    uint32_t max_patch_len = 0;

    switch(determine_type(symbol_name)) {
    case HEX_OFFSET: {
        /* Direct hexadecimal memory or file offset calculation */
        const macho_basic_info_t *basic_info = parse_basic_info(fp);
        cputype = basic_info->cputype;
        append_match(out, cputype, max_patch_len,
                     str2uint64(symbol_name) + basic_info->base_offset + basic_info->vm_slide, NULL, basic_info->base_offset);
        free((void *)basic_info);
        break;
    }
    case REGULAR_SYMBOL: {
        /* Search Mach-O export trie and standard symbol tables */
        const macho_symbol_info_t *symbol_info = parse_symbol_info(fp);
        symbol_matches_t matches;

        cputype = symbol_info->cputype;
        symbol_matches_init(&matches);
        solve_symbol(fp, symbol_info, symbol_name, search_mode, search_case, &matches);
        for (size_t i = 0; i < matches.count; i++) {
            append_match(out, cputype, max_patch_len, matches.addrs[i], matches.names[i], symbol_info->base_offset);
        }
        symbol_matches_free(&matches);
        free((void *)symbol_info);
        break;
    }
    case OBJC_SYMBOL: {
        /* Search Objective-C runtime metadata structures */
        const macho_objc_info_t *objc_info = parse_objc_info(fp);
        symbol_matches_t matches;

        cputype = objc_info->cputype;
        symbol_matches_init(&matches);
        solve_objc_symbol(fp, objc_info, symbol_name, search_mode, search_case, &matches);
        for (size_t i = 0; i < matches.count; i++) {
            append_match(out, cputype, max_patch_len, matches.addrs[i], matches.names[i], objc_info->base_offset);
        }
        symbol_matches_free(&matches);
        free((void *)objc_info);
        break;
    }
    default:
        break;
    }

    return out->count - before;
}
