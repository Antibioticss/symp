#include "resolve.h"
#include "private.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

typedef enum {
    HEX_OFFSET, REGULAR_SYMBOL, OBJC_SYMBOL
} symtype_t;

/* convert a VALID uint64 hex str to num */
static uint64_t str2uint64(const char* str) {
    int i = 1;
    uint64_t num = 0;
    while (str[++i] == '0'); /* remove 0 prefix */
    /* assume the length is valid too */
    for (char c = str[i]; c; c = str[++i]) {
        num <<= 4;
        if (c >= '0' && c <= '9') num |= c - '0';
        else if (c >= 'A' && c <= 'F') num |= c - 'A' + 10;
        else if (c >= 'a' && c <= 'f') num |= c - 'a' + 10;
        /* assume all the chars are valid */
    }
    return num;
}

static symtype_t determine_type(const char *symbol_name) {
    size_t len = strlen(symbol_name);
    if (symbol_name[0] == '0' &&
        (symbol_name[1] == 'x' || symbol_name[1] == 'X')) {
        int i = 1;
        while (symbol_name[++i] == '0'); /* remove 0 prefix */
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

bool lookup_symbol_macho(FILE *fp, const char *symbol_name, patch_off_t *poffout) {
    bool found = false;
    int32_t cputype = 0;
    uint32_t max_patch_len = 0;
    long symbol_address = 0;

    switch(determine_type(symbol_name)) {
    case HEX_OFFSET: {
        const macho_basic_info_t *basic_info = parse_basic_info(fp);
        cputype = basic_info->cputype;
        poffout->vm_slide = basic_info->vm_slide;
        symbol_address = str2uint64(symbol_name) + basic_info->base_offset + basic_info->vm_slide;
        free((void *)basic_info);
        break;
    }
    case REGULAR_SYMBOL: {
        const macho_symbol_info_t *symbol_info = parse_symbol_info(fp);
        cputype = symbol_info->cputype;
        poffout->vm_slide = symbol_info->vm_slide;
        // max_patch_len = symbol_info->stub_len; // we don't know if the symbol is from stubs
        symbol_address = solve_symbol(fp, symbol_info, symbol_name);
        free((void *)symbol_info);
        break;
    }
    case OBJC_SYMBOL: {
        const macho_objc_info_t *objc_info = parse_objc_info(fp);
        cputype = objc_info->cputype;
        if (objc_info->text_vm.addr != 0)
            poffout->vm_slide = objc_info->text_vm.off - objc_info->text_vm.addr;
        else
            poffout->vm_slide = 0;
        symbol_address = solve_objc_symbol(fp, objc_info, symbol_name);
        free((void *)objc_info);
        break;
    }
    default:
        break;
    }
    if (symbol_address != 0) {
        found = true;
        poffout->cputype = cputype;
        poffout->fileoff = symbol_address;
        poffout->maxplen = max_patch_len;
    }
    return found;
}
