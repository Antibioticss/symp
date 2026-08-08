#ifndef SYM_PRIVATE
#define SYM_PRIVATE

#include "../private.h"

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>

 #define max(a,b) \
   ({ __typeof__ (a) _a = (a); \
       __typeof__ (b) _b = (b); \
     _a > _b ? _a : _b; })

typedef struct {
    uint32_t off;
    uint64_t size;
} fileseg_t;

typedef struct {
    uint32_t off;
    uint64_t addr;
    uint64_t size;
} vmseg_t;

typedef struct {
    int32_t cputype;
    long base_offset;

    /* __TEXT vm slide */
    int64_t vm_slide;
} macho_basic_info_t;

typedef struct {
    int32_t cputype;
    long base_offset;

    /* __TEXT vm slide */
    int64_t vm_slide;

    /* from LC_SYMTAB */
    uint32_t symoff;
    uint32_t nsyms;
    fileseg_t strtab;

    /* from LC_DYLD_INFO(_ONLY) or LC_DYLD_EXPORTS_TRIE */
    fileseg_t export;

    /* from LC_DYSYMTAB */
    uint32_t indirectsymoff;

    /* from S_SYMBOL_STUBS section */
    fileseg_t stubs;
    uint32_t indirectsym_idx;
    uint32_t stub_len;
} macho_symbol_info_t;

typedef struct {
    int32_t cputype;
    long base_offset;

    /* vm segment */
    vmseg_t text_vm;  // TEXT
    vmseg_t datac_vm; // DATA_CONST
    vmseg_t data_vm;  // DATA (last)

    /* has LC_DYLD_CHAINED_FIXUPS? */
    bool chained_fixup;

    /* objc sections */
    fileseg_t objc_classlist;
    fileseg_t objc_catlist;
} macho_objc_info_t;

/* 
 * defined in macho.c
 * fp -> start of macho file 
 */
macho_basic_info_t *parse_basic_info(FILE *fp);

macho_symbol_info_t *parse_symbol_info(FILE *fp);

macho_objc_info_t *parse_objc_info(FILE *fp);

typedef struct {
    uint64_t *addrs;
    size_t count;
    size_t capacity;
} symbol_matches_t;

void symbol_matches_init(symbol_matches_t *m);
void symbol_matches_free(symbol_matches_t *m);

/* defined in symbol.c */
size_t solve_symbol(FILE *fp, const macho_symbol_info_t *macho_info, const char *symbol_name,
                    search_mode_t search_mode, search_case_t search_case, symbol_matches_t *out);

/* defined in objcmeta.c */
long solve_objc_symbol(FILE *fp, const macho_objc_info_t *mi, const char* symbol_name);

#endif