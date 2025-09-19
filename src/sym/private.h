#ifndef SYM_PRIVATE
#define SYM_PRIVATE

#include <stdio.h>
#include <stdint.h>

typedef struct {
    int32_t cputype;
    long base_offset;

    /* __TEXT vm slide */
    uint64_t vm_slide;
} macho_basic_info_t;

typedef struct {
    int32_t cputype;
    long base_offset;

    /* __TEXT vm slide */
    uint64_t vm_slide;

    /* from LC_SYMTAB */
    uint32_t symoff;
    uint32_t nsyms;
    uint32_t stroff;
    uint32_t strsize;

    /* from LC_DYLD_INFO(_ONLY) or LC_DYLD_EXPORTS_TRIE */
    uint32_t export_off;
    uint32_t export_size;

    /* from LC_DYSYMTAB */
    uint32_t indirectsymoff;

    /* from S_SYMBOL_STUBS section */
    uint32_t stubs_off;
    uint64_t stubs_size;
    uint32_t indirectsym_idx;
    uint32_t stub_len;
} macho_symbol_info_t;

typedef struct {
    int32_t cputype;
    long base_offset;

    /* __TEXT vm slide */
    uint64_t vm_slide;

    /* mapped file end offset we will read up to (covers __TEXT + __DATA*) */
    uint64_t dataend_off;

    /* objc sections */
    uint32_t objc_classlist_off;
    uint64_t objc_classlist_size;
} macho_objc_info_t;

/* 
 * defined in macho.c
 * fp -> start of macho file 
 */
macho_basic_info_t *parse_basic_info(FILE *fp);

macho_symbol_info_t *parse_symbol_info(FILE *fp);

macho_objc_info_t *parse_objc_info(FILE *fp);

/* defined in symbol.c */
long solve_symbol(FILE *fp, const macho_symbol_info_t *macho_info, const char* symbol_name);

/* defined in objcmeta.c */
long solve_objc_symbol(FILE *fp, const macho_objc_info_t *macho_info, const char* symbol_name);

#endif