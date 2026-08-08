#ifndef SYMSOLVE_H
#define SYMSOLVE_H

#include "../private.h"

#include <stdio.h>
#include <stdbool.h>

typedef struct {
    int cputype;
    int maxplen;  /* max patch lenth */
    long fileoff;
    char *symbol_name; /* set for substring/regexp matches; owned by patch_off_list_t */
} patch_off_t;

typedef struct {
    patch_off_t *items;
    size_t count;
    size_t capacity;
} patch_off_list_t;

void patch_off_list_init(patch_off_list_t *list);
void patch_off_list_free(patch_off_list_t *list);

/*
 * append all matching symbols to out; return number of matches added
 * fp -> start of macho file
 */
size_t lookup_symbol_macho(FILE *fp, const char *symbol_name, patch_off_list_t *out,
                           search_mode_t search_mode, search_case_t search_case);

#endif