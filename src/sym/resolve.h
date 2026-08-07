#ifndef SYMSOLVE_H
#define SYMSOLVE_H

#include "../private.h"

#include <stdio.h>
#include <stdbool.h>

typedef struct {
    int cputype;
    int maxplen;  /* max patch lenth */
    long fileoff;
} patch_off_t;

/* 
 * return true if found
 * update fileoff and maxplen of the patch_off_t
 * fp -> start of macho file
 */
bool lookup_symbol_macho(FILE *fp, const char *symbol_name, patch_off_t *poffout, search_mode_t search_mode);

#endif