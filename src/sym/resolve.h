#ifndef SYMSOLVE_H
#define SYMSOLVE_H

#include <stdio.h>
#include <stdbool.h>

typedef struct {
    int cputype;
    int maxplen;  /* max patch lenth */
    long fileoff;
    long vm_slide;
} patch_off_t;

/* 
 * return true if found
 * update fileoff and maxplen of the patch_off_t
 * fp -> start of macho file
 */
bool lookup_symbol_macho(FILE *fp, const char *symbol_name, patch_off_t *poffout);

#endif