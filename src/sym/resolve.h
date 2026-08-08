#ifndef SYMSOLVE_H
#define SYMSOLVE_H

#include "../private.h"

#include <stdio.h>
#include <stdbool.h>

/**
 * @struct patch_off_t
 * @brief Represents a single resolved symbol patch entry with metadata.
 */
typedef struct {
    int cputype;        /**< CPU architecture type (e.g., CPU_TYPE_ARM64, CPU_TYPE_X86_64). */
    int maxplen;        /**< Maximum length available/allowed for the patch. */
    long fileoff;       /**< Raw file offset of the symbol within the binary. */
    long addr;          /**< Virtual address or slide-adjusted address of the symbol. */
    char *symbol_name;  /**< Allocated symbol name (set for substring or regex matches; memory owned by patch_off_list_t). */
} patch_off_t;

/**
 * @struct patch_off_list_t
 * @brief Dynamic array structure for holding multiple patch offset items.
 */
typedef struct {
    patch_off_t *items; /**< Pointer to dynamically allocated array of patch offset entries. */
    size_t count;       /**< Number of items currently stored in the list. */
    size_t capacity;    /**< Total allocated capacity of the items array. */
} patch_off_list_t;

/**
 * @brief Initializes a patch offset list structure to an empty state.
 *
 * @param list Pointer to the patch_off_list_t structure to initialize.
 */
void patch_off_list_init(patch_off_list_t *list);

/**
 * @brief Releases all memory allocated for a patch offset list.
 *
 * Frees duplicated symbol names, the internal items buffer, and resets the list state.
 *
 * @param list Pointer to the patch_off_list_t structure to free.
 */
void patch_off_list_free(patch_off_list_t *list);

/**
 * @brief Resolves symbol targets within a Mach-O file and appends results to the output list.
 *
 * Automatically detects whether symbol_name is a raw hex offset, standard Mach-O symbol, or an
 * Objective-C method, then dispatches resolution to the appropriate search routines.
 *
 * @param fp Opened FILE pointer pointing to the Mach-O binary.
 * @param symbol_name Query string representing a symbol name, regex pattern, or hex address.
 * @param out List structure where resolved patch offsets will be appended.
 * @param search_mode Matching mode strategy (e.g., exact match, substring, regex).
 * @param search_case Case-sensitivity flag for matching strings.
 * @return The number of new matching offsets discovered and appended in this call.
 */
size_t lookup_symbol_macho(FILE *fp, const char *symbol_name, patch_off_list_t *out,
                           search_mode_t search_mode, search_case_t search_case);

#endif /* SYMSOLVE_H */
