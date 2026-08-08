#include "private.h"
#include "fileio.h"
#include "sym/resolve.h"

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <mach-o/fat.h>
#include <mach-o/dyld.h>
#include <mach-o/loader.h>

/**
 * @brief Mapping between CPU type integer identifier and its human-readable string representation.
 */
typedef struct {
    int32_t cputype; /**< Mach-O CPU type identifier (e.g., CPU_TYPE_X86_64). */
    char *name;      /**< Human-readable architecture name string. */
} arch_name_t;

/**
 * @brief Lookup table for supported CPU architectures and their names.
 */
static const arch_name_t cpu_archs[] = {
    {CPU_TYPE_X86_64, "x86_64"},
    {CPU_TYPE_ARM64, "arm64"}
};

/**
 * @brief Global bitmask recording all CPU architectures processed during execution.
 */
static int32_t g_searched_arch = 0;

/**
 * @brief Converts a Mach-O CPU type identifier to its architecture name string.
 *
 * @param arch The Mach-O CPU type identifier.
 * @return String representation of the architecture, or NULL if unknown.
 */
static char *arch2str(int32_t arch) {
    for (int i = 0; i < ARRAY_LEN(cpu_archs); i++) {
        if (arch == cpu_archs[i].cputype)
            return cpu_archs[i].name;
    }
    return NULL;
}

/**
 * @brief Returns a descriptive label for the given symbol search mode.
 *
 * @param mode The search mode enum value.
 * @return A constant string describing the search mode.
 */
static const char *search_mode_label(search_mode_t mode) {
    switch (mode) {
    case FULL_STRING_MATCH: return "exact match";
    case SUBSTRING_MATCH:     return "substring";
    case REGEXP_MATCH:        return "regular expression";
    }
    return "unknown";
}

/**
 * @brief Returns a descriptive label for the case sensitivity setting.
 *
 * @param search_case Case sensitivity setting.
 * @return A constant string ("case-insensitive" or "case-sensitive").
 */
static const char *search_case_label(search_case_t search_case) {
    return search_case == SEARCH_CASE_INSENSITIVE ? "case-insensitive" : "case-sensitive";
}

/**
 * @brief Prints current search parameters (search mode and case sensitivity) to stdout.
 *
 * @param search_mode The search mode.
 * @param search_case Case sensitivity mode.
 */
static void print_search_info(search_mode_t search_mode, search_case_t search_case) {
    printf("search mode: %s (%s)\n", search_mode_label(search_mode), search_case_label(search_case));
}

/**
 * @brief Prints the address formatting type being used in the output.
 *
 * @param is_vmaddr_output True if printing Virtual Memory addresses, false for file offsets.
 */
static void print_addresses_info(bool is_vmaddr_output) {
    printf("Addresses type: %s\n", is_vmaddr_output ? "Virtual memory address (vmaddr)" : "File offset (from start of file)");
}

/**
 * @brief Prints a header with the architecture name being processed.
 *
 * @param cputype Mach-O CPU type identifier.
 */
static void print_arch_header(int32_t cputype) {
    const char *arch_name = arch2str(cputype);
    if (arch_name != NULL)
        printf("architecture: %s\n", arch_name);
    else
        printf("architecture: unknown (0x%x)\n", cputype);
}

/**
 * @brief Prints symbol lookup results for a specified index range in the offset list.
 *
 * @param poffs Pointer to the list of found patch offsets.
 * @param start Start index in the list (inclusive).
 * @param end End index in the list (exclusive).
 * @param search_mode The search mode used (determines whether symbol names are printed).
 */
static void print_lookup_results_range(const patch_off_list_t *poffs, size_t start, size_t end,
                                       search_mode_t search_mode) {
    bool show_symbol_names = search_mode != FULL_STRING_MATCH;

    for (size_t i = start; i < end; i++) {
        const patch_off_t *poff = &poffs->items[i];
        const long display_value = o_vmaddr_output ? poff->addr : poff->fileoff;
        if (show_symbol_names && poff->symbol_name != NULL)
            printf("0x%lx: %s\n", display_value, poff->symbol_name);
        else
            printf("0x%lx\n", display_value);
    }
}

/**
 * @brief Prints all resolved symbol lookup results from the patch offset list.
 *
 * @param poffs Pointer to the list of found patch offsets.
 * @param search_mode The search mode used.
 */
static void print_lookup_results(const patch_off_list_t *poffs, search_mode_t search_mode) {
    print_lookup_results_range(poffs, 0, poffs->count, search_mode);
}

/**
 * @brief Prints a summary line indicating the number of matched symbols.
 *
 * @param count Total number of matches found.
 */
static void print_lookup_summary(size_t count) {
    if (count == 1)
        printf("1 match found\n");
    else
        printf("%zu matches found\n", count);
}

/**
 * @brief Searches for target symbols in a Mach-O image slice at a given file offset.
 *
 * Checks if the target architecture matches requested filter options, sets file offset,
 * invokes Mach-O symbol resolution, and records new matches in the offsets list.
 *
 * @param fp Pointer to the opened file stream.
 * @param offset File offset to the Mach-O header slice.
 * @param cputype Architecture CPU type of the current slice.
 * @param poffs Output list where discovered symbol offsets are added.
 * @param search_mode Search mode (exact, substring, or regex).
 * @param search_case Case sensitivity setting.
 * @return Number of new symbol matches found for this architecture slice.
 */
int find_symbol(FILE *fp, int offset, int32_t cputype, patch_off_list_t *poffs,
                search_mode_t search_mode, search_case_t search_case) {
    size_t before = poffs->count;
    if (o_patch_arch == 0 || (cputype & o_patch_arch) == cputype) {
        g_searched_arch |= cputype;
        fseek(fp, offset, SEEK_SET);
        if (lookup_symbol_macho(fp, o_symbol, poffs, search_mode, search_case) == 0)
            fprintf(stderr, "symbol not found for arch '%s'!\n", arch2str(cputype));

        if (o_mode == LOOKUP_MODE && !o_quiet) {
            const size_t added = poffs->count - before;
            if (added > 0) {
                print_arch_header(cputype);
                print_lookup_results_range(poffs, before, poffs->count, search_mode);
            }
        }
    }
    return (int)(poffs->count - before);
}

/**
 * @brief Applies a patch payload to the specified file location.
 *
 * Writes either a custom user-defined patch or an architecture-specific built-in patch
 * into the target file at `poff.fileoff`. Validates maximum patch length safety limit.
 *
 * @param fp Pointer to the opened binary file stream (opened in write/update mode).
 * @param poff Structure describing patch location, architecture, and length constraints.
 * @return 0 on success, or 1 on error (e.g., buffer overflow or write failure).
 */
int patch_file(FILE* fp, patch_off_t poff) {
    const data_t *final_patch = &o_patch_data;
    if (o_use_builtin_patch) {
        if (poff.cputype == CPU_TYPE_X86_64)
            final_patch = &builtin_patches[o_builtin_idx].x86_64_p;
        else if (poff.cputype == CPU_TYPE_ARM64)
            final_patch = &builtin_patches[o_builtin_idx].arm64_p;
        else {
            fprintf(stderr, "symp: unknown arch in patch_off_t!\n");
            return 1;
        }
    }
    if (poff.maxplen != 0 && final_patch->len > poff.maxplen) {
        fprintf(stderr, "symp: patch length(%zu) exceeded! (max %d)\n", final_patch->len, poff.maxplen);
        return 1;
    }
    fseek(fp, poff.fileoff, SEEK_SET);
    if (fwrite(final_patch->buf, final_patch->len, 1, fp) != 1) {
        perror("fwrite");
        return 1;
    }
    return 0;
}

/**
 * @brief Main entry point for the executable patching/lookup utility (`symp`).
 *
 * Parses CLI arguments, detects Mach-O format (Single 64-bit vs FAT Universal Binary),
 * resolves symbol locations across target architectures, and executes either a symbol
 * lookup display or binary patching.
 *
 * @param argc Number of command-line arguments.
 * @param argv Array of command-line argument strings.
 * @return 0 on success, or non-zero error code on failure.
 */
int main(int argc, char **argv) {
    int error = 0;

    /* Parse CLI flags and arguments */
    if (parse_arguments(argc, argv) != 0)
        return 1;
    if (o_mode == USAGE_MODE)
        return 0; /* usage info already printed */

    patch_off_list_t poffs;
    patch_off_list_init(&poffs);

    /* Open target file in binary read or update mode depending on operational mode */
    char *fmode = "rb";
    if (o_mode == PATCH_MODE)
        fmode = "rb+";
    FILE *fp = fopen(o_file, fmode);
    if (fp == NULL) {
        perror("fopen");
        return 1;
    }

    /* Identify binary header type (Mach-O magic header detection) */
    uint32_t file_magic;
    fread(&file_magic, sizeof(uint32_t), 1, fp);
    switch(file_magic) {
    case MH_MAGIC_64: { /* Single 64-bit Mach-O binary */
        int32_t cputype;
        fread(&cputype, sizeof(int32_t), 1, fp);
        find_symbol(fp, 0, cputype, &poffs, o_search_mode, o_search_case);
        break;
    }
    case FAT_CIGAM: { /* FAT Universal Binary (on little-endian host CPU) (big-endian headers on disk) */
        uint32_t nfat_arch;
        fread(&nfat_arch, sizeof(int32_t), 1, fp);
        nfat_arch = OSSwapInt32(nfat_arch);
        size_t total_size = nfat_arch * sizeof(struct fat_arch);
        struct fat_arch *archs = read_file(fp, total_size);
        for (int i = 0; i < nfat_arch; i++) {
            const int32_t cputype = OSSwapInt32(archs[i].cputype);
            const int32_t offset = OSSwapInt32(archs[i].offset);
            find_symbol(fp, offset, cputype, &poffs, o_search_mode, o_search_case);
        }
        free(archs);
        break;
    }
    default:
        fprintf(stderr, "symp: not a valid Mach-O or FAT file\n");
        goto err_ret;
    }

    /* Verify that all requested architectures were present in the file */
    if (o_patch_arch != 0 && g_searched_arch != o_patch_arch) {
        error = 1;
        int32_t unsearched_arch = o_patch_arch ^ g_searched_arch;
        for (int i = 0; i < ARRAY_LEN(cpu_archs); i++) {
            if ((unsearched_arch & cpu_archs[i].cputype) == cpu_archs[i].cputype)
                fprintf(stderr, "symp: offered arch '%s' not found in the file\n", cpu_archs[i].name);
        }
        goto err_ret;
    }

    /* Check if any symbol matches were found */
    if (poffs.count == 0) {
        error = 1;
        if (!o_quiet)
            printf("no matches found!\n");
        goto err_ret;
    }

    /* Process results according to active working mode */
    if (o_mode == LOOKUP_MODE) {
        if (o_quiet) {
            for (size_t i = 0; i < poffs.count; i++) {
                const patch_off_t *poff = &poffs.items[i];
                const long display_value = o_vmaddr_output ? poff->addr : poff->fileoff;
                printf("0x%lx\n", display_value);
            }
        } else {
            print_addresses_info(o_vmaddr_output);
            print_search_info(o_search_mode, o_search_case);
            print_lookup_summary(poffs.count);
        }
    }
    else if (o_mode == PATCH_MODE) {
        int patched = 0;
        for (; patched < (int)poffs.count; patched++) {
            if (patch_file(fp, poffs.items[patched]) != 0) {
                error = 1;
                break;
            }
        }
        if (!o_quiet) {
            print_addresses_info(o_vmaddr_output);
            print_search_info(o_search_mode, o_search_case);
            if (patched <= 1)
                printf("%d(%zu) match patched\n", patched, poffs.count);
            else {
                if (!o_use_builtin_patch)
                    fprintf(stderr, "symp: warning, multiple arches used the same patch\n");
                printf("%d(%zu) matches patched\n", patched, poffs.count);
            }
        }
    }
    else {
        error = 1;
        fprintf(stderr, "symp: unknown working mode!\n");
    }

err_ret:
    /* Clean up dynamic resources */
    patch_off_list_free(&poffs);
    fclose(fp);
    free(o_patch_data.buf);
    return error;
}