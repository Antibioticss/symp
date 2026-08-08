/**
 * @file symp_private.h
 * @brief Internal definitions, data structures, and command-line options for the symp tool.
 */

#ifndef SYMP_PRIVATE_H
#define SYMP_PRIVATE_H

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>

/** Current application version string. */
#define VERSION_STR "1.3"

/**
 * @brief Calculates the number of elements in a static array.
 * @param arr Target array.
 */
#define ARRAY_LEN(arr) (sizeof(arr) / sizeof((arr)[0]))

/**
 * @brief Operational modes of the application.
 */
typedef enum {
    USAGE_MODE,  /**< Display usage information and exit. */
    LOOKUP_MODE, /**< Search and resolve symbols in a target binary. */
    PATCH_MODE   /**< Patch a symbol location with specified bytes. */
} work_mode_t;

/**
 * @brief Matching strategies for symbol searching.
 */
typedef enum {
    FULL_STRING_MATCH, /**< Match exact full string. */
    SUBSTRING_MATCH,   /**< Match partial substring. */
    REGEXP_MATCH       /**< Match using regular expressions. */
} search_mode_t;

/**
 * @brief Case sensitivity options for string matching.
 */
typedef enum {
    SEARCH_CASE_SENSITIVE,   /**< Case-sensitive search. */
    SEARCH_CASE_INSENSITIVE  /**< Case-insensitive search. */
} search_case_t;

/**
 * @brief Container for raw binary data buffer and its length.
 */
typedef struct {
    size_t len;   /**< Size of the buffer in bytes. */
    uint8_t *buf; /**< Pointer to the byte array payload. */
} data_t;

/**
 * @brief Represents a pre-defined built-in patch payload per architecture.
 */
typedef struct {
    char *name;         /**< Human-readable identifier/name of the patch. */
    data_t x86_64_p;    /**< Binary patch payload for x86_64 architecture. */
    data_t arm64_p;     /**< Binary patch payload for ARM64 architecture. */
} builtin_patch_t;

/* Global declarations defined in builtin.c */

/** Array of available built-in patches. */
extern builtin_patch_t builtin_patches[];

/** Total count of items in the builtin_patches array. */
extern int builtin_patches_count;

/* Global CLI options defined in cli.c */

extern work_mode_t o_mode;            /**< Active work mode selected via CLI. */
extern search_mode_t o_search_mode;   /**< Selected symbol matching strategy. */
extern search_case_t o_search_case;   /**< Selected case sensitivity option. */
extern char *o_symbol;                /**< Target symbol name, substring, or regex pattern. */
extern char *o_file;                  /**< Path to the target binary file. */
extern int o_patch_arch;              /**< Architecture ID targeted for patching. */
extern data_t o_patch_data;           /**< User-provided custom patch bytes. */
extern bool o_use_builtin_patch;      /**< Flag indicating if a built-in patch is used. */
extern int o_builtin_idx;             /**< Index of the selected built-in patch. */
extern bool o_quiet;                  /**< Quiet flag to suppress non-essential output. */
extern bool o_vmaddr_output;          /**< Flag to print virtual addresses instead of file offsets. */

/**
 * @brief Parses command-line arguments and sets global configuration flags.
 *
 * @param argc Argument count.
 * @param argv Argument vector.
 * @return 0 on successful parsing, non-zero on error or when help/version is requested.
 */
int parse_arguments(int argc, char **argv);

#endif /* SYMP_PRIVATE_H */
