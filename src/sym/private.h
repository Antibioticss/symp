/**
 * @file sym_private.h
 * @brief Internal structures, parsing functions, and helper utilities for 
 *        Mach-O symbol resolution and Objective-C metadata inspection.
 */

#ifndef SYM_PRIVATE
#define SYM_PRIVATE

#include "../private.h"

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <regex.h>

/**
 * @brief Type-safe maximum macro using GNU statement expressions.
 * @param a First value to compare.
 * @param b Second value to compare.
 * @return The greater of @p a and @p b.
 */
#define max(a,b) \
  ({ __typeof__ (a) _a = (a); \
      __typeof__ (b) _b = (b); \
    _a > _b ? _a : _b; })

/**
 * @brief Represents a offset-based slice or segment within a file.
 */
typedef struct {
    uint32_t off;   /**< File offset in bytes from the start of the file or sub-slice. */
    uint64_t size;  /**< Size of the segment in bytes. */
} fileseg_t;

/**
 * @brief Represents a virtual memory segment mapped from a file.
 */
typedef struct {
    uint32_t off;   /**< Offset within the file in bytes. */
    uint64_t addr;  /**< Virtual memory address where the segment is loaded. */
    uint64_t size;  /**< Size of the segment in virtual memory in bytes. */
} vmseg_t;

/**
 * @brief Basic architectural and positioning information for a Mach-O binary.
 */
typedef struct {
    int32_t cputype;   /**< Target CPU architecture (e.g., CPU_TYPE_X86_64, CPU_TYPE_ARM64). */
    long base_offset;  /**< Base file offset for fat/universal binaries or single Mach-O images. */

    /* __TEXT vm slide */
    int64_t vm_slide;  /**< Virtual memory slide adjustment for the __TEXT segment. */
} macho_basic_info_t;

/**
 * @brief Symbol-related metadata parsed from various Mach-O load commands.
 */
typedef struct {
    int32_t cputype;   /**< Target CPU architecture type. */
    long base_offset;  /**< Base offset within the binary file. */

    /* __TEXT vm slide */
    int64_t vm_slide;  /**< Virtual memory slide adjustment. */

    /* from LC_SYMTAB */
    uint32_t symoff;   /**< File offset to the symbol table (`struct nlist_64`). */
    uint32_t nsyms;    /**< Number of entries in the symbol table. */
    fileseg_t strtab;  /**< File segment containing the string table. */

    /* from LC_DYLD_INFO(_ONLY) or LC_DYLD_EXPORTS_TRIE */
    fileseg_t export;  /**< File segment pointing to the Dyld Export Trie data. */

    /* from LC_DYSYMTAB */
    uint32_t indirectsymoff; /**< File offset to the indirect symbol table. */

    /* from S_SYMBOL_STUBS section */
    fileseg_t stubs;          /**< File segment containing code stubs for external symbols. */
    uint32_t indirectsym_idx; /**< Index in the indirect symbol table corresponding to stubs. */
    uint32_t stub_len;        /**< Length of an individual stub instruction block in bytes. */
} macho_symbol_info_t;

/**
 * @brief Structural information for parsing Objective-C runtime metadata.
 */
typedef struct {
    int32_t cputype;   /**< Target CPU architecture type. */
    long base_offset;  /**< Base file offset of the Mach-O binary. */

    /* vm segment */
    vmseg_t text_vm;   /**< Virtual memory metadata for the __TEXT segment. */
    vmseg_t datac_vm;  /**< Virtual memory metadata for the __DATA_CONST segment. */
    vmseg_t data_vm;   /**< Virtual memory metadata for the __DATA segment. */

    /* has LC_DYLD_CHAINED_FIXUPS? */
    bool chained_fixup; /**< Flag indicating presence of Dyld chained fixups. */

    /* objc sections */
    fileseg_t objc_classlist; /**< File segment containing pointers to Objective-C classes. */
    fileseg_t objc_catlist;   /**< File segment containing pointers to Objective-C categories. */
} macho_objc_info_t;

/* 
 * defined in macho.c
 */

/**
 * @brief Parses basic structural information from a Mach-O file header.
 * @param fp Open file handle pointing to the Mach-O binary.
 * @return Pointer to dynamically allocated `macho_basic_info_t`, or NULL on failure.
 */
macho_basic_info_t *parse_basic_info(FILE *fp);

/**
 * @brief Parses symbol tables, export tries, and stub sections from a Mach-O file.
 * @param fp Open file handle pointing to the Mach-O binary.
 * @return Pointer to dynamically allocated `macho_symbol_info_t`, or NULL on failure.
 */
macho_symbol_info_t *parse_symbol_info(FILE *fp);

/**
 * @brief Parses Objective-C metadata sections and segment info from a Mach-O file.
 * @param fp Open file handle pointing to the Mach-O binary.
 * @return Pointer to dynamically allocated `macho_objc_info_t`, or NULL on failure.
 */
macho_objc_info_t *parse_objc_info(FILE *fp);

/**
 * @brief Dynamic array container for storing resolved symbol matches.
 */
typedef struct {
    uint64_t *addrs;  /**< Array of resolved virtual/file addresses. */
    char **names;     /**< Array of dynamically allocated symbol names. */
    size_t count;     /**< Current number of matched symbols. */
    size_t capacity;  /**< Current allocated capacity of the internal buffers. */
} symbol_matches_t;

/**
 * @brief Initializes a `symbol_matches_t` structure.
 * @param m Pointer to the match container to initialize.
 */
void symbol_matches_init(symbol_matches_t *m);

/**
 * @brief Frees memory allocated inside a `symbol_matches_t` structure.
 * @param m Pointer to the match container to release.
 */
void symbol_matches_free(symbol_matches_t *m);

/**
 * @brief Appends a matched address and symbol name to the container.
 * @param m Pointer to the match container.
 * @param addr Resolved address for the symbol.
 * @param name Name of the matched symbol (will be duplicated internally).
 */
void symbol_matches_push(symbol_matches_t *m, uint64_t addr, const char *name);

/**
 * @brief Compares two strings for equality based on the specified case sensitivity mode.
 * @param a First null-terminated string.
 * @param b Second null-terminated string.
 * @param search_case Sensitivity option (case-sensitive or case-insensitive).
 * @return True if strings are equal according to the rules, false otherwise.
 */
bool str_equals(const char *a, const char *b, search_case_t search_case);

/**
 * @brief Checks if a substring exists within a string based on case sensitivity rules.
 * @param haystack String to search within.
 * @param needle Substring to search for.
 * @param search_case Sensitivity option (case-sensitive or case-insensitive).
 * @return True if needle is found inside haystack, false otherwise.
 */
bool str_contains(const char *haystack, const char *needle, search_case_t search_case);

/**
 * @brief Compiles a regular expression with configured case sensitivity flags.
 * @param preg Output compiled POSIX regex object.
 * @param pattern Regex pattern string.
 * @param search_case Case sensitivity configuration.
 * @return True if compilation succeeded, false on regex syntax error.
 */
bool compile_regex(regex_t *preg, const char *pattern, search_case_t search_case);

/**
 * @brief Evaluates whether a candidate symbol string matches search criteria.
 * @param string Candidate symbol string to test.
 * @param pattern Search pattern (exact string, substring, or regex pattern).
 * @param mode Matching mode (exact, substring, or regex).
 * @param search_case Sensitivity option (case-sensitive or case-insensitive).
 * @param preg Pre-compiled regex object (used if mode is SEARCH_MODE_REGEX).
 * @return True if the string satisfies the criteria, false otherwise.
 */
bool match_symbol(const char *string, const char *pattern, search_mode_t mode,
                  search_case_t search_case, const regex_t *preg);

/* defined in symbol.c */

/**
 * @brief Searches and resolves symbols in standard Mach-O symbol structures 
 *        (Export Trie, Symbol Stubs, and Symbol Table).
 * @param fp Open file handle pointing to the Mach-O file.
 * @param macho_info Mach-O symbol metadata parsed previously.
 * @param symbol_name Symbol query pattern.
 * @param search_mode Matching strategy (exact match, substring, regex, etc.).
 * @param search_case Case sensitivity setting.
 * @param out Output match container receiving matched address-name pairs.
 * @return Total number of matched symbols added to @p out.
 */
size_t solve_symbol(FILE *fp, const macho_symbol_info_t *macho_info, const char *symbol_name,
                    search_mode_t search_mode, search_case_t search_case, symbol_matches_t *out);

/* defined in objcmeta.c */

/**
 * @brief Resolves Objective-C symbols (classes, categories, methods) matching search criteria.
 * @param fp Open file handle pointing to the Mach-O file.
 * @param mi Objective-C metadata parser info.
 * @param symbol_name Query string/pattern to match against Objective-C symbols.
 * @param search_mode Matching strategy.
 * @param search_case Case sensitivity setting.
 * @param out Output match container receiving matched address-name pairs.
 * @return Total number of matched Objective-C symbols added to @p out.
 */
size_t solve_objc_symbol(FILE *fp, const macho_objc_info_t *mi, const char* symbol_name,
                         search_mode_t search_mode, search_case_t search_case, symbol_matches_t *out);

#endif
