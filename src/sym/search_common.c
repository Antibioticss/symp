#include "private.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <regex.h>

/**
 * @brief Default initial allocation capacity for symbol matches dynamic arrays.
 */
static const size_t SYMBOL_MATCHES_INIT_CAP = 16;

/**
 * @brief Initializes a symbol_matches_t collection structure.
 *
 * Resets internal pointers, counters, and capacity to zero/NULL.
 *
 * @param m Pointer to the symbol matches structure to initialize.
 */
void symbol_matches_init(symbol_matches_t *m) {
    m->addrs = NULL;
    m->names = NULL;
    m->count = 0;
    m->capacity = 0;
}

/**
 * @brief Frees all allocated memory within a symbol_matches_t collection.
 *
 * Deallocates every dynamically copied symbol name, the addresses buffer,
 * and the names buffer, then resets the structure to an empty state.
 *
 * @param m Pointer to the symbol matches structure to free.
 */
void symbol_matches_free(symbol_matches_t *m) {
    if (m->names != NULL) {
        for (size_t i = 0; i < m->count; i++)
            free(m->names[i]);
    }
    free(m->addrs);
    free(m->names);
    symbol_matches_init(m);
}

/**
 * @brief Pushes a new symbol match (address and name) to the collection.
 *
 * Deduplicates entries by checking if the address already exists in the collection.
 * Dynamically reallocates capacity if the internal array is full.
 *
 * @param m Pointer to the symbol matches collection.
 * @param addr Address of the matched symbol.
 * @param name Name of the matched symbol (duplicated via strdup if non-NULL).
 */
void symbol_matches_push(symbol_matches_t *m, uint64_t addr, const char *name) {
    for (size_t i = 0; i < m->count; i++) {
        if (m->addrs[i] == addr)
            return;
    }

    if (m->count == m->capacity) {
        size_t new_cap = m->capacity == 0 ? SYMBOL_MATCHES_INIT_CAP : m->capacity * 2;
        uint64_t *new_addrs = realloc(m->addrs, new_cap * sizeof(uint64_t));
        char **new_names = realloc(m->names, new_cap * sizeof(char *));
        if (new_addrs == NULL || new_names == NULL) {
            fprintf(stderr, "symp: out of memory while collecting symbol matches\n");
            free(new_addrs);
            free(new_names);
            return;
        }
        m->addrs = new_addrs;
        m->names = new_names;
        m->capacity = new_cap;
    }
    m->addrs[m->count] = addr;
    m->names[m->count] = name ? strdup(name) : NULL;
    m->count++;
}

/**
 * @brief Compares two strings for equality with configurable case-sensitivity.
 *
 * @param a First null-terminated string.
 * @param b Second null-terminated string.
 * @param search_case Flag indicating whether the search should be case-sensitive.
 * @return true if the strings match, false otherwise.
 */
bool str_equals(const char *a, const char *b, search_case_t search_case) {
    if (search_case == SEARCH_CASE_INSENSITIVE)
        return strcasecmp(a, b) == 0;
    return strcmp(a, b) == 0;
}

/**
 * @brief Checks if a string contains a specified substring.
 *
 * @param haystack Target string to search within.
 * @param needle Substring to search for.
 * @param search_case Flag indicating whether the search should be case-sensitive.
 * @return true if needle is found within haystack, false otherwise.
 */
bool str_contains(const char *haystack, const char *needle, search_case_t search_case) {
    if (search_case == SEARCH_CASE_INSENSITIVE)
        return strcasestr(haystack, needle) != NULL;
    return strstr(haystack, needle) != NULL;
}

/**
 * @brief Compiles a POSIX regular expression pattern.
 *
 * Configures the regex with extended syntax (REG_EXTENDED), enhanced features (REG_ENHANCED),
 * and disables subgroup location recording (REG_NOSUB) for optimal performance.
 *
 * @param[out] preg Pointer to the target regex_t structure.
 * @param[in] pattern Regular expression pattern string to compile.
 * @param[in] search_case Flag indicating whether matching should be case-insensitive.
 * @return true if regex compilation succeeds, false otherwise.
 */
bool compile_regex(regex_t *preg, const char *pattern, search_case_t search_case) {
    int regflags = REG_EXTENDED | REG_ENHANCED | REG_NOSUB;
    if (search_case == SEARCH_CASE_INSENSITIVE)
        regflags |= REG_ICASE;
    return regcomp(preg, pattern, regflags) == 0;
}

/**
 * @brief Tests a candidate symbol string against search criteria.
 *
 * Supports exact string matching, substring matching, and POSIX regular expressions.
 *
 * @param string Candidate symbol string to evaluate.
 * @param pattern Text pattern for exact or substring search mode.
 * @param mode Matching mode (FULL_STRING_MATCH, SUBSTRING_MATCH, or REGEXP_MATCH).
 * @param search_case Case-sensitivity option (used for string and substring comparisons).
 * @param preg Pointer to a pre-compiled regex object (required for REGEXP_MATCH mode).
 * @return true if the candidate string matches the search criteria, false otherwise.
 */
bool match_symbol(const char *string, const char *pattern, search_mode_t mode,
                  search_case_t search_case, const regex_t *preg) {
    switch (mode) {
    case FULL_STRING_MATCH:
        return str_equals(string, pattern, search_case);
    case SUBSTRING_MATCH:
        return str_contains(string, pattern, search_case);
    case REGEXP_MATCH:
        return preg != NULL && regexec(preg, string, 0, NULL, 0) == 0;
    default:
        return false;
    }
}
