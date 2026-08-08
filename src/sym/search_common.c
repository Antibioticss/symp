#include "private.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <regex.h>

static const size_t SYMBOL_MATCHES_INIT_CAP = 16;

void symbol_matches_init(symbol_matches_t *m) {
    m->addrs = NULL;
    m->names = NULL;
    m->count = 0;
    m->capacity = 0;
}

void symbol_matches_free(symbol_matches_t *m) {
    if (m->names != NULL) {
        for (size_t i = 0; i < m->count; i++)
            free(m->names[i]);
    }
    free(m->addrs);
    free(m->names);
    symbol_matches_init(m);
}

void symbol_matches_push(symbol_matches_t *m, uint64_t addr, const char *name) {
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

bool str_equals(const char *a, const char *b, search_case_t search_case) {
    if (search_case == SEARCH_CASE_INSENSITIVE)
        return strcasecmp(a, b) == 0;
    return strcmp(a, b) == 0;
}

bool str_contains(const char *haystack, const char *needle, search_case_t search_case) {
    if (search_case == SEARCH_CASE_INSENSITIVE)
        return strcasestr(haystack, needle) != NULL;
    return strstr(haystack, needle) != NULL;
}

bool compile_regex(regex_t *preg, const char *pattern, search_case_t search_case) {
    int regflags = REG_EXTENDED | REG_ENHANCED | REG_NOSUB;
    if (search_case == SEARCH_CASE_INSENSITIVE)
        regflags |= REG_ICASE;
    return regcomp(preg, pattern, regflags) == 0;
}

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
