#ifndef SYMP_PRIVATE_H
#define SYMP_PRIVATE_H

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>

#define VERSION_STR "1.3"

#define ARRAY_LEN(arr) (sizeof(arr) / sizeof((arr)[0]))

typedef enum {
	USAGE_MODE,
	LOOKUP_MODE,
	PATCH_MODE
} work_mode_t;

typedef enum {
	FULL_STRING_MATCH,
	SUBSTRING_MATCH,
	REGEXP_MATCH
} search_mode_t;

typedef enum {
	SEARCH_CASE_SENSITIVE,
	SEARCH_CASE_INSENSITIVE
} search_case_t;

typedef struct {
	size_t len;
    uint8_t *buf;
} data_t;

typedef struct {
	char *name;
	data_t x86_64_p, arm64_p;
} builtin_patch_t;

/* defined in builtin.c */
extern builtin_patch_t builtin_patches[];
extern int builtin_patches_count;

/* (o)ptions, defined in cli.c */
extern work_mode_t o_mode;
extern search_mode_t o_search_mode;
extern search_case_t o_search_case;
extern char *o_symbol, *o_file;
extern int o_patch_arch;
extern data_t o_patch_data;
extern bool o_use_builtin_patch;
extern int o_builtin_idx;
extern bool o_quiet;

int parse_arguments(int argc, char **argv);

#endif