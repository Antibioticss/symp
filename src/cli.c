#include "private.h"

#include <string.h>
#include <stdint.h>
#include <getopt.h>
#include <mach-o/fat.h>

/** @brief Current operation mode of the tool (e.g., LOOKUP_MODE, PATCH_MODE, USAGE_MODE). */
work_mode_t o_mode = LOOKUP_MODE;

/** @brief Target symbol name or pattern to search for or patch. */
char *o_symbol;

/** @brief Path to the target Mach-O binary file. */
char *o_file;

/** @brief Bitmask representing target CPU architectures (e.g., CPU_TYPE_X86_64, CPU_TYPE_ARM64). */
int o_patch_arch = 0;

/** @brief Holds raw byte buffer and length for custom patches loaded from file or hex string. */
data_t o_patch_data = {0, NULL};

/** @brief Flag indicating whether a built-in patch preset is selected. */
bool o_use_builtin_patch = false;

/** @brief Index of the selected built-in patch preset in the global patches array. */
int o_builtin_idx = -1;

/** @brief Suppresses match count and non-critical messages when true. */
bool o_quiet = false;

/** @brief Prints target addresses as virtual memory addresses instead of file offsets when true. */
bool o_vmaddr_output = false;

/** @brief Symbol matching mode (FULL_STRING_MATCH, REGEXP_MATCH, or SUBSTRING_MATCH). */
search_mode_t o_search_mode = FULL_STRING_MATCH;

/** @brief Case sensitivity option for symbol matching (SEARCH_CASE_SENSITIVE or SEARCH_CASE_INSENSITIVE). */
search_case_t o_search_case = SEARCH_CASE_SENSITIVE;

/**
 * @brief Displays tool usage and available command-line options.
 */
static void usage() {
    puts("symp - Mach-O symbol patching tool");
    puts("usage: symp [options] -- <symbol> <file>");
    puts("options:");
    puts("  -a, --arch <arch>         select an arch in the binary, supported: x86_64/arm64");
    puts("  -p, --patch <patch>       use builtin patches, available: nop, ret, ret0, ret1, ret2");
    puts("  -b, --binary <binary>     use a binary file as patch");
    puts("  -x, --hex <hex string>    hex string of the patch");
    puts("  -q, --quiet               suppress match count messages");
    puts("  --vmaddr                  print addresses as architecture-relative offsets");
    puts("  -v, --version             show version number");
    puts("  -h, --help                show this usage text");
    puts("  -r, --regexp              use regular expressions for symbol matching");
    puts("  -s, --substring           use substring matching for symbol matching");
    puts("  -i, --ignore-case         case-insensitive symbol matching");
    puts("  -c, --case-sensitive      case-sensitive symbol matching (default)");
}

/**
 * @brief Parses command-line arguments and sets global configuration variables.
 *
 * @param argc Argument count passed from main().
 * @param argv Argument vector passed from main().
 * @return 0 on successful parsing, 1 on syntax error or invalid argument combinations.
 */
int parse_arguments(int argc, char **argv) {
    if (argc <= 1) {
        usage();
        return 1;
    }

    size_t xlen = 0;
    uint8_t *xbuf = NULL;
    bool case_option_set = false;

    while(1) {
        /* Long options definitions for getopt_long */
        static struct option long_options[] = {
            {"arch",           required_argument, 0, 'a'},
            {"patch",          required_argument, 0, 'p'},
            {"binary",         required_argument, 0, 'b'},
            {"hex",            required_argument, 0, 'x'},
            {"quiet",          no_argument,       0, 'q'},
            {"vmaddr",         no_argument,       0, 0},
            {"version",        no_argument,       0, 'v'},
            {"help",           no_argument,       0, 'h'},
            {"regexp",         no_argument,       0, 'r'},
            {"substring",      no_argument,       0, 's'},
            {"ignore-case",    no_argument,       0, 'i'},
            {"case-sensitive", no_argument,       0, 'c'},
            {0, 0, 0, 0}
        };
        int option_index = 0;
        int c = getopt_long(argc, argv, "a:p:b:x:qvhrsci", long_options, &option_index);
        if (c == -1)
            break;

        switch (c) {
        case 'a':
            /* Target CPU architecture selection */
            if (strcmp("x86_64", optarg) == 0)
                o_patch_arch |= CPU_TYPE_X86_64;
            else if (strcmp("arm64", optarg) == 0)
                o_patch_arch |= CPU_TYPE_ARM64;
            else {
                fprintf(stderr, "symp: unsupported arch %s\n", optarg);
                goto err;
            }
            break;

        case 'r':
            /* Enable regular expression matching mode */
            if (o_search_mode == SUBSTRING_MATCH) {
                fprintf(stderr, "symp: only one of regexp/substring can be offered\n");
                goto err;
            }
            o_search_mode = REGEXP_MATCH;
            break;

        case 's':
            /* Enable substring matching mode */
            if (o_search_mode == REGEXP_MATCH) {
                fprintf(stderr, "symp: only one of regexp/substring can be offered\n");
                goto err;
            }
            o_search_mode = SUBSTRING_MATCH;
            break;

        case 'i':
            /* Enable case-insensitive search */
            if (case_option_set) {
                fprintf(stderr, "symp: only one of ignore-case/case-sensitive can be offered\n");
                goto err;
            }
            o_search_case = SEARCH_CASE_INSENSITIVE;
            case_option_set = true;
            break;

        case 'c':
            /* Enable case-sensitive search (default) */
            if (case_option_set) {
                fprintf(stderr, "symp: only one of ignore-case/case-sensitive can be offered\n");
                goto err;
            }
            o_search_case = SEARCH_CASE_SENSITIVE;
            case_option_set = true;
            break;

        case 'b':
            /* Load patch payload from a binary file */
            if (xbuf || o_use_builtin_patch) {
                fprintf(stderr, "symp: only one of -p/-b/-x should be offered\n");
                goto err;
            }
            FILE * bfp = fopen(optarg, "rb");
            if (bfp != 0) {
                fseek(bfp, 0, SEEK_END);
                xlen = ftell(bfp);
                xbuf = malloc(xlen);
                fread(xbuf, xlen, 1, bfp);
                fclose(bfp);
            }
            else {
                perror("fopen");
                goto err;
            }
            break;

        case 'p':
            /* Select a built-in patch preset by name */
            if (xbuf || o_use_builtin_patch) {
                fprintf(stderr, "symp: only one of -p/-b/-x should be offered\n");
                goto err;
            }
            o_use_builtin_patch = true;
            for (int i = 0; i < builtin_patches_count; i++) {
                if (strcmp(builtin_patches[i].name, optarg) == 0) {
                    o_builtin_idx = i;
                    break;
                }
            }
            if (o_builtin_idx == -1) {
                fprintf(stderr, "symp: unknow patch %s\n", optarg);
                goto err;
            }
            break;

        case 'x':
            /* Parse raw hex string payload into binary buffer */
            if (xbuf || o_use_builtin_patch) {
                fprintf(stderr, "symp: only one of -p/-b/-x should be offered\n");
                goto err;
            }
            xlen = 0;
            size_t buf_size = strlen(optarg) >> 1;
            xbuf = malloc(buf_size);
            memset(xbuf, 0, buf_size);

            for (int i = 0; optarg[i]; i++) {
                char ch = optarg[i];
                if (ch >= '0' && ch <= '9')      xbuf[xlen>>1] |= (ch-'0')     << (((xlen+1)%2)*4), ++xlen;
                else if (ch >= 'A' && ch <= 'F') xbuf[xlen>>1] |= (ch-'A'+10) << (((xlen+1)%2)*4), ++xlen;
                else if (ch >= 'a' && ch <= 'f') xbuf[xlen>>1] |= (ch-'a'+10) << (((xlen+1)%2)*4), ++xlen;
                else if (ch != ' ' && ch != '\t' && ch != '\r' && ch != '\n') {
                    fprintf(stderr, "symp: invalid character '%c' in hex string\n", ch);
                    goto err;
                }
            }
            if (xlen%2 != 0) {
                fprintf(stderr, "symp: hex string length should be oven\n");
                goto err;
            }
            xlen >>= 1;
            break;

        case 'q':
            o_quiet = true;
            break;

        case 0:
            /* Handle options without single-letter shortcuts (e.g., --vmaddr) */
            if (strcmp(long_options[option_index].name, "vmaddr") == 0) {
                o_vmaddr_output = true;
                break;
            }
            /* fall through */

        case 'v':
            /* Output version information */
            printf("symp v%s\n", VERSION_STR);
            o_mode = USAGE_MODE;
            free(xbuf);
            return 0;

        case 'h':
            /* Output help text */
            usage();
            o_mode = USAGE_MODE;
            free(xbuf);
            return 0;

        case '?':
            goto err;

        default:
            abort();
        }
    }

    /* Validate required positional arguments: <symbol> and <file> */
    if (argc - optind != 2) {
        if (argc - optind < 2)
            fprintf(stderr, "symp: arguments not enough!\n");
        else
            fprintf(stderr, "symp: too many arguments!\n");
        goto err;
    }

    /* Configure operating mode and patch buffer if a patch source was specified */
    if (xbuf != NULL) {
        o_mode = PATCH_MODE;
        o_patch_data.len = xlen;
        o_patch_data.buf = xbuf;
    }
    else if (o_use_builtin_patch) {
        o_mode = PATCH_MODE;
    }

    /* Store positional parameters */
    o_symbol = argv[optind++];
    o_file = argv[optind++];
    return 0;

err:
    free(xbuf);
    return 1;
}