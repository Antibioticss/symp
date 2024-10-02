#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <mach-o/fat.h>
#include <mach-o/dyld.h>
#include <mach-o/nlist.h>
#include <mach-o/loader.h>

/* builtin patches */
#define     BUILTIN_RET     1
#define     BUILTIN_RET0    1<<1
#define     BUILTIN_RET1    1<<2
#define     MAX_PATCH_SIZE  8

unsigned char x86_64_ret[]  = {0xC3};                    // ret
unsigned char x86_64_ret0[] = {0x48, 0x31, 0xC0,         // xor  rax, rax
                               0xC3};                    // ret
unsigned char x86_64_ret1[] = {0x48, 0x31, 0xC0,         // xor  rax, rax
                               0xB0, 0x01,               // mov  al, 0x1
                               0xC3};                    // ret

unsigned char arm64_ret[]  = {0xC0, 0x03, 0x5F, 0xD6};   // ret
unsigned char arm64_ret0[] = {0x00, 0x00, 0x80, 0xD2,    // mov  x0, 0x0
                              0xC0, 0x03, 0x5F, 0xD6};   // ret
unsigned char arm64_ret1[] = {0x20, 0x00, 0x80, 0xD2,    // mov  x0, 0x0
                              0xC0, 0x03, 0x5F, 0xD6};   // ret


char *symbol, *file;
unsigned char* patch_bytes = NULL;
int patch_count = 0, patch_arch = 0, builtin_patch = 0;

struct patch_off {
    int cputype;
    long int symoff;
};

void usage() {
    puts("symp - a symbol patching tool");
    puts("usage: symp [options] symbol file");
    puts("options:");
    puts("  -a, --arch <arch>         arch of the binary to be patched, only x86_64 and arm64 are supported");
    puts("  -p, --patch <patch>       use builtin patches, available: ret, ret0, ret1");
    puts("  -b, --binary <binary>     use a binary file as patch");
    puts("  -x, --hex <hex string>    hex string of the patch");
    return;
}

int parse_arguments(int argc, char **argv) {
    if (argc <= 2) {
        usage();
        return 1;
    }

    while(1) {
        static struct option long_options[] = {
            {"arch",   required_argument, 0, 'a'},
            {"patch",  required_argument, 0, 'p'},
            {"binary", required_argument, 0, 'b'},
            {"hex",    required_argument, 0, 'x'},
            {"help",   no_argument, 0, 'h'},
            {0, 0, 0, 0}
        };
        int option_index = 0;
        int c = getopt_long(argc, argv, "a:p:b:x:h", long_options, &option_index);
        if (c == -1)
            break;
        switch (c) {
        case 'a':
            if (strcmp("x86_64", optarg) == 0)
                patch_arch |= CPU_TYPE_X86_64;
            else if (strcmp("arm64", optarg) == 0)
                patch_arch |= CPU_TYPE_ARM64;
            else {
                fprintf(stderr, "symp: unsupported arch %s\n", optarg);
                return 1;
            }
            break;
        case 'b':
            if (patch_bytes || builtin_patch) {
                fprintf(stderr, "symp: only one of -p/-b/-x should be offered\n");
                return 1;
            }
            FILE * bfp = fopen(optarg, "rb");
            if (bfp != 0) {
                fseek(bfp, 0, SEEK_END);
                patch_count = ftell(bfp);
                patch_bytes = (unsigned char*)malloc(patch_count);
                fread(patch_bytes, patch_count, 1, bfp);
                fclose(bfp);
            }
            else {
                perror("fopen");
                return 1;
            }
            break;
        case 'p':
            if (patch_bytes || builtin_patch) {
                fprintf(stderr, "symp: only one of -p/-b/-x should be offered\n");
                return 1;
            }
            if (strcmp("ret", optarg) == 0)
                builtin_patch = BUILTIN_RET;
            else if (strcmp("ret0", optarg) == 0)
                builtin_patch = BUILTIN_RET0;
            else if (strcmp("ret1", optarg) == 0)
                builtin_patch = BUILTIN_RET1;
            else {
                fprintf(stderr, "symp: unknow patch %s\n", optarg);
                return 1;
            }
            break;
        case 'x':
            if (patch_bytes || builtin_patch) {
                fprintf(stderr, "symp: only one of -p/-b/-x should be offered\n");
                return 1;
            }
            int xlen = 0;

            patch_count = strlen(optarg) >> 1;
            patch_bytes = (unsigned char*)malloc(patch_count);
            memset(patch_bytes, 0, patch_count);
            for (int i = 0; optarg[i]; i++) {
                char ch = optarg[i];
                if (ch >= '0' && ch <= '9') patch_bytes[xlen>>1] |= (ch-'0') << (((xlen+1)%2)*4), ++xlen;
                else if (ch >= 'A' && ch <= 'F') patch_bytes[xlen>>1] |= (ch-'A'+10) << (((xlen+1)%2)*4), ++xlen;
                else if (ch >= 'a' && ch <= 'f') patch_bytes[xlen>>1] |= (ch-'a'+10) << (((xlen+1)%2)*4), ++xlen;
                else if (ch != ' ' && ch != '\t' && ch != '\r' && ch != '\n') {
                    fprintf(stderr, "symp: invalid character '%c' in hex string\n", ch);
                    return 1;
                }
            }
            if (xlen%2 != 0) {
                fprintf(stderr, "symp: hex string length should be oven\n");
                return 1;
            }
            patch_count = xlen >> 1;
            break;
        case 'h':
            usage();
            return 0;
        case '?':
            return 1;
        default:
            abort();
        }
    }

    if (patch_bytes == 0 && builtin_patch == 0) {
        fprintf(stderr, "symp: one of -p/-b/-x must be offered\n");
        return 1;
    }

    if (argc - optind != 2) {
        if (argc - optind < 2)
            fprintf(stderr, "symp: arguments not enough!\n");
        else
            fprintf(stderr, "symp: too many arguments!\n");
        return 1;
    }

    symbol = argv[optind++];
    file = argv[optind++];

    return 0;
}

char *arch2str(int arch) {
    if (arch == CPU_TYPE_X86_64)
        return "x86_64";
    else if (arch == CPU_TYPE_ARM64)
        return "arm64";
    else
        return NULL;
}

long int solve_mach_header(const struct mach_header_64* header, const char* symbol_name) {
    long int symbol_address = 0;
    const struct load_command* command = (void*)header + sizeof(struct mach_header_64);
    for (int i = 0; i < header->ncmds; i++) {
        if (command->cmd == LC_SYMTAB) {
            const struct symtab_command* symtab_cmd = (struct symtab_command*)command;
            const struct nlist_64* nl_tbl = (void*)header + symtab_cmd->symoff;
            const char* str_tbl = (char*)header + symtab_cmd->stroff;
            for (int j = 0; j < symtab_cmd->nsyms; j++)
                if (strcmp(symbol_name, str_tbl+nl_tbl[j].n_un.n_strx) == 0) {
                    symbol_address = nl_tbl[j].n_value;
                    break;
                }
            break;
        }
        command = (void*)command + command->cmdsize;
    }
    return symbol_address;
}

int find_symbol(FILE* fp, struct patch_off *poffs) {
    int offind = 0;
    long int symbol_address;
    struct fat_header *header = (struct fat_header *)malloc(sizeof(struct fat_header));
    fread(header, sizeof(struct fat_header), 1, fp);
    if (header->magic == MH_MAGIC_64) {
        fseek(fp, 0, SEEK_END);
        int file_size = ftell(fp);
        struct mach_header_64 *mh_header = (struct mach_header_64 *)malloc(file_size);
        rewind(fp);
        fread(mh_header, file_size, 1, fp);
        if (patch_arch == 0 || (mh_header->cputype & patch_arch) == mh_header->cputype) {
            symbol_address = solve_mach_header(mh_header, symbol);
            if (symbol_address && mh_header->filetype == MH_EXECUTE)
                symbol_address -= 0x100000000;
            if (symbol_address) {
                poffs[offind].cputype = mh_header->cputype;
                poffs[offind].symoff = symbol_address;
                offind++;
            }
            else
                fprintf(stderr, "symp: symbol '%s' not found in arch '%s'\n", symbol, arch2str(mh_header->cputype));
        }
        else
            fprintf(stderr, "symp: offered arch '%s' not found in the file\n", arch2str(patch_arch));
        free(mh_header);
    }
    else if (header->magic == FAT_CIGAM) {
        int archs_size = OSSwapInt32(header->nfat_arch) * sizeof(struct fat_arch);
        struct fat_arch *archs = (struct fat_arch *)malloc(archs_size);
        fread(archs, archs_size, 1, fp);
        for (int i = 0; i < OSSwapInt32(header->nfat_arch); i++) {
            if (patch_arch == 0 || (archs[i].cputype & OSSwapInt32(patch_arch)) == archs[i].cputype) {
                struct mach_header_64* macho = (struct mach_header_64*)malloc(OSSwapInt32(archs[i].size));
                fseek(fp, OSSwapInt32(archs[i].offset), SEEK_SET);
                fread(macho, OSSwapInt32(archs[i].size), 1, fp);
                symbol_address = solve_mach_header(macho, symbol);
                if (symbol_address) {
                    symbol_address += OSSwapInt32(archs[i].offset);
                    if (macho->filetype == MH_EXECUTE)
                        symbol_address -= 0x100000000;
                    poffs[offind].cputype = OSSwapInt32(archs[i].cputype);
                    poffs[offind].symoff = symbol_address;
                    offind++;
                }
                else
                    fprintf(stderr, "symp: symbol '%s' not found in arch '%s'\n", symbol, arch2str(macho->cputype));
                free(macho);
            }
            else if (patch_arch != 0)
                fprintf(stderr, "symp: offered arch '%s' not found in the file\n", arch2str(patch_arch));
        }
        free(archs);
    }
    else {
        fprintf(stderr, "symp: not a valid macho file\n");
    }
    free(header);

    return offind;
}

void patch_file(FILE* fp, int cputype, long int symoff) {
    int pat_cnt = patch_count;
    unsigned char* pat_byt = patch_bytes;
    if (builtin_patch) {
        if (cputype == CPU_TYPE_X86_64) {
            switch (builtin_patch) {
            case BUILTIN_RET:
                pat_cnt = sizeof(x86_64_ret);
                pat_byt = x86_64_ret;
                break;
            case BUILTIN_RET0:
                pat_cnt = sizeof(x86_64_ret0);
                pat_byt = x86_64_ret0;
                break;
            case BUILTIN_RET1:
                pat_cnt = sizeof(x86_64_ret1);
                pat_byt = x86_64_ret1;
                break;
            default:
                break;
            }
        }
        else if (cputype == CPU_TYPE_ARM64) {
            switch (builtin_patch) {
            case BUILTIN_RET:
                pat_cnt = sizeof(arm64_ret);
                pat_byt = arm64_ret;
                break;
            case BUILTIN_RET0:
                pat_cnt = sizeof(arm64_ret0);
                pat_byt = arm64_ret0;
                break;
            case BUILTIN_RET1:
                pat_cnt = sizeof(arm64_ret1);
                pat_byt = arm64_ret1;
                break;
            default:
                break;
            }
        }
    }
    fseek(fp, symoff, SEEK_SET);
    fwrite(pat_byt, pat_cnt, 1, fp);
    return;
}

void perform_patches(FILE* fp, int offcnt, const struct patch_off *poffs) {
    for (int i = 0; i < offcnt; i++) {
        patch_file(fp, poffs[i].cputype, poffs[i].symoff);
    }
    return;
}

int main(int argc, char **argv) {
    if (parse_arguments(argc, argv) != 0)
        goto err_ret;

    struct patch_off poffs[5];

    FILE *fp = fopen(file, "rb+");
    if (fp == NULL) {
        perror("fopen");
        goto err_ret;
    }

    int offset_count = find_symbol(fp, poffs);
    if (offset_count == 0) {
        fprintf(stderr, "no symbol patched\n");
        fclose(fp);
        goto err_ret;
    }
    else {
        perform_patches(fp, offset_count, poffs);
        if (offset_count == 1)
            fprintf(stdout, "1 symbol patched\n");
        else {
            if (builtin_patch == 0)
                fprintf(stderr, "symp: warning, multiple arches used the same patch\n");
            fprintf(stdout, "%d symbols patched\n", offset_count);
        }
    }

    fclose(fp);
    free(patch_bytes);
    return 0;
err_ret:
    free(patch_bytes);
    return 1;
}
