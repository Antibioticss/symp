#include "private.h"
#include "../fileio.h"

#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <mach-o/loader.h>

macho_basic_info_t *parse_basic_info(FILE *fp) {
    macho_basic_info_t *macho_info = malloc(sizeof(macho_basic_info_t));
    memset(macho_info, 0, sizeof(macho_basic_info_t));
    macho_info->base_offset = ftell(fp);

    const struct mach_header_64 *header = read_file(fp, sizeof(struct mach_header_64));
    const struct load_command* commands = read_file(fp, header->sizeofcmds);
    const struct load_command* command = commands;
    macho_info->cputype = header->cputype;
    for (int i = 0; i < header->ncmds; i++) {
        if (command->cmd == LC_SEGMENT_64) {
            const struct segment_command_64 *seg_cmd = (void *)command;
            if (strcmp(seg_cmd->segname, SEG_TEXT) == 0) { /* __TEXT */
                /* addr_vm - text_vm = addr_file - text_file */
                macho_info->vm_slide = seg_cmd->fileoff - seg_cmd->vmaddr;
                break;
            }
        }
        command = (void*)command + command->cmdsize;
    }
    free((void *)header);
    free((void *)commands);
    return macho_info;
}

macho_symbol_info_t *parse_symbol_info(FILE *fp) {
    macho_symbol_info_t *macho_info = malloc(sizeof(macho_symbol_info_t));
    memset(macho_info, 0, sizeof(macho_symbol_info_t));
    macho_info->base_offset = ftell(fp);

    const struct mach_header_64 *header = read_file(fp, sizeof(struct mach_header_64));
    const struct load_command* commands = read_file(fp, header->sizeofcmds);
    const struct load_command* command = commands;
    macho_info->cputype = header->cputype;
    for (int i = 0; i < header->ncmds; i++) {
        switch(command->cmd) {
        case LC_SEGMENT_64: {
            const struct segment_command_64 *seg_cmd = (void *)command;
            if (strcmp(seg_cmd->segname, SEG_TEXT) == 0) { /* __TEXT */
                /* addr_vm - text_vm = addr_file - text_file */
                macho_info->vm_slide = seg_cmd->fileoff - seg_cmd->vmaddr;

                const struct section_64 *text_sect = (void *)(seg_cmd + 1);
                for (int j = 0; j < seg_cmd->nsects; j++) {
                    if ((text_sect[j].flags & SECTION_TYPE) == S_SYMBOL_STUBS) {
                        macho_info->stubs_off = text_sect[j].offset;
                        macho_info->stubs_size = text_sect[j].size;
                        macho_info->indirectsym_idx = text_sect[j].reserved1;
                        macho_info->stub_len = text_sect[j].reserved2;
                        break;
                    }
                }
            }
            break;
        }
        case LC_SYMTAB: {
            const struct symtab_command* symtab_cmd = (void *)command;
            macho_info->symoff = symtab_cmd->symoff;
            macho_info->nsyms = symtab_cmd->nsyms;
            macho_info->stroff = symtab_cmd->stroff;
            macho_info->strsize = symtab_cmd->strsize;
            break;
        }
        case LC_DYSYMTAB: {
            const struct dysymtab_command *dysymtab_cmd = (void *)command;
            macho_info->indirectsymoff = dysymtab_cmd->indirectsymoff;
            break;
        }
        case LC_DYLD_INFO:
        case LC_DYLD_INFO_ONLY: {
            const struct dyld_info_command *dyldinfo_cmd = (void *)command;
            macho_info->export_off = dyldinfo_cmd->export_off;
            macho_info->export_size = dyldinfo_cmd->export_size;
            break;
        }
        case LC_DYLD_EXPORTS_TRIE: {
            const struct linkedit_data_command *export_trie = (void *)command;
            macho_info->export_off = export_trie->dataoff;
            macho_info->export_size = export_trie->datasize;
            break;
        }
        default:
            break;
        }
        command = (void*)command + command->cmdsize;
    }
    free((void *)header);
    free((void *)commands);
    return macho_info;
}

macho_objc_info_t *parse_objc_info(FILE *fp) {
    macho_objc_info_t *macho_info = malloc(sizeof(macho_objc_info_t));
    memset(macho_info, 0, sizeof(macho_objc_info_t));
    macho_info->base_offset = ftell(fp);

    const struct mach_header_64 *header = read_file(fp, sizeof(struct mach_header_64));
    const struct load_command* commands = read_file(fp, header->sizeofcmds);
    const struct load_command* command = commands;
    uint64_t dataend = 0;
    macho_info->cputype = header->cputype;
    for (int i = 0; i < header->ncmds; i++) {
        if (command->cmd == LC_SEGMENT_64) {
            const struct segment_command_64 *seg_cmd = (void *)command;
            if (strcmp(seg_cmd->segname, SEG_TEXT) == 0) { /* __TEXT */
                /* addr_vm - text_vm = addr_file - text_file */
                macho_info->vm_slide = seg_cmd->fileoff - seg_cmd->vmaddr;
                /* also include __TEXT in the mapped end */
                if (dataend < seg_cmd->fileoff + seg_cmd->filesize)
                    dataend = seg_cmd->fileoff + seg_cmd->filesize;
            }
            if (strncmp(seg_cmd->segname, "__DATA", 6) == 0) {
                if (dataend < seg_cmd->fileoff + seg_cmd->filesize)
                    dataend = seg_cmd->fileoff + seg_cmd->filesize;
                
                const struct section_64 *data_sect = (void *)(seg_cmd + 1);
                for (int j = 0; j < seg_cmd->nsects; j++) {
                    if (strncmp(data_sect[j].sectname, "__objc_classlist", 16) == 0) {
                        /* reached max len 16, no '\0' ending */
                        macho_info->objc_classlist_off = data_sect[j].offset;
                        macho_info->objc_classlist_size = data_sect[j].size;
                    }
                }
            }
        }
        command = (void*)command + command->cmdsize;
    }
    macho_info->dataend_off = dataend;
    free((void *)header);
    free((void *)commands);
    return macho_info;
}
