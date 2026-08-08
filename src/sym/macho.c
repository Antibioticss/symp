#include "private.h"
#include "../fileio.h"

#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <mach-o/loader.h>

/**
 * @brief Parses basic structural information from a 64-bit Mach-O binary header.
 *
 * This function reads the Mach-O header and iterates through its load commands
 * to extract core attributes such as the CPU type and virtual memory slide 
 * (difference between file offset and virtual memory address) for the __TEXT segment.
 *
 * @param fp Open file pointer positioned at the start of the Mach-O binary/slice.
 * @return macho_basic_info_t* Pointer to the dynamically allocated basic info structure.
 *         The caller is responsible for freeing this memory using free().
 */
macho_basic_info_t *parse_basic_info(FILE *fp) {
    // Allocate and zero-initialize memory for basic information structure
    macho_basic_info_t *macho_info = malloc(sizeof(macho_basic_info_t));
    memset(macho_info, 0, sizeof(macho_basic_info_t));
    
    // Save the initial file offset (important for FAT universal binaries)
    macho_info->base_offset = ftell(fp);

    // Read the 64-bit Mach-O header and load commands buffer
    const struct mach_header_64 *header = read_file(fp, sizeof(struct mach_header_64));
    const struct load_command* commands = read_file(fp, header->sizeofcmds);
    const struct load_command* command = commands;

    macho_info->cputype = header->cputype;

    // Iterate over all load commands
    for (int i = 0; i < header->ncmds; i++) {
        if (command->cmd == LC_SEGMENT_64) {
            const struct segment_command_64 *seg_cmd = (void *)command;
            
            // Look for the primary __TEXT segment to calculate the VM slide offset
            if (strcmp(seg_cmd->segname, SEG_TEXT) == 0) { /* __TEXT */
                /* VM slide formula: addr_vm - text_vm = addr_file - text_file */
                macho_info->vm_slide = seg_cmd->fileoff - seg_cmd->vmaddr;
                break;
            }
        }
        // Move pointer to the next load command
        command = (void*)command + command->cmdsize;
    }

    // Clean up temporary buffers
    free((void *)header);
    free((void *)commands);
    
    return macho_info;
}

/**
 * @brief Parses symbol-related metadata from a Mach-O binary.
 *
 * Scans load commands to gather symbol table offsets, dynamic symbol tables,
 * symbol stubs information, export trie structures (DYLD info or Dyld Exports Trie),
 * and string table properties.
 *
 * @param fp Open file pointer positioned at the start of the Mach-O binary/slice.
 * @return macho_symbol_info_t* Pointer to the dynamically allocated symbol info structure.
 *         The caller is responsible for freeing this memory using free().
 */
macho_symbol_info_t *parse_symbol_info(FILE *fp) {
    macho_symbol_info_t *macho_info = malloc(sizeof(macho_symbol_info_t));
    memset(macho_info, 0, sizeof(macho_symbol_info_t));
    macho_info->base_offset = ftell(fp);

    const struct mach_header_64 *header = read_file(fp, sizeof(struct mach_header_64));
    const struct load_command* commands = read_file(fp, header->sizeofcmds);
    const struct load_command* command = commands;

    macho_info->cputype = header->cputype;

    // Process each load command relevant to symbol resolution
    for (int i = 0; i < header->ncmds; i++) {
        switch(command->cmd) {
        case LC_SEGMENT_64: {
            const struct segment_command_64 *seg_cmd = (void *)command;
            if (strcmp(seg_cmd->segname, SEG_TEXT) == 0) { /* __TEXT */
                /* Calculate VM slide based on __TEXT segment with formula addr_vm - text_vm = addr_file - text_file */
                macho_info->vm_slide = seg_cmd->fileoff - seg_cmd->vmaddr;

                // Inspect sections inside __TEXT to locate stub sections
                const struct section_64 *text_sect = (void *)(seg_cmd + 1);
                for (int j = 0; j < seg_cmd->nsects; j++) {
                    if ((text_sect[j].flags & SECTION_TYPE) == S_SYMBOL_STUBS) {
                        macho_info->stubs.off = text_sect[j].offset;
                        macho_info->stubs.size = text_sect[j].size;
                        macho_info->indirectsym_idx = text_sect[j].reserved1; // Indirect symbol table index
                        macho_info->stub_len = text_sect[j].reserved2;        // Size of individual stub
                        break;
                    }
                }
            }
            break;
        }
        case LC_SYMTAB: {
            // Standard Symbol Table command (offsets and counts for nlist structures)
            const struct symtab_command* symtab_cmd = (void *)command;
            macho_info->symoff = symtab_cmd->symoff;
            macho_info->nsyms = symtab_cmd->nsyms;
            macho_info->strtab.off = symtab_cmd->stroff;
            macho_info->strtab.size = symtab_cmd->strsize;
            break;
        }
        case LC_DYSYMTAB: {
            // Dynamic Symbol Table command (used for indirect symbol lookup)
            const struct dysymtab_command *dysymtab_cmd = (void *)command;
            macho_info->indirectsymoff = dysymtab_cmd->indirectsymoff;
            break;
        }
        case LC_DYLD_INFO:
        case LC_DYLD_INFO_ONLY: {
            // Legacy DYLD compressed export trie info
            const struct dyld_info_command *dyldinfo_cmd = (void *)command;
            macho_info->export.off = dyldinfo_cmd->export_off;
            macho_info->export.size = dyldinfo_cmd->export_size;
            break;
        }
        case LC_DYLD_EXPORTS_TRIE: {
            // Modern standalone Export Trie data command (macOS 12+ / iOS 15+)
            const struct linkedit_data_command *export_trie = (void *)command;
            macho_info->export.off = export_trie->dataoff;
            macho_info->export.size = export_trie->datasize;
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

/**
 * @brief Parses Objective-C runtime structures and segment metadata.
 *
 * Extracts segment dimensions (__TEXT, __DATA, __DATA_CONST) and locates
 * Objective-C specific section headers such as class lists (__objc_classlist)
 * and category lists (__objc_catlist). Also detects presence of chained fixups.
 *
 * @param fp Open file pointer positioned at the start of the Mach-O binary/slice.
 * @return macho_objc_info_t* Pointer to the dynamically allocated Obj-C info structure.
 *         The caller is responsible for freeing this memory using free().
 */
macho_objc_info_t *parse_objc_info(FILE *fp) {
    macho_objc_info_t *macho_info = malloc(sizeof(macho_objc_info_t));
    memset(macho_info, 0, sizeof(macho_objc_info_t));
    macho_info->base_offset = ftell(fp);

    const struct mach_header_64 *header = read_file(fp, sizeof(struct mach_header_64));
    const struct load_command* commands = read_file(fp, header->sizeofcmds);
    const struct load_command* command = commands;

    macho_info->cputype = header->cputype;

    for (int i = 0; i < header->ncmds; i++) {
        if (command->cmd == LC_SEGMENT_64) {
            const struct segment_command_64 *seg_cmd = (void *)command;

            // Capture __TEXT segment bounds
            if (strcmp(seg_cmd->segname, SEG_TEXT) == 0) { /* __TEXT */
                /* addr_vm - text_vm = addr_file - text_file */
                // macho_info->vm_slide = seg_cmd->fileoff - seg_cmd->vmaddr;
                macho_info->text_vm.off = seg_cmd->fileoff;
                macho_info->text_vm.addr = seg_cmd->vmaddr;
                macho_info->text_vm.size = seg_cmd->filesize;
            }

            // Capture __DATA and __DATA_CONST segment bounds and Obj-C sections
            if (strncmp(seg_cmd->segname, SEG_DATA, 6) == 0) {
                if (strcmp(seg_cmd->segname, "__DATA_CONST") == 0) {
                    macho_info->datac_vm.off = seg_cmd->fileoff;
                    macho_info->datac_vm.addr = seg_cmd->vmaddr;
                    macho_info->datac_vm.size = seg_cmd->filesize;
                }
                else {
                    macho_info->data_vm.off = seg_cmd->fileoff;
                    macho_info->data_vm.addr = seg_cmd->vmaddr;
                    macho_info->data_vm.size = seg_cmd->filesize;
                }

                // Iterate through section headers inside the data segment
                const struct section_64 *data_sect = (void *)(seg_cmd + 1);
                for (int j = 0; j < seg_cmd->nsects; j++) {
                    /* Section names are fixed 16-byte arrays without guaranteed null termination */
                    if (strncmp(data_sect[j].sectname, "__objc_classlist", 16) == 0) {
                        /* reached max len 16, no '\0' ending */
                        macho_info->objc_classlist.off = data_sect[j].offset;
                        macho_info->objc_classlist.size = data_sect[j].size;
                    }
                    else if (strcmp(data_sect[j].sectname, "__objc_catlist") == 0) {
                        macho_info->objc_catlist.off = data_sect[j].offset;
                        macho_info->objc_catlist.size = data_sect[j].size;
                    }
                }
            }
        }
        else if (command->cmd == LC_DYLD_CHAINED_FIXUPS) {
            // Flag if modern iOS/macOS chained fixups format is used instead of traditional rebase/binds
            macho_info->chained_fixup = true;
        }
        command = (void*)command + command->cmdsize;
    }

    free((void *)header);
    free((void *)commands);
    return macho_info;
}
