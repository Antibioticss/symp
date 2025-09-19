#include "private.h"
#include "../fileio.h"

#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stddef.h>

/* copied from dyld source code */

#define ISA_MASK 0x7fffffffffffULL
#define FAST_DATA_MASK 0xfffffffcUL

struct objc_class_t {
    uint64_t isaVMAddr;
    uint64_t superclassVMAddr;
    uint64_t methodCacheBuckets;
    uint64_t methodCacheProperties;
    uint64_t dataVMAddrAndFastFlags;
};

struct class_ro_t {
    uint32_t flags;
    uint32_t instanceStart;
    union {
        uint32_t   instanceSize;
        uint64_t   pad;
    } instanceSize;
    uint64_t ivarLayoutVMAddr;
    uint64_t nameVMAddr;
    uint64_t baseMethodsVMAddr;
    uint64_t baseProtocolsVMAddr;
    uint64_t ivarsVMAddr;
    uint64_t weakIvarLayoutVMAddr;
    uint64_t basePropertiesVMAddr;
};

struct method_list_t {
    uint32_t entsize;
    uint32_t count;
};

struct method_t {
    uint64_t nameVMAddr;   // SEL
    uint64_t typesVMAddr;  // const char *
    uint64_t impVMAddr;    // IMP
};

struct relative_method_t {
    int32_t nameOffset;   // SEL*
    int32_t typesOffset;  // const char *
    int32_t impOffset;    // IMP
};

void seperate_method(const char *symbol_name, char **class_name, char **sel_name) {
    /* assume this is valid */
    char *split = strchr(symbol_name, ' ');
    size_t cls_len = split - symbol_name - 2; /* remove '-[' */
    size_t sel_len = strlen(symbol_name) - cls_len - 4; /* remove '-[ ]' */
    char *clsn = malloc(cls_len + 1);
    char *seln = malloc(sel_len + 1);
    strncpy(clsn, symbol_name + 2, cls_len);
    strncpy(seln, split + 1, sel_len);
    clsn[cls_len] = '\0';
    seln[sel_len] = '\0';
    *class_name = clsn;
    *sel_name = seln;
}

long solve_objc_symbol(FILE *fp, const macho_objc_info_t *macho_info, const char* symbol_name) {
    uint64_t symbol_address = 0;
    const long base_offset = macho_info->base_offset;
    const uint64_t vm_slide = macho_info->vm_slide;

    if (macho_info->objc_classlist_off == 0) {
        fprintf(stderr, "symp: missing __objc_classlist section!\n");
        return 0;
    }

    char sym_type = symbol_name[0];
    char *sym_cls, *sym_sel;
    seperate_method(symbol_name, &sym_cls, &sym_sel);

    const void *macho_data = read_file_off(fp, macho_info->dataend_off, base_offset);
    #define VM_TO_FILE_OFF(vmaddr) ((uint64_t)((vmaddr) & ISA_MASK) + vm_slide)
    const uint64_t *classlist = macho_data + macho_info->objc_classlist_off;
    uint64_t nclasses = macho_info->objc_classlist_size / sizeof(uint64_t);
    for (int i = 0; i < nclasses; i++) {
        const struct objc_class_t *objc_cls = macho_data + VM_TO_FILE_OFF(classlist[i]);
        if (sym_type == '+') /* class method are in metaclass */
            objc_cls = macho_data + VM_TO_FILE_OFF(objc_cls->isaVMAddr);
        const struct class_ro_t *class_data = macho_data + (VM_TO_FILE_OFF(objc_cls->dataVMAddrAndFastFlags) & FAST_DATA_MASK);
        const char *class_name = macho_data + VM_TO_FILE_OFF(class_data->nameVMAddr);
        if (strcmp(class_name, sym_cls) != 0)
            continue;
        if ((class_data->baseMethodsVMAddr) != 0) {
            const struct method_list_t *method_list = macho_data + VM_TO_FILE_OFF(class_data->baseMethodsVMAddr);
            uint32_t entsize = method_list->entsize & 0x0000FFFC; /* methodListSizeMask */
            const void *cur_method = (void *)(method_list + 1);
            for (int j = 0; j < method_list->count; j++) {
                const char *method_name = NULL;
                uint64_t method_imp_off = 0;
                if ((method_list->entsize & 0x80000000) != 0) { /* usesRelativeOffsets */
                    const struct relative_method_t *rel_method = cur_method;
                    const uint64_t *method_sel = (void *)rel_method + offsetof(struct relative_method_t, nameOffset) + rel_method->nameOffset;
                    method_name = macho_data + VM_TO_FILE_OFF(*method_sel);
                    method_imp_off = (uint64_t)rel_method - (uint64_t)macho_data + offsetof(struct relative_method_t, impOffset) + rel_method->impOffset;
                }
                else {
                    const struct method_t *method = cur_method;
                    method_name = macho_data + VM_TO_FILE_OFF(method->nameVMAddr);
                    method_imp_off = VM_TO_FILE_OFF(method->impVMAddr);
                }
                if (strcmp(method_name, sym_sel) == 0) {
                    symbol_address = base_offset + method_imp_off;
                    break;
                }
                cur_method += entsize;
            }
            break; /* class name already matched */
        }
    }

    free(sym_cls);
    free(sym_sel);
    free((void *)macho_data);
    #undef VM_TO_FILE_OFF
    return (long)symbol_address;
}
