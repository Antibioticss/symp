#include "private.h"
#include "../fileio.h"

#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stddef.h>

/* copied from dyld source code */

#define ISA_MASK                0x00007fffffffffffUL
#define FAST_DATA_MASK          0x0f007ffffffffff8UL
#define FAST_IS_RW_POINTER      0x8000000000000000UL

struct objc_class {
    uint64_t isaVMAddr;
    uint64_t superclassVMAddr;
    uint64_t methodCacheBuckets;
    uint64_t methodCacheProperties;
    uint64_t dataVMAddrAndFastFlags;
};

struct objc_category {
    uint64_t nameVMAddr;
    uint64_t clsVMAddr;
    uint64_t instanceMethodsVMAddr;
    uint64_t classMethodsVMAddr;
    uint64_t protocolsVMAddr;
    uint64_t instancePropertiesVMAddr;
};

struct class_ro {
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

struct method_list {
    uint32_t entsize;
    uint32_t count;
};

struct method {
    uint64_t nameVMAddr;   // SEL
    uint64_t typesVMAddr;  // const char *
    uint64_t impVMAddr;    // IMP
};

struct relative_method {
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

uint64_t vm2fileoff(uint64_t vmaddr, const macho_objc_info_t *mi) {
    uint64_t fileoff;
    if (mi->chained_fixup)
        return vmaddr; // might be buggy here
    if (vmaddr >= mi->text_vm.addr && vmaddr < mi->text_vm.addr + mi->text_vm.size)
        fileoff = vmaddr + mi->text_vm.off - mi->text_vm.addr;
    else if (vmaddr >= mi->datac_vm.addr && vmaddr < mi->datac_vm.addr + mi->datac_vm.size)
        fileoff = vmaddr + mi->datac_vm.off - mi->datac_vm.addr;
    else if (vmaddr >= mi->data_vm.addr && vmaddr < mi->data_vm.addr + mi->data_vm.size)
        fileoff = vmaddr + mi->data_vm.off - mi->data_vm.addr;
    else {
        fprintf(stderr, "vm2fileoff: vmaddr '0x%llx' in unknown segment\n", vmaddr);
        return -1;
    }
    return fileoff;
}

uint64_t solve_methodlist(const char *sym_sel, const struct method_list *method_list, const macho_objc_info_t *mi, void *macho_data) {
    uint32_t entsize = method_list->entsize & 0x0000FFFC; /* methodListSizeMask */
    void *cur_method = (void *)(method_list + 1);
    for (int j = 0; j < method_list->count; j++) {
        char *method_name = NULL;
        uint64_t method_imp_off = 0;
        if ((method_list->entsize & 0x80000000) != 0) { /* usesRelativeOffsets */
            struct relative_method *rel_method = cur_method;
            uint64_t *method_sel = (void *)rel_method + offsetof(struct relative_method, nameOffset) + rel_method->nameOffset;
            method_name = macho_data + vm2fileoff(*method_sel & ISA_MASK, mi);
            method_imp_off = (uint64_t)rel_method - (uint64_t)macho_data + offsetof(struct relative_method, impOffset) + rel_method->impOffset;
        }
        else {
            struct method *method = cur_method;
            method_name = macho_data + vm2fileoff(method->nameVMAddr & ISA_MASK, mi);
            method_imp_off = vm2fileoff(method->impVMAddr & ISA_MASK, mi);
        }
        if (strcmp(method_name, sym_sel) == 0) {
            return method_imp_off;
        }
        cur_method += entsize;
    }
    return 0;
}

long solve_objc_symbol(FILE *fp, const macho_objc_info_t *mi, const char* symbol_name) {
    uint64_t symbol_address = 0;
    const long base_offset = mi->base_offset;

    if (mi->objc_classlist.off == 0) {
        fprintf(stderr, "symp: missing __objc_classlist section!\n");
        return 0;
    }

    char sym_type = symbol_name[0];
    char *sym_cls, *sym_sel;
    seperate_method(symbol_name, &sym_cls, &sym_sel);

    void *macho_data = read_file_off(fp, mi->data_vm.off + mi->data_vm.size, base_offset);

    uint64_t *classlist = macho_data + mi->objc_classlist.off;
    uint64_t nclasses = mi->objc_classlist.size / sizeof(uint64_t);
    for (int i = 0; i < nclasses; i++) {
        struct objc_class *objc_cls = macho_data + vm2fileoff(classlist[i] & ISA_MASK, mi);
        if (sym_type == '+') /* class method are in metaclass */
            objc_cls = macho_data + vm2fileoff(objc_cls->isaVMAddr & ISA_MASK, mi);
        struct class_ro *class_data = macho_data + vm2fileoff(objc_cls->dataVMAddrAndFastFlags & FAST_DATA_MASK, mi);
        char *class_name = macho_data + vm2fileoff(class_data->nameVMAddr & ISA_MASK, mi);
        if (strcmp(class_name, sym_cls) != 0)
            continue;
        if (class_data->baseMethodsVMAddr != 0) {
            struct method_list *method_list = macho_data + vm2fileoff(class_data->baseMethodsVMAddr & ISA_MASK, mi);
            uint64_t method_imp_off = solve_methodlist(sym_sel, method_list, mi, macho_data);
            if (method_imp_off != 0)
                symbol_address = base_offset + method_imp_off;
        }
        break; /* class name already matched */
    }
    if (symbol_address != 0)
        goto exit;

    uint64_t *catlist = macho_data + mi->objc_catlist.off;
    uint64_t ncategories = mi->objc_catlist.size / sizeof(uint64_t);
    for (int i = 0; i < ncategories; i++) {
        struct objc_category *objc_cat = macho_data + vm2fileoff(catlist[i] & ISA_MASK, mi);
        char *cat_name = macho_data + vm2fileoff(objc_cat->nameVMAddr & ISA_MASK, mi);
        if (strcmp(cat_name, sym_cls) != 0)
            continue;
        uint64_t method_vmaddr = sym_type == '+' ? objc_cat->classMethodsVMAddr: objc_cat->instanceMethodsVMAddr;
        if (method_vmaddr != 0) {
            struct method_list *method_list = macho_data + vm2fileoff(method_vmaddr & ISA_MASK, mi);
            uint64_t method_imp_off = solve_methodlist(sym_sel, method_list, mi, macho_data);
            if (method_imp_off != 0)
                symbol_address = base_offset + method_imp_off;
        }
        break; /* class name already matched */
    }

exit:
    free(sym_cls);
    free(sym_sel);
    free((void *)macho_data);
    return (long)symbol_address;
}
