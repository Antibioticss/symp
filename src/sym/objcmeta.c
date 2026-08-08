/**
 * @file objc_symbol_solver.c
 * @brief Utilities for parsing Objective-C metadata structures in Mach-O binaries
 *        and resolving Objective-C symbols (classes, categories, and methods).
 */

#include "private.h"
#include "../fileio.h"

#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stddef.h>

/* Bitmasks copied from Apple dyld / Objective-C runtime source code */

/** Mask used to extract clean VM addresses by stripping PAC/metadata bits from ISA pointers. */
#define ISA_MASK                0x00007fffffffffffUL

/** Mask used to extract the class_ro_t structure pointer from class data flags. */
#define FAST_DATA_MASK          0x0f007ffffffffff8UL

/** Flag indicating whether the class data pointer points to a read-write runtime structure. */
#define FAST_IS_RW_POINTER      0x8000000000000000UL

/**
 * @brief Represents 64-bit Objective-C class structure layout in Mach-O binaries.
 */
struct objc_class {
    uint64_t isaVMAddr;              /**< Virtual address of the ISA/metaclass structure. */
    uint64_t superclassVMAddr;       /**< Virtual address of the superclass. */
    uint64_t methodCacheBuckets;     /**< Method cache buckets pointer. */
    uint64_t methodCacheProperties;  /**< Method cache properties/mask pointer. */
    uint64_t dataVMAddrAndFastFlags; /**< Virtual address pointing to class_ro_t and runtime flags. */
};

/**
 * @brief Represents Objective-C category structure layout in Mach-O binaries.
 */
struct objc_category {
    uint64_t nameVMAddr;                 /**< Virtual address of the category name string. */
    uint64_t clsVMAddr;                  /**< Virtual address of the target class. */
    uint64_t instanceMethodsVMAddr;      /**< Virtual address of the instance method list. */
    uint64_t classMethodsVMAddr;         /**< Virtual address of the class method list. */
    uint64_t protocolsVMAddr;            /**< Virtual address of the adopted protocol list. */
    uint64_t instancePropertiesVMAddr;   /**< Virtual address of instance properties list. */
};

/**
 * @brief Represents Objective-C read-only class data (class_ro_t).
 */
struct class_ro {
    uint32_t flags;                 /**< Class flags (e.g., RO_META, RO_ROOT). */
    uint32_t instanceStart;         /**< Start offset of instance variables. */
    union {
        uint32_t   instanceSize;    /**< Total size of an instance. */
        uint64_t   pad;             /**< Padding for alignment on 64-bit platforms. */
    } instanceSize;
    uint64_t ivarLayoutVMAddr;      /**< Virtual address of GC/ARC ivar layout string. */
    uint64_t nameVMAddr;            /**< Virtual address of the C-string class name. */
    uint64_t baseMethodsVMAddr;     /**< Virtual address of the base method list. */
    uint64_t baseProtocolsVMAddr;   /**< Virtual address of the base protocol list. */
    uint64_t ivarsVMAddr;           /**< Virtual address of the instance variable list. */
    uint64_t weakIvarLayoutVMAddr;  /**< Virtual address of the weak ivar layout string. */
    uint64_t basePropertiesVMAddr;  /**< Virtual address of the base property list. */
};

/**
 * @brief Header structure preceding a list of Objective-C methods.
 */
struct method_list {
    uint32_t entsize; /**< Size of each entry + flags (e.g., 0x80000000 for relative offsets). */
    uint32_t count;   /**< Total number of methods in this list. */
};

/**
 * @brief Absolute-address Objective-C method structure (legacy layout).
 */
struct method {
    uint64_t nameVMAddr;   /**< Virtual address of the selector string (SEL). */
    uint64_t typesVMAddr;  /**< Virtual address of the method type encoding string. */
    uint64_t impVMAddr;    /**< Virtual address of the implementation function (IMP). */
};

/**
 * @brief Relative-offset Objective-C method structure (modern layout used in modern iOS/macOS).
 */
struct relative_method {
    int32_t nameOffset;   /**< 32-bit relative offset to the selector pointer/string. */
    int32_t typesOffset;  /**< 32-bit relative offset to the type encoding string. */
    int32_t impOffset;    /**< 32-bit relative offset to the implementation function. */
};

/**
 * @brief Parses an Objective-C method signature string into class and selector components.
 * 
 * Example: Transforms "-[MyClass mySelector:]" into class_name = "MyClass" and sel_name = "mySelector:".
 *
 * @param[in]  symbol_name Full symbol name string to parse.
 * @param[out] class_name  Allocated heap string containing extracted class name. Must be freed by caller.
 * @param[out] sel_name    Allocated heap string containing extracted selector name. Must be freed by caller.
 */
void seperate_method(const char *symbol_name, char **class_name, char **sel_name) {
    if (symbol_name == NULL || symbol_name[0] == '\0') {
        *class_name = strdup("");
        *sel_name = strdup("");
        return;
    }

    char *split = strchr(symbol_name, ' ');
    if (split == NULL || split[1] == '\0') {
        *class_name = strdup(symbol_name);
        *sel_name = strdup(symbol_name);
        return;
    }

    size_t cls_len = (size_t)(split - symbol_name - 2); /* Remove leading '-[' or '+[' */
    size_t sel_len = strlen(symbol_name) - cls_len - 4; /* Remove leading '-[' and trailing ']' */
    char *clsn = malloc(cls_len + 1);
    char *seln = malloc(sel_len + 1);
    if (clsn == NULL || seln == NULL) {
        free(clsn);
        free(seln);
        *class_name = strdup("");
        *sel_name = strdup("");
        return;
    }
    strncpy(clsn, symbol_name + 2, cls_len);
    strncpy(seln, split + 1, sel_len);
    clsn[cls_len] = '\0';
    seln[sel_len] = '\0';
    *class_name = clsn;
    *sel_name = seln;
}

/**
 * @brief Converts a Virtual Memory (VM) address to a Mach-O raw file offset.
 *
 * Checks against mapped segment bounds (__TEXT, __DATA_CONST, __DATA).
 *
 * @param[in] vmaddr Target virtual memory address.
 * @param[in] mi     Pointer to Mach-O Objective-C information structure containing segment mappings.
 * @return Raw file offset corresponding to the VM address, or -1 on conversion failure.
 */
uint64_t vm2fileoff(uint64_t vmaddr, const macho_objc_info_t *mi) {
    uint64_t fileoff;
    if (mi->chained_fixup)
        return vmaddr; // Might be buggy for binaries using chained fixups
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

/**
 * @brief Searches a method list for a specific selector and calculates its implementation file offset.
 *
 * Supports both standard (absolute address) and modern (32-bit relative offset) method entries.
 *
 * @param[in] sym_sel     Selector name string to match.
 * @param[in] method_list Pointer to the method list structure in memory.
 * @param[in] mi          Pointer to Mach-O Objective-C metadata info.
 * @param[in] macho_data  Pointer to loaded buffer of Mach-O binary file content.
 * @return File offset of method implementation (IMP), or 0 if not found.
 */
uint64_t solve_methodlist(const char *sym_sel, const struct method_list *method_list, const macho_objc_info_t *mi, void *macho_data) {
    uint32_t entsize = method_list->entsize & 0x0000FFFC; /* Mask out flag bits to get entry size */
    void *cur_method = (void *)(method_list + 1);
    for (int j = 0; j < method_list->count; j++) {
        char *method_name = NULL;
        uint64_t method_imp_off = 0;
        if ((method_list->entsize & 0x80000000) != 0) { /* Flag indicating relative offsets usage */
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

/**
 * @brief Helper function to format an Objective-C method symbol, test for search matches, 
 *        and push matched items to the output vector.
 *
 * @param[in,out] out         Output collection to store matching symbols.
 * @param[in]     addr        Calculated file address of the method implementation.
 * @param[in]     class_name  Class or category name string.
 * @param[in]     method_name Selector / method name string.
 * @param[in]     pattern     Search pattern or query string.
 * @param[in]     mode        Search mode strategy (exact, substring, regex, etc.).
 * @param[in]     search_case Search case-sensitivity mode.
 * @param[in]     preg        Compiled regex object (used if mode == REGEXP_MATCH).
 * @param[in]     prefix      Method type prefix ('+' for class methods, '-' for instance methods).
 */
static void add_objc_match(symbol_matches_t *out, uint64_t addr, const char *class_name,
                            const char *method_name, const char *pattern, search_mode_t mode,
                            search_case_t search_case, const regex_t *preg, char prefix) {
    char method_symbol[4096];
    int written = snprintf(method_symbol, sizeof(method_symbol), "%c[%s %s]",
                           prefix, class_name, method_name);
    if (written < 0 || (size_t)written >= sizeof(method_symbol))
        return;

    if (match_symbol(method_symbol, pattern, mode, search_case, preg) ||
        match_symbol(class_name, pattern, mode, search_case, preg) ||
        match_symbol(method_name, pattern, mode, search_case, preg)) {
        symbol_matches_push(out, addr, method_symbol);
    }
}

/**
 * @brief Searches all Objective-C class and category tables in a Mach-O binary for matching methods.
 *
 * Iterates through `__objc_classlist` and `__objc_catlist` sections, resolving both standard and
 * relative offset method lists, and appends matched symbols to the output matches array.
 *
 * @param[in]     fp          Open file handle to the Mach-O binary.
 * @param[in]     mi          Pointer to Mach-O Objective-C metadata info.
 * @param[in]     symbol_name Symbol query pattern or regular expression to match against.
 * @param[in]     search_mode Search match mode (e.g., exact match, regex match).
 * @param[in]     search_case Case-sensitivity setting.
 * @param[in,out] out         Output array storing matched symbols and addresses.
 * @return Number of new matching symbols added during this operation.
 */
size_t solve_objc_symbol(FILE *fp, const macho_objc_info_t *mi, const char* symbol_name,
                         search_mode_t search_mode, search_case_t search_case, symbol_matches_t *out) {
    size_t before = out->count;
    const long base_offset = mi->base_offset;

    if (mi->objc_classlist.off == 0) {
        fprintf(stderr, "symp: missing __objc_classlist section!\n");
        return 0;
    }

    char sym_type = symbol_name[0];
    char *sym_cls, *sym_sel;
    seperate_method(symbol_name, &sym_cls, &sym_sel);

    regex_t preg;
    bool preg_compiled = false;
    if (search_mode == REGEXP_MATCH) {
        if (!compile_regex(&preg, symbol_name, search_case)) {
            fprintf(stderr, "Could not compile regex: %s\n", symbol_name);
            free(sym_cls);
            free(sym_sel);
            return 0;
        }
        preg_compiled = true;
    }

    /* Read Objective-C data section into buffer */
    void *macho_data = read_file_off(fp, mi->data_vm.off + mi->data_vm.size, base_offset);

    /* Process __objc_classlist */
    uint64_t *classlist = macho_data + mi->objc_classlist.off;
    uint64_t nclasses = mi->objc_classlist.size / sizeof(uint64_t);
    for (int i = 0; i < nclasses; i++) {
        struct objc_class *objc_cls = macho_data + vm2fileoff(classlist[i] & ISA_MASK, mi);
        if (sym_type == '+') /* Class methods reside in the metaclass */
            objc_cls = macho_data + vm2fileoff(objc_cls->isaVMAddr & ISA_MASK, mi);
        struct class_ro *class_data = macho_data + vm2fileoff(objc_cls->dataVMAddrAndFastFlags & FAST_DATA_MASK, mi);
        char *class_name = macho_data + vm2fileoff(class_data->nameVMAddr & ISA_MASK, mi);
        if (class_data->baseMethodsVMAddr != 0) {
            struct method_list *method_list = macho_data + vm2fileoff(class_data->baseMethodsVMAddr & ISA_MASK, mi);
            for (int j = 0; j < method_list->count; j++) {
                char *method_name = NULL;
                uint64_t method_imp_off = 0;
                void *cur_method = (void *)(method_list + 1) + j * (method_list->entsize & 0x0000FFFC);
                if ((method_list->entsize & 0x80000000) != 0) { /* Relative offset encoding */
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
                if (method_imp_off != 0) {
                    add_objc_match(out, base_offset + method_imp_off, class_name, method_name,
                                   symbol_name, search_mode, search_case, preg_compiled ? &preg : NULL,
                                   sym_type);
                }
            }
        }
    }

    /* Process __objc_catlist (Categories) */
    uint64_t *catlist = macho_data + mi->objc_catlist.off;
    uint64_t ncategories = mi->objc_catlist.size / sizeof(uint64_t);
    for (int i = 0; i < ncategories; i++) {
        struct objc_category *objc_cat = macho_data + vm2fileoff(catlist[i] & ISA_MASK, mi);
        char *cat_name = macho_data + vm2fileoff(objc_cat->nameVMAddr & ISA_MASK, mi);
        uint64_t method_vmaddr = sym_type == '+' ? objc_cat->classMethodsVMAddr: objc_cat->instanceMethodsVMAddr;
        if (method_vmaddr != 0) {
            struct method_list *method_list = macho_data + vm2fileoff(method_vmaddr & ISA_MASK, mi);
            for (int j = 0; j < method_list->count; j++) {
                char *method_name = NULL;
                uint64_t method_imp_off = 0;
                void *cur_method = (void *)(method_list + 1) + j * (method_list->entsize & 0x0000FFFC);
                if ((method_list->entsize & 0x80000000) != 0) { /* Relative offset encoding */
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
                if (method_imp_off != 0) {
                    add_objc_match(out, base_offset + method_imp_off, cat_name, method_name,
                                   symbol_name, search_mode, search_case, preg_compiled ? &preg : NULL,
                                   sym_type);
                }
            }
        }
    }

    if (preg_compiled) {
        regfree(&preg);
    }
    free(sym_cls);
    free(sym_sel);
    free((void *)macho_data);
    return out->count - before;
}
