#include "private.h"

#include <stdint.h>

uint8_t x86_64_nop[]  = {0x90};                     // nop
uint8_t x86_64_ret[]  = {0xC3};                     // ret
uint8_t x86_64_ret0[] = {0x48, 0x31, 0xC0,          // xor  rax, rax
                         0xC3};                     // ret
uint8_t x86_64_ret1[] = {0x48, 0x31, 0xC0,          // xor  rax, rax
                         0xB0, 0x01,                // mov  al, 0x1
                         0xC3};                     // ret
uint8_t x86_64_ret2[] = {0x48, 0x31, 0xC0,          // xor  rax, rax
                         0xB0, 0x02,                // mov  al, 0x2
                         0xC3};                     // ret

uint8_t arm64_nop[]   = {0x1F, 0x20, 0x03, 0xD5};   // nop
uint8_t arm64_ret[]   = {0xC0, 0x03, 0x5F, 0xD6};   // ret
uint8_t arm64_ret0[]  = {0x00, 0x00, 0x80, 0xD2,    // mov  x0, 0x0
                         0xC0, 0x03, 0x5F, 0xD6};   // ret
uint8_t arm64_ret1[]  = {0x20, 0x00, 0x80, 0xD2,    // mov  x0, 0x1
                         0xC0, 0x03, 0x5F, 0xD6};   // ret
uint8_t arm64_ret2[]  = {0x40, 0x00, 0x80, 0xD2,    // mov  x0, 0x2
                         0xC0, 0x03, 0x5F, 0xD6};   // ret

builtin_patch_t builtin_patches[] = {
    {"nop", {sizeof x86_64_nop, x86_64_nop}, {sizeof arm64_nop, arm64_nop}},
    {"ret", {sizeof x86_64_ret, x86_64_ret}, {sizeof arm64_ret, arm64_ret}},
    {"ret0", {sizeof x86_64_ret0, x86_64_ret0}, {sizeof arm64_ret0, arm64_ret0}},
    {"ret1", {sizeof x86_64_ret1, x86_64_ret1}, {sizeof arm64_ret1, arm64_ret1}},
    {"ret2", {sizeof x86_64_ret2, x86_64_ret2}, {sizeof arm64_ret2, arm64_ret2}}
};

int builtin_patches_count = ARRAY_LEN(builtin_patches);
