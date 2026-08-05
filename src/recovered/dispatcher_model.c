#include <stdint.h>
#include <stddef.h>

/*
 * Structural pseudocode for the observed dispatcher family.
 * This file deliberately separates confirmed facts from unknown semantics.
 */
typedef struct VmContextModel {
    const uint8_t *bytecode;  /* observed role: ESI-like stream pointer */
    uint32_t *vstack;         /* observed role: EBX-like virtual stack */
    uint32_t key;
    uintptr_t next_handler;
} VmContextModel;

static uintptr_t decode_handler_model(VmContextModel *vm, uint32_t encoded) {
    /* The concrete decoder is virtualized and has not been recovered. */
    (void)vm;
    return (uintptr_t)encoded;
}

void dispatcher_loop_model(VmContextModel *vm) {
    while (vm && vm->bytecode && vm->vstack) {
        uint32_t encoded = 0;
        /* The real width and transformation vary by handler. */
        encoded |= (uint32_t)vm->bytecode[0];
        encoded |= (uint32_t)vm->bytecode[1] << 8;
        encoded |= (uint32_t)vm->bytecode[2] << 16;
        encoded |= (uint32_t)vm->bytecode[3] << 24;
        vm->bytecode += 4;
        vm->next_handler = decode_handler_model(vm, encoded);

        /* Indirect JMP is confirmed; invoking it here would invent ABI details. */
        break;
    }
}
