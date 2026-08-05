#ifndef SPARK_RECOVERED_VM_INDEX_H
#define SPARK_RECOVERED_VM_INDEX_H

#include <stddef.h>
#include <stdint.h>

typedef struct RecoveredVmStub {
    uint32_t file_offset;
    uint32_t virtual_address;
    uint8_t pushed_registers[3];
    uint8_t scratch_register;
    uint32_t key;
    uint32_t slot;
    uint32_t vm_target;
    uint32_t dispatcher;
} RecoveredVmStub;

extern const RecoveredVmStub g_recovered_vm_stubs[];
extern const size_t g_recovered_vm_stub_count;

const RecoveredVmStub *recovered_find_vm_stub(uint32_t virtual_address);

#endif
