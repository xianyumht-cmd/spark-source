/*
 * Recovered first-stage pseudocode.
 * This file expresses only instructions proven by the static disassembly.
 * It is not claimed to be the original application source.
 */
#include <stdint.h>

#define IMAGE_BASE          0x00400000u
#define DISK_ENTRY_VA       0x03883820u
#define FIRST_VM_STUB_VA    0x0595D9C0u
#define VM_DISPATCHER_VA    0x058B0B0Du

struct vm_seed_frame {
    uint32_t value0;
    uint32_t value1;
    uint32_t value2;
};

/* Exact constants observed in the first reachable stub. */
static struct vm_seed_frame recovered_first_seed(void) {
    struct vm_seed_frame frame;
    frame.value0 = 0x058EA33Eu;
    frame.value1 = 0x00000000u;
    frame.value2 = 0x94ABC499u;
    return frame;
}

/* Logical representation of the protected disk entry. */
void protected_disk_entry(void) {
    struct vm_seed_frame frame = recovered_first_seed();
    (void)frame;

    /* Native control transfers to VM_DISPATCHER_VA.
       The dispatcher consumes the seed frame and virtual bytecode. */
}
