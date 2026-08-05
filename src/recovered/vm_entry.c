#include "vm_entry.h"
#include "pe_layout.h"

const VmEntryFrame g_initial_vm_frame = {
    0x058EA33Eu,
    0x00000000u,
    0x94ABC499u,
};

void recovered_vm_dispatch_model(const VmEntryFrame *frame) {
    /*
     * Confirmed machine-level model:
     *   - execution transfers to REC_VM_DISPATCHER_VA with JMP;
     *   - the dispatcher consumes a three-dword stack frame;
     *   - computed indirect jumps select subsequent handlers;
     *   - ESI and EBX are repeatedly used as stream/virtual-stack pointers.
     *
     * The protected handler semantics are intentionally not invented here.
     */
    (void)frame;
}

void recovered_protected_entry_model(void) {
    /* PE entry VA 0x03883820 performs a direct JMP to 0x0595D9C0. */
    recovered_vm_dispatch_model(&g_initial_vm_frame);
}
