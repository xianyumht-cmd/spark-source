#ifndef SPARK_RECOVERED_VM_ENTRY_H
#define SPARK_RECOVERED_VM_ENTRY_H

#include <stdint.h>

/* Stack layout recovered from the wrapper at VA 0x0595D9C0. */
typedef struct VmEntryFrame {
    uint32_t next_node;
    uint32_t state;
    uint32_t token;
} VmEntryFrame;

extern const VmEntryFrame g_initial_vm_frame;

/* Analysis model only. The real dispatcher is virtualized machine code. */
void recovered_vm_dispatch_model(const VmEntryFrame *frame);
void recovered_protected_entry_model(void);

#endif
