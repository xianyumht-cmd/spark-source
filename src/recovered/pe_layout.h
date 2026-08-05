#ifndef SPARK_RECOVERED_PE_LAYOUT_H
#define SPARK_RECOVERED_PE_LAYOUT_H

#include <stdint.h>

/* Constants recovered directly from the PE headers. */
enum {
    REC_IMAGE_BASE       = 0x00400000u,
    REC_ENTRY_RVA        = 0x03483820u,
    REC_ENTRY_VA         = 0x03883820u,
    REC_VM_GATE_VA       = 0x0595D9C0u,
    REC_VM_DISPATCHER_VA = 0x058B0B0Du,
};

typedef struct RecoveredSectionLayout {
    const char *name;
    uint32_t rva;
    uint32_t virtual_size;
    uint32_t raw_offset;
    uint32_t raw_size;
    uint32_t characteristics;
} RecoveredSectionLayout;

extern const RecoveredSectionLayout g_recovered_sections[8];

#endif
