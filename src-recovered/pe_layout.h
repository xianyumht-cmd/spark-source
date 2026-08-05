#ifndef RECOVERED_PE_LAYOUT_H
#define RECOVERED_PE_LAYOUT_H

#define REC_IMAGE_BASE       0x00400000u
#define REC_ENTRY_RVA        0x03483820u
#define REC_ENTRY_VA         0x03883820u
#define REC_SIZE_OF_IMAGE    0x0558B000u
#define REC_SECTION_COUNT    8u

struct recovered_section {
    const char *name;
    unsigned virtual_address;
    unsigned virtual_size;
    unsigned raw_pointer;
    unsigned raw_size;
};

static const struct recovered_section REC_SECTIONS[REC_SECTION_COUNT] = {
    { ".text",  0x00001000u, 0x001B6C9Au, 0x00000000u, 0x00000000u },
    { ".rdata", 0x001B8000u, 0x0051F036u, 0x00000000u, 0x00000000u },
    { ".data",  0x006D8000u, 0x0008B7D1u, 0x00000000u, 0x00000000u },
    { ".9z",    0x00764000u, 0x000EE000u, 0x00001000u, 0x000EE000u },
    { ".q896d", 0x00852000u, 0x00001000u, 0x00000000u, 0x00000000u },
    { ".zng",   0x00853000u, 0x02C30000u, 0x00000000u, 0x00000000u },
    { ".5497y", 0x03483000u, 0x020E7000u, 0x000EF000u, 0x020E7000u },
    { ".rsrc",  0x0556A000u, 0x00021000u, 0x021D6000u, 0x00021000u }
};

#endif
