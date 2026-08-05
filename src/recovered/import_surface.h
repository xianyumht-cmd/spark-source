#ifndef SPARK_RECOVERED_IMPORT_SURFACE_H
#define SPARK_RECOVERED_IMPORT_SURFACE_H

#include <stddef.h>
#include <stdint.h>

typedef struct RecoveredImport {
    const char *module;
    const char *symbol;
    uint16_t ordinal;
} RecoveredImport;

extern const RecoveredImport g_recovered_imports[16];
extern const size_t g_recovered_import_count;

#endif
