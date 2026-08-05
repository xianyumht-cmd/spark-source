#ifndef SPARK_RECOVERED_DYNAMIC_IMPORT_INDEX_H
#define SPARK_RECOVERED_DYNAMIC_IMPORT_INDEX_H

#include <stddef.h>
#include <stdint.h>

typedef struct RecoveredDynamicImport {
    uint32_t encoded_file_offset;
    const char *module;
    const char *symbol;
} RecoveredDynamicImport;

extern const RecoveredDynamicImport g_recovered_dynamic_imports[];
extern const size_t g_recovered_dynamic_import_count;

#endif
