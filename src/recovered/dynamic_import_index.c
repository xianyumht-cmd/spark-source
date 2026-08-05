#include "dynamic_import_index.h"

const RecoveredDynamicImport g_recovered_dynamic_imports[] = {
#include "dynamic_import_index_part01.inc"
#include "dynamic_import_index_part02.inc"
#include "dynamic_import_index_part03.inc"
#include "dynamic_import_index_part04.inc"
#include "dynamic_import_index_part05.inc"
#include "dynamic_import_index_part06.inc"
};

const size_t g_recovered_dynamic_import_count =
    sizeof(g_recovered_dynamic_imports) / sizeof(g_recovered_dynamic_imports[0]);
