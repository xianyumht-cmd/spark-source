#include "import_surface.h"

/* Exact static import-table surface; this is not necessarily the runtime API set. */
const RecoveredImport g_recovered_imports[16] = {
    { "MSVFW32.dll",  "DrawDibDraw",            0 },
    { "AVIFIL32.dll", "AVIStreamInfoA",         0 },
    { "iphlpapi.dll", "GetAdaptersInfo",        0 },
    { "WINMM.dll",    "midiStreamOut",          0 },
    { "WS2_32.dll",   0,                       115 },
    { "KERNEL32.dll", "GetTimeZoneInformation", 0 },
    { "USER32.dll",   "wvsprintfA",            0 },
    { "GDI32.dll",    "CreateSolidBrush",      0 },
    { "MSIMG32.dll",  "GradientFill",          0 },
    { "WINSPOOL.DRV", "DocumentPropertiesA",   0 },
    { "comdlg32.dll", "ChooseColorA",          0 },
    { "ADVAPI32.dll", "RegCreateKeyExA",       0 },
    { "SHELL32.dll",  "Shell_NotifyIconA",     0 },
    { "ole32.dll",    "CoTaskMemAlloc",        0 },
    { "OLEAUT32.dll", 0,                        23 },
    { "COMCTL32.dll", "ImageList_Destroy",     0 },
};

const size_t g_recovered_import_count =
    sizeof(g_recovered_imports) / sizeof(g_recovered_imports[0]);
