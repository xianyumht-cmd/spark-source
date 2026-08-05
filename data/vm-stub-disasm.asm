; First reachable VM entry stub

0595d9c0: 52                push edx
0595d9c1: 57                push edi
0595d9c2: 50                push eax
0595d9c3: b8 99 c4 ab 94    mov eax, 0x94abc499
0595d9c8: 89 44 24 08       mov dword ptr [esp + 0x8], eax
0595d9cc: b8 00 00 00 00    mov eax, 0x0
0595d9d1: 89 44 24 04       mov dword ptr [esp + 0x4], eax
0595d9d5: b8 3e a3 8e 05    mov eax, 0x058ea33e
0595d9da: 87 04 24          xchg dword ptr [esp], eax
0595d9dd: e9 2b 31 f5 ff    jmp 0x058b0b0d
