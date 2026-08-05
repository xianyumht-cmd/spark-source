; Common dispatcher excerpt reached from the first VM stub

058b0b0d: 9c                pushfd
058b0b0e: 56                push esi
058b0b0f: f9                stc
058b0b10: f8                clc
058b0b11: f5                cmc
058b0b12: 50                push eax
058b0b13: f9                stc
058b0b14: f5                cmc
058b0b15: 66 98             cbw
058b0b17: 53                push ebx
058b0b18: 51                push ecx
058b0b19: f5                cmc
058b0b1a: 98                cwde
058b0b1b: f9                stc
058b0b1c: 66 98             cbw
058b0b1e: e9 2d 00 00 00    jmp 0x058b0b50

058b0b50: 0f b7 c3          movzx eax, bx
058b0b53: 52                push edx
058b0b54: f9                stc
058b0b55: 0f bf db          movsx ebx, bx
058b0b58: 66 98             cbw
058b0b5a: 66 99             cwd
058b0b5c: 99                cdq
058b0b5d: 57                push edi
058b0b5e: 0f b7 d6          movzx edx, si
058b0b61: 0f bf cd          movsx ecx, bp
058b0b64: 55                push ebp
058b0b65: 98                cwde
058b0b66: 99                cdq
058b0b67: 0f bf f8          movsx edi, ax
058b0b6a: e9 46 01 00 00    jmp 0x058b0cb5
