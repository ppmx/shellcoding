# Shellcoding

Tooling around shellcode. 

## Example for opcodes.py
```
$ # see also https://github.com/ppmx/elfi/tree/master/shellcode
$ python3 opcodes.py -b ../elfi/shellcode/output/hello_world  
[+] Analyzing: ../elf/shellcode/output/hello_world
[+] Extracting: _start
[+] Dump of assembler code for function _start:
   0x0000000000001038 <+0>:   55                            push   rbp
   0x0000000000001039 <+1>:   48 89 e5                      mov    rbp,rsp
   0x000000000000103c <+4>:   48 b8 48 65 6c 6c 6f 20 77 6f movabs rax,0x6f77206f6c6c6548
   0x0000000000001046 <+14>:  48 89 45 da                   mov    QWORD PTR [rbp-0x26],rax
   0x000000000000104a <+18>:  c7 45 e2 72 6c 64 2e          mov    DWORD PTR [rbp-0x1e],0x2e646c72
   0x0000000000001051 <+25>:  66 c7 45 e6 0a 00             mov    WORD PTR [rbp-0x1a],0xa
   0x0000000000001057 <+31>:  c7 45 fc 01 00 00 00          mov    DWORD PTR [rbp-0x4],0x1
   0x000000000000105e <+38>:  48 8d 45 da                   lea    rax,[rbp-0x26]
   0x0000000000001062 <+42>:  48 89 45 f0                   mov    QWORD PTR [rbp-0x10],rax
   0x0000000000001066 <+46>:  c7 45 ec 0e 00 00 00          mov    DWORD PTR [rbp-0x14],0xe
   0x000000000000106d <+53>:  8b 45 fc                      mov    eax,DWORD PTR [rbp-0x4]
   0x0000000000001070 <+56>:  48 98                         cdqe   
   0x0000000000001072 <+58>:  48 89 c7                      mov    rdi,rax
   0x0000000000001075 <+61>:  48 8b 45 f0                   mov    rax,QWORD PTR [rbp-0x10]
   0x0000000000001079 <+65>:  48 89 c6                      mov    rsi,rax
   0x000000000000107c <+68>:  8b 45 ec                      mov    eax,DWORD PTR [rbp-0x14]
   0x000000000000107f <+71>:  48 98                         cdqe   
   0x0000000000001081 <+73>:  48 89 c2                      mov    rdx,rax
   0x0000000000001084 <+76>:  48 c7 c0 01 00 00 00          mov    rax,0x1
   0x000000000000108b <+83>:  0f 05                         syscall 
   0x000000000000108d <+85>:  89 c0                         mov    eax,eax
   0x000000000000108f <+87>:  89 45 e8                      mov    DWORD PTR [rbp-0x18],eax
   0x0000000000001092 <+90>:  48 31 ff                      xor    rdi,rdi
   0x0000000000001095 <+93>:  48 c7 c0 3c 00 00 00          mov    rax,0x3c
   0x000000000000109c <+100>: 0f 05                         syscall 
   0x000000000000109e <+102>: eb f2                         jmp    0x1092 <_start+90>

[+] Opcodes from function '_start' of binary '../elf/shellcode/output/hello_world'
554889e548b848656c6c6f20776f488945dac745e2726c642e66c745e60a00c745fc01000000488d45da488945f0c745ec0e0000008b45fc48984889c7488b45f04889c68b45ec48984889c248c7c0010000000f0589c08945e84831ff48c7c03c0000000f05ebf2
```

This extracted code can also be stored inside a file using the `-o` flag.
The shellcode executor tool is then useful to test this extracted shellcode.