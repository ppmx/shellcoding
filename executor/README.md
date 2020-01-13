# Shellcode Runner

Program to execute shellcode stored in a file.

## Example

```
$ make
$ ./build/shellcode-runner /tmp/hello.shellcode 
[+] shellcode file: /tmp/hello.shellcode
[+] size of file: 104 bytes
[+] hexdump of shellcode:
00000000  55 48 89 e5 48 b8 48 65  6c 6c 6f 20 77 6f 48 89 |UH..H.Hello woH.|
00000010  45 da c7 45 e2 72 6c 64  2e 66 c7 45 e6 0a 00 c7 |E..E.rld.f.E....|
00000020  45 fc 01 00 00 00 48 8d  45 da 48 89 45 f0 c7 45 |E.....H.E.H.E..E|
00000030  ec 0e 00 00 00 8b 45 fc  48 98 48 89 c7 48 8b 45 |......E.H.H..H.E|
00000040  f0 48 89 c6 8b 45 ec 48  98 48 89 c2 48 c7 c0 01 |.H...E.H.H..H...|
00000050  00 00 00 0f 05 89 c0 89  45 e8 48 31 ff 48 c7 c0 |........E.H1.H..|
00000060  3c 00 00 00 0f 05 eb f2                          |<.......|
[+] entering shellcode:
Hello world.
```
