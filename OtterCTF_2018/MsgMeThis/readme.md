# Msg Me This

**Category:** Reverse Engineering
**Points:** 500
**Solves:** 15
**Description:**

Rick created another vicious program

Could you get the correct flag?

[MsgMeThis.exe](MsgMeThis.exe)

## Write-up

We have c++ 32bit windows binary build in debug mode, load it in the disassembler.

In `main` function we have next code [(short write-up how to get so clear code)](https://github.com/KosBeg/ctf-writeups/issues/1#issuecomment-446560726) and [(fast way to locate the main function when it isn't recognized by IDA)](https://github.com/KosBeg/ctf-writeups/issues/1#issuecomment-446636801):
```C
int __cdecl main(int argc, const char **argv, const char **envp)
{
  int v3; // edx
  int v4; // ecx
  int v5; // edx
  int v6; // ecx
  int v7; // edx
  int v8; // ST0C_4
  LPVOID v10; // [esp+D0h] [ebp-148h]
  char v11; // [esp+DCh] [ebp-13Ch]
  char v12; // [esp+DDh] [ebp-13Bh]
  char v13; // [esp+DEh] [ebp-13Ah]
  char v14; // [esp+DFh] [ebp-139h]
  int j; // [esp+E8h] [ebp-130h]
  unsigned __int8 *i; // [esp+F4h] [ebp-124h]
  void (*v17)(); // [esp+100h] [ebp-118h]
  int v18; // [esp+10Ch] [ebp-10Ch]
  LPVOID lpAddress; // [esp+118h] [ebp-100h]
  DWORD flOldProtect; // [esp+124h] [ebp-F4h]
  char shellcode[223]; // [esp+130h] [ebp-E8h]
  int v22; // [esp+214h] [ebp-4h]
  int savedregs; // [esp+218h] [ebp+0h]

  qmemcpy(shellcode, f_shellcode, sizeof(shellcode));
  flOldProtect = 0;
  v18 = 222;
  v17 = (sub_42AB72 + 1);
  for ( i = sub_42AB72 + *(sub_42AB72 + 1); *i == 0xCC; ++i )
    ;
  i += 30;
  for ( j = 0; i[j] != 0x90; ++j )
    ;
  lpAddress = sub_42C413(shellcode, v18);
  sub_42B112(lpAddress, (j + v18) | -__CFADD__(j, v18));
  VirtualProtect(lpAddress, j + v18, 0x40u, &flOldProtect);
  sub_42B33D(v4, v3);
  sub_42ACEE(lpAddress + j, lpAddress, v18);
  v11 = v18;
  v12 = 0;
  v13 = 0;
  v14 = 0;
  sub_42ACEE(lpAddress, i, j);
  sub_42ACEE(lpAddress + 20, &v11, 4);
  v10 = lpAddress;
  (lpAddress)();
  sub_42B33D(v6, v5);
  sub_42C2BF(&savedregs, &dword_43024C, 0, v7);
  return sub_42B33D(&savedregs ^ v22, v8);
}
```

Of course, we can analyze and try to understand what and how this code does. But there an easier way.

Pay attention to
```C
  qmemcpy(shellcode, f_shellcode, sizeof(shellcode));
```

Let's analyze f_shellcode instead!

```C
int f_shellcode()
{
  int v0; // ebx
  _DWORD *v1; // edx
  int *v2; // esi
  int v3; // ecx
  int v4; // eax
  _DWORD *v5; // eax
  int (__stdcall *v6)(int, int *, signed int, signed int, signed int, _DWORD, _DWORD, int, int (__cdecl *)(_DWORD, _DWORD, _DWORD, _DWORD)); // edx
  int (__cdecl *v7)(int, _DWORD *, signed int, signed int); // eax
  int v8; // ecx
  int v9; // eax
  int v10; // eax
  int v12; // [esp-Ch] [ebp-20h]
  int v13; // [esp-4h] [ebp-18h]
  int v14; // [esp+0h] [ebp-14h]
  int v15; // [esp+4h] [ebp-10h]
  int v16; // [esp+8h] [ebp-Ch]
  int v17; // [esp+Ch] [ebp-8h]
  int v18; // [esp+10h] [ebp-4h]
  int (__cdecl *savedregs)(int, _DWORD *, signed int, signed int); // [esp+14h] [ebp+0h]

  v0 = *(***(*(__readfsdword(0x30u) + 12) + 20) + 16);
  v1 = (v0 + *(v0 + *(v0 + 60) + 120));
  v2 = (v0 + v1[8]);
  v3 = 0;
  do
  {
    do
    {
      ++v3;
      v4 = *v2;
      ++v2;
      v5 = (v0 + v4);
    }
    while ( *v5 != 0x50746547 );
  }
  while ( v5[1] != 0x41636F72 || v5[2] != 0x65726464 );
  LOWORD(v3) = *(v0 + v1[9] + 2 * v3);
  v6 = (v0 + *(v0 + v1[7] + 4 * (v3 - 1)));
  v7 = v6(v0, &v13, 0x64616F4C, 0x7262694C, 0x41797261, 0, v6, v0, savedregs);
  v8 = savedregs;
  savedregs = v7;
  v18 = v8;
  LOWORD(v8) = 0x6C6C;
  v9 = v7(&v15, 0x72657375, 0x642E3233, v8);
  v17 = 0;
  v16 = 0x41786F;
  v10 = savedregs(v9, &v14, 0x7373654D, 0x42656761);
  v15 = 0;
  return (v10)(0, &v12, &v12, 0, v10 ^ 0x67616C66, v10 ^ 0x6568537B, v10 ^ 0x6F436C6C, v10 ^ 0x7D646564);
}
```

Pay attention to

```C
  return (v10)(0, &v12, &v12, 0, v10 ^ 0x67616C66, v10 ^ 0x6568537B, v10 ^ 0x6F436C6C, v10 ^ 0x7D646564);
```

If we convert numbers to ASCII we'll have

```C
  return (v10)(0, &v12, &v12, 0, v10 ^ 'galf', v10 ^ 'ehS{', v10 ^ 'oCll', v10 ^ '}ded');
```

`galf` is reversed `flag`...

Ok
```
flag
{She
llCo
ded}
```

Concatenate it and

Flag is: **flag{ShellCoded}**
