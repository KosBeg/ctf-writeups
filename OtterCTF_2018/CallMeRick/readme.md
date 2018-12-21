# Call Me Rick

**Category:** Reverse Engineering
**Points:** 450
**Solves:** 7
**Description:**

Rick created this twisted program that will only work if you enter the right two numbers.

Remember to return from the function and use nops to fill in any gaps.

EDIT: There were multiple possible answers so I changed the flag format.

flag{uppercase hex values of the 5 bytes necessary to win the flag}

[CallMeRick.exe](CallMeRick.exe)

## Write-up

We have c++ 32bit windows binary built in debug mode, load it in the disassembler.

In `main` function we have a pretty easy code [(short write-up how to get so clear code)](https://github.com/KosBeg/ctf-writeups/issues/1#issuecomment-446560726) and [(fast way to locate the main function when it isn't recognized by IDA)](https://github.com/KosBeg/ctf-writeups/issues/1#issuecomment-446636801):
```C
int main()
{
  int num;
  LPVOID lpAddress;
  DWORD flOldProtect;
  int savedregs;

  flOldProtect = 0;
  lpAddress = &write_here;
  VirtualProtect(&write_here, 8u, 0x40u, &flOldProtect);
  scanf("%d %d", lpAddress, lpAddress + 4);     // write 2 numbers to `write_here` location
  num = 1;
  check_stack(&savedregs, &tmp_pptr);
  return 0;
}
```

`write_here` loc is part of main function
```C
.text:0045D22B 51                                   push    ecx
.text:0045D22C 68 68 DE 50 00                       push    offset format   ; "%d %d"
.text:0045D231 E8 1E C6 FF FF                       call    scanf
.text:0045D231
.text:0045D236 83 C4 0C                             add     esp, 0Ch
.text:0045D236
.text:0045D239
.text:0045D239                      write_here:                             ; DATA XREF: main+2F↑o
.text:0045D239 C7 45 DC 06 00 00 00                 mov     [ebp+num], 6
.text:0045D240 BB C3 08 00 00                       mov     ebx, 8C3h
```

So we need to enter 8 bytes shellcode, but what we can do with it?

Then I found `Congratulations` in strings, and by xrefs get to function `sub_45D0B0`

```C
.text:0045D0D0 6A 00                                push    0               ; uType
.text:0045D0D2 68 50 DE 50 00                       push    offset Caption  ; "Win"
.text:0045D0D7 68 54 DE 50 00                       push    offset Text     ; "Congratulations"
.text:0045D0DC 6A 00                                push    0               ; hWnd
.text:0045D0DE FF 15 BC 71 53 00                    call    ds:__imp_MessageBoxA
```

Ok, we need to call `sub_45D0B0` function in the way that program doesn't crash.

We can do something like this

```C
E8 72 FE FF FF        call sub_45D0B0
90                    nop                   ; use nops to fill in any gaps
90                    nop                   ; use nops to fill in any gaps
BB                    db BBh                ; do not change the byte, so as it didn't crash
```

We need to enter 2 numbers: 4294865640(0xFFFE72E8) and 3146813695(0xBB9090FF)

Sum of this num is hex(0xFFFE72E8+0xBB9090FF) = 1BB8F03E7 

Flag is: **CTF{1BB8F03E7}**
