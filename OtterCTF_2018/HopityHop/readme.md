# Hopity Hop

**Category:** Reverse Engineering
**Points:** 275
**Solves:** 24
**Description:**

Morty wrote his own RE challenge, but it doesn't work correctly. When Morty asked Rick what was the problem he took a quick look and only said: "Aina ya data imesainiwa" it probably has some meaning in BirdMan's tongue or something...

[HopityHop.exe](HopityHop.exe)

## Write-up

We have small c++ 64bit windows binary, load it in the disassembler.

In `main` function we have a pretty easy code [(short write-up how to get so clear code)](https://github.com/KosBeg/ctf-writeups/issues/1#issuecomment-446560726) and [(fast way to locate the main function when it isn't recognized by IDA)](https://github.com/KosBeg/ctf-writeups/issues/1#issuecomment-446636801):
```C
int main()
{
    int i;
    char next_skip;
    int skip;
    char skip_table[20];
    char buff[1732];

    i = 0;
    memcpy(buff, "some big string", 1732);
    _mm_storeu_si128(skip_table, _mm_load_si128(&g_skip_table));
    *&skip_table[16] = 0x2697;
    next_skip = 0x94u;
    skip_table[18] = 0;
    do
    {
        printf("%c", buff[i]); // print char from buff with i index
        skip = next_skip;
        next_skip = *++skip_table;
        i += skip + 1; // index
    } while (*skip_table);
    return 0;
}
```

Run this binary and we'll have some strange string with non-printable chars:
```
PS C:\Users\PC\Desktop> .\HopityHop.exe
foWznvJXRMZOFtvKe
```

Then carefully read the description and found strange words: "Aina ya data imesainiwa".

Goto google.translate and we'll have: "Data type is signed"(from Swahili). 

But in binary, we have two movsx(sign extend) and one movzx(zero extend).

So patch this binary at 0x1400010D4

```c
.text:00000001400010C0 print_loop:                             ; CODE XREF: main+76↓j
.text:00000001400010C0                 movsxd  rax, ebx
.text:00000001400010C3                 lea     rcx, Format     ; "%c"
.text:00000001400010CA                 movsx   edx, [rsp+rax+718h+buff] ; load byte and print
.text:00000001400010CF                 call    printf
.text:00000001400010CF
.text:00000001400010D4                 movsx   eax, sil        ; patch `movsx` here to `movzx`
.text:00000001400010D8                 lea     rdi, [rdi+1]
.text:00000001400010DC                 movzx   esi, byte ptr [rdi]
.text:00000001400010DF                 inc     ebx
.text:00000001400010E1                 add     ebx, eax        ; increment skip-counter
.text:00000001400010E3                 test    sil, sil
.text:00000001400010E6                 jnz     short print_loop
```

Re-run it and we'll have
```
PS C:\Users\PC\Desktop> .\HopityHop.exe
flag{H0p_N0p_D0p3}
```

Flag is: **flag{H0p_N0p_D0p3}**
