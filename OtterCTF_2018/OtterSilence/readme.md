# Otter Silence

**Category:** Reverse Engineering
**Points:** 300
**Solves:** 17
**Description:**

Yet another one of Rick's creations...

Be quick.

[OtterSilence.exe](OtterSilence.exe)

## Write-up

We have small c++ 32bit windows binary, load it in disassembler.

In `main` function we have prety easy code:
```C
int main()
{
  HMODULE cur_proc; 
  char byte; 
  int idx; 
  unsigned int i; 
  char xor_byte; 
  char xored_flag[27]; 
  char buff_2[260]; 
  char buff_1[256]; 
  char xor_key[4]; 
  char v13; 

  cur_proc = GetModuleHandleA(0);
  memset(buff_1, 0, 255);
  memset(&buff_2[4], 0, 255);
  if ( !LoadStringA(cur_proc, 1337u, buff_1, 255) )
    return -1;
  byte = buff_1[0];
  if ( buff_1[0] )
  {
    idx = 0;
    do                                          // decode string by xor
    {
      buff_2[++idx + 3] = byte ^ 0x30;          // "++idx + 3" always >= 4
      byte = buff_1[idx];
    }
    while ( byte );
  }
  memset(buff_1, 0, 255);
  if ( !LoadStringA(cur_proc, 666u, buff_1, 255) )
    return -1;
  *xor_key = 0;
  v13 = 0;
  *buff_2 = 5;
  if ( RegGetValueA(HKEY_CURRENT_USER, &buff_2[4], buff_1, 0xFFFF, 0, xor_key, buff_2) )// load decrypt key
    return -1;
  i = 0;
  *xored_flag = g_xored_flag_part;
  *&xored_flag[16] = 0x354567C;
  xor_byte = 0x72;
  *&xored_flag[20] = 0x4503696E;
  *&xored_flag[24] = 0x4E53;
  xored_flag[26] = 0;
  do                                            // decrypt xored flag
  {
    printf("%c", xor_byte ^ xor_key[i % (*buff_2 - 1)]);// *buff_2 - 1 == 4
    xor_byte = xored_flag[i++ + 1];
  }
  while ( xor_byte );
  return 0;
}
```

Briefly: we get string-resource with `uID = 1337`, then decode this string by xoring with 0x30, then load string with `uID = 666` an use it for `RegGetValueA` and load xor_key to decode xored_flag

```C
00C5110D | 50                       | push eax                                | LPDWORD pcbData = "Keyboard Layout\\Toggle"
00C5110E | 8D45 F4                  | lea eax,dword ptr ss:[ebp-C]            |
00C51111 | C645 F8 00               | mov byte ptr ss:[ebp-8],0               |
00C51115 | 50                       | push eax                                | PVOID pvData = "Keyboard Layout\\Toggle"
00C51116 | 6A 00                    | push 0                                  | LPDWORD pdwType = REG_NONE
00C51118 | 68 FFFF0000              | push FFFF                               | DWORD dwFlags = FFFF
00C5111D | 8D85 F4FEFFFF            | lea eax,dword ptr ss:[ebp-10C]          |
00C51123 | C785 F0FDFFFF 05000000   | mov dword ptr ss:[ebp-210],5            |
00C5112D | 50                       | push eax                                | LPCTSTR lpValue = "Keyboard Layout\\Toggle"
00C5112E | 8D85 F4FDFFFF            | lea eax,dword ptr ss:[ebp-20C]          |
00C51134 | 50                       | push eax                                | LPCTSTR lpSubKey = "Keyboard Layout\\Toggle"
00C51135 | 68 01000080              | push 80000001                           | HANDLE hkey = HKEY_CURRENT_USER
00C5113A | FF15 0040C600            | call dword ptr ds:[<&RegGetValueA>]     | RegGetValueA
```

So we need only 4 char xor_key that we can just brute(long way) or we can use flag format to restore key `¯\_(ツ)_/¯`

Xor first 4 bytes of xored_flag with `CTF{` we'll have xor key `1337` or `31 33 33 37` as bytes

```python
>>> a = [0x72, 0x67, 0x75, 0x4C]
>>> chr(a[0] ^ ord('C'))
'1'
>>> chr(a[1] ^ ord('T'))
'3'
>>> chr(a[2] ^ ord('F'))
'3'
>>> chr(a[3] ^ ord('{'))
'7'
```

Now we can set `HKEY_CURRENT_USER\Keyboard Layout\Toggle\UltraMegaOtter` to `1337`, and run binary:

```
PS C:\Users\PC\Desktop> .\OtterSilence.exe
CTF{Ultr4_Lutra_Meg4_Z0rb}
```

Flag is: **CTF{Ultr4_Lutra_Meg4_Z0rb}**
