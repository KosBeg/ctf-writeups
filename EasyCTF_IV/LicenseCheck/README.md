# LicenseCheck

**Category:** Reverse Engineering
**Points:** 300
**Solves:** 12
**Description:**

I want a valid license for a piece of software, [here](https://github.com/EasyCTF/easyctf-iv-problems/raw/master/license_check/license_check.exe) is the license validation software. Can you give me a valid license for the email `mzisthebest@notarealemail.com`?

Note: flag is _not_ in easyctf{} format.

## Write-up

Load the binary in IDA, and we see that it's obfuscated.

Obfuscation is not complex, mostly
1) `opaque predicate` that is
  a) always executed,
  b) never executed;
2) jump to the middle of the command;
3) mov eax, jmp_loc; jmp eax;
4) antidebug

Like

```
.text:00401370 B8 95 66 E4+                mov     eax, 4E46695h
.text:00401375 3D 36 55 ED+                cmp     eax, 0F4ED5536h ; loc_401383 is bad loc
.text:0040137A 74 07                       jz      short loc_401383 ; and `opaque predicate` that is never executed
```
```
.text:00401327 74 03                       jz      short near ptr loc_40132B+1 ; jump to the middle of the command
.text:00401329 75 01                       jnz     short near ptr loc_40132B+1 ; and `opaque predicate` that is always executed
.text:0040132B             loc_40132B:                             ; CODE XREF: .text:00401327j
.text:0040132B D9 B9 04 00+                fnstcw  word ptr [ecx+4]
```
```
.text:0040137C B8 89 13 40+                mov     eax, offset loc_401389
.text:00401381 FF E0                       jmp     eax ; jmp to loc_401389, but IDA doesn't see it
```
```
.text:0040106B C6 45 E7 00                 mov     byte ptr [ebp-19h], 0
.text:0040106F C7 45 FC 00+                mov     dword ptr [ebp-4], 0
.text:00401076 9C                          pushf
.text:00401077 81 0C 24 00+                or      dword ptr [esp], 100h
.text:0040107E 9D                          popf ; if program under debugger - we jump to seh at 0x0040108F
.text:0040107F 90                          nop ; else - normal execution
.text:00401080 C7 45 FC FE+                mov     dword ptr [ebp-4], 0FFFFFFFEh
.text:00401087 EB 14                       jmp     short loc_40109D
.text:00401087
```
```
.text:004010A5 FF 15 00 30+                call    ds:IsDebuggerPresent
.text:004010AB 85 C0                       test    eax, eax
.text:004010AD 74 51                       jz      short deb_detected_loc
```

I don't know how to deobfuscate automatically, so I'll do it manually. For deobfuscation we need:
1) keypatch - [keystone-engine.org/keypatch/](https://www.keystone-engine.org/keypatch/) 
2) brain
3) a bit of luck

After deobfuscation(nop all unnecessary code) and decompilation we have very beautiful code, you can even compile it, for me it working fine in vc17 :D
**UPD:** [original source of this task](https://github.com/EasyCTF/easyctf-iv-problems/tree/master/license_check/source)

```C
#include "stdafx.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// int f_strlen(const char *str);
unsigned int f_check_key(int *key);

int main(int argc, const char **argv, const char **envp)
{
  if (argc >= 3)                              // we need `email` and `key`
  {
    const char *email = (const char *)argv[1];
    const char *key = (const char *)argv[2];
    if (strlen(key) == 16)             // `key` len must be 16(4x4 parts)
    {
      size_t email_len = strlen(email);
      if (email_len >= 10)                    // `email` len must be >= 10
                          // len("mzisthebest@notarealemail.com") = 29, all is ok :D
      {
        unsigned int email_hash = 0xAED0DEA;                    // initial email_hash value
        bool is_domain = false;
        unsigned char byte;
        for (size_t i = 0; i < email_len; ++i)
        {
          byte = email[i];
          if (byte == '@')            // start of domain in email
            is_domain = true;
          if (is_domain)
            email_hash ^= byte;            // for domain of email we xor email_hash with ord(byte)
          else
            email_hash += byte;            // for nickname of email we add to email_hash ord(byte)
        }
        if (email_hash == 0xAED12F1 && !(f_check_key((int *)key) ^ 0x1AE33))// `email_hash == 0xAED12F1`
                                        // is always rigth for `mzisthebest@notarealemail.com`
          puts("correct!");
      }
    }
  }
  else
  {
    printf("Usage: %s <email> <license key>\n", *argv);
  }
}

/*
int f_strlen(const char *str) // just strlen, we no need it and will use standart strlen
{
  for (int len = 0; ; ++len)
    if (!*str++)
      break;
  return len;
}
*/

unsigned int f_check_key(int *key)
{
  unsigned int key_part;
  char *endPtr;

  unsigned int key_hash = 0;
  for (int i = 0; i < 4; ++i)
  {
    key_part = key[i];
    key_hash ^= strtol((char *)&key_part, &endPtr, 30);
  }
  return key_hash;
}
```

We do not need to check the email (because it always passes successfully), we need key check: when f_check_key return 0x1AE33 we will win.
In function f_check_key our key with len 16 is cut into 4x4 parts, convert parts from the base 30 (0_0) to base 10 and xor them among themselves.
```
key_hash_0 ^  key_part_0 == key_hash_1 ; key_hash_0 = 0
key_hash_1 ^  key_part_1 == key_hash_2
key_hash_2 ^  key_part_2 == key_hash_3
key_hash_3 ^  key_part_3 == 0x1AE33
```

After simplify this expressions we have
```
key_part_0 ^  key_part_1 ^  key_part_2 ^  key_part_3 == 0x1AE33
```

Let's write z3 script-keygen! :D

```python
from z3 import *
import string

digs = string.digits + string.letters
def int2base(x, base = 30):
  if x < 0:
    sign = -1
  elif x == 0:
    return digs[0]
  else:
    sign = 1
  x *= sign
  digits = []
  while x:
    digits.append(digs[x % base])
    x /= base
  if sign < 0:
    digits.append('-')
  digits.reverse()
  return ''.join(digits)

k0, k1, k2, k3 = BitVecs('k0 k1 k2 k3', 32)

s = Solver()
s.add( k0 >= 27000, k0 <= 809999 ) # 27000 is 1000 in 30 base, the least digit with 4 symbols
s.add( k1 >= 27000, k1 <= 809999 ) # 809999 is TTTT in 30 base, the largest digit with 4 symbols
s.add( k2 >= 27000, k2 <= 809999 )
s.add( k3 >= 27000, k3 <= 809999 )

# for a bit of fun :D
s.add( k0 == 583574 ) # LICE in 30 base
s.add( k1 == 646635 ) # NSEF in 30 base
s.add( k2 == 672974 ) # ORME in 30 base

s.add(k0 ^ k1 ^ k2 ^ k3 == 0x1AE33)

while s.check() == sat:
  r = s.model()
  print int2base(r[k0].as_long()) + int2base(r[k1].as_long()) + int2base(r[k2].as_long()) + int2base(r[k3].as_long())
#  s.add(k0 != r[k0])
#  s.add(k1 != r[k1])
#  s.add(k2 != r[k2])
  s.add(k3 != r[k3])
```

```
PS C:\Users\PC\Desktop> python.exe .\LicenseCheck_keygen.py
licenseformeq7eg
```

That's all :)
