# Listen Carefully

**Category:** Reverse Engineering
**Points:** 450
**Solves:** 8
**Description:**

Plug in your loudest speakers and enjoy the ride

[ListenCarefully.exe](ListenCarefully.exe)

## Write-up

As for me - this is the most interesting and complex RE-task on this CTF.

Ok, let's start!

We have big for CTF(13 mb) c++ 32bit windows binary, load it in disassembler.

In `main` function we have next code [(short write-up how to get so clear code)](https://github.com/KosBeg/ctf-writeups/issues/1#issuecomment-446560726):
```C
int __cdecl main(int argc, const char **argv, const char **envp)
{
  HRSRC resz; // eax
  HGLOBAL WAWE; // eax MAPDST
  char *final_flag; // eax MAPDST
  int WAWE_offset; // esi MAPDST
  char user_char; // al
  signed int cur_pass_idx; // esi
  int idx; // ecx
  char *byte_i2_1; // eax
  int sum; // edx
  char xx0; // bl MAPDST
  bool is_zero; // zf
  int i_1; // ebx
  int xx2; // edx
  int xx2_and_xx1; // edi
  int j; // [esp+8h] [ebp-10h]
  int ja; // [esp+8h] [ebp-10h]
  _BYTE *locked_WAWE; // [esp+Ch] [ebp-Ch]

  CreateThread(0, 0, StartAddress, L"Music", 0, 0);
  resz = FindResourceW(0, L"Data", L"WAVE");
  if ( resz )
  {
    WAWE = LoadResource(0, resz);
    if ( WAWE )
    {
      locked_WAWE = LockResource(WAWE);         // load resource with name `WAVE`
      if ( locked_WAWE )
      {
        printf("Enter password: ");
        final_flag = (char *)malloc(0x19u);
        for ( WAWE_offset = 0; locked_WAWE[WAWE_offset] != 0xFFu || locked_WAWE[WAWE_offset + 1] != 0xFBu; ++WAWE_offset )
          ;
        WAWE_offset += 2;                       // find some offset in resource
        if ( WAWE_offset != 0xFFFFFFFF )
        {
          final_flag = g_xor2_28db;             // load xored flag
          j = final_flag - g_xor2_28db;
          do
          {
            if ( !*final_flag )                 // if cur char zero -> goto next_loc
              break;
            user_char = get_char();             // read 1 char from user
            if ( user_char != 10 )
            {
              if ( (unsigned __int8)(user_char - 0x21) > 0x5Du )// if it's non printable -> exit
                goto free;
              final_flag[j] = *final_flag ^ locked_WAWE[WAWE_offset + user_char];// xor some buff with WAWE[off + user_char]
                                                // eq to
                                                // final_flag[j] ^= locked_WAWE[WAWE_offset + user_char];
                                                // 
              ++final_flag;                     // goto next char
              while ( locked_WAWE[WAWE_offset] != -1 || locked_WAWE[WAWE_offset + 1] != -5 )
                ++WAWE_offset;
              WAWE_offset += 2;                 // find next offset in file
            }
          }
          while ( WAWE_offset != -1 );
        }
        final_flag[24] = 0;
        cur_pass_idx = 0;
        ja = 3 - (_DWORD)final_flag;
        while ( 1 )
        {
          idx = cur_pass_idx;
          byte_i2_1 = &final_flag[cur_pass_idx];
          sum = 0;
          xx0 = final_flag[cur_pass_idx];
          is_zero = xx0 == 0;
          i_1 = cur_pass_idx / 3;
          if ( !is_zero )
          {
            do
            {
              if ( idx >= (signed int)&final_flag[cur_pass_idx + ja] )// check if idx <= 3
                                                // eg for one do-while loop we will check
                                                // 3 < 6, 4 < 6, 5 < 6
                break;
              ++idx;
              sum += *byte_i2_1;                // add char of password
              byte_i2_1 = &final_flag[idx];
            }
            while ( final_flag[idx] );
          }
          if ( sum != g_sum_8dd[i_1] )          // and then check sum of this 3 chars
            break;
          xx2 = final_flag[cur_pass_idx + 2];
          xx2_and_xx1 = xx2 & final_flag[cur_pass_idx + 1];
          if ( (xx2_and_xx1 ^ xx0) != g_xor_8dd[i_1]// check_2
            || (xx2_and_xx1 ^ 8 * xx0) != g_xor_mul8_8dd[i_1]// check_3
            || (16 * xx2 ^ (xx0 - final_flag[cur_pass_idx + 1])) != g_math_8dd[i_1] )// check_4
                                                // final_flag[cur_pass_idx + 1] == xx1
          {
            break;
          }
          cur_pass_idx += 3;                    // if all is ok -> goto next 3 chars of password
          if ( cur_pass_idx >= 24 )
          {
            puts(final_flag);                   // if all chars is ok -> print decrypted flag
            break;
          }
        }
      }
free:
      FreeResource(WAWE);
    }
  }
  return 0;
}
```

Briefly: we load resourse, find some offsets in this res, read user input, then xor some buffer(xored flag) with res[off + user_input], eg
```
offset = 0x5d
user_char = 'U' = 0x55
so we will have

final_flag[j] = *final_flag ^ WAWE[0x5d + 0x55]; 
->
final_flag[j] = *final_flag ^ WAWE[0xb2];
->
final_flag[j] = final_flag[j] ^ WAWE[0xb2];
->
final_flag[j] ^= WAWE[0xb2];
```

Then we check three char of unxored flag in a cycle by some equations, like
```c
xx0 = flag[i*3 + 0]
xx1 = flag[i*3 + 1]
xx2 = flag[i*3 + 2]

if xx0 + xx1 + xx2 != g_sum_8dd[i]
|| (xx2 & xx1) ^ xx0 != g_xor_8dd[i]
|| ((xx2 & xx1) ^ 8 * xx0) != g_xor_mul8_8dd[i]
|| (16 * xx2 ^ (xx0 - xx1)) != g_math_8dd[i] {
  goto fail;
} else {
  i++; // goto next loop
}
```

We can try to brute this 3 chars, but we need get `WAWE` resource(eg by resource hacker) and we need all `WAWE_offset` values at
```C
final_flag[j] = *final_flag ^ locked_WAWE[WAWE_offset + user_char];// xor some buff with WAWE[off + user_char]
```

Ok, I'm get this values in debugger by breakpoint at 0x401166
```C
.text:0040115D                 mov     ecx, [ebp+locked_WAWE]
.text:00401160                 mov     edx, [ebp+j]
.text:00401163                 movsx   eax, al
.text:00401166                 add     eax, esi          ; <<<< `esi` here is our value
.text:00401168                 mov     al, [eax+ecx]
.text:0040116B                 xor     al, [ebx]
.text:0040116D                 mov     [edx+ebx], al
.text:00401170                 inc     ebx
```
```python
ranges = [0x5d, 0x41d, 0x7dd, 0xb9d, 0xf5d, 0x131d, 0x16dd, 0x1a9d, 0x1e5d, 0x221d, 0x25dd, 0x299d, 0x2d5d, 0x311d, 0x34dd, 0x389d, 0x3c5d, 0x401d, 0x43dd, 0x479d, 0x4b5d, 0x4f1d, 0x52dd, 0x569d, 0x5a5d]  # by hand, in debugger
```

Now write some script to brute pass:
```python
g_xor_8dd = [7, 58, 88, 111, 70, 31, 18, 2]  # 0041A518
g_xor2_28db = [0x66, 0x04, 0x01, 0x6E, 0xEB, 0x0A, 0xE8, 0xA3, 0x22, 0x60, 0xA1,
               0xAF, 0x41, 0x14, 0xC3, 0x7A, 0x54, 0xC3, 0x25, 0xA3, 0x8D, 0x75, 0x6E, 0xC8]  # 0041A538
g_math_8dd = [4294966159, 1960, 4294965491,
              1903, 1889, 1629, 1777, 2002]  # 0041A554
g_sum_8dd = [221, 311, 271, 259, 281, 278, 329, 329]  # 0041A574
g_xor_mul8_8dd = [604, 921, 416, 712, 914, 696, 980, 861]  # 0041A594
ranges = [0x5d, 0x41d, 0x7dd, 0xb9d, 0xf5d, 0x131d, 0x16dd, 0x1a9d, 0x1e5d, 0x221d, 0x25dd, 0x299d,
          0x2d5d, 0x311d, 0x34dd, 0x389d, 0x3c5d, 0x401d, 0x43dd, 0x479d, 0x4b5d, 0x4f1d, 0x52dd, 0x569d, 0x5a5d]  # by hand, in debugger

b = open('ListenCarefully.exe', 'rb').read()[0x1ACF0:]  # read WAWE resource from exe file

for r in xrange(0, len(ranges) - 1, 3):
    print r
    x_0 = b[ranges[r + 0]:]  # range1 of bytes to brute
    x_1 = b[ranges[r + 1]:]  # range2 of bytes to brute
    x_2 = b[ranges[r + 2]:]  # range3 of bytes to brute
    for x0 in xrange(0x20, 0x7F):  # brute first user char
        for x1 in xrange(0x20, 0x7F):  # brute second user char
            for x2 in xrange(0x20, 0x7F):  # brute third user char
                idx = r/3
                xx0 = ord(x_0[x0]) ^ g_xor2_28db[r + 0]
                xx1 = ord(x_1[x1]) ^ g_xor2_28db[r + 1]
                xx2 = ord(x_2[x2]) ^ g_xor2_28db[r + 2]
                if xx0 + xx1 + xx2 == g_sum_8dd[idx]:  # check eq1
                    xx2_and_xx1 = xx2 & xx1
                    if xx2_and_xx1 ^ xx0 == g_xor_8dd[idx]:  # check eq2
                        # check eq3
                        if xx2_and_xx1 ^ 8 * xx0 == g_xor_mul8_8dd[idx]:
                            # check eq4
                            if (16 * xx2 ^ (xx0 - xx1)) & 0xFFFFFFFF == g_math_8dd[idx]:
                                # if all is ok -> print this chars
                                print chr(x0) + chr(x1) + chr(x2)
    print
```

Output is
```
0
Ul2
Ul]
Ult

3
r4_
rq_
rx_

6
Lu7

9
RG_
Ra_
`G_
`a_

12
&5_
&v_
15_
1v_

15
7h$
7h3

18
_83

21
57!
87!
}7!
```

well... we have some collisions...

let's try to do the most readable flag from these parts. As for me - it's `Ultr4_Lu7Ra_15_7h3_8357!`

Run binary and enter our pass
```
PS C:\Users\PC\Desktop> .\ListenCarefully.exe
Enter password: Ultr4_Lu7Ra_15_7h3_8357!
CTF{Cy8er_0tt3r_Revenge}
```

Yahoo! Finally, we get flag!

Flag is: **CTF{Cy8er_0tt3r_Revenge}**

**Overall, I really liked `OtterCTF`, good CTF with good problems.**

**Thanks for this `Asaf Eitani`.**

**See you next time!**
