# Junuior ARM4 - mid

**Category:** rev
**Points:** 290
**Solves:** 11
**Description:**

Can you reverse engineer this code and get the flag?

This code is ARM Thumb 2 code which runs on an STM32F103CBT6. You should not need such a controller to solve this challenge.

There are 5 stages in total which share all the same code base, so you are able to compare code from the first stage with all the other stages to see what code is actually relevant.

If you should need a datasheet, [you can get it here](http://www.st.com/content/ccc/resource/technical/document/reference_manual/59/b9/ba/7f/11/af/43/d5/CD00171190.pdf/files/CD00171190.pdf/jcr:content/translations/en.CD00171190.pdf).

In case you need to refresh your ARM assembly, [check out Azeria's cool articles](https://azeria-labs.com/writing-arm-assembly-part-1/).

[Challenge binary](arm_stage4.bin)

## Write-up

Load file in IDA, set "Processor type" to "ARM little-endian", then set "ROM start address" and "Loading address" to 0x8000000.

sub_8000108 - is first function(entry point), and only call function sub_8001180, sub_8001180 call sub_8000290, sub_8000290 is main.

In main we have code like this
```
int __cdecl __noreturn main(int argc, const char **argv, const char **envp)
{
  unsigned int i; // [sp+Ch] [bp+Ch]@1

  sub_8001100();
  sub_8000FE8();
  print_text("Enter flag: ");
  for ( i = 0; i <= 13; ++i )
  {
    *(_BYTE *)(i + 0x20000444) = sub_80010DC();
    read_char(*(_BYTE *)(i + 0x20000444));       // read 13 bytes
  }
  print_text("\r\n");
  if ( 34 * v20000451
     + -4 * (v20000445 + -5 * v20000444 + -16 * v20000446 + 3 * v20000447)
     + -73 * v20000448
     + -65 * v20000449
     + 77 * v2000044A
     + 20 * v2000044B
     + -66 * v2000044C
     + 4 * v2000044D
     + -58 * v2000044E
     + -6 * v2000044F
     + 94 * v20000450 != 8701
    || -48 * v20000451
     + -66 * v20000444
     + 56 * v20000445
     + -37 * v20000446
     + -8 * v20000447
     + -26 * v20000448
     + -79 * v20000449
     + -28 * v2000044A
     + -99 * v2000044B
     + -87 * v2000044C
     + -86 * v2000044D
     + 71 * v2000044E
     + -69 * v2000044F
     + -43 * v20000450 != -40417
    || 38 * v20000451
     + 93 * v20000444
     + 77 * v20000445
     + -43 * v20000446
     + -19 * v20000447
     + 99 * v20000448
     + 61 * v20000449
     + 5 * v2000044A
     + -67 * v2000044B
     + -60 * v2000044C
     + 88 * v2000044D
     + 41 * v2000044E
     + 19 * v2000044F
     + 70 * v20000450 != 34075
    || (v20000451 << 6)
     + -44 * v20000444
     + -32 * v20000445
     + -30 * v20000446
     + 5 * v20000447
     + 56 * v20000448
     + -28 * v20000449
     + 61 * v2000044A
     + 9 * v2000044B
     + 80 * v2000044C
     + 40 * v2000044D
     + -66 * v2000044E
     + -42 * v2000044F
     + 62 * v20000450 != 17090
    || -40 * v20000451
     + -61 * v20000444
     + 46 * v20000445
     + 35 * v20000446
     + -33 * v20000447
     + 91 * v20000448
     + -13 * v20000449
     + -39 * v2000044A
     + 7 * v2000044B
     + 51 * v2000044C
     + 93 * v2000044D
     + 55 * v2000044E
     + 49 * v2000044F
     + 94 * v20000450 != 31516
    || 33 * v20000451
     + 17 * v20000444
     + -61 * v20000445
     + 51 * v20000446
     + 26 * v20000447
     + 75 * v20000448
     + 14 * v20000449
     + -32 * v2000044A
     + -46 * v2000044B
     + -10 * v2000044C
     + -36 * v2000044D
     + 81 * v2000044E
     + 69 * v2000044F
     + -32 * v20000450 != 10846
    || 29 * v20000451
     + 69 * v20000444
     + -92 * v20000445
     + 24 * v20000446
     + -33 * v20000447
     + 16 * v20000448
     + 57 * v20000449
     + -31 * v2000044A
     + 91 * v2000044B
     + 85 * v2000044C
     + 72 * v2000044D
     + 23 * v2000044E
     + 21 * v2000044F
     + 45 * v20000450 != 31883
    || -66 * v20000451
     + -22 * v20000444
     + 21 * v20000445
     + 52 * v20000446
     + 71 * v20000447
     + 76 * v20000448
     + -80 * v20000449
     + -97 * v2000044A
     + 4 * v2000044B
     + 99 * v2000044C
     + -7 * v2000044D
     + -43 * v2000044E
     + -13 * v2000044F
     + 37 * v20000450 != -2288
    || -63 * v20000451
     + -59 * v20000444
     + 74 * v20000445
     + 65 * v20000446
     + 61 * v20000447
     + -21 * v20000448
     + -9 * v20000449
     + 44 * v2000044A
     + 13 * v2000044B
     + 30 * v2000044C
     + 13 * v2000044D
     + -69 * v2000044E
     + -2 * v2000044F
     + 9 * v20000450 != 891
    || 74 * v20000451
     + 51 * v20000444
     + 58 * v20000445
     + 16 * v20000446
     + 58 * v20000447
     + 83 * v20000448
     + 30 * v20000449
     + -57 * v2000044A
     + -27 * v2000044B
     + -28 * v2000044C
     + 94 * v2000044D
     + 55 * v2000044E
     + 72 * v2000044F
     + -96 * v20000450 != 24772
    || 56 * v20000451
     + 68 * v20000444
     + -5 * v20000445
     + 19 * v20000446
     + -85 * v20000447
     + 38 * v20000448
     + 84 * v20000449
     + 17 * v2000044A
     + 77 * v2000044B
     + -98 * v2000044C
     + -37 * v2000044D
     + -38 * v2000044E
     + 32 * v2000044F
     + -45 * v20000450 != 7094
    || 59 * v20000451
     + 13 * v20000444
     + 99 * v20000445
     + -21 * v20000446
     + 58 * v20000447
     + 26 * v20000448
     + 18 * v20000449
     + -87 * v2000044A
     + 26 * v2000044B
     + -77 * v2000044C
     + -47 * v2000044D
     + 33 * v2000044E
     + -45 * v2000044F
     + -78 * v20000450 != -4767
    || 31 * v20000451
     + -95 * v20000444
     + 63 * v20000445
     + 18 * v20000446
     + -12 * v20000447
     + 56 * v20000448
     + -77 * v20000449
     + 68 * v2000044A
     + 70 * v2000044B
     + 54 * v2000044C
     + 41 * v2000044D
     + 25 * v2000044E
     + -78 * v2000044F
     + 43 * v20000450 != 27400
    || -78 * v20000451
     + 22 * v20000444
     + -33 * v20000445
     + -31 * v20000446
     + -46 * v20000447
     + 20 * v20000448
     + 80 * v20000449
     + -54 * v2000044A
     + 55 * v2000044B
     + 77 * v2000044C
     + 94 * v2000044D
     + -89 * v2000044E
     + 51 * v2000044F
     + -27 * v20000450 != -4494 )
  {
    print_text("Wrong!\r\n");
  }
  else
  {
    print_text("Correct!\r\n");
  }
  while ( 1 )
    ;
}
```

Readed flag started from 0x20000444, and we have
```
from z3 import *                                                              

x0 = Int('x0')
x1 = Int('x1')
x2 = Int('x2')
x3 = Int('x3')
x4 = Int('x4')
x5 = Int('x5')
x6 = Int('x6')
x7 = Int('x7')
x8 = Int('x8')
x9 = Int('x9')
x10 = Int('x10')
x11 = Int('x11')
x12 = Int('x12')
x13 = Int('x13')

s = Solver()

s.add(32 <= x0)
s.add(x0 <= 127)
s.add(32 <= x1)
s.add(x1 <= 127)
s.add(32 <= x2)
s.add(x2 <= 127)
s.add(32 <= x3)
s.add(x3 <= 127)
s.add(32 <= x4)
s.add(x4 <= 127)
s.add(32 <= x5)
s.add(x5 <= 127)
s.add(32 <= x6)
s.add(x6 <= 127)
s.add(32 <= x7)
s.add(x7 <= 127)
s.add(32 <= x8)
s.add(x8 <= 127)
s.add(32 <= x9)
s.add(x9 <= 127)
s.add(32 <= x10)
s.add(x10 <= 127)
s.add(32 <= x11)
s.add(x11 <= 127)
s.add(32 <= x12)
s.add(x12 <= 127)
s.add(32 <= x13)
s.add(x13 <= 127)

s.add(34 * x13 + -4 * (x1 + -5 * x0 + -16 * x2 + 3 * x3) + -73 * x4 + -65 * x5 + 77 * x6 + 20 * x7 + -66 * x8 + 4 * x9 + -58 * x10 + -6 * x11 + 94 * x12 == 8701)
s.add(-48 * x13 + -66 * x0 + 56 * x1 + -37 * x2 + -8 * x3 + -26 * x4 + -79 * x5 + -28 * x6 + -99 * x7 + -87 * x8 + -86 * x9 + 71 * x10 + -69 * x11 + -43 * x12 == -40417)
s.add(38 * x13 + 93 * x0 + 77 * x1 + -43 * x2 + -19 * x3 + 99 * x4 + 61 * x5 + 5 * x6 + -67 * x7 + -60 * x8 + 88 * x9 + 41 * x10 + 19 * x11 + 70 * x12 == 34075)
# s.add((x13 << 6) + -44 * x0 + -32 * x1 + -30 * x2 + 5 * x3 + 56 * x4 + -28 * x5 + 61 * x6 + 9 * x7 + 80 * x8 + 40 * x9 + -66 * x10 + -42 * x11 + 62 * x12 == 17090)
s.add(-40 * x13 + -61 * x0 + 46 * x1 + 35 * x2 + -33 * x3 + 91 * x4 + -13 * x5 + -39 * x6 + 7 * x7 + 51 * x8 + 93 * x9 + 55 * x10 + 49 * x11 + 94 * x12 == 31516)
s.add(33 * x13 + 17 * x0 + -61 * x1 + 51 * x2 + 26 * x3 + 75 * x4 + 14 * x5 + -32 * x6 + -46 * x7 + -10 * x8 + -36 * x9 + 81 * x10 + 69 * x11 + -32 * x12 == 10846)
s.add(29 * x13 + 69 * x0 + -92 * x1 + 24 * x2 + -33 * x3 + 16 * x4 + 57 * x5 + -31 * x6 + 91 * x7 + 85 * x8 + 72 * x9 + 23 * x10 + 21 * x11 + 45 * x12 == 31883)
s.add(-66 * x13 + -22 * x0 + 21 * x1 + 52 * x2 + 71 * x3 + 76 * x4 + -80 * x5 + -97 * x6 + 4 * x7 + 99 * x8 + -7 * x9 + -43 * x10 + -13 * x11 + 37 * x12 == -2288)
s.add(-63 * x13 + -59 * x0 + 74 * x1 + 65 * x2 + 61 * x3 + -21 * x4 + -9 * x5 + 44 * x6 + 13 * x7 + 30 * x8 + 13 * x9 + -69 * x10 + -2 * x11 + 9 * x12 == 891)
s.add(74 * x13 + 51 * x0 + 58 * x1 + 16 * x2 + 58 * x3 + 83 * x4 + 30 * x5 + -57 * x6 + -27 * x7 + -28 * x8 + 94 * x9 + 55 * x10 + 72 * x11 + -96 * x12 == 24772)
s.add(56 * x13 + 68 * x0 + -5 * x1 + 19 * x2 + -85 * x3 + 38 * x4 + 84 * x5 + 17 * x6 + 77 * x7 + -98 * x8 + -37 * x9 + -38 * x10 + 32 * x11 + -45 * x12 == 7094)
s.add(59 * x13 + 13 * x0 + 99 * x1 + -21 * x2 + 58 * x3 + 26 * x4 + 18 * x5 + -87 * x6 + 26 * x7 + -77 * x8 + -47 * x9 + 33 * x10 + -45 * x11 + -78 * x12 == -4767)
s.add(31 * x13 + -95 * x0 + 63 * x1 + 18 * x2 + -12 * x3 + 56 * x4 + -77 * x5 + 68 * x6 + 70 * x7 + 54 * x8 + 41 * x9 + 25 * x10 + -78 * x11 + 43 * x12 == 27400)
s.add(-78 * x13 + 22 * x0 + -33 * x1 + -31 * x2 + -46 * x3 + 20 * x4 + 80 * x5 + -54 * x6 + 55 * x7 + 77 * x8 + 94 * x9 + -89 * x10 + 51 * x11 + -27 * x12 == -4494)

s.check()
zz = s.model()

key = ''
key += chr(zz[x0].as_long())
key += chr(zz[x1].as_long())
key += chr(zz[x2].as_long())
key += chr(zz[x3].as_long())
key += chr(zz[x4].as_long())
key += chr(zz[x5].as_long())
key += chr(zz[x6].as_long())
key += chr(zz[x7].as_long())
key += chr(zz[x8].as_long())
key += chr(zz[x9].as_long())
key += chr(zz[x10].as_long())
key += chr(zz[x11].as_long())
key += chr(zz[x12].as_long())
key += chr(zz[x13].as_long())
print key # 34C3_1_d0_m4th
```

Flag is: **34C3_1_d0_m4th**
