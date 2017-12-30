# Junuior ARM3 - easy

**Category:** rev
**Points:** 171
**Solves:** 25
**Description:**

Can you reverse engineer this code and get the flag?

This code is ARM Thumb 2 code which runs on an STM32F103CBT6. You should not need such a controller to solve this challenge.

There are 5 stages in total which share all the same code base, so you are able to compare code from the first stage with all the other stages to see what code is actually relevant.

If you should need a datasheet, [you can get it here](http://www.st.com/content/ccc/resource/technical/document/reference_manual/59/b9/ba/7f/11/af/43/d5/CD00171190.pdf/files/CD00171190.pdf/jcr:content/translations/en.CD00171190.pdf).

In case you need to refresh your ARM assembly, [check out Azeria's cool articles](https://azeria-labs.com/writing-arm-assembly-part-1/).

[Challenge binary](arm_stage3.bin)

## Write-up

Load file in IDA, set "Processor type" to "ARM little-endian", then set "ROM start address" and "Loading address" to 0x8000000.

sub_8000108 - is first function(entry point), and only call function sub_80005D8, sub_80005D8 call sub_8000290, sub_8000290 is main.

In main we have code like this
```
int __cdecl __noreturn main(int argc, const char **argv, const char **envp)
{
  signed int i; // [sp+Ch] [bp+Ch]@1

  sub_8000558();
  sub_8000440();
  print_text("Enter flag: ");
  for ( i = 0; i <= 29; ++i )
  {
    *(_BYTE *)(i + 0x20000444) = sub_8000534();
    read_char(*(_BYTE *)(i + 0x20000444));      // read 29 bytes
  }
  print_text("\r\n");
  if ( v2000044D != '_'
    || v20000459 != '0'
    || v2000045E != '_'
    || v20000446 != 'C'
    || v20000452 != '1'
    || v20000444 != '3'
    || v20000460 != 'o'
    || v2000044F != 'a'
    || v20000448 != '_'
    || v2000045F != 'n'
    || v20000455 != '4'
    || v2000044C != 'k'
    || v20000447 != '3'
    || v2000045B != 'A'
    || v20000453 != '_'
    || v2000044B != '0'
    || v20000445 != '4'
    || v2000045C != 'R'
    || v20000456 != 'n'
    || v20000449 != 'L'
    || v20000458 != 'd'
    || v20000450 != '!'
    || v2000045A != '_'
    || v20000451 != '_'
    || v2000044E != 'm'
    || v20000461 != 'w'
    || v20000454 != 'c'
    || v20000457 != '_'
    || v2000045D != 'M' )
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
flag[0] == '3'
flag[1] == '4'
flag[2] == 'C'
flag[3] == '3'
flag[4] == '_'
flag[5] == 'L'

flag[7] == '0'
flag[8] == 'k'
flag[9] == '_'
flag[10] == 'm'
flag[11] == 'a'
flag[12] == '!'
flag[13] == '_'
flag[14] == '1'
flag[15] == '_'
flag[16] == 'c'
flag[17] == '4'
flag[18] == 'n'
flag[19] == '_'
flag[20] == 'd'
flag[21] == '0'
flag[22] == '_'
flag[23] == 'A'
flag[24] == 'R'
flag[25] == 'M'
flag[26] == '_'
flag[27] == 'n'
flag[28] == 'o'
flag[29] == 'w'

// flag = "34C3_L 0k_ma!_1_c4n_d0_ARM_now"
```
flag[6] is really absent, it's not a hex-rays mistake, but ctf system accept flag[6] == "0"

Flag is: **34C3_L00k_ma!_1_c4n_d0_ARM_now**
