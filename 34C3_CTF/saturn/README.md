# Junuior Saturn

**Category:** rev
**Points:** 136
**Solves:** 34
**Description:**

Wanna go to [saturn](saturn_63cd2ac2c06835921e90816bf580631c)? Give me the launch codes from: nc 35.198.169.47 1337

## Write-up

Firstly we must find **main** function:

```
.text:00000656                 push    ds:(off_1FF8 - 1FACh)[ebx] ; main
```

1) In debugger we see that main at 0x843

2) Fix stack, and decompile
```
.text:00000632 000                 pop     esi
.text:00000633 -04                 mov     ecx, esp
.text:00000635 -04                 and     esp, 0FFFFFFF0h
.text:00000638 -04                 push    eax
.text:00000639 000                 push    esp             ; stack_end
```

```
.text:00000632 000                 pop     esi
.text:00000633 000                 mov     ecx, esp
.text:00000635 000                 and     esp, 0FFFFFFF0h
.text:00000638 000                 push    eax
.text:00000639 004                 push    esp             ; stack_end
```

```
__libc_start_main(sub_843, retaddr, &retaddr, sub_9D0, nullsub_1, a2, &a1); // main is sub_843
```

```
int main(int argc, const char **argv, const char **envp)
{
  int num_1, num_2, num_3, num_4, num;

  num = 1;
  f_alarm();
  scanf("%d %d %d %d", &num_1, &num_2, &num_3, &num_4);
  if ( num_1 <= 123456788 || num_1 > 987654321 )
    return -1;
  if ( num_2 <= 123456788 || num_2 > 987654321 )
    return -1;
  if ( num_3 <= 123456788 || num_3 > 987654321 )
    return -1;
  if ( num_4 <= 123456788 || num_4 > 987654321 )
    return -1;
  num = num_3 * num_2 * num_1 * num_4 * ((num_1 << 25) % 30);
  num ^= num_2 >> 3;
  num += num_3 - num_4;
  if ( num == 842675475 )
  {
    puts("Correct! Here is your flag:\n");
    f_give_flag();
  }
  else
  {
    puts("Wrong!\n");
  }
  return 0;
}
```

Solver
```C
#include <stdio.h>

int main() {
  int num_1, num_2, num_3, num_4, num;

  for (num_1 = 123456789; num_1 < 987654321; num_1++) {
    for (num_2 = 123456789; num_2 < 987654321; num_2++) {
      for (num_3 = 123456789; num_3 < 987654321; num_3++) {
        for (num_4 = 123456789; num_4 < 987654321; num_4++) {
          num = num_3 * num_2 * num_1 * num_4 * ((num_1 << 25) % 30);
          num ^= num_2 >> 3;
          num += num_3 - num_4;
          if (num == 842675475) {
            printf("Correct! Here is your flag: %d %d %d %d\n", num_1, num_2, num_3, num_4);
          }
        }
      }
    }
  }
}
```

```
Correct! Here is your flag: 123456789 123456789 123456801 447146224                                                   
Correct! Here is your flag: 123456789 123456789 123456803 199754714                                                   
Correct! Here is your flag: 123456789 123456789 123456805 637654116                                                   
...
```
```
pc@pc:~/Desktop$ nc 35.198.169.47 1337
123456789 123456789 123456801 447146224
Correct! Here is your flag:

34c3_th3re_is_n0_w4ter_on_s4turn!
```

Flag is: **34c3_th3re_is_n0_w4ter_on_s4turn!**
