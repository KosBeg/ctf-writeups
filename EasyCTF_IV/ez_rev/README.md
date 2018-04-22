# ez_rev

**Category:** Reverse Engineering
**Points:** 140
**Solves:** ???
**Description:**

Take a look at [executable](executable). Objdump the executable and read some assembly!

## Write-up

I'm a bad boy, and I don't use Objdump, only IDA :D

So we have:
```C
void main(int argc, const char **argv, const char **envp) {
  unsigned int flag[5];
  const char *flag_a;

  signal(2, sigintHandler);
  target = *argv;
  if ( argc == 2 )
  {
    flag_a = argv[1];
    flag[0] = 1;
    flag[1] = 2;
    flag[2] = 3;
    flag[3] = 4;
    flag[4] = 5;
    flag[0] = flag_a[0] + 1;
    flag[1] = flag_a[1] + 2;
    flag[2] = flag_a[2] + 3;
    flag[3] = flag_a[3] + 4;
    flag[4] = flag_a[4] + 5;
    if ( flag[3] != 0x6F || flag[2] != 0x7D || flag[0] != flag[4] - 10 || flag[1] != 0x35 || flag[4] != flag[3] + 3 )
    {
      sleep(2);
      remove(*argv);
      puts("successfully deleted!");
    }
    else
    {
      printf("Now here is your flag: ", sigintHandler, argv);
      print_flag(flag);
    }
  }
}
```

After simplify
```
(x3 + 4) == 0x6F
(x2 + 3) == 0x7D
(x0 + 1) == (x4 + 5) - 10
(x1 + 2) == 0x35
(x4 + 5) == (x3 + 4) + 3 )
```

We can solve these simple equations in the mind, on a piece of paper or... that would add a little fan to this boring task - z3 script :D

```Python
from z3_staff import * # https://github.com/KosBeg/z3_staff

var_num = 5
create_vars(var_num, type='int')
solver()
init_vars(globals())
set_ranges(var_num)

add_eq( (x3 + 4) == 0x6F )
add_eq( (x2 + 3) == 0x7D )
add_eq( (x0 + 1) == (x4 + 5) - 10 )
add_eq( (x1 + 2) == 0x35 )
add_eq( (x4 + 5) == (x3 + 4) + 3 )

i = 0
start_time = time.time()
while s.check() == sat:
  prepare_founded_values(var_num)
  print prepare_key(var_num)
  iterate_all(var_num)
  i += 1
print('--- %.2f seconds && %d answer(s) ---' % ((time.time() - start_time), i) )
```
```
PS C:\!CTF> python solver.py
g3zkm
--- 0.01 seconds && 1 answer(s) ---
```

and answer is `g3zkm`

![screen-0_ez_rev](screen_0_ez_rev.png)

Flag is: **easyctf{10453125111114}**
