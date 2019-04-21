from pwn import *
r=remote('echo.tghack.no',5555)
while(True):
	data=r.recvline()
	r.sendline(data.strip('\n'))