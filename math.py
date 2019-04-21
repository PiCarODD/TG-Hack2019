from pwn import *
r=remote('math.tghack.no',10000)
print r.recvline()
data=r.recvline().split(' ')
print data
if data[1]=="/":
	res=int(data[0])/int(data[2].strip('\n'))
	print res
	r.sendline(str(res))
if data[1]=="*":
	res=int(data[0])*int(data[2].strip('\n'))
	print res
	r.sendline(str(res))
if data[1]=="+":
	res=int(data[0])+int(data[2].strip('\n'))
	print res
	r.sendline(str(res))
if data[1]=="-":
	res=int(data[0])-int(data[2].strip('\n'))
	print res
	r.sendline(str(res))
print "end"

while(True):
	print r.recvline()
	print r.recvline()
	data=r.recvline().split(' ')
	print data
	if data[1]=="/":
		res=int(data[0])/int(data[2].strip('\n'))
		print res
		r.sendline(str(res))
	if data[1]=="*":
		res=int(data[0])*int(data[2].strip('\n'))
		print res
		r.sendline(str(res))
	if data[1]=="+":
		res=int(data[0])+int(data[2].strip('\n'))
		print res
		r.sendline(str(res))
	if data[1]=="-":
		res=int(data[0])-int(data[2].strip('\n'))
		print res
		r.sendline(str(res))