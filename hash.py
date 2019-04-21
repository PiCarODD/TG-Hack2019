import hashlib
from pwn import *
r=remote('hash.tghack.no',2001)
print r.recvline()
print r.recvline()
print r.recvline()
data=r.recvline().split(': ')
print data[0]
print data[1]
print data
if 'MD5' in data[0]:
	md5=hashlib.md5(data[1].strip('\n').encode('utf-8')).hexdigest()
	print md5
	r.sendline(md5)
if 'SHA512' in data[0]:
	sha512=hashlib.sha512(data[1].strip('\n').encode('utf-8')).hexdigest()
	print sha512
	r.sendline(sha512)
if 'SHA256' in data[0]:
	sha256=hashlib.sha256(data[1].strip('\n').encode('utf-8')).hexdigest()
	print sha256
	r.sendline(sha256)
while(True):
	data=r.recvline().split(': ')
	print data[0]
	print data[1]
	print data
	if 'MD5' in data[1]:
		md5=hashlib.md5(data[2].strip('\n').encode('utf-8')).hexdigest()
		print md5
		r.sendline(md5)
	if 'SHA512' in data[1]:
		sha512=hashlib.sha512(data[2].strip('\n').encode('utf-8')).hexdigest()
		print sha512
		r.sendline(sha512)
	if 'SHA256' in data[1]:
		sha256=hashlib.sha256(data[2].strip('\n').encode('utf-8')).hexdigest()
		print sha256
		r.sendline(sha256)
