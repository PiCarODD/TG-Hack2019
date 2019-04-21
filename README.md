# TG-Hack2019
TG:Hack is a (semi) onsite jeopardy style CTF hosted every year at Norway's largest LAN party The Gathering, which takes place at the Viking ship in Hamar. We focus on making guiding tasks for beginners, and challenging tasks for a little more experienced CTFers. 
## Noob
My Beginner scripts for Noob category
## Echo Chamber
```
#!/usr/bin/env python2
from pwn import *
r=remote('echo.tghack.no',5555)
while(True):
	data=r.recvline()
	r.sendline(data.strip('\n'))
 ```
## Math Bonanza
```
#!/usr/bin/env python2
from pwn import *
r=remote('math.tghack.no',10000)
print r.recvline()
data=r.recvline().split(' ')
print data
if data[1]=="/":
	res=int(data[0])/int(data[2].strip('\n'))
	r.sendline(str(res))
if data[1]=="*":
	res=int(data[0])*int(data[2].strip('\n'))
	r.sendline(str(res))
if data[1]=="+":
	res=int(data[0])+int(data[2].strip('\n'))
	r.sendline(str(res))
if data[1]=="-":
	res=int(data[0])-int(data[2].strip('\n'))
	r.sendline(str(res))
while(True):
	print r.recvline()
	print r.recvline()
	data=r.recvline().split(' ')
	if data[1]=="/":
		res=int(data[0])/int(data[2].strip('\n'))
		r.sendline(str(res))
	if data[1]=="*":
		res=int(data[0])*int(data[2].strip('\n'))
		r.sendline(str(res))
	if data[1]=="+":
		res=int(data[0])+int(data[2].strip('\n'))
		r.sendline(str(res))
	if data[1]=="-":
		res=int(data[0])-int(data[2].strip('\n'))
		r.sendline(str(res))
  ```
 ## Let's Hash it Out
 ```
 #!/usr/bin/env python2
 import hashlib
from pwn import *
r=remote('hash.tghack.no',2001)
print r.recvline()
print r.recvline()
print r.recvline()
data=r.recvline().split(': ')
if 'MD5' in data[0]:
	md5=hashlib.md5(data[1].strip('\n').encode('utf-8')).hexdigest()
	r.sendline(md5)
if 'SHA512' in data[0]:
	sha512=hashlib.sha512(data[1].strip('\n').encode('utf-8')).hexdigest()
	r.sendline(sha512)
if 'SHA256' in data[0]:
	sha256=hashlib.sha256(data[1].strip('\n').encode('utf-8')).hexdigest()
	r.sendline(sha256)
while(True):
	data=r.recvline().split(': ')
	if 'MD5' in data[1]:
		md5=hashlib.md5(data[2].strip('\n').encode('utf-8')).hexdigest()
		r.sendline(md5)
	if 'SHA512' in data[1]:
		sha512=hashlib.sha512(data[2].strip('\n').encode('utf-8')).hexdigest()
		r.sendline(sha512)
	if 'SHA256' in data[1]:
		sha256=hashlib.sha256(data[2].strip('\n').encode('utf-8')).hexdigest()
		r.sendline(sha256)
	print data
```
