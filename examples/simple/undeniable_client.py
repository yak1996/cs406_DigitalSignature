from __future__ import print_function

import os
import select
import socket
import sys
import random
from OpenSSL import SSL, crypto
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import hashlib
from cryptography.hazmat.primitives.asymmetric import padding

import hashlib

clientsocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
clientsocket.connect((sys.argv[1], int(sys.argv[2])))

pub = clientsocket.recv(4096)
spl = pub.split(',')
prime = int(spl[0])
y = int(spl[1])

print("public key: (prime, y) received")
clientsocket.send("Recieved public key.")
message = clientsocket.recv(4096)
sign = message.split(',')
m = int(sign[0])
z = int(sign[1])

print("Signed message received.")

clientsocket.send('Got your message!, can you verify it?')

ans = clientsocket.recv(4096)

if(ans == "yes"):
	print("Initiating Confirmation protocol....")
	a = random.randint(0, prime-1)
	b = random.randint(0, prime-1)
	c = (pow(m,a,prime)*pow(2, b, prime))%prime
	clientsocket.send(str(c))
	print("Sent c.")
	ss = clientsocket.recv(4096)
	sb = ss.split(',')
	s1 = int(sb[0])
	s2 = int(sb[1])
	print("Received s1, s2")
	clientsocket.send(str(a)+","+str(b))
	print("Sent a, b.")
	q = clientsocket.recv(4096)
	if(q == "Cannot verify c. Bye."):
		print(q)
		sys.exit()
	q = int(q)
	print("Received q.")
	s1_temp = (c*pow(2,q,prime))%prime
	s2_temp = (pow(z, a, prime)*pow(y, b+q, prime))%prime
	if(s1 == s1_temp and s2 == s2_temp):
		clientsocket.send("Signature Verified")
		print("Signature Verified")
	else:
		clientsocket.send("Signature not verified")
		print("Signature is fake.")
else:
	print("Initiating Disavowal protocol....")
	k = 1023
	clientsocket.send(str(k))
	s = random.randint(0, 1023)
	print("s: ", s)
	a = random.randint(0, prime-1)
	v1 = (pow(m, s, prime)*pow(2, a, prime))%prime
	v2 = (pow(z, s, prime)*pow(y, a, prime))%prime
	clientsocket.send(str(v1)+","+str(v2))
	print("Sent a, b.")
	hash_i = clientsocket.recv(4096)
	print("Received hash(r, i).")
	clientsocket.send(str(a))
	r = clientsocket.recv(4096)
	print("Received r.")
	data = str(r)+str(s)
	hash_object = hashlib.sha1(data.encode())
	hex_dig = hash_object.hexdigest()
	if(str(hex_dig) == hash_i):
		clientsocket.send("Okay, you din't sign it")
		print("The server really did not sign it.")
	else:
		clientsocket.send("LIAR! LIAR!")
		print("The server signed it but is denying now.")
