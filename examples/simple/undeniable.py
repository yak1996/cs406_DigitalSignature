# /usr/local/Cellar/openssl/1.0.2k/bin/openssl  genpkey -genparam -algorithm DH -out dhp.pem 
# /usr/local/Cellar/openssl/1.0.2k/bin/openssl genpkey -paramfile dhp.pem -out dhkey1.pem
# /usr/local/Cellar/openssl/1.0.2k/bin/openssl pkey -in dhkey1.pem -text -noout > text.txt

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

cmd = "/usr/local/Cellar/openssl/1.0.2k/bin/openssl  genpkey -genparam -algorithm DH -out dhp.pem" + "\n" + "/usr/local/Cellar/openssl/1.0.2k/bin/openssl genpkey -paramfile dhp.pem -out dhkey1.pem" + "\n" +"/usr/local/Cellar/openssl/1.0.2k/bin/openssl pkey -in dhkey1.pem -text -noout > text.txt" + "\n" +"tr -d '\n' < text.txt  > test.txt" + "\n" +"tr -d ' ' < test.txt  > test1.txt" + "\n" +"cat test1.txt | sed -n \"s/.*private-key:\(.*\)public.*/\\1/p\" > priv_key.txt" + "\n" + "cat test1.txt | sed -n \"s/.*public-key:\(.*\)prime.*/\\1/p\" > pub_key.txt" + "\n" + "cat test1.txt | sed -n \"s/.*prime:\(.*\)generator.*/\\1/p\" > prime.txt" 

print(cmd)
t=os.system(cmd)

gen = 2

f=open('priv_key.txt','r')
priv_key=f.read()
f.close()

priv=int(''.join((priv_key.replace(":","")).split()),16)    

f=open('pub_key.txt','r')
pub_key=f.read()
f.close()

pub=int(''.join((pub_key.replace(":","")).split()),16)    

f=open('prime.txt','r')
pr=f.read()
f.close()

prime=int(''.join((pr.replace(":","")).split()),16)    

# print(gen)
# print( priv)
# print(pub)
# print( prime)

message = random.randint(1, prime-1)
z = pow(message, priv, prime)
#print(z)
mode=raw_input('Do you want to sign the message? Answer [yes|no]: ')
if(mode == "yes"):
	z1 = z
else:
	z1 = random.randint(1, prime-1)


send = str(message)+","+str(z1)
# if len(sys.argv) < 2:
#     print('Usage: python server.py PORT')
#     sys.exit(1)
# print(sys.argv)


serversocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
serversocket.bind(('localhost', int(sys.argv[1])))
serversocket.listen(5) # become a server socket, maximum 5 connections

connection, address = serversocket.accept()
connection.send(str(prime)+","+str(pub))
ack = connection.recv(4096)
connection.send(send)
buf = connection.recv(4096)
print(buf)
mode=raw_input('Do you want to verify your signature? Answer [yes|no]: ')
if(mode == "yes"):
	connection.send("yes")
	c = int(connection.recv(4096))
	print("Received c.")
	q = random.randint(0, prime-1)
	s1 = (c*pow(2,q, prime))%prime
	s2 = pow(s1, priv, prime)
	connection.send(str(s1)+","+str(s2))
	print("Sent s1, s2.")
	ab = connection.recv(4096)
	arr = ab.split(',')
	a = int(arr[0])
	b = int(arr[1])
	print("Received a, b.")
	ver = (pow(message, a, prime)*pow(2, b, prime))%prime
	if(ver != c):
		connection.send("Cannot verify c. Bye.")
		print("Cannot verify c. Closing connection....")
		connection.close()
	else:
		connection.send(str(q))
		verdict = connection.recv(4096)
		print("Client says: ",verdict)
		connection.close()

else:
	connection.send("no")
	lying = 0
	k = int(connection.recv(4096))

	v = connection.recv(4096)
	vx = v.split(',')
	v1 = int(vx[0])
	v2 = int(vx[1])
	print("Received v1, v2.")
	v1x = pow(v1, priv, prime)
	idt = (v1x*pow(v2, prime-2, prime))%prime
	ver = (z*pow(z1, prime-2, prime))%prime

	prev = 1

	ans = -1
	for i in range(0, k+1):
		if(prev == idt):
			ans = i
			break
		else:
			prev = (prev*ver)%prime

	if(idt == 1):
		lying = 1
		ans = random.randint(0, k)

	print("i:  ", ans)
	r = random.randint(0, prime)
	data = str(r)+str(ans)
	hash_object = hashlib.sha1(data.encode())
	hex_dig = hash_object.hexdigest()
	connection.send(str(hex_dig))
	print("Sent hash(r, i).")
	a = int(connection.recv(4096))

	print("Received a.")
	v1_temp = (pow(message, ans, prime)*pow(2,a,prime))%prime
	v2_temp = (pow(z1, ans, prime)*pow(pub,a,prime))%prime
	if((v1 != v1_temp or v2 != v2_temp) and lying == 0):
		connection.send("Cannot verify v1, v2. Bye")
		print("Cannot verify v1, v2. Bye")
		connection.close()
	else:
		connection.send(str(r))
		print("Sent r.")
		verdict = connection.recv(4096)
		print("Client says: ",verdict)
		connection.close()

