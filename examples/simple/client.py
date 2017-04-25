# -*- coding: latin-1 -*-
#
# Copyright (C) AB Strakt
# Copyright (C) Jean-Paul Calderone
# See LICENSE for details.

"""
Simple SSL client, using blocking I/O
"""

import os
import socket
import sys
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

from OpenSSL import SSL, crypto
from cryptography.hazmat.primitives.asymmetric import padding


def verify_cb(conn, cert, errnum, depth, ok):
    certsubject = crypto.X509Name(cert.get_subject())
    commonname = certsubject.commonName
    print('Got certificate: ' + commonname)
    return ok


if len(sys.argv) < 3:
    print('Usage: python client.py HOST PORT')
    sys.exit(1)


dir = os.path.dirname(sys.argv[0])
if dir == '':
    dir = os.curdir


# Initialize context
ctx = SSL.Context(SSL.SSLv23_METHOD)
ctx.set_options(SSL.OP_NO_SSLv2)
ctx.set_options(SSL.OP_NO_SSLv3)
ctx.set_verify(SSL.VERIFY_PEER, verify_cb)  # Demand a certificate
ctx.use_privatekey_file(os.path.join(dir, 'client.pkey'))
ctx.use_certificate_file(os.path.join(dir, 'client.cert'))
ctx.load_verify_locations(os.path.join(dir, 'CA.cert'))

# Set up client
sock = SSL.Connection(ctx, socket.socket(socket.AF_INET, socket.SOCK_STREAM))
sock.connect((sys.argv[1], int(sys.argv[2])))
pad=padding.OAEP(
         mgf=padding.MGF1(algorithm=hashes.SHA1()),
         algorithm=hashes.SHA1(),
         label=None
     )

basics=sock.recv(1024).decode('utf-8')   
basic_list=str(basics).split(',')
#print(basic_list)

q=int(basic_list[0])
p=int(basic_list[1])
g=int(basic_list[2])
x_send=int(basic_list[3])
x=int(basic_list[4])
print("basics")
print(q)

key=crypto.PKey()
key.generate_key(crypto.TYPE_RSA, 1024)
tmp=key.to_cryptography_key()
print(tmp)
bkc=tmp.public_key()
print(bkc)
buf=crypto.dump_publickey(crypto.FILETYPE_PEM,key)
print(buf)

sock.send(buf)
sys.stdout.write(sock.recv(1024).decode('utf-8'))    

while 1:
    line = sys.stdin.readline()
    if line == '':
        break
    try:
        sock.send(line)
        
        
        ret=sock.recv(1024) 
        
        #ret_list=ret.split(',')   #better way to plit required as encrypt can have ,
        print("start")
        
        print(len(ret))
        i=len(ret)-1
        check=False
        while i>=0:
            if(ret[i]==',' and not(check)):
                check=True
                index1=i
            elif (ret[i]==','and check):
                index2=i
                break
            i=i-1
        enc=ret[0:index2]
        r=int(ret[index2+1:index1])
        s=int(ret[index1+1:])
        print(r)
        print(s)
        print(q)
        if r>=q or s>=q or r<=0 or s<=0:
            print("signature error : invalid")
            continue
        w=1
        mod=s%q
        i=1
        while i<=q-2:
            w=(w*mod)%q
            i=i+1

        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest.update(enc)
        t=digest.finalize()
        val=int(t.encode('hex'),16)
        print('val')
        print(val)
        print("k")
        kl1=(val*w)+(x*r*w)
        print(kl1%q)
        kl=kl1%q
        u1=(val*w)%q
        u2=(r*w)%q
        value1=1
        mod=g%p
        i=1
        while i<=u1:
            value1=(value1*mod)%p
            i=i+1

        value2=1
        mod=x_send%p
        i=1
        while i<=u2:
            value2=(value2*mod)%p
            i=i+1
        
        tp=(value1*value2)%p

        print('tp')
        print(tp)
        #print(a)
        value3=1
        mod=g%p
        i=1
        while i<=kl:
            value3=(value3*mod)%p
            i=i+1
        print(value3)
        v=tp%q
        print ("v")
        print(v)
        print(r)  

        text= tmp.decrypt(enc,pad)
        
        sys.stdout.write(text)
        
        sys.stdout.flush()
    except SSL.Error:
        print('Connection died unexpectedly')
        break


sock.shutdown()
sock.close()
