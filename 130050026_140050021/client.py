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

def pow (a,b,c):
    if(b==0):
        return 1
    tmp=pow(a,b/2,c)
    if (b%2==0):
        return (tmp*tmp)%c
    else:
        return (tmp*tmp)%c
        
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
y=int(basic_list[3])
key=crypto.PKey()
key.generate_key(crypto.TYPE_RSA, 1024)
tmp=key.to_cryptography_key()
bkc=tmp.public_key()
buf=crypto.dump_publickey(crypto.FILETYPE_PEM,key)

sock.send(buf)
sock.recv(1024).decode('utf-8')
print("connection with server established")
while 1:
    print("send message to the server")
    line = sys.stdin.readline()
    if line == '':
        break
    try:
        sock.send(line)
        
        
        ret=sock.recv(1024) 
        
        
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
        text= tmp.decrypt(enc,pad)
        

        '''
        r=int(ret[index2+1:index1])
        s=int(ret[index1+1:])
        print(s)
        print(r)
        if r>=q or r<=0 or s>=q or s<=0:
            print("signature error")
            continue
        #w=pow(s,q-2,q)
        a=s%q
        i=q-2
        w=1
        while True:
            t=i%2
            i=i/2
            if(t==1):
                w=(w*a)%q
            if(i==0):
                break
            a=(a*a)%q
        print('w')
        print(w)
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest.update(enc)
        t=digest.finalize()
        val=int(t.encode('hex'),16)
        u1=(val*w)%q
        u2=(r*w)%q
        v1=pow(g,u1,p)
        print("v1")
        print(v1)
        v2=pow(y,u2,p)
        print(v2)
        v=(v1*v2)%p
        v=v%q
        
        value1=1
        a=g%p
        i=u1
        while True:
            t=i%2
            i=i/2
            if(t==1):
                value1=(value1*a)%p
            if(i==0):
                break
            a=(a*a)%p

        value2=1
        a=y%p
        i=u2
        while True:
            t=i%2
            i=i/2
            if(t==1):
                value2=(value2*a)%p
            if(i==0):
                break
            a=(a*a)%p
        
        tp=(value1*value2)%p
        tp=tp%q
        
        print("v")
        if(v!=r):
            print("Invalid Signature")
            continue
        '''
        e=int(ret[index2+1:index1])
        s=int(ret[index1+1:])
        if(s>0):
            #v1=pow(g,s,p)
            a=g%p
            i=s
            b=1
            while(True):
                t=i%2
                i=i/2
                if(t==1):
                    b=(b*a)%p
                if(i==0):
                    break
                a=(a*a)%p
            v1=b

        else:
            #v11=pow(g,s,p)
            a=g%p
            i=-s
            b=1
            while(True):
                t=i%2
                i=i/2
                if(t==1):
                    b=(b*a)%p
                if(i==0):
                    break
                a=(a*a)%p
            v11=b

            #v12=pow(g,p-2,p)
            a=v11%p
            i=p-2
            b=1
            while(True):
                t=i%2
                i=i/2
                if(t==1):
                    b=(b*a)%p
                if(i==0):
                    break
                a=(a*a)%p
            v1=b

            
        #v2=pow(y,e,p)
        a=y%p
        i=e
        b=1
        while(True):
            t=i%2
            i=i/2
            if(t==1):
                b=(b*a)%p
            if(i==0):
                break
            a=(a*a)%p
        v2=b
        v=(v1*v2)%p
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest.update(text)
        digest.update(str(v))
        t=digest.finalize()
        val=int(t.encode('hex'),16)
        if(val!=e):
            print ("Invalid Signature")
            continue
        
        print("message received from the server")
        sys.stdout.write(text)
        sys.stdout.flush()
    except SSL.Error:
        print('Connection died unexpectedly')
        break


sock.shutdown()
sock.close()
