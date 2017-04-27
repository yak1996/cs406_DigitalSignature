# -*- coding: latin-1 -*-
#
# Copyright (C) AB Strakt
# Copyright (C) Jean-Paul Calderone
# See LICENSE for details.

"""
Simple echo server, using nonblocking I/O
"""

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


def pow (a,b,c):
    if(b==0):
        return 1
    tmp=pow(a,b/2,c)
    if (b%2==1):
        return (a*tmp*tmp)%c
    else:
        return (tmp*tmp)%c



def verify_cb(conn, cert, errnum, depth, ok):
    certsubject = crypto.X509Name(cert.get_subject())
    commonname = certsubject.commonName
    print('Got certificate: ' + commonname)
    return ok


if len(sys.argv) < 2:
    print('Usage: python server.py PORT')
    sys.exit(1)

dir = os.path.dirname(sys.argv[0])
if dir == '':
    dir = os.curdir
# Initialize context
ctx = SSL.Context(SSL.SSLv23_METHOD)
ctx.set_options(SSL.OP_NO_SSLv2)
ctx.set_options(SSL.OP_NO_SSLv3)

ctx.set_verify(
    SSL.VERIFY_PEER | SSL.VERIFY_FAIL_IF_NO_PEER_CERT, verify_cb
)  # Demand a certificate

ctx.use_privatekey_file(os.path.join(dir, 'server.pkey'))
ctx.use_certificate_file(os.path.join(dir, 'server.cert'))
ctx.load_verify_locations(os.path.join(dir, 'CA.cert'))

#setting up digital signature field KeyGen
bashc="openssl dsa -in dsa_pub.pem -pubin -text -noout"
ashc1="openssl dsaparam 1024 < /dev/random -out dsaparam.pem "+"\n"+"openssl gendsa dsaparam.pem -out dsa_priv.pem > /dev/null 2>&1 "+"\n"+"openssl dsa -in dsa_priv.pem -pubout -out dsa_pub.pem > /dev/null 2>&1"+"\n"+"openssl dsa -in dsa_priv.pem -text -noout > key.txt"

t=os.system(ashc1)
f=open('key.txt','r')
key=f.read()
f.close()
os.system("rm key.txt")
os.system("rm *.pem")
#print(key)
count=0
for i in range(len(key)):
    if(key[i]=='v' and count==0):
        count=1
    elif(key[i]=='v' and count==1):
        index1=i+2
        count=2
    elif(key[i]=='p' and count==2):
        index11=i
        index2=i+4
        count=3
    elif(key[i]=='P'and count==3):
        index21=i
        index3=i+2
        count=4
    elif(key[i]=='Q'and count==4):
        index31=i
        index4=i+2
        count=5
    elif(key[i]=='G'and count==5):
        index41=i
        index5=i+2
        count=6
   
x=int(''.join((key[index1:index11].replace(":","")).split()),16)    
y=int(''.join((key[index2:index21].replace(":","")).split()),16)
p=int(''.join((key[index3:index31].replace(":","")).split()),16)
q=int(''.join((key[index4:index41].replace(":","")).split()),16)
g=int(''.join((key[index5:].replace(":","")).split()),16)


send_str=str(q)+','+str(p)+','+str(g)+','+str(y)
print('ready to accept connections')

# Set up server
server = SSL.Connection(ctx, socket.socket(socket.AF_INET, socket.SOCK_STREAM))
server.bind(('', int(sys.argv[1])))
server.listen(3)
server.setblocking(0)

clients = {}
writers = {}
pkeys = {}
first ={}
pad=padding.OAEP(
         mgf=padding.MGF1(algorithm=hashes.SHA1()),
         algorithm=hashes.SHA1(),
         label=None
     )


def dropClient(cli, errors=None):
    if errors:
        print('Client %s left unexpectedly:' % (clients[cli],))
        print('  ', errors)
    else:
        print('Client %s left politely' % (clients[cli],))
    del clients[cli]
    if cli in writers:
        del writers[cli]
    if not errors:
        cli.shutdown()
    cli.close()


while 1:
    try:
        r, w, _ = select.select(
            [server] + list(clients.keys()), list(writers.keys()), []
        )
    except:
        break

    for cli in r:
        if cli == server:
            cli, addr = server.accept()
            print('Connection from %s' % (addr,))
            clients[cli] = addr
            first[cli] = 0
            cli.send(send_str)


        else:
            try:
                if(first[cli]==0):
                    ret = cli.recv(1024).decode('utf-8')
                    pkey=crypto.load_publickey(crypto.FILETYPE_PEM,ret)
                    pkeys[cli]=pkey.to_cryptography_key()
                    #pkeys[cli]=tmp.public_key()
                    first[cli]=1
                else:
                    ret = cli.recv(1024).decode('utf-8')
                    
                    ret_list=[ret[i:i+86] for i in range(0, len(ret), 86)]    
                    enc=''
                    for i in range(0,len(ret_list)):
                        enc=enc.join(pkeys[cli].encrypt(str(ret_list[i]),pad))
                    #enc="jkl"
                    k=random.randint(1,q-1)
                    #schnorr

                    #r=pow(g,k,p)
                    t=random.randint(1,100)
                    if(t<70):
                        r=1
                        i=k
                        a=g%p
                        while True:
                            t=i%2
                            i=i/2
                            if(t==1):
                                r=(r*a)%p
                            if i==0:
                                break
                            a=(a*a)%p
                    else:
                        r=1
                        i=k
                        a=g%(p+1)
                        while True:
                            t=i%2
                            i=i/2
                            if(t==1):
                                r=(r*a)%(p+1)
                            if i==0:
                                break
                            a=(a*a)%(p+1)
                    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
                    
                    digest.update(str(ret))
                    digest.update(str(r))

                    t=digest.finalize()
                    e=int(t.encode('hex'),16)
                    s=k-(x*e)
                    ret = enc +','+str(e)+','+str(s)
                    
                    #DSA
                    '''
                    
                    #r=pow(g,k,p)
                    r=1
                    i=k
                    a=g%p
                    while True:
                        t=i%2
                        i=i/2
                        if(t==1):
                            r=(r*a)%p
                        if i==0:
                            break
                        a=(a*a)%p
                    
                    r=r%q
                    
                    #s1=pow(k,q-2,q)
                    s1=1
                    i=q-2
                    a=k%q
                    while True:
                        t=i%2
                        i=i/2
                        if(t==1):
                            s1=(s1*a)%q
                        if i==0:
                            break
                        a=(a*a)%q
                    
                    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
                    digest.update(enc)
                    t=digest.finalize()
                    e=int(t.encode('hex'),16)
                    s2=(e+(x*r))%q
                    s=(s1*s2)%q
                    ret = enc +','+str(r)+','+str(s)
                    '''
            except (SSL.WantReadError,
                    SSL.WantWriteError,
                    SSL.WantX509LookupError):
                pass
            except SSL.ZeroReturnError:
                dropClient(cli)
            except SSL.Error as errors:
                dropClient(cli, errors)
            else:
                if cli not in writers:
                    writers[cli] = ''
                writers[cli] = writers[cli] + ret

    for cli in w:
        try:
            ret = cli.send(writers[cli])
        except (SSL.WantReadError,
                SSL.WantWriteError,
                SSL.WantX509LookupError):
            pass
        except SSL.ZeroReturnError:
            dropClient(cli)
        except SSL.Error as errors:
            dropClient(cli, errors)
        else:
            writers[cli] = writers[cli][ret:]
            if writers[cli] == '':
                del writers[cli]

for cli in clients.keys():
    cli.close()
server.close()
