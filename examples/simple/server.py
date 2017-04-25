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
q=5
t=random.randint(0,8)
r1=pow(2,21+t)
r2=pow(2,22+t)
p1=random.randint(r1+1,r2-1)
rem=p1%q
p=(p1-rem)+1
p=31
h=random.randint(2,p-2)
g=1
while (g==1):
    h=random.randint(2,p-2)
    g=1
    mod=2%p
    i=1
    while i<=(p-1)/q:
        g=(g*mod)%p
        i=i+1


x=random.randint(1,q-1)
x_send=1

mod=g%p
i=1
while i<=x:
    x_send=(x_send*mod)%p
    i=i+1
print(g)
print(x)
print(x_send)
print(p)
print(q)

gmp=1
mod=g%p
i=1
while i<=q:
    gmp=(gmp*mod)%p
    i=i+1
print(gmp)

send_str=str(q)+','+str(p)+','+str(g)+','+str(x_send)+','+str(x)
print('done')

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
                    print(pkey)
                    pkeys[cli]=pkey.to_cryptography_key()
                    #pkeys[cli]=tmp.public_key()
                    print(pkeys[cli])
                    first[cli]=1
                else:
                    ret = cli.recv(1024).decode('utf-8')
                    enc=pkeys[cli].encrypt(str(ret),pad)
                    k=random.randint(1,q-1)
                    print("k")
                    print(k)
                    r=0
                    while(r==0):
                        r=1
                        mod=g%p
                        i=1
                        while i<=k:
                            r=(r*mod)%p
                            i=i+1
                        r=r%q
                    print("r")
                    print(r)
                    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
                    digest.update(enc)
                    t=digest.finalize()
                    val=int(t.encode('hex'),16)
                    print('val')
                    print(val)
                    val=(val+x*r)%q
                    
                    s=1
                    mod=k%q
                    i=1
                    while i<=q-2:
                        s=(s*mod)%q
                        i=i+1
                    s=(s*val)%q
                    print("s")
                    print(s)
                    ret = enc +','+str(r)+','+str(s)

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
