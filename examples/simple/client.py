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
        
        '''
        print("a")
        print(line)
        print("b")
        enc=bkc.encrypt(line,pad)
        print(enc)
        print("c")
        text=tmp.decrypt(enc,pad)
        print(text)
        print("d")
        '''
        ret=sock.recv(1024) 
        text= tmp.decrypt(ret,pad)
        #sys.stdout.write(ret)
        print("a")
        sys.stdout.write(text)
        
        sys.stdout.flush()
    except SSL.Error:
        print('Connection died unexpectedly')
        break


sock.shutdown()
sock.close()
