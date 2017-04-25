from OpenSSL import SSL as ssl
import socket
print ssl.get_server_certificate(('www.google.com', 443))
cert=ssl.get_server_certificate(('www.google.com', 443))
# OpenSSL
x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)
x509.get_subject().get_components()