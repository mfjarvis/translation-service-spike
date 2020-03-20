import datetime

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography import x509

def load_private_key():
    print("Loading private key")
    with open("test_rsa", "rb") as key_file:
        private_key_bytes = key_file.read()
        return serialization.load_pem_private_key(private_key_bytes, None, default_backend())

def load_public_key():
    print("Loading public key")
    with open("test_rsa.pub", "rb") as key_file:
        public_key_bytes = key_file.read()
        return serialization.load_ssh_public_key(public_key_bytes, default_backend())

def load_public_key_from_cert():
    print("Loading public key from certificate")
    with open("test_cert.pem", "rb") as cert_file:
        cert_bytes = cert_file.read()
        cert = x509.load_pem_x509_certificate(cert_bytes, default_backend())
        #TODO - Check that we trust the certificate
        return cert.public_key()

def sign_message(message, private_key):
    print("Signing message")
    return private_key.sign(
        message,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256()
    )

def verify_message(message, signature, public_key):
    print("Verifying message")
    public_key.verify(
        signature,
        message,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256()
    )

def create_self_signed_cert(private_key):
    print("Creating self-signed certificate")
    name = x509.Name([
        x509.NameAttribute(x509.NameOID.COUNTRY_NAME, "GB"),
        x509.NameAttribute(x509.NameOID.STATE_OR_PROVINCE_NAME, "West Yorkshire"),
        x509.NameAttribute(x509.NameOID.LOCALITY_NAME, "Leeds"),
        x509.NameAttribute(x509.NameOID.ORGANIZATION_NAME, "Infinity Works")
    ])
    cert = x509.CertificateBuilder(
        name,
        name,
        private_key.public_key(),
        x509.random_serial_number(),
        datetime.datetime.utcnow(),
        datetime.datetime.utcnow() + datetime.timedelta(days=1000)
    ).sign(private_key, hashes.SHA256(), default_backend())
    with open("test_cert.pem", "wb") as cert_file:
        cert_file.write(cert.public_bytes(serialization.Encoding.PEM))