# WERSJA GIT
# WERSJA GIT
# WERSJA GIT
# WERSJA GIT
# WERSJA GIT

import os
import tempfile
from cryptography.hazmat.primitives import serialization
from requests import Session
from cryptography.hazmat.primitives.serialization import pkcs12
from zeep import Client
from zeep.transports import Transport
from lxml import etree
from zeep.wsse.signature import Signature
import xmlsec

tls_cert_p12_file = 'C:\\Users\\aniol\\Downloads\\certyfikaty\\Podmiot_leczniczy_289-tls.p12'
wss_cert_p12_file = 'C:\\Users\\aniol\\Downloads\\certyfikaty\\Podmiot_leczniczy_289-wss.p12'

password='pknq9qmVRCJo'
temp_dir = './'

private_tls_key_file_name = 'tls_private_key.pem'
public_tls_key_file_name = 'tls_public_key.pem'
tls_cert_file_name = 'tls_certificate.pem'


private_wss_key_file_name = 'wss_private_key.pem'
public_wss_key_file_name = 'wss_public_key.pem'
wss_cert_file_name = 'wss_certificate.pem'


def create_cert(cert_file_):
    with open(cert_file_, 'rb') as f:
        (
            private_key,
            certificate,
            additional_certificates
        ) = serialization.pkcs12.load_key_and_certificates(
            f.read(), password.encode()
        )
    return private_key, certificate


def save_public_key(dir, public_key_file_name, certificate):
    public_key_path = os.path.join(dir, public_key_file_name)
    if not os.path.exists(public_key_path):
        with open(public_key_path, 'wb') as public_key_file:
            public_key_file.write(
                certificate.public_key().public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                )
            )
    return public_key_path


def save_private_key(dir, private_key_file_name, private_key):
    private_key_path = os.path.join(dir, private_key_file_name)
    if not os.path.exists(private_key_path):
        with open(private_key_path, 'wb') as key_file:
            key_file.write(
                private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption(),
                )
            )
    return private_key_path


def save_cert_to_file(dir, cert_file_name):
    cert_path = os.path.join(dir, cert_file_name)
    with open(cert_path, 'wb+') as cert_file:
        cert_file.write(
            tls_certificate.public_bytes(serialization.Encoding.PEM),
        )
    return cert_path


if __name__ == '__main__':

    tls_private_key, tls_certificate = create_cert(tls_cert_p12_file)
    wss_private_key, wss_certificate = create_cert(wss_cert_p12_file)

    public_tls_key_path = save_public_key(temp_dir, public_tls_key_file_name, tls_certificate)
    public_wss_key_path = save_public_key(temp_dir, public_wss_key_file_name, wss_certificate)

    private_wss_key_path = save_private_key(temp_dir, private_wss_key_file_name, wss_private_key)
    private_tls_key_path = save_private_key(temp_dir, private_tls_key_file_name, tls_private_key)

    tls_cert_path = save_cert_to_file(temp_dir, tls_cert_file_name)
    wss_cert_path = save_cert_to_file(temp_dir, wss_cert_file_name)

    session = Session()
    session.cert = tls_cert_path, private_tls_key_file_name
    session.verify = True

    transport = Transport(session=session)

    client = Client('https://isus.ezdrowie.gov.pl/services/ObslugaEksportuRejestruLekowWS?wsdl', transport=transport, wsse=Signature(private_wss_key_path, public_wss_key_path))

    client.service.pobierzPlikZrzutuRejestruLekow()