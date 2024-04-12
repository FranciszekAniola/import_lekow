import os
import tempfile
from cryptography.hazmat.primitives import serialization
from requests import Session
from cryptography.hazmat.primitives.serialization import pkcs12
from zeep import Client
from zeep.transports import Transport
from lxml import etree
from zeep.wsse.signature import BinarySignature, Signature
import xmlsec
from zeep import xsd
from zeep.plugins import HistoryPlugin

password='pknq9qmVRCJo'

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


def save_cert_to_file(dir, cert_file_name, certificate):
    cert_path = os.path.join(dir, cert_file_name)
    with open(cert_path, 'wb+') as cert_file:
        cert_file.write(
            certificate.public_bytes(serialization.Encoding.PEM),
        )
    return cert_path








if __name__ == '__main__':
    # NAZWY KLUCZY CERTYFIKATÓW
    private_wss_key_file_name = 'wss_private_key.key.pem'
    public_wss_key_file_name = 'wss_public_key.key.pem'
    wss_cert_file_name = 'wss_certificate.crt.pem'

    private_tls_key_file_name = 'tls_private_key.key.pem'
    public_tls_key_file_name = 'tls_public_key.key.pem'
    tls_cert_file_name = 'tls_certificate.crt.pem'

    # ŚCIEŻKI DO PLIKÓW .pem
    tls_cert_p12_file = 'C:\\Users\\aniol\\Downloads\\certyfikaty\\Podmiot_leczniczy_289-tls.p12'
    wss_cert_p12_file = 'C:\\Users\\aniol\\Downloads\\certyfikaty\\Podmiot_leczniczy_289-wss.p12'
    temp_dir = './'

    tls_private_key, tls_certificate = create_cert(tls_cert_p12_file)
    wss_private_key, wss_certificate = create_cert(wss_cert_p12_file)

    public_tls_key_path = save_public_key(temp_dir, public_tls_key_file_name, tls_certificate)
    public_wss_key_path = save_public_key(temp_dir, public_wss_key_file_name, wss_certificate)

    private_wss_key_path = save_private_key(temp_dir, private_wss_key_file_name, wss_private_key)
    private_tls_key_path = save_private_key(temp_dir, private_tls_key_file_name, tls_private_key)

    tls_cert_path = save_cert_to_file(temp_dir, tls_cert_file_name, tls_certificate)
    wss_cert_path = save_cert_to_file(temp_dir, wss_cert_file_name, wss_certificate)

    session = Session()
    session.cert = tls_cert_path, private_tls_key_file_name

    session.verify = True
    transport = Transport(session=session)
    wsdl = 'https://isus.ezdrowie.gov.pl/services/ObslugaEksportuRejestruLekowWS?wsdl'
    client = Client(wsdl=wsdl,
                    transport=transport,
                    wsse=BinarySignature(private_wss_key_path, wss_cert_path, password)
                    )
    url = "https://isus.ezdrowie.gov.pl/services/ObslugaEksportuRejestruLekowWS"

    client._default_service = client.create_service(binding_name='{http://csioz.gov.pl/p1/ws/v20191108/ZrzutRejestruLekowWS/}ObslugaEksportuRejestruLekowWSSoap11Binding', address=url)

    soap_header = xsd.Element(
        '{http://csioz.gov.pl/p1/kontekst/mt/v20180509}kontekstWywolania',
        xsd.ComplexType([
            xsd.Element('{http://csioz.gov.pl/p1/kontekst/mt/v20180509}atrybut', xsd.ComplexType([
                xsd.Element('{http://csioz.gov.pl/p1/kontekst//mtv20180509}nazwa', xsd.String()),
                xsd.Element('{http://csioz.gov.pl/p1/kontekst/mt/v20180509}wartosc', xsd.String())
            ]))
        ])
    )
    header_value = soap_header(
        atrybut=[
            {
                "nazwa": "urn:csioz:p1:kontekst:idPodmiotuOidRoot",
                "wartosc": "2.7.553"
            },
            {
                "nazwa": "urn:csioz:p1:kontekst:idPodmiotuOidExt",
                "wartosc": "628681020681b56d739f76caf874b5b786d23a86"
            },
            {
                "nazwa": "urn:csioz:p1:kontekst:rolaBiznesowa",
                "wartosc": "SYSTEM_ZEWNETRZNY_PODMIOTU_LECZNICZEGO"
            },
        ]
    )
    # try:
    x = client.service.pobierzPlikZrzutuRejestruLekow(_soapheaders=[header_value])
# except Exception as e:
    #     print(e)

