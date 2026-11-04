import base64
import datetime

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID, ObjectIdentifier

MDOC_DS_EKU = ObjectIdentifier("1.0.18013.5.1.2")
_KEY_USAGES = ("digital_signature", "content_commitment", "key_encipherment", "data_encipherment",
               "key_agreement", "key_cert_sign", "crl_sign", "encipher_only", "decipher_only")


def _name(cn):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn), x509.NameAttribute(NameOID.COUNTRY_NAME, "FC")])


def make_certificate(subject_key, cn, issuer_key=None, issuer_cn=None, ca=False, days=(-1, 365),
                     path_length=None, key_usage=None, eku=None, basic_constraints=True):
    """key_usage: KeyUsage flag names to set (None: no KeyUsage); eku: OIDs (None: no EKU)."""
    now = datetime.datetime.now(datetime.timezone.utc)
    builder = (
        x509.CertificateBuilder()
        .subject_name(_name(cn))
        .issuer_name(_name(issuer_cn or cn))
        .public_key(subject_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now + datetime.timedelta(days=days[0]))
        .not_valid_after(now + datetime.timedelta(days=days[1]))
    )
    if basic_constraints:
        builder = builder.add_extension(x509.BasicConstraints(ca=ca, path_length=path_length), critical=True)
    if key_usage is not None:
        builder = builder.add_extension(x509.KeyUsage(**{u: u in key_usage for u in _KEY_USAGES}), critical=True)
    if eku is not None:
        builder = builder.add_extension(x509.ExtendedKeyUsage(eku), critical=True)
    return builder.sign(issuer_key or subject_key, hashes.SHA256())


def make_ca(subject_key, cn, issuer_key=None, issuer_cn=None, path_length=None, **kwargs):
    """A CA certificate (IACA or intermediate): cA and KeyUsage keyCertSign, cRLSign."""
    kwargs.setdefault("key_usage", {"key_cert_sign", "crl_sign"})
    return make_certificate(subject_key, cn, issuer_key, issuer_cn, ca=True, path_length=path_length, **kwargs)


def make_ds(subject_key, cn, issuer_key, issuer_cn, **kwargs):
    """A document signer certificate as ISO 18013-5 profiles it."""
    kwargs.setdefault("key_usage", {"digital_signature"})
    kwargs.setdefault("eku", [MDOC_DS_EKU])
    return make_certificate(subject_key, cn, issuer_key, issuer_cn, **kwargs)


def cose_private_key(private_key):
    """pycose dict form of an EC P-256 private key (as the issuer backend builds it)."""
    return {
        "KTY": "EC2",
        "CURVE": "P_256",
        "ALG": "ES256",
        "D": private_key.private_numbers().private_value.to_bytes(32, "big"),
        "KID": b"test-issuer",
    }


def pem_device_key(public_key):
    """Device key as the issuer backend passes it: base64url of a PEM public key."""
    pem = public_key.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    return base64.urlsafe_b64encode(pem).decode()


class Pki:
    def __init__(self):
        self.iaca_key = ec.generate_private_key(ec.SECP256R1())
        self.iaca = make_ca(self.iaca_key, "Test IACA", path_length=0)
        self.ds_key = ec.generate_private_key(ec.SECP256R1())
        self.ds = make_ds(self.ds_key, "Test DS", self.iaca_key, "Test IACA")
        self.device_key = ec.generate_private_key(ec.SECP256R1())

    def write_ds(self, path):
        path.write_bytes(self.ds.public_bytes(serialization.Encoding.DER))
        return str(path)


@pytest.fixture
def pki():
    return Pki()


@pytest.fixture
def validity():
    now = datetime.datetime.now(datetime.timezone.utc)
    return {"issuance_date": now, "expiry_date": now + datetime.timedelta(days=30)}
