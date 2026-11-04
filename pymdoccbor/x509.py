import datetime

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from . import settings


def cose_key_to_cryptography(cose_key) -> ec.EllipticCurvePrivateKey:
    """The cryptography private key of a pycose EC2 private key."""
    _curve = cose_key.crv.curve_obj
    if isinstance(_curve, type):
        _curve = _curve()
    return ec.derive_private_key(int.from_bytes(cose_key.d, "big"), _curve)


class MsoX509Fabric:

    def selfsigned_x509cert(self, encoding: str = "DER"):
        """
            returns a self-signed X.509 certificate of the MSO issuer's key.

            For tests and demos only: a verifier only trusts certificates that
            chain to its trust anchors, so a self-signed certificate is never
            used implicitly when issuing.
        """
        private_key = cose_key_to_cryptography(self.private_key)
        now = datetime.datetime.now(datetime.timezone.utc)

        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, settings.X509_COUNTRY_NAME),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, settings.X509_STATE_OR_PROVINCE_NAME),
            x509.NameAttribute(NameOID.LOCALITY_NAME, settings.X509_LOCALITY_NAME),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, settings.X509_ORGANIZATION_NAME),
            x509.NameAttribute(NameOID.COMMON_NAME, settings.X509_COMMON_NAME),
        ])
        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            private_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            now
        ).not_valid_after(
            now + datetime.timedelta(days=settings.X509_NOT_VALID_AFTER_DAYS)
        ).add_extension(
            x509.SubjectAlternativeName(
                [
                    x509.UniformResourceIdentifier(
                        settings.X509_SAN_URL
                    )
                ]
            ),
            critical=False,
        ).sign(private_key, hashes.SHA256())

        if not encoding:
            return cert
        else:
            return cert.public_bytes(
                getattr(serialization.Encoding, encoding)
            )
