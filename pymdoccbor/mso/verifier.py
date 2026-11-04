import datetime
import logging
from typing import Iterable, Optional, Union

import cbor2
import cryptography
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ObjectIdentifier
from pycose.headers import Algorithm
from pycose.keys import EC2Key
from pycose.messages import Sign1Message

from pymdoccbor import settings
from pymdoccbor.exceptions import MsoX509ChainNotFound, UnsupportedMsoDataFormat
from pymdoccbor.tools import bytes2CoseSign1, cborlist2CoseSign1

logger = logging.getLogger("pymdoccbor")

X5CHAIN = 33

#: ISO 18013-5 extended key usage of an mdoc document signer (DS) certificate
MDOC_DS_EKU = ObjectIdentifier("1.0.18013.5.1.2")

#: COSE algorithms accepted for the MSO signature, and the issuer key curve each requires
COSE_ALG_CURVES = {"ES256": "secp256r1", "ES384": "secp384r1", "ES512": "secp521r1"}
_COSE_ALG_IDS = {-7: "ES256", -35: "ES384", -36: "ES512"}


def load_trusted_certificate(cert: Union[x509.Certificate, bytes, str]) -> x509.Certificate:
    """A trust anchor given as a certificate object, DER or PEM."""
    if isinstance(cert, x509.Certificate):
        return cert
    if isinstance(cert, str):
        cert = cert.encode()
    if cert.lstrip().startswith(b"-----BEGIN"):
        return x509.load_pem_x509_certificate(cert)
    return x509.load_der_x509_certificate(cert)


def _valid_at(cert: x509.Certificate, when: datetime.datetime) -> bool:
    utc = datetime.timezone.utc
    # cryptography < 42 only has the naive (UTC) properties
    before = getattr(cert, "not_valid_before_utc", None) or cert.not_valid_before.replace(tzinfo=utc)
    after = getattr(cert, "not_valid_after_utc", None) or cert.not_valid_after.replace(tzinfo=utc)
    return before <= when <= after


def _issued_by(cert: x509.Certificate, issuer: x509.Certificate) -> bool:
    try:
        cert.verify_directly_issued_by(issuer)
        return True
    except Exception:
        return False


def _extension(cert: x509.Certificate, ext_type):
    try:
        return cert.extensions.get_extension_for_class(ext_type).value
    except x509.ExtensionNotFound:
        return None


def _ca_problem(cert: x509.Certificate, cas_below: int) -> Optional[str]:
    """
        Why cert may not issue the certificate below it, or None.
        cas_below: intermediate CA certificates between cert and the leaf.
    """
    constraints = _extension(cert, x509.BasicConstraints)
    if constraints is None or not constraints.ca:
        return "is not a CA (BasicConstraints cA)"
    usage = _extension(cert, x509.KeyUsage)
    if usage is None or not usage.key_cert_sign:
        return "may not sign certificates (KeyUsage keyCertSign)"
    if constraints.path_length is not None and cas_below > constraints.path_length:
        return f"has pathLenConstraint {constraints.path_length} but {cas_below} CA certificates below it"
    return None


def _leaf_problem(cert: x509.Certificate) -> Optional[str]:
    """Why cert is not a document signer certificate, or None."""
    constraints = _extension(cert, x509.BasicConstraints)
    if constraints is not None and constraints.ca:
        return "is a CA certificate"
    usage = _extension(cert, x509.KeyUsage)
    if usage is not None and not usage.digital_signature:
        return "may not sign (KeyUsage digitalSignature)"
    eku = _extension(cert, x509.ExtendedKeyUsage)
    if eku is not None and MDOC_DS_EKU not in eku:
        return f"has no mdoc document signer extended key usage ({MDOC_DS_EKU.dotted_string})"
    return None


class MsoVerifier:
    """
    Parameters
        data: CBOR TAG 24

    Example:
        MsoParser(mdoc['documents'][0]['issuerSigned']['issuerAuth'])

    Note
        The signature is contained in an untagged COSE_Sign1
        structure as defined in RFC 8152.
    """

    def __init__(self, data: cbor2.CBORTag):
        self._data = data
        # not used
        if isinstance(self._data, bytes):
            self.object: Sign1Message = bytes2CoseSign1(
                cbor2.dumps(cbor2.CBORTag(18, value=self._data)))
        elif isinstance(self._data, list):
            self.object: Sign1Message = cborlist2CoseSign1(self._data)
        else:
            raise UnsupportedMsoDataFormat(
                f"MsoParser only supports raw bytes and list, a {type(data)} was provided"
            )

        self.object.key: Optional[EC2Key] = None
        self.public_key: Optional[ec.EllipticCurvePublicKey] = None
        self.x509_certificates: list = []

    @property
    def payload_as_cbor(self):
        """
        return the decoded payload
        """
        return cbor2.loads(self.object.payload)

    @property
    def payload_as_raw(self):
        return self.object.payload

    @property
    def payload_as_dict(self):
        return cbor2.loads(
            cbor2.loads(self.object.payload).value
        )

    @property
    def raw_public_keys(self) -> list:
        """
            the DER certificates of the x5chain header (label 33), leaf first,
            from the protected or the unprotected header
        """
        for headers in (self.object.phdr, self.object.uhdr):
            for h, v in headers.items():
                if getattr(h, "identifier", h) == X5CHAIN:
                    return list(v) if isinstance(v, list) else [v]

        raise MsoX509ChainNotFound(
            "I can't find any valid X509certs, identified by label number 33, "
            "in this MSO."
        )

    def load_public_key(self):
        self.x509_certificates = [
            cryptography.x509.load_der_x509_certificate(i) for i in self.raw_public_keys
        ]

        self.public_key = self.x509_certificates[0].public_key()
        if not isinstance(self.public_key, ec.EllipticCurvePublicKey):
            raise UnsupportedMsoDataFormat("The issuer certificate does not hold an EC key")
        curve = self.public_key.curve.name
        if curve not in settings.COSEKEY_HAZMAT_CRV_MAP:
            raise UnsupportedMsoDataFormat(f"Unsupported issuer key curve: {curve}")
        size = settings.CRV_LEN_MAP[curve]
        numbers = self.public_key.public_numbers()
        self.object.key = EC2Key(
            crv=settings.COSEKEY_HAZMAT_CRV_MAP[curve],
            x=numbers.x.to_bytes(size, "big"),
            y=numbers.y.to_bytes(size, "big"),
        )

    def verify_chain(
        self,
        trusted_certificates: Iterable[Union[x509.Certificate, bytes, str]],
        at_time: Optional[datetime.datetime] = None,
    ) -> bool:
        """
            The x5chain is valid at at_time (default: now) and:
            - each certificate is issued by the next one;
            - the leaf (DS) is not a trust anchor, is not a CA, has KeyUsage
              digitalSignature if it has KeyUsage, and has the mdoc DS extended
              key usage (1.0.18013.5.1.2) if it has an EKU extension;
            - every certificate issuing another one, trust anchor included, is
              a CA (BasicConstraints cA) with KeyUsage keyCertSign, within its
              pathLenConstraint;
            - the last certificate is one of the trusted certificates (e.g. an
              IACA) or is directly issued by one.
        """
        when = at_time or datetime.datetime.now(datetime.timezone.utc)
        if when.tzinfo is None:
            when = when.replace(tzinfo=datetime.timezone.utc)
        if not self.x509_certificates:
            self.load_public_key()
        chain = self.x509_certificates
        anchors = [load_trusted_certificate(c) for c in trusted_certificates or []]

        if any(chain[0] == anchor for anchor in anchors):
            logger.warning("Issuer certificate 0 is a trust anchor, not a document signer certificate")
            return False
        problem = _leaf_problem(chain[0])
        if problem:
            logger.warning(f"Issuer certificate 0 {problem}")
            return False

        for position, cert in enumerate(chain):
            if not _valid_at(cert, when):
                logger.warning(f"Issuer certificate {position} is not valid at {when.isoformat()}")
                return False
            if position + 1 < len(chain) and not _issued_by(cert, chain[position + 1]):
                logger.warning(f"Issuer certificate {position} is not issued by certificate {position + 1}")
                return False
            if position > 0:
                problem = _ca_problem(cert, cas_below=position - 1)
                if problem:
                    logger.warning(f"Issuer certificate {position} {problem}")
                    return False

        last = chain[-1]
        if any(last == anchor for anchor in anchors):
            if _valid_at(last, when):
                return True
        for anchor in anchors:
            if not _valid_at(anchor, when) or not _issued_by(last, anchor):
                continue
            problem = _ca_problem(anchor, cas_below=len(chain) - 1)
            if problem:
                logger.warning(f"Trust anchor {anchor.subject.rfc4514_string()} {problem}")
                continue
            return True
        logger.warning("The issuer certificate chain does not end at or below a trusted certificate")
        return False

    def check_algorithm(self) -> str:
        """
            The COSE alg of the MSO signature: it must be in the protected
            header (and not in the unprotected one), be ES256, ES384 or ES512,
            and match the issuer key's curve.

            Raises UnsupportedMsoDataFormat otherwise.
        """
        if not self.public_key:
            self.load_public_key()
        if any(getattr(h, "identifier", h) == Algorithm.identifier for h in self.object.uhdr):
            raise UnsupportedMsoDataFormat("The COSE alg must only be in the protected header")
        alg = next((v for h, v in self.object.phdr.items() if getattr(h, "identifier", h) == Algorithm.identifier), None)
        name = _COSE_ALG_IDS.get(alg) if isinstance(alg, int) else getattr(alg, "fullname", None)
        if name not in COSE_ALG_CURVES:
            raise UnsupportedMsoDataFormat(f"Unsupported or missing COSE alg in the protected header: {alg!r}")
        if COSE_ALG_CURVES[name] != self.public_key.curve.name:
            raise UnsupportedMsoDataFormat(f"COSE alg {name} does not match the issuer key curve {self.public_key.curve.name}")
        return name

    def verify_signature(self) -> bool:

        if not self.object.key:
            self.load_public_key()
        self.check_algorithm()

        return self.object.verify_signature()
