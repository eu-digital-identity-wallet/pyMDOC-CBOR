import binascii
import cbor2
import datetime
import hashlib
import logging

from typing import Iterable, List, Optional

from pymdoccbor import settings
from pymdoccbor.exceptions import InvalidMdoc
from pymdoccbor.mdoc.issuersigned import IssuerSigned

logger = logging.getLogger('pymdoccbor')


class MobileDocument:
    _states = {
        True: "valid",
        False: "failed",
    }

    def __init__(self, docType: str, issuerSigned: dict, deviceSigned: dict = None, **kwargs):
        self.doctype: str = docType  # eg: 'org.iso.18013.5.1.mDL'
        self.issuersigned: IssuerSigned = IssuerSigned(**issuerSigned)
        self.is_valid = False
        #: why the last verify() failed
        self.errors: List[str] = []

        # TODO: device authentication (deviceSigned) is not verified
        self.devicesigned: dict = deviceSigned or {}

    def dumps(self) -> str:
        """
            returns an AF binary repr of the document
        """
        return binascii.hexlify(self.dump())

    def dump(self) -> bytes:
        """
            returns bytes
        """
        return cbor2.dumps(
            cbor2.CBORTag(24, value={
                'docType': self.doctype,
                'issuerSigned': self.issuersigned.dumps()
            }
            )
        )

    def _check_digests(self, mso: dict) -> None:
        hash_name = settings.HASHALG_MAP.get(mso.get("digestAlgorithm"))
        if not hash_name:
            self.errors.append(f"unsupported digestAlgorithm {mso.get('digestAlgorithm')!r}")
            return
        value_digests = mso.get("valueDigests") or {}
        for ns, items in (self.issuersigned.namespaces or {}).items():
            for item in items:
                if not isinstance(item, cbor2.CBORTag) or item.tag != 24:
                    self.errors.append(f"{ns}: IssuerSignedItem is not a tag 24 bstr")
                    continue
                element = cbor2.loads(item.value)
                expected = value_digests.get(ns, {}).get(element.get("digestID"))
                digest = hashlib.new(hash_name, cbor2.dumps(item)).digest()
                if expected != digest:
                    self.errors.append(f"digest mismatch for {ns}/{element.get('elementIdentifier')}")

    def verify(
        self,
        trusted_certificates: Optional[Iterable] = None,
        at_time: Optional[datetime.datetime] = None,
    ) -> bool:
        """
            The document is valid when all of these hold:
            - the issuer certificate chain leads to one of trusted_certificates;
            - the MSO signature (ES256, ES384 or ES512, alg in the protected
              header) verifies with the issuer certificate;
            - every disclosed element matches its digest in the MSO;
            - the MSO docType is the document's docType;
            - the MSO is valid at at_time (default: now).

            Without trusted certificates the document is never valid.

            This authenticates the issuer data (issuerSigned) only. Device
            authentication (deviceSigned / DeviceAuth over the
            SessionTranscript) is not implemented, so it does not prove the
            presenter holds the device key: a copied issuerSigned verifies.
        """
        self.errors = []
        when = at_time or datetime.datetime.now(datetime.timezone.utc)
        if when.tzinfo is None:
            when = when.replace(tzinfo=datetime.timezone.utc)
        issuer_auth = self.issuersigned.issuer_auth

        try:
            if not issuer_auth.verify_signature():
                self.errors.append("issuer signature is invalid")
        except Exception as e:
            self.errors.append(f"issuer signature could not be verified: {e}")

        trusted = list(trusted_certificates or [])
        if not trusted:
            self.errors.append("no trusted certificates given: the issuer cannot be trusted")
        else:
            try:
                if not issuer_auth.verify_chain(trusted, at_time=when):
                    self.errors.append("issuer certificate chain is not trusted or not valid")
            except Exception as e:
                self.errors.append(f"issuer certificate chain could not be checked: {e}")

        try:
            mso = issuer_auth.payload_as_dict
            if not isinstance(mso, dict):
                raise InvalidMdoc(f"the MSO is a {type(mso).__name__}, not a map")
            if mso.get("docType") != self.doctype:
                self.errors.append(f"MSO docType {mso.get('docType')!r} is not the document docType {self.doctype!r}")
            validity = mso.get("validityInfo")
            valid_from = validity.get("validFrom") if isinstance(validity, dict) else None
            valid_until = validity.get("validUntil") if isinstance(validity, dict) else None
            if not isinstance(valid_from, datetime.datetime) or not isinstance(valid_until, datetime.datetime):
                self.errors.append("MSO validityInfo is malformed")
            elif not valid_from <= when <= valid_until:
                self.errors.append(f"MSO is not valid at {when.isoformat()} ({valid_from} - {valid_until})")
        except Exception as e:
            self.errors.append(f"MSO could not be decoded: {e}")
            mso = None

        if mso is not None:
            try:
                self._check_digests(mso)
            except Exception as e:
                self.errors.append(f"digests could not be checked: {e}")

        self.is_valid = not self.errors
        if self.errors:
            logger.warning(f"Document {self.doctype} is not valid: {self.errors}")
        return self.is_valid

    def __repr__(self):
        return f"{self.__module__}.{self.__class__.__name__} [{self._states[self.is_valid]}]"


class MdocCbor:

    def __init__(self):
        self.data_as_bytes: bytes = b""
        self.data_as_cbor_dict: dict = {}

        self.documents: List[MobileDocument] = []
        self.documents_invalid: list = []

    def loads(self, data: str):
        """
        data is a AF BINARY
        """
        if isinstance(data, bytes):
            data = binascii.hexlify(data)

        self.data_as_bytes = binascii.unhexlify(data)
        self.data_as_cbor_dict = cbor2.loads(self.data_as_bytes)

    def dump(self) -> bytes:
        """
            returns bytes
        """
        return self.data_as_bytes

    def dumps(self) -> str:
        """
            returns AF binary string representation
        """
        return binascii.hexlify(self.data_as_bytes)

    @property
    def data_as_string(self) -> str:
        return self.dumps().decode()

    def verify(
        self,
        trusted_certificates: Optional[Iterable] = None,
        at_time: Optional[datetime.datetime] = None,
    ) -> bool:
        """
            Verifies every document (see MobileDocument.verify). True only when
            all documents are valid; without trusted_certificates nothing is.

            trusted_certificates: issuer trust anchors (e.g. IACA certificates),
            as cryptography certificates, DER or PEM.
        """
        cdict = self.data_as_cbor_dict

        for i in ('version', 'documents'):
            if i not in cdict:
                raise InvalidMdoc(
                    f"Mdoc is invalid since it doesn't contain the '{i}' element"
                )

        self.documents = []
        self.documents_invalid = []
        trusted = list(trusted_certificates or [])
        if not trusted:
            logger.error("No trusted certificates given: no document can be valid")

        doc_cnt = 1
        for doc in cdict['documents']:
            try:
                mso = MobileDocument(**doc)
            except Exception as e:
                logger.error(f"Document number #{doc_cnt} is malformed: {e}")
                self.documents_invalid.append(doc)
                doc_cnt += 1
                continue

            if mso.verify(trusted_certificates=trusted, at_time=at_time):
                self.documents.append(mso)
            else:
                self.documents_invalid.append(mso)

            doc_cnt += 1

        return False if self.documents_invalid or not self.documents else True

    def __repr__(self):
        return (
            f"{self.__module__}.{self.__class__.__name__} "
            f"[{len(self.documents)} valid documents]"
        )
