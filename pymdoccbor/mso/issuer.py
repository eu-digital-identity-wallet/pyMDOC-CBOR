# Modifications have been made to the original file (available at https://github.com/IdentityPython/pyMDOC-CBOR)
# All modifications Copyright (c) 2023 European Commission

# All modifications licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at

#     http://www.apache.org/licenses/LICENSE-2.0

# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.


import datetime
import hashlib
import secrets
import uuid

from typing import Union

import cbor2
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from pycose.headers import Algorithm
from pycose.keys import CoseKey
from pycose.messages import Sign1Message

from pymdoccbor import settings
from pymdoccbor.exceptions import MsoPrivateKeyRequired, MsoX509ChainNotFound
from pymdoccbor.tools import shuffle_dict
from pymdoccbor.x509 import MsoX509Fabric

#: MSO signing algorithm -> (hashlib name, MSO digestAlgorithm)
ALG_DIGEST = {
    "ES256": ("sha256", "SHA-256"),
    "ES384": ("sha384", "SHA-384"),
    "ES512": ("sha512", "SHA-512"),
}


def _tag_value(name: str, value):
    """Wrap a value in the CBOR tag registered for its element name, once."""
    tag = settings.CBORTAGS_ATTR_MAP.get(name)
    if tag is not None and not isinstance(value, cbor2.CBORTag):
        return cbor2.CBORTag(tag, value=value)
    return value


def _copy_containers(value):
    """A copy of the maps and arrays in value; other objects are shared.

    (copy.deepcopy cannot copy the C implementation of cbor2.CBORTag.)
    """
    if isinstance(value, dict):
        return {k: _copy_containers(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_copy_containers(v) for v in value]
    return value


def tag_element_value(name: str, value):
    """Return the element value with its date tags, without changing the input.

    Dates are tagged at the top level, in nested maps and in maps inside
    arrays (e.g. mDL driving_privileges). Other array items are kept as they are.
    """
    value = _tag_value(name, _copy_containers(value))
    if isinstance(value, dict):
        return {k: _tag_value(k, v) for k, v in value.items()}
    if isinstance(value, list):
        return [
            {k: _tag_value(k, v) for k, v in item.items()} if isinstance(item, dict) else item
            for item in value
        ]
    return value


def load_certificate(cert: bytes) -> x509.Certificate:
    """A certificate in DER or PEM."""
    if cert.lstrip().startswith(b"-----BEGIN"):
        return x509.load_pem_x509_certificate(cert)
    return x509.load_der_x509_certificate(cert)


class MsoIssuer(MsoX509Fabric):
    """Builds and signs a Mobile Security Object (ISO/IEC 18013-5 9.1.2.4)."""

    def __init__(
        self,
        data: dict,
        validity: dict,
        revocation: dict = None,
        cert_path: str = None,
        key_label: str = None,
        user_pin: str = None,
        lib_path: str = None,
        slot_id: int = None,
        kid: str = None,
        alg: str = None,
        private_key: Union[dict, CoseKey] = None,
        digest_alg: str = settings.PYMDOC_HASHALG,
        cert: bytes = None,
    ):
        """
        :param data: ``{namespace: {element identifier: value}}``
        :param validity: ``{"issuance_date": datetime, "expiry_date": datetime}``
        :param cert_path: path of the issuer (DS) certificate, DER or PEM
        :param cert: the issuer (DS) certificate itself, DER or PEM (instead of cert_path)
        :param alg: ES256, ES384 or ES512; defaults to the key's algorithm, then ES256
        """
        if private_key and isinstance(private_key, dict):
            self.private_key = CoseKey.from_dict(private_key)
            if not self.private_key.kid:
                self.private_key.kid = str(uuid.uuid4())
        elif private_key and isinstance(private_key, CoseKey):
            self.private_key = private_key
        else:
            raise MsoPrivateKeyRequired("MSO Writer requires a valid private key")

        if alg is None:
            alg = getattr(self.private_key.alg, "fullname", None) or "ES256"
        if alg not in ALG_DIGEST:
            raise ValueError(f"Unsupported MSO signing algorithm: {alg}")
        if not self.private_key.alg:
            self.private_key.alg = alg

        self.data: dict = data
        self.hash_map: dict = {}
        self.cert_path = cert_path
        self.cert = cert
        self.disclosure_map: dict = {}
        self.digest_alg: str = ALG_DIGEST[alg][1]
        self.key_label = key_label
        self.user_pin = user_pin
        self.lib_path = lib_path
        self.slot_id = slot_id
        self.alg = alg
        self.kid = kid
        self.validity = validity
        self.revocation = revocation

        hashfunc = getattr(hashlib, ALG_DIGEST[alg][0])

        digest_cnt = 0
        for ns, values in data.items():
            self.disclosure_map[ns] = {}
            self.hash_map[ns] = {}
            for k, v in shuffle_dict(values).items():
                _rnd_salt = secrets.token_bytes(settings.DIGEST_SALT_LENGTH)

                self.disclosure_map[ns][digest_cnt] = cbor2.CBORTag(
                    24,
                    value=cbor2.dumps(
                        {
                            "digestID": digest_cnt,
                            "random": _rnd_salt,
                            "elementIdentifier": k,
                            "elementValue": tag_element_value(k, v),
                        },
                        canonical=True,
                    ),
                )

                self.hash_map[ns][digest_cnt] = hashfunc(
                    cbor2.dumps(self.disclosure_map[ns][digest_cnt], canonical=True)
                ).digest()

                digest_cnt += 1

    def format_datetime_repr(self, dt: datetime.datetime) -> str:
        """RFC 3339 date-time in UTC, without fractions (tdate). Naive datetimes are UTC."""
        if dt.tzinfo is not None:
            dt = dt.astimezone(datetime.timezone.utc)
        return dt.strftime("%Y-%m-%dT%H:%M:%SZ")

    def _issuer_certificate(self) -> x509.Certificate:
        if self.cert:
            cert = load_certificate(self.cert)
        elif self.cert_path:
            with open(self.cert_path, "rb") as file:
                cert = load_certificate(file.read())
        else:
            raise MsoX509ChainNotFound(
                "An issuer (DS) certificate is required: pass cert_path or cert"
            )
        public = cert.public_key()
        _x = getattr(self.private_key, "x", None)
        if _x and int.from_bytes(_x, "big") != public.public_numbers().x:
            raise ValueError("The issuer certificate does not match the signing key")
        return cert

    def sign(
        self,
        device_key: Union[dict, None] = None,
        valid_from: Union[None, datetime.datetime] = None,
        doctype: str = None,
    ) -> Sign1Message:
        """
        sign a mso and returns it

        :param valid_from: start of validity (``validFrom``) when it is later
            than the issuance date (``signed``); default the issuance date.
            It was accepted and then ignored before.
        """
        try:
            signed = self.validity["issuance_date"]
            exp = self.validity["expiry_date"]
        except (KeyError, TypeError):
            raise ValueError("MSO validity requires issuance_date and expiry_date")
        valid_from = valid_from or signed

        if settings.PYMDOC_EXP_DELTA_HOURS:
            exp = valid_from + datetime.timedelta(hours=settings.PYMDOC_EXP_DELTA_HOURS)

        # ISO 18013-5 9.1.2.4: validFrom is not before signed, validUntil after validFrom.
        if self.format_datetime_repr(valid_from) < self.format_datetime_repr(signed):
            raise ValueError("MSO validity: valid_from must not be before issuance_date")
        if self.format_datetime_repr(exp) <= self.format_datetime_repr(valid_from):
            raise ValueError("MSO validity: expiry_date must be after issuance_date")

        payload = {
            "docType": doctype or next(iter(self.hash_map)),
            "version": "1.0",
            "validityInfo": {
                "signed": cbor2.CBORTag(0, self.format_datetime_repr(signed)),
                "validFrom": cbor2.CBORTag(0, self.format_datetime_repr(valid_from)),
                "validUntil": cbor2.CBORTag(0, self.format_datetime_repr(exp)),
            },
            "valueDigests": self.hash_map,
            "deviceKeyInfo": {
                "deviceKey": device_key,
            },
            "digestAlgorithm": self.digest_alg,
        }

        if self.revocation is not None:
            payload.update({"status": self.revocation})

        _cert = self._issuer_certificate().public_bytes(serialization.Encoding.DER)

        mso = Sign1Message(
            phdr={Algorithm: self.private_key.alg},
            # x5chain (RFC 9360, label 33) in the unprotected header (ISO/IEC 18013-5 9.1.2.4)
            uhdr={33: _cert},
            payload=cbor2.dumps(
                cbor2.CBORTag(24, cbor2.dumps(payload, canonical=True)),
                canonical=True,
            ),
        )

        mso.key = self.private_key

        return mso
