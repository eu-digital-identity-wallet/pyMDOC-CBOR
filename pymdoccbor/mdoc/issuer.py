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


import base64
import binascii
import logging
from typing import Union

import cbor2
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from pycose.keys import CoseKey

from pymdoccbor import settings
from pymdoccbor.exceptions import MsoPrivateKeyRequired
from pymdoccbor.mso.issuer import MsoIssuer

logger = logging.getLogger("pymdoccbor")

#: COSE_Key parameters that only a private key has (EC2 d, OKP d, symmetric k)
PRIVATE_COSE_KEY_LABELS = {-4}


def device_key_to_cose(devicekeyinfo: Union[dict, CoseKey, str]) -> dict:
    """The holder's public key as a COSE_Key map for the MSO deviceKeyInfo.

    Accepts a base64url-encoded PEM public key (EC), a COSE_Key map (integer
    or pycose string labels) or a pycose CoseKey. Private keys are rejected.
    """
    if isinstance(devicekeyinfo, str):
        try:
            public_key = serialization.load_pem_public_key(base64.urlsafe_b64decode(devicekeyinfo.encode("utf-8")))
        except Exception as e:
            raise ValueError(f"Unreadable device key: {e}")
        if not isinstance(public_key, ec.EllipticCurvePublicKey):
            raise ValueError("Unsupported device key: only EC keys are supported")
        curve_name = public_key.curve.name
        curve_id = settings.COSE_CURVE_IDS.get(curve_name)
        if curve_id is None:
            raise ValueError(f"Unsupported device key curve: {curve_name}")
        size = (public_key.curve.key_size + 7) // 8
        numbers = public_key.public_numbers()
        return {1: 2, -1: curve_id, -2: numbers.x.to_bytes(size, "big"), -3: numbers.y.to_bytes(size, "big")}

    if isinstance(devicekeyinfo, dict) and not all(isinstance(k, int) for k in devicekeyinfo):
        devicekeyinfo = CoseKey.from_dict(devicekeyinfo)
    if isinstance(devicekeyinfo, CoseKey):
        devicekeyinfo = cbor2.loads(devicekeyinfo.encode())
    if not isinstance(devicekeyinfo, dict) or 1 not in devicekeyinfo:
        raise ValueError("Unsupported device key format")
    if PRIVATE_COSE_KEY_LABELS & set(devicekeyinfo):
        raise ValueError("The device key must be a public key: it contains private parameters")
    return dict(devicekeyinfo)


class MdocCborIssuer:
    def __init__(
        self,
        key_label: str = None,
        user_pin: str = None,
        lib_path: str = None,
        slot_id: int = None,
        alg: str = None,
        kid: str = None,
        private_key: Union[dict, CoseKey] = None,
    ):
        if any(v is not None for v in (key_label, user_pin, lib_path, slot_id)):
            raise NotImplementedError("HSM signing (key_label, user_pin, lib_path, slot_id) is not supported")
        self.version: str = "1.0"
        self.status: int = 0
        if isinstance(private_key, dict) and private_key:
            self.private_key = CoseKey.from_dict(private_key)
        elif isinstance(private_key, CoseKey):
            self.private_key = private_key
        else:
            raise MsoPrivateKeyRequired("MdocCborIssuer requires a private key")

        self.signed: dict = {}
        self.key_label = key_label
        self.user_pin = user_pin
        self.lib_path = lib_path
        self.slot_id = slot_id
        self.alg = alg
        self.kid = kid

    def new(
        self,
        data: dict,
        doctype: str,
        validity: dict = None,
        devicekeyinfo: Union[dict, CoseKey, str] = None,
        cert_path: str = None,
        revocation: dict = None,
        cert: bytes = None,
    ):
        """
        create a new mdoc with signed mso

        :param cert_path: path of the issuer (DS) certificate, DER or PEM
        :param cert: the issuer (DS) certificate, DER or PEM (instead of cert_path)
        """
        msoi = MsoIssuer(
            data=data,
            private_key=self.private_key,
            alg=self.alg,
            cert_path=cert_path,
            cert=cert,
            validity=validity,
            revocation=revocation,
        )

        mso = msoi.sign(doctype=doctype, device_key=device_key_to_cose(devicekeyinfo))

        mso_cbor = mso.encode(tag=False)

        # TODO: for now just a single document, it would be trivial having
        # also multiple but for now I don't have use cases for this
        res = {
            "nameSpaces": {
                ns: [v for k, v in dgst.items()]
                for ns, dgst in msoi.disclosure_map.items()
            },
            "issuerAuth": cbor2.loads(mso_cbor),
        }

        self.signed = res
        return self.signed

    def dump(self):
        """
        returns bytes
        """
        return cbor2.dumps(self.signed, canonical=True)

    def dumps(self):
        """
        returns AF binary repr
        """
        return binascii.hexlify(cbor2.dumps(self.signed, canonical=True))
