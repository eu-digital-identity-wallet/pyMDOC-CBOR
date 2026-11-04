import cbor2

from pycose.messages import Sign1Message

from pymdoccbor.mdoc.issuer import MdocCborIssuer
from pymdoccbor.mdoc.verifier import MdocCbor
from pymdoccbor.mso.issuer import MsoIssuer
from . pid_data import PID_DATA
from .conftest import cose_private_key, pem_device_key


def test_mso_writer(pki, validity, tmp_path):
    msoi = MsoIssuer(
        data=PID_DATA,
        validity=validity,
        private_key=cose_private_key(pki.ds_key),
        cert_path=pki.write_ds(tmp_path / "ds.der"),
    )

    assert set(msoi.hash_map["eu.europa.ec.eudiw.pid.1"]) == set(range(len(PID_DATA["eu.europa.ec.eudiw.pid.1"])))

    mso = msoi.sign(device_key=cbor2.loads(cbor2.dumps({1: 2})), doctype="eu.europa.ec.eudiw.pid.1")

    Sign1Message.decode(mso.encode())


def test_mdoc_issuer(pki, validity, tmp_path):
    mdoci = MdocCborIssuer(
        private_key=cose_private_key(pki.ds_key)
    )

    mdoc = mdoci.new(
        doctype="eu.europa.ec.eudiw.pid.1",
        data=PID_DATA,
        validity=validity,
        devicekeyinfo=pem_device_key(pki.device_key.public_key()),
        cert_path=pki.write_ds(tmp_path / "ds.der"),
    )

    mdocp = MdocCbor()
    aa = cbor2.dumps({"version": "1.0", "documents": [{"docType": "eu.europa.ec.eudiw.pid.1", "issuerSigned": mdoc}]})
    mdocp.loads(aa)
    assert mdocp.verify(trusted_certificates=[pki.iaca])

    mdoci.dump()
    mdoci.dumps()
