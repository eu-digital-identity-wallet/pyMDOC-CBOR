"""Regression tests: issuer correctness and a verifier that fails closed."""

import copy
import datetime

import cbor2
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.x509.oid import ExtendedKeyUsageOID
from pycose.keys import CoseKey

from pymdoccbor.exceptions import MsoX509ChainNotFound
from pymdoccbor.mdoc.issuer import MdocCborIssuer
from pymdoccbor.mdoc.verifier import MdocCbor
from pymdoccbor.mso.issuer import MsoIssuer

from .conftest import MDOC_DS_EKU, Pki, cose_private_key, make_ca, make_certificate, make_ds, pem_device_key

MDL = "org.iso.18013.5.1.mDL"
NS = "org.iso.18013.5.1"


def mdl_data():
    return {
        NS: {
            "family_name": "Doe",
            "birth_date": "1990-01-01",
            "nationality": ["FC", "PT"],
            "driving_privileges": [
                {"vehicle_category_code": "B", "issue_date": "2020-01-01", "expiry_date": "2030-01-01"}
            ],
        }
    }


def issue(pki, tmp_path, validity, data=None, doctype=MDL, device_key=None, signer=None, cert=None):
    issuer = MdocCborIssuer(private_key=cose_private_key(signer or pki.ds_key), alg="ES256")
    return issuer.new(
        data=data if data is not None else mdl_data(),
        doctype=doctype,
        validity=validity,
        devicekeyinfo=device_key if device_key is not None else pem_device_key(pki.device_key.public_key()),
        cert_path=pki.write_ds(tmp_path / "ds.der") if cert is None else None,
        cert=cert,
    )


def elements(signed, ns=NS):
    return {e["elementIdentifier"]: e["elementValue"] for e in (cbor2.loads(i.value) for i in signed["nameSpaces"][ns])}


def mso(signed):
    return cbor2.loads(cbor2.loads(signed["issuerAuth"][2]).value)


def as_device_response(signed, doctype=MDL):
    return cbor2.dumps({"version": "1.0", "documents": [{"docType": doctype, "issuerSigned": signed}], "status": 0})


def verify(signed, trusted, doctype=MDL, **kwargs):
    mdoc = MdocCbor()
    mdoc.loads(as_device_response(signed, doctype))
    return mdoc.verify(trusted_certificates=trusted, **kwargs), mdoc


# ------------------------------------------------------------------ issuer ---


def test_issuing_twice_does_not_double_tag_or_mutate_the_data(pki, tmp_path, validity):
    data = mdl_data()
    original = copy.deepcopy(data)
    issue(pki, tmp_path, validity, data=data)
    second = issue(pki, tmp_path, validity, data=data)
    privileges = elements(second)["driving_privileges"][0]
    # cbor2 >= 5.5 decodes the full-date tag (1004) itself
    assert privileges["issue_date"] in (cbor2.CBORTag(1004, "2020-01-01"), datetime.date(2020, 1, 1))
    assert data == original


def test_already_tagged_values(pki, tmp_path, validity):
    data = mdl_data()
    data[NS]["birth_date"] = cbor2.CBORTag(1004, "1990-01-01")
    data[NS]["driving_privileges"][0]["issue_date"] = cbor2.CBORTag(1004, "2020-01-01")
    issued = elements(issue(pki, tmp_path, validity, data=data))
    assert issued["birth_date"] in (cbor2.CBORTag(1004, "1990-01-01"), datetime.date(1990, 1, 1))


def test_list_of_plain_values_is_kept(pki, tmp_path, validity):
    data = mdl_data()
    data[NS]["un_distinguishing_signs"] = ["FC", "PT"]  # a list of strings not in any allow-list
    assert elements(issue(pki, tmp_path, validity, data=data))["un_distinguishing_signs"] == ["FC", "PT"]


@pytest.mark.parametrize(
    "curve,crv",
    [(ec.SECP256R1(), 1), (ec.SECP384R1(), 2), (ec.BrainpoolP256R1(), 256), (ec.BrainpoolP384R1(), 258), (ec.BrainpoolP512R1(), 259)],
)
def test_device_key_curve_identifiers(pki, tmp_path, validity, curve, crv):
    device = ec.generate_private_key(curve).public_key()
    key = mso(issue(pki, tmp_path, validity, device_key=pem_device_key(device)))["deviceKeyInfo"]["deviceKey"]
    assert key[1] == 2 and key[-1] == crv
    assert int.from_bytes(key[-2], "big") == device.public_numbers().x


def _cose_device_dict(public_key):
    n = public_key.public_numbers()
    return {1: 2, -1: 1, -2: n.x.to_bytes(32, "big"), -3: n.y.to_bytes(32, "big")}


@pytest.mark.parametrize("form", ["dict", "cosekey"])
def test_device_key_as_cose_key(pki, tmp_path, validity, form):
    device = _cose_device_dict(pki.device_key.public_key())
    if form == "cosekey":
        device = CoseKey.from_dict(device)
    key = mso(issue(pki, tmp_path, validity, device_key=device))["deviceKeyInfo"]["deviceKey"]
    assert key == _cose_device_dict(pki.device_key.public_key())


def test_private_device_key_rejected(pki, tmp_path, validity):
    device = _cose_device_dict(pki.device_key.public_key())
    device[-4] = pki.device_key.private_numbers().private_value.to_bytes(32, "big")
    with pytest.raises(ValueError, match="private"):
        issue(pki, tmp_path, validity, device_key=device)


def test_unsupported_device_key_type(pki, tmp_path, validity):
    device = pem_device_key(rsa.generate_private_key(65537, 2048).public_key())
    with pytest.raises(ValueError, match="device key"):
        issue(pki, tmp_path, validity, device_key=device)


def test_certificate_is_required(pki, validity):
    issuer = MdocCborIssuer(private_key=cose_private_key(pki.ds_key), alg="ES256")
    with pytest.raises(MsoX509ChainNotFound):
        issuer.new(data=mdl_data(), doctype=MDL, validity=validity,
                   devicekeyinfo=pem_device_key(pki.device_key.public_key()))


def test_certificate_as_bytes(pki, validity, tmp_path):
    signed = issue(pki, tmp_path, validity, cert=pki.ds.public_bytes(serialization.Encoding.DER))
    assert verify(signed, [pki.iaca])[0]


@pytest.mark.parametrize("tz", [datetime.timezone.utc, datetime.timezone(datetime.timedelta(hours=2)), None])
def test_validity_tdates(pki, tmp_path, tz):
    start = datetime.datetime(2026, 1, 1, 12, 0, 0, 0, tzinfo=tz)
    validity = {"issuance_date": start, "expiry_date": start + datetime.timedelta(days=1)}
    payload = cbor2.loads(issue(pki, tmp_path, validity)["issuerAuth"][2]).value
    expected = "2026-01-01T10:00:00Z" if tz and tz.utcoffset(None) else "2026-01-01T12:00:00Z"
    assert f"validFrom\xc0t{expected}".encode("latin-1") in payload


def _mso_validity(pki, tmp_path, validity, **sign_args):
    msoi = MsoIssuer(data=mdl_data(), validity=validity, private_key=cose_private_key(pki.ds_key),
                     cert_path=pki.write_ds(tmp_path / "ds.der"))
    signed = msoi.sign(device_key=cbor2.loads(cbor2.dumps({1: 2})), doctype=MDL, **sign_args)
    return cbor2.loads(cbor2.loads(signed.payload).value)["validityInfo"]


def test_valid_from_defaults_to_the_issuance_date(pki, tmp_path):
    start = datetime.datetime(2026, 1, 1, 12, 0, 0, tzinfo=datetime.timezone.utc)
    info = _mso_validity(pki, tmp_path, {"issuance_date": start, "expiry_date": start + datetime.timedelta(days=1)})
    assert info["signed"] == info["validFrom"] == datetime.datetime(2026, 1, 1, 12, 0, 0, tzinfo=datetime.timezone.utc)


def test_valid_from_is_used_when_given(pki, tmp_path):
    """sign(valid_from=...) was accepted and then ignored."""
    start = datetime.datetime(2026, 1, 1, 12, 0, 0, tzinfo=datetime.timezone.utc)
    later = start + datetime.timedelta(hours=6)
    info = _mso_validity(pki, tmp_path, {"issuance_date": start, "expiry_date": start + datetime.timedelta(days=1)},
                         valid_from=later)
    assert info["signed"] == start and info["validFrom"] == later


def test_valid_from_before_signed_is_refused(pki, tmp_path):
    start = datetime.datetime(2026, 1, 1, 12, 0, 0, tzinfo=datetime.timezone.utc)
    with pytest.raises(ValueError, match="valid_from must not be before"):
        _mso_validity(pki, tmp_path, {"issuance_date": start, "expiry_date": start + datetime.timedelta(days=1)},
                      valid_from=start - datetime.timedelta(hours=1))


def test_validity_must_be_ordered(pki, tmp_path, validity):
    validity["expiry_date"] = validity["issuance_date"] - datetime.timedelta(days=1)
    with pytest.raises(ValueError, match="validity"):
        issue(pki, tmp_path, validity)


def test_default_algorithm(pki, tmp_path, validity):
    issuer = MdocCborIssuer(private_key=cose_private_key(pki.ds_key))
    signed = issuer.new(data=mdl_data(), doctype=MDL, validity=validity,
                        devicekeyinfo=pem_device_key(pki.device_key.public_key()),
                        cert_path=pki.write_ds(tmp_path / "ds.der"))
    assert mso(signed)["digestAlgorithm"] == "SHA-256"


def test_cosekey_private_key_is_used(pki, tmp_path, validity):
    issuer = MdocCborIssuer(private_key=CoseKey.from_dict(cose_private_key(pki.ds_key)), alg="ES256")
    signed = issuer.new(data=mdl_data(), doctype=MDL, validity=validity,
                        devicekeyinfo=pem_device_key(pki.device_key.public_key()),
                        cert_path=pki.write_ds(tmp_path / "ds.der"))
    assert verify(signed, [pki.iaca])[0]


def test_hsm_arguments_are_not_silently_ignored(pki):
    with pytest.raises(NotImplementedError):
        MdocCborIssuer(private_key=cose_private_key(pki.ds_key), alg="ES256", key_label="hsm-key")


def test_unknown_algorithm(pki):
    with pytest.raises(ValueError, match="algorithm"):
        MsoIssuer(data=mdl_data(), validity={}, private_key=cose_private_key(pki.ds_key), alg="HS256")


# ---------------------------------------------------------------- verifier ---


def test_genuine_mdoc_always_verifies(pki, tmp_path, validity):
    """The verification key used to miss its y coordinate: about half of the mdocs failed."""
    for _ in range(16):
        pki.ds_key = ec.generate_private_key(ec.SECP256R1())
        pki.ds = make_certificate(pki.ds_key, "Test DS", pki.iaca_key, "Test IACA")
        valid, mdoc = verify(issue(pki, tmp_path, validity), [pki.iaca])
        assert valid, mdoc.documents_invalid[0].errors


@pytest.mark.parametrize("curve", [ec.SECP384R1(), ec.SECP521R1()])
def test_other_issuer_curves(pki, tmp_path, validity, curve):
    pki.ds_key = ec.generate_private_key(curve)
    pki.ds = make_certificate(pki.ds_key, "Test DS", pki.iaca_key, "Test IACA")
    size = (curve.key_size + 7) // 8
    key = {"KTY": "EC2", "CURVE": {384: "P_384", 521: "P_521"}[curve.key_size],
           "ALG": {384: "ES384", 521: "ES512"}[curve.key_size],
           "D": pki.ds_key.private_numbers().private_value.to_bytes(size, "big")}
    issuer = MdocCborIssuer(private_key=key, alg=key["ALG"])
    signed = issuer.new(data=mdl_data(), doctype=MDL, validity=validity,
                        devicekeyinfo=pem_device_key(pki.device_key.public_key()),
                        cert_path=pki.write_ds(tmp_path / "ds.der"))
    assert verify(signed, [pki.iaca])[0]


def test_no_trust_anchors_fails_closed(pki, tmp_path, validity):
    assert verify(issue(pki, tmp_path, validity), None)[0] is False
    assert verify(issue(pki, tmp_path, validity), [])[0] is False


def test_self_signed_attacker_rejected(pki, tmp_path, validity):
    attacker = Pki()
    signed = issue(attacker, tmp_path, validity)
    valid, mdoc = verify(signed, [pki.iaca])
    assert valid is False
    assert any("trust" in e for e in mdoc.documents_invalid[0].errors)


def test_tampered_element_rejected(pki, tmp_path, validity):
    signed = issue(pki, tmp_path, validity)
    items = []
    for item in signed["nameSpaces"][NS]:
        element = cbor2.loads(item.value)
        if element["elementIdentifier"] == "family_name":
            element["elementValue"] = "Mallory"
        items.append(cbor2.CBORTag(24, cbor2.dumps(element)))
    signed["nameSpaces"][NS] = items
    valid, mdoc = verify(signed, [pki.iaca])
    assert valid is False
    assert any("digest" in e for e in mdoc.documents_invalid[0].errors)


def test_doctype_mismatch_rejected(pki, tmp_path, validity):
    valid, mdoc = verify(issue(pki, tmp_path, validity), [pki.iaca], doctype="eu.europa.ec.eudi.pid.1")
    assert valid is False
    assert any("docType" in e for e in mdoc.documents_invalid[0].errors)


def test_expired_mdoc_rejected(pki, tmp_path, validity):
    signed = issue(pki, tmp_path, validity)
    later = validity["expiry_date"] + datetime.timedelta(days=1)
    pki_later = verify(signed, [pki.iaca], at_time=later)
    assert pki_later[0] is False
    assert any("valid" in e for e in pki_later[1].documents_invalid[0].errors)


def test_expired_ds_certificate_rejected(pki, tmp_path, validity):
    pki.ds = make_certificate(pki.ds_key, "Test DS", pki.iaca_key, "Test IACA", days=(-30, -1))
    assert verify(issue(pki, tmp_path, validity), [pki.iaca])[0] is False


def test_trusted_certificate_formats(pki, tmp_path, validity):
    signed = issue(pki, tmp_path, validity)
    assert verify(signed, [pki.iaca.public_bytes(serialization.Encoding.DER)])[0]
    assert verify(signed, [pki.iaca.public_bytes(serialization.Encoding.PEM)])[0]


# ------------------------------------------------------- chain validation ---


def der(cert):
    return cert.public_bytes(serialization.Encoding.DER)


def with_x5chain(signed, *certs):
    """The x5chain (unprotected header, not signed) replaced by certs, leaf first."""
    phdr, uhdr, payload, signature = signed["issuerAuth"]
    signed = dict(signed)
    signed["issuerAuth"] = [phdr, {**uhdr, 33: [der(c) for c in certs]}, payload, signature]
    return signed


class Hierarchy:
    """IACA -> intermediate CA -> DS, with the DS key from pki."""

    def __init__(self, pki, iaca_path_length=1, intermediate=None, ds=None):
        self.iaca_key = ec.generate_private_key(ec.SECP256R1())
        self.iaca = make_ca(self.iaca_key, "Test IACA", path_length=iaca_path_length)
        self.int_key = ec.generate_private_key(ec.SECP256R1())
        self.int = (intermediate or (lambda k, ik: make_ca(k, "Test INT", ik, "Test IACA", path_length=0)))(self.int_key, self.iaca_key)
        self.ds = (ds or (lambda k, ik: make_ds(k, "Test DS", ik, "Test INT")))(pki.ds_key, self.int_key)
        pki.ds = self.ds


def test_chain_with_intermediate_ca_verifies(pki, tmp_path, validity):
    h = Hierarchy(pki)
    valid, mdoc = verify(with_x5chain(issue(pki, tmp_path, validity), h.ds, h.int), [h.iaca])
    assert valid, mdoc.documents_invalid[0].errors


@pytest.mark.parametrize(
    "intermediate",
    [
        lambda k, ik: make_certificate(k, "Test INT", ik, "Test IACA", ca=False, key_usage={"key_cert_sign"}),
        lambda k, ik: make_certificate(k, "Test INT", ik, "Test IACA", basic_constraints=False, key_usage={"key_cert_sign"}),
        lambda k, ik: make_ca(k, "Test INT", ik, "Test IACA", key_usage=None),
        lambda k, ik: make_ca(k, "Test INT", ik, "Test IACA", key_usage={"digital_signature", "crl_sign"}),
    ],
    ids=["not-ca", "no-basic-constraints", "no-key-usage", "no-key-cert-sign"],
)
def test_issuing_certificate_must_be_a_ca(pki, tmp_path, validity, intermediate):
    h = Hierarchy(pki, intermediate=intermediate)
    assert verify(with_x5chain(issue(pki, tmp_path, validity), h.ds, h.int), [h.iaca])[0] is False


def test_trust_anchor_must_be_a_ca_with_key_cert_sign(pki, tmp_path, validity):
    pki.iaca = make_certificate(pki.iaca_key, "Test IACA", ca=True, key_usage={"crl_sign"})
    assert verify(issue(pki, tmp_path, validity), [pki.iaca])[0] is False


def test_trust_anchor_path_length(pki, tmp_path, validity):
    h = Hierarchy(pki, iaca_path_length=0)
    assert verify(with_x5chain(issue(pki, tmp_path, validity), h.ds, h.int), [h.iaca])[0] is False


def test_intermediate_path_length(pki, tmp_path, validity):
    h = Hierarchy(pki, iaca_path_length=None)
    int2_key = ec.generate_private_key(ec.SECP256R1())
    int2 = make_ca(int2_key, "Test INT2", h.int_key, "Test INT")  # h.int has pathLenConstraint 0
    pki.ds = make_ds(pki.ds_key, "Test DS", int2_key, "Test INT2")
    assert verify(with_x5chain(issue(pki, tmp_path, validity), pki.ds, int2, h.int), [h.iaca])[0] is False


@pytest.mark.parametrize(
    "ds_kwargs",
    [
        {"ca": True, "key_usage": {"digital_signature", "key_cert_sign"}},
        {"key_usage": {"key_cert_sign"}},
        {"key_usage": {"key_agreement"}},
        {"eku": [ExtendedKeyUsageOID.SERVER_AUTH]},
        {"eku": [ExtendedKeyUsageOID.ANY_EXTENDED_KEY_USAGE]},
    ],
    ids=["ca", "key-cert-sign-only", "key-agreement-only", "eku-server-auth", "eku-any"],
)
def test_document_signer_certificate_profile(pki, tmp_path, validity, ds_kwargs):
    pki.ds = make_ds(pki.ds_key, "Test DS", pki.iaca_key, "Test IACA", **ds_kwargs)
    assert verify(issue(pki, tmp_path, validity), [pki.iaca])[0] is False


@pytest.mark.parametrize(
    "ds_kwargs",
    [{"key_usage": None, "eku": None}, {"basic_constraints": False}, {"eku": [ExtendedKeyUsageOID.SERVER_AUTH, MDOC_DS_EKU]}],
    ids=["no-key-usage-no-eku", "no-basic-constraints", "eku-includes-mdoc-ds"],
)
def test_document_signer_optional_extensions(pki, tmp_path, validity, ds_kwargs):
    pki.ds = make_ds(pki.ds_key, "Test DS", pki.iaca_key, "Test IACA", **ds_kwargs)
    valid, mdoc = verify(issue(pki, tmp_path, validity), [pki.iaca])
    assert valid, mdoc.documents_invalid[0].errors


def test_trust_anchor_is_not_accepted_as_leaf(pki, tmp_path, validity):
    """The issuer signs with the IACA key and sends the IACA as its x5chain."""
    signed = issue(pki, tmp_path, validity, signer=pki.iaca_key, cert=der(pki.iaca))
    assert verify(signed, [pki.iaca])[0] is False


def test_chain_must_end_at_or_below_a_trust_anchor(pki, tmp_path, validity):
    """The DS is issued by the IACA key, but the chain continues to an untrusted root."""
    rogue_key = ec.generate_private_key(ec.SECP256R1())
    rogue_root = make_ca(rogue_key, "Rogue Root")
    cross_signed_iaca = make_ca(pki.iaca_key, "Test IACA", rogue_key, "Rogue Root")
    signed = with_x5chain(issue(pki, tmp_path, validity), pki.ds, cross_signed_iaca, rogue_root)
    assert verify(signed, [pki.iaca])[0] is False


# ------------------------------------------------------------- COSE alg ---


def resign(signed, key, phdr, uhdr=None, hash_alg=None, payload=None):
    """issuerAuth signed again by key with the given headers (and payload)."""
    phdr_bytes = cbor2.dumps(phdr) if phdr else b""
    _, old_uhdr, old_payload, _ = signed["issuerAuth"]
    payload = old_payload if payload is None else payload
    to_sign = cbor2.dumps(["Signature1", phdr_bytes, b"", payload])
    r, s = decode_dss_signature(key.sign(to_sign, ec.ECDSA(hash_alg or hashes.SHA256())))
    size = (key.curve.key_size + 7) // 8
    signed = dict(signed)
    signed["issuerAuth"] = [phdr_bytes, {**old_uhdr, **(uhdr or {})}, payload, r.to_bytes(size, "big") + s.to_bytes(size, "big")]
    return signed


def test_resigned_mdoc_verifies(pki, tmp_path, validity):
    """Control for the tests below: the helper produces a valid signature."""
    signed = resign(issue(pki, tmp_path, validity), pki.ds_key, {1: -7})
    valid, mdoc = verify(signed, [pki.iaca])
    assert valid, mdoc.documents_invalid[0].errors


@pytest.mark.parametrize(
    "phdr, uhdr, hash_alg",
    [
        ({}, {1: -7}, hashes.SHA256()),  # alg only in the unprotected header
        ({1: -7}, {1: -7}, hashes.SHA256()),  # alg in both headers
        ({1: -35}, None, hashes.SHA384()),  # ES384 with a P-256 key
        ({1: -36}, None, hashes.SHA512()),  # ES512 with a P-256 key
        ({1: -8}, None, hashes.SHA256()),  # EdDSA
        ({1: 5}, None, hashes.SHA256()),  # HS256
        ({}, None, hashes.SHA256()),  # no alg
    ],
    ids=["unprotected-only", "both-headers", "es384-p256", "es512-p256", "eddsa", "hs256", "missing"],
)
def test_cose_alg_must_be_protected_and_match_the_key(pki, tmp_path, validity, phdr, uhdr, hash_alg):
    signed = resign(issue(pki, tmp_path, validity), pki.ds_key, phdr, uhdr, hash_alg)
    valid, mdoc = verify(signed, [pki.iaca])
    assert valid is False
    # Rejected for its alg, not by chance inside pycose.
    assert any("COSE alg" in e for e in mdoc.documents_invalid[0].errors)


# ---------------------------------------------------- malformed MSO input ---


@pytest.mark.parametrize(
    "mso_value, error",
    [
        ([1, 2, 3], "not a map"),
        ("mso", "not a map"),
        (lambda m: {**m, "validityInfo": ["2020-01-01"]}, "validityInfo"),
        (lambda m: {**m, "validityInfo": None}, "validityInfo"),
    ],
    ids=["list", "string", "validity-info-list", "validity-info-missing"],
)
def test_malformed_mso_fails_without_raising(pki, tmp_path, validity, mso_value, error):
    signed = issue(pki, tmp_path, validity)
    value = mso_value(mso(signed)) if callable(mso_value) else mso_value
    payload = cbor2.dumps(cbor2.CBORTag(24, cbor2.dumps(value)))
    valid, mdoc = verify(resign(signed, pki.ds_key, {1: -7}, payload=payload), [pki.iaca])
    assert valid is False
    assert any(error in e for e in mdoc.documents_invalid[0].errors)


# Element order (digest IDs): from the OS CSPRNG, uniform (SonarCloud S2245).


def test_shuffle_dict_keeps_every_item():
    from pymdoccbor.tools import shuffle_dict

    data = {f"element_{i}": i for i in range(20)}
    assert shuffle_dict(data) == data


def test_shuffle_dict_reaches_every_order():
    from collections import Counter

    from pymdoccbor.tools import shuffle_dict

    orders = Counter(tuple(shuffle_dict({"a": 1, "b": 2, "c": 3})) for _ in range(3000))
    assert len(orders) == 6
    assert min(orders.values()) > 350  # 500 expected for each order


def test_shuffle_dict_does_not_use_the_random_module(monkeypatch):
    import random

    from pymdoccbor.tools import shuffle_dict

    def refuse(*args, **kwargs):
        raise AssertionError("random module used")

    for name in ("shuffle", "randint", "random", "randrange", "choice"):
        monkeypatch.setattr(random, name, refuse)
    monkeypatch.setattr(random.SystemRandom, "shuffle", refuse)
    shuffle_dict({"a": 1, "b": 2, "c": 3})
