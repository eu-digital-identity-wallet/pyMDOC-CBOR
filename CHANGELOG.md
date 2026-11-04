# Changelog

## [0.7.0]

_04 Nov 2026_

### Changed
- `MsoVerifier.verify_chain()` checks certificate profiles (CA BasicConstraints, KeyUsage, pathLenConstraint, DS EKU `1.0.18013.5.1.2`), and the chain must end at a trust anchor.
- The MSO `alg` must be in the protected header, be ES256, ES384 or ES512, and match the key's curve (`MsoVerifier.check_algorithm()`).
- `tools.shuffle_dict()` uses a Fisher-Yates shuffle with `secrets.randbelow` (SonarCloud S2245).
- README and `verify()` document that device authentication is not implemented.

### Fixed
- `MsoIssuer.sign(valid_from=...)` was ignored; it sets `validFrom`, which must not be before the issuance date (ISO 18013-5 9.1.2.4).
- `MobileDocument.verify()` raised on a malformed MSO or `validityInfo` instead of returning `False`.

## [0.6.0]

_07 Oct 2026_

### Changed
- `MdocCbor.verify()` / `MobileDocument.verify()` fail closed. They take `trusted_certificates` (e.g. IACA certificates) and an optional `at_time`, and a document is valid only when its x5chain leads to a trusted certificate, the MSO signature verifies, every disclosed element matches its digest, the MSO `docType` matches and the MSO is within its validity period. Before, any mdoc signed under the certificate it carried itself was valid (a self-signed mdoc verified) and the element digests were never checked. Failure reasons are in `MobileDocument.errors`.
- `MsoVerifier.verify_chain(trusted_certificates, at_time=None)` checks the x5chain; the x5chain is read from the protected or unprotected header, as a single certificate or an array.
- Issuing requires the issuer (DS) certificate (`cert_path`, or the new `cert` argument, DER or PEM) and checks it matches the signing key. The silent fallback to a self-signed "mysite.com" certificate is removed; `MsoX509Fabric.selfsigned_x509cert` remains for tests and demos.
- Dependencies: `cwt` is no longer used (the self-signed certificate is built with `cryptography`), so `cryptography` is no longer capped below 42. `install_requires` is now `cbor2>=5.4,<6`, `pycose>=1.0.1,<2`, `cryptography>=41`. cbor2 6 is excluded: pycose cannot decode COSE messages with it (tagged arrays are decoded as tuples).
- Device keys: a COSE_Key map, a pycose `CoseKey` or a base64url PEM EC public key is written to the MSO as a public COSE_Key map; keys with private parameters and non-EC PEM keys are rejected.
- Elements are shuffled with a cryptographic RNG before digestIDs are assigned.
- HSM arguments (`key_label`, `user_pin`, `lib_path`, `slot_id`) raise `NotImplementedError`; they were silently ignored and the software key was used.
- `alg` defaults to the key's algorithm, then ES256; unsupported algorithms raise `ValueError`. `MsoIssuer` requires `validity`, with the expiry after the issuance date.

### Fixed
- Issuing mutated the caller's data: date tags were added in place to nested maps and arrays, so issuing again with the same data (batch issuance) double-tagged them, e.g. `driving_privileges` `issue_date` became `1004(1004("2020-01-01"))`.
- Arrays of values other than maps (outside `nationality`, `codes`, `capacities`) crashed issuance.
- Brainpool device keys were given the COSE curve identifiers 8, 9 and 10 (8 is secp256k1) instead of 256, 258 and 259.
- A device key given as a map or `CoseKey` could not be encoded (`CBOREncodeTypeError`).
- `validityInfo` dates are always RFC 3339 UTC (`YYYY-MM-DDThh:mm:ssZ`); a timezone-aware datetime without microseconds produced `…+00:00Z`.
- The verification key was built without its `y` coordinate, so genuine mdocs randomly failed to verify; P-384 and P-521 issuer keys are supported.
- `MdocCborIssuer(private_key=CoseKey)` did not keep the key; `alg=None` crashed; `PYMDOC_EXP_DELTA_HOURS` from the environment was not converted to a number.
- `cbor2.decoder.loads` (removed in newer cbor2) replaced with `cbor2.loads`; the unused, undeclared `cbor_diag` import is removed.
