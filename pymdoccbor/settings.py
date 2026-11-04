import os

COSEKEY_HAZMAT_CRV_MAP = {"secp256r1": "P_256", "secp384r1": "P_384", "secp521r1": "P_521"}

CRV_LEN_MAP = {
    "secp256r1": 32,
    "secp384r1": 48,
    "secp521r1": 66,
}

#: COSE elliptic curve identifiers (IANA "COSE Elliptic Curves")
COSE_CURVE_IDS = {
    "secp256r1": 1,
    "secp384r1": 2,
    "secp521r1": 3,
    "brainpoolP256r1": 256,
    "brainpoolP384r1": 258,
    "brainpoolP512r1": 259,
}

PYMDOC_HASHALG: str = os.getenv("PYMDOC_HASHALG", "SHA-256")
PYMDOC_EXP_DELTA_HOURS: int = int(os.getenv("PYMDOC_EXP_DELTA_HOURS", 0))

HASHALG_MAP = {
    "SHA-256": "sha256",
    "SHA-384": "sha384",
    "SHA-512": "sha512",
}

DIGEST_SALT_LENGTH = 32


X509_DER_CERT = os.getenv("X509_DER_CERT", None)

# Subject of MsoX509Fabric.selfsigned_x509cert (tests and demos only: issuing
# requires a real issuer certificate)

X509_COUNTRY_NAME = os.getenv("X509_COUNTRY_NAME", "US")
X509_STATE_OR_PROVINCE_NAME = os.getenv("X509_STATE_OR_PROVINCE_NAME", "California")
X509_LOCALITY_NAME = os.getenv("X509_LOCALITY_NAME", "San Francisco")
X509_ORGANIZATION_NAME = os.getenv("X509_ORGANIZATION_NAME", "My Company")
X509_COMMON_NAME = os.getenv("X509_COMMON_NAME", "mysite.com")

X509_NOT_VALID_AFTER_DAYS = int(os.getenv("X509_NOT_VALID_AFTER_DAYS", 10))

X509_SAN_URL = os.getenv(
    "X509_SAN_URL", "https://credential-issuer.oidc-federation.online"
)

CBORTAGS_ATTR_MAP = {
    "birth_date": 1004,
    "expiry_date": 1004,
    "issue_date": 1004,
    "issuance_date": 1004,
    "effective_from_date": 0,
}
