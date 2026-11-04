import cbor2
import json
import secrets


from cbor2.tool import (
    DefaultEncoder,
    key_to_str
)
from pycose.messages import Sign1Message


def bytes2CoseSign1(data: bytes) -> Sign1Message:
    """
    Gets bytes and return a COSE_Sign1 object
    """
    decoded = Sign1Message.decode(cbor2.loads(data).value)

    return decoded


def cborlist2CoseSign1(data: list) -> Sign1Message:
    """ 
        Gets cbor2 decoded COSE Sign1 as a list and return a COSE_Sign1 object
    """
    decoded = Sign1Message.decode(
        cbor2.dumps(
            cbor2.CBORTag(18, value=data)
        )
    )

    return decoded


def pretty_print(cbor_loaded: dict):
    _obj = key_to_str(cbor_loaded)
    res = json.dumps(
        _obj,
        indent=(None, 4),
        cls=DefaultEncoder
    )
    print(res)


def shuffle_dict(d: dict):
    """The items of d in a random order.

    The order sets the digest IDs of an mdoc's elements, which must not reveal
    which element is which (ISO 18013-5), so it comes from the OS CSPRNG
    (``secrets``): a Fisher-Yates shuffle, every order equally likely.
    """
    keys = list(d.keys())
    for i in range(len(keys) - 1, 0, -1):
        j = secrets.randbelow(i + 1)
        keys[i], keys[j] = keys[j], keys[i]
    return {key: d[key] for key in keys}
