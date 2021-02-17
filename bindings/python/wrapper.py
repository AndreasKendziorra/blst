#!/usr/bin/env python3

import blst

DST = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_"

# sk_bytes, msg and dst must be of type bytes
def sign(sk_bytes, msg, dst=DST):
    SK = blst.SecretKey()
    SK.from_bendian(sk_bytes)
    return blst.P2().hash_to(msg, dst).sign_with(SK).compress()


# sk_bytes must be of type bytes
def SkToPk(sk_bytes):
    SK = blst.SecretKey()
    SK.from_bendian(sk_bytes)
    return blst.P1(SK).compress()
