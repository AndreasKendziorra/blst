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


# pk_bytes, msg, sig and dst must be of type bytes
# Note: We do not need to perform the logic as specified in the function
# KeyValidate as specified here:
# https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bls-signature#section-2.5
# The reason is that all checks are already done during public key registration,
# i.e., in PopVerify, and signature validation is only done for registered
# public keys.
def verify(pk_bytes, msg, sig, dst=DST):
    try:
        SIG = blst.P2_Affine(sig)
    except:
        # sig is not a point on E2
        return False
    PK = blst.P1_Affine(pk_bytes)
    try:
        return SIG.core_verify(PK, True, msg, dst) == blst.BLST_SUCCESS
    except:
        return False
