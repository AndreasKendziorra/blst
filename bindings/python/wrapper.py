#!/usr/bin/env python3

import blst

DST_SIG = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_"
DST_POP = b"BLS_POP_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_"
INVALID_AGG_SIG = [False, bytes()]

# sk_bytes, msg and dst must be of type bytes
def sign(sk_bytes, msg, dst=DST_SIG):
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
def verify(pk_bytes, msg, sig, dst=DST_SIG):
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


# sk_bytes must be of type bytes
def PopProve(sk_bytes):
    PK = SkToPk(sk_bytes)
    return sign(sk_bytes, PK, DST_POP)


def KeyValidate(pk_bytes):
    try:
        PK = blst.P1_Affine(pk_bytes)
    except:
        # pk_bytes does not represent a point on E1
        return False
    if not PK.in_group():
        # PK is not in group G1
        return False
    if PK.is_inf():
        # PK is the identity point in G1
        return False
    return True


# pk_bytes and proof must be of type bytes
def PopVerify(pk_bytes, proof):
    if not KeyValidate(pk_bytes):
        return False
    return verify(pk_bytes, pk_bytes, proof, DST_POP)


# sigs must be an array of signatures where each signature is of type bytes
# returns [True/False, aggregate signature]
def Aggregate(sigs):
    if len(sigs) == 0:
        return INVALID_AGG_SIG
    try:
        agg_sig = blst.P2(sigs[0])
    except:
        # sigs[0] does not represent a point on E2
        return INVALID_AGG_SIG
    for sig in sigs[1:]:
        try:
            SIG = blst.P2_Affine(sig)
        except:
            # sig does not represent a point on E2
            return INVALID_AGG_SIG
        agg_sig.add(SIG)
    return [True, agg_sig.compress()]
