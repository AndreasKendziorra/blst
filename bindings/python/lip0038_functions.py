#!/usr/bin/env python3

import wrapper
import math


def tagMessage(tag, netId, msg):
    return b"".join([tag, netId, msg])


def signBLS(sk, tag, netId, msg):
    taggedMsg = tagMessage(tag, netId, msg)
    return wrapper.sign(sk, taggedMsg)


def verifyBLS(pk, tag, netId, msg, sig):
    taggedMsg = tagMessage(tag, netId, msg)
    return wrapper.verify(pk, taggedMsg, sig)


def createAggSig(keysList, pubKeySignaturePairs):
    l = math.ceil(len(keysList) / 8.0)
    aggBytes = [0 for x in range(l)]
    sigs = []
    for p in pubKeySignaturePairs:
        sigs.append(p[1])
        index = keysList.index(p[0])
        [byte_index, bit_index] = divmod(index, 8)
        aggBytes[byte_index] |= 1 << bit_index
    sig = wrapper.Aggregate(sigs)[1]
    aggBits = b"".join([x.to_bytes(1, "big") for x in aggBytes])
    return [aggBits, sig]


def verifyAggSig(keysList, aggBits, sig, tag, netId, msg):
    taggedMsg = tagMessage(tag, netId, msg)
    pks = []
    for i in range(len(keysList)):
        [byte_index, bit_index] = divmod(i, 8)
        if aggBits[byte_index] & (1 << bit_index):
            pks.append(keysList[i])
    return wrapper.FastAggregateVerify(pks, taggedMsg, sig)
