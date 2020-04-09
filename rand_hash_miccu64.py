import hashlib
from basic_utilities import XOR, toByte


def H(KEY, M):
    # H: SHA2-256(toByte(1, 32) || KEY || M)
    toBytes = toByte(1, 4)
    help_ = hashlib.sha256(toBytes + KEY + M).hexdigest()
    out = bytearray()
    out.extend(map(ord, help_))
    return out


def PRF(KEY, M):
    # PRF: SHA2-256(toByte(3, 32) || KEY || M)
    toBytes = toByte(3, 4)
    KEY2 = bytearray()
    KEY2.extend(map(ord, KEY))
    help_ = hashlib.sha256(toBytes + KEY2 + M.keyAndMask).hexdigest()
    out = bytearray()
    out.extend(map(ord, help_))
    return out


# Algorithm 7: RAND_HASH
# LEFT and RIGHT #represent the left and the right halves of the hash function input
# Input: n-byte value LEFT, n-byte value RIGHT, seed SEED, address ADRS
# Output: n-byte randomized hash
def RAND_HASH(left, right, SEED, ADRS):
    ADRS.setKeyAndMask(0)
    KEY = PRF(SEED, ADRS)
    ADRS.setKeyAndMask(1)
    BM_0 = PRF(SEED, ADRS)
    ADRS.setKeyAndMask(2)
    BM_1 = PRF(SEED, ADRS)
    return H(KEY, XOR(left, BM_0) + XOR(right, BM_1))
