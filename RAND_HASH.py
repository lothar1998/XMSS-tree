import hashlib
from basic_utilities import XOR, toByte
from ADRS import *


def H(KEY: bytearray, M: bytearray) -> bytearray:
    # H: SHA2-256(toByte(1, 32) || KEY || M)
    key_len = len(KEY)
    toBytes = toByte(1, 4)
    help_ = hashlib.sha256(toBytes + KEY + M).hexdigest()[:key_len]
    out = bytearray()
    out.extend(map(ord, help_))
    return out


def PRF(KEY: str, M: ADRS) -> bytearray:
    # PRF: SHA2-256(toByte(3, 32) || KEY || M)
    toBytes = toByte(3, 4)
    key_len = len(KEY)
    KEY2 = bytearray()
    KEY2.extend(map(ord, KEY))
    help_ = hashlib.sha256(toBytes + KEY2 + M.keyAndMask).hexdigest()[:key_len*2]
    out = bytearray()
    out.extend(map(ord, help_))
    return out


# Algorithm 7: RAND_HASH
# LEFT and RIGHT #represent the left and the right halves of the hash function input
# Input: n-byte value LEFT, n-byte value RIGHT, seed SEED, address ADRS
# Output: n-byte randomized hash
def RAND_HASH(left: bytearray, right: bytearray, SEED: str, adrs: ADRS):
    adrs.setKeyAndMask(0)
    KEY = PRF(SEED, adrs)
    adrs.setKeyAndMask(1)
    BM_0 = PRF(SEED, adrs)
    adrs.setKeyAndMask(2)
    BM_1 = PRF(SEED, adrs)

    return H(KEY, XOR(left, BM_0) + XOR(right, BM_1))


if __name__ == '__main__':
    value = RAND_HASH(bytearray("ABCD".encode()), bytearray("EFGH".encode()), "1232", ADRS())
    print(value)
