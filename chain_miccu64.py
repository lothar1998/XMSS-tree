# Algorithm 2 - Chaining Function
# everything is in big-endian

# If x and y are non-negative integers, we define Z = toByte(x, y) to be the y-byte
# string containing the binary representation of x in big-endian byte order.

# If X is an x-byte string and Y a y-byte string, then X || Y denotes
# the concatenation of X and Y, with X || Y = X[0] ... X[x-1] Y[0] ... Y[y-1].

import hashlib
from basic_utilities import toByte, XOR
from rand_hash_miccu64 import PRF


def F(KEY, M):
    # F: SHA2-256(toByte(0, 32) || KEY || M)
    toBytes = toByte(0, 4)
    help_ = hashlib.sha256(toBytes + KEY + M).hexdigest()
    out = bytearray()
    out.extend(map(ord, help_))
    return out


# Input: Input string X, start index i, number of steps s, seed SEED, address ADRS
# Output: value of F iterated s times on X (it returns byte array)
def chain(X, i, s, SEED, ADRS, tmp=bytearray()):
    # w is 4 or 16, depends of us - CHOOSE ONE VALUE EVERYWHERE
    w = 16
    if s == 0:
        # it returns X as byte array
        help_ = bytearray()
        help_.extend(map(ord, X))
        return help_
    if (i + s) > (w - 1):
        return None
    tmp = (chain(X, i, s - 1, SEED, ADRS, tmp))

    ADRS.setHashAddress((i + s - 1))
    ADRS.setKeyAndMask(0)
    KEY = PRF(SEED, ADRS)
    ADRS.setKeyAndMask(1)
    BM = PRF(SEED, ADRS)  # SAVE BM
    # BM means BitMask
    tmp = F(KEY, XOR(tmp, BM))
    # returns byte array
    return tmp



# from ADRS import ADRS
# from basic_utilities import generate_seed
# # TEST
# seed = generate_seed(32)
# adrs = ADRS()
# res = chain("asdffthutrehgftyhui654ui867ytr5fasdffthutrehgftyhui654ui867ytr5f", 3, 8, seed, adrs)
# print(res)
#
