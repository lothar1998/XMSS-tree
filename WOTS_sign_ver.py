from math import ceil, floor, log2, log
from base_w import *
from chain_miccu64 import *


def WOTS_sign_ver(message: bytes, signature: [bytes], w: int in {4, 16}, ADRS, SEED):
    checksum = 0

    n = len(message)  # length of message
    len_1, len_2, len_all = lengths(n, w)

    msg = base_w(message, w, len_1)  # transformation message into base w

    for i in range(0, len_1):  # computing checksum
        checksum += w - 1 - msg[i]

    checksum = checksum << int(8 - ((len_2 * log2(w)) % 8))  # multiplying checksum by 2 ^ (8 - (len_2 * log2(w)) % 8)

    # len_2_bytes = ceil((len_2 * log2(w)) / 8)  # computing byte length of checksum
    len_2_bytes = bytes_needed(checksum)

    # transforming checksum into base w and appending it to message msg
    msg.extend(base_w(toByte(checksum, len_2_bytes), w, len_2))

    tmp_pk = [bytes()] * len_all  # declaration of len_all = len_1 + len_2 array of bytes

    for i in range(0, len_all):  # Computing a WOTS+ public key from a message and its signature
        ADRS.setChainAddress(i)
        tmp_pk[i] = chain(signature[i], msg[i], w - 1 - msg[i], SEED, ADRS, w)

    return tmp_pk


# get x integer as bytes in big endian with y byte length
def toByte(x, y):
    return x.to_bytes(y, byteorder='big')


# compute all required lengths
def lengths(n: int, w: int in {4, 16}):
    len_1 = ceil(8 * n / log2(w))
    len_2 = floor(log2(len_1 * (w - 1)) / log2(w)) + 1
    len_all = len_1 + len_2
    return len_1, len_2, len_all


def bytes_needed(n):
    if n == 0:
        return 1
    return int(log(n, 256)) + 1
