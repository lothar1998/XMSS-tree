from chain_miccu64 import chain
from basic_utilities import *


def WOTS_genPK(private_key: [bytes], length: int, w: int in {4, 16}, SEED, ADRS):

    if isinstance(private_key, bytearray):
        public_key = [bytes()] * (length // 2)  # declaring array of n-bytes strings
        for i, j in zip(range(0, length, 2), range(0, length // 2, 1)):  # generating public key based on chain function with given private key
            ADRS.setChainAddress(j)
            public_key[j] = chain(private_key[i:i+2], 0, w - 1, SEED, ADRS, w)

    else:
        public_key = [bytes()] * length  # declaring array of n-bytes strings
        for i in range(length):  # generating public key based on chain function with given private key
            ADRS.setChainAddress(i)
            public_key[i] = chain(private_key[i], 0, w - 1, SEED, ADRS, w)

    return public_key
