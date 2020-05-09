from math import floor

from XMSS_keyGen import XMSS_keyGen
from XMSS_sign import XMSS_sign
from generate_pk_kuglan import *
from RAND_HASH import *
from ltree import *
from WOTS_pkFromSig import *
from ADRS import *


def XMSS_rootFromSig(idx_sig: int, sig_ots, auth: List[bytearray], message: bytearray, h: int, w: int in {4, 16}, seed, adrs: ADRS):
    n = len(message) // 2
    len_1, len_2, length_all = lengths(n, w)

    adrs.setType(0)
    adrs.setOTSAddress(idx_sig)
    pk_ots = WOTS_pkFromSig(message, sig_ots, w, adrs, seed)
    adrs.setType(1)
    adrs.setLTreeAddress(idx_sig)
    node = [bytearray, bytearray]
    node[0] = ltree(pk_ots, adrs, seed, length_all)
    adrs.setType(2)
    adrs.setTreeIndex(idx_sig)

    for k in range(0, h):
        adrs.setTreeHeight(k)
        if floor(idx_sig / (2 ** k)) % 2 == 0:
            adrs.setTreeIndex(int.from_bytes(adrs.getTreeIndex(), byteorder='big') // 2)
            node[1] = RAND_HASH(node[0], auth[k], seed, adrs)
        else:
            adrs.setTreeIndex((int.from_bytes(adrs.getTreeIndex(), byteorder='big') - 1) // 2)
            node[1] = RAND_HASH(auth[k], node[0], seed, adrs)

        node[0] = node[1]

    return node[0]


if __name__ == '__main__':
    message = bytearray(b'0e4575aa2c51')
    KeyPair = XMSS_keyGen(2, 6, 16)
    len_1, len_2, len_all = lengths(6, 16)
    signature = XMSS_sign(message, KeyPair.getSK(), 16, ADRS(), 2)
    result = XMSS_rootFromSig(0, signature.sig.getSig_ots(), signature.sig.getAuth(), message, 2, 16, KeyPair.getSK().getSEED(), ADRS())
    print(result)

