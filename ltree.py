from math import floor, ceil

from ADRS import ADRS
from RAND_HASH import RAND_HASH


# PART 2 - 4.1.5. L-Trees
# Input: WOTS+ public key pk, address ADRS, seed SEED
# Output: n-byte compressed public key value pk[0]

# To compute the leaves of the binary hash tree, a so-called L-tree is
# used. An L-tree is an unbalanced binary hash tree, distinct but
# similar to the main XMSS binary hash tree. The algorithm ltree
# (Algorithm 8) takes as input a WOTS+ public key pk and compresses it
# to a single n-byte value pk[0]. It also takes as input an L-tree
# address ADRS that encodes the address of the L-tree and the seed SEED.
from basic_utilities import lengths, generate_seed
from generate_pk_kuglan import WOTS_genPK
from generate_sk import generate_secret_key
from typing import List


def ltree(pk: List[bytearray], adrs: ADRS, SEED: str, length: int) -> bytearray:
    # unsigned int len’ = len; w RFCku cos takiego z dupy wzięte w sumie więc zakładam ze chodzi o dlugosc pk
    adrs.setTreeHeight(0)

    # print(pk[0])
    while length > 1:
        for i in range(floor(length / 2)):
            adrs.setTreeIndex(i)
            pk[i] = RAND_HASH(pk[2 * i], pk[2 * i + 1], SEED, adrs)

        if length % 2 == 1:
            pk[floor(length / 2)] = pk[length - 1]

        length = ceil(length / 2)
        height = adrs.getTreeHeight()
        height = int.from_bytes(height, byteorder='big')
        adrs.setTreeHeight(height + 1)
    # print(pk[0])

    return pk[0]

#
# if __name__ == '__main__':
#     msg_len = 6
#     w = 16
#     len_1, len_2, length_all = lengths(msg_len, w)
#
#     SEED = generate_seed(msg_len)
#     adrs = ADRS()
#
#     sk = generate_secret_key(length_all, msg_len)
#     pk = WOTS_genPK(sk, length_all, w, SEED, adrs)
#
#     value = ltree(pk, adrs, SEED, length_all)
#
#
#     print("XD")