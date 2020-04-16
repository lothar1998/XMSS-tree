import math
from rand_hash_miccu64 import RAND_HASH


# PART 2 - 4.1.5. L-Trees
# Input: WOTS+ public key pk, address ADRS, seed SEED
# Output: n-byte compressed public key value pk[0]

# To compute the leaves of the binary hash tree, a so-called L-tree is
# used. An L-tree is an unbalanced binary hash tree, distinct but
# similar to the main XMSS binary hash tree. The algorithm ltree
# (Algorithm 8) takes as input a WOTS+ public key pk and compresses it
# to a single n-byte value pk[0]. It also takes as input an L-tree
# address ADRS that encodes the address of the L-tree and the seed SEED.

def compute_tree_leaves(pk, ADRS, SEED):
    # unsigned int len’ = len; w RFCku cos takiego z dupy wzięte w sumie więc zakładam ze chodzi o dlugosc pk
    length = len(pk)
    ADRS.setTreeHeight(0)

    # print(pk[0])
    while length > 1:
        for i in range(math.floor(length / 2)):
            ADRS.setTreeIndex(i)
            # print(RAND_HASH(pk[2 * i], pk[2 * i + 1], SEED, ADRS))
            pk[i] = RAND_HASH(pk[2 * i], pk[2 * i + 1], SEED, ADRS)

        if length % 2 == 1:
            pk[math.floor(length / 2)] = pk[length - 1]

        length = math.ceil(length / 2)
        height = ADRS.getTreeHeight()
        height = int.from_bytes(height, byteorder='big')
        ADRS.setTreeHeight(height + 1)
    # print(pk[0])

    return pk[0]
