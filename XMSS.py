from WOTS import *
from typing import List
from DataStructure import *


def ltree(pk: List[bytearray], address: ADRS, SEED: str, length: int) -> bytearray:

    address.setTreeHeight(0)

    while length > 1:
        for i in range(floor(length / 2)):
            address.setTreeIndex(i)
            pk[i] = RAND_HASH(pk[2 * i], pk[2 * i + 1], SEED, address)

        if length % 2 == 1:
            pk[floor(length / 2)] = pk[length - 1]

        length = ceil(length / 2)
        height = address.getTreeHeight()
        height = int.from_bytes(height, byteorder='big')
        address.setTreeHeight(height + 1)

    return pk[0]


def treeHash(SK: XMSSPrivateKey, s: int, t: int, address: ADRS, w: int in {4, 16}, length_all: int) -> bytearray:

    class StackElement:
        def __init__(self, node_value=None, height=None):
            self.node_value = node_value
            self.height = height

    Stack = []

    if s % (1 << t) != 0:
        raise ValueError("should be s % (1 << t) != 0")

    for i in range(0, int(pow(2, t))):
        SEED = SK.SEED
        address.setType(0)
        address.setOTSAddress(s + i)
        pk = WOTS_genPK(SK.wots_private_keys[s + i], length_all, w, SEED, address)
        address.setType(1)
        address.setLTreeAddress(s + i)
        node = ltree(pk, address, SEED, length_all)

        node_as_stack_element = StackElement(node, 0)

        address.setType(2)
        address.setTreeHeight(0)
        address.setTreeIndex(i + s)

        while len(Stack) != 0 and Stack[len(Stack) - 1].height == node_as_stack_element.height:
            address.setTreeIndex(int((int.from_bytes(address.getTreeHeight(), byteorder='big') - 1) / 2))

            previous_height = node_as_stack_element.height

            node = RAND_HASH(Stack.pop().node_value, node_as_stack_element.node_value, SEED, address)

            node_as_stack_element = StackElement(node, previous_height + 1)

            address.setTreeHeight(int.from_bytes(address.getTreeHeight(), byteorder='big') + 1)

        Stack.append(node_as_stack_element)

    return Stack.pop().node_value


def XMSS_keyGen(height: int, n: int, w: int in {4, 16}) -> XMSSKeypair:

    len_1, len_2, len_all = compute_lengths(n, w)

    wots_sk = []
    for i in range(0, 2 ** height):
        wots_sk.append(WOTS_genSK(len_all, n))

    SK = XMSSPrivateKey()
    PK = XMSSPublicKey()
    idx = 0

    SK.SK_PRF = generate_random_value(n)
    SEED = generate_random_value(n)
    SK.SEED = SEED
    SK.wots_private_keys = wots_sk

    adrs = ADRS()

    root = treeHash(SK, 0, height, adrs, w, len_all)

    SK.idx = idx
    SK.root_value = root

    PK.OID = generate_random_value(n)
    PK.root_value = root
    PK.SEED = SEED

    KeyPair = XMSSKeypair(SK, PK)
    return KeyPair


def buildAuth(SK: XMSSPrivateKey, index: int, address: ADRS, w: int in {4, 16}, length_all: int, h: int) -> List[bytearray]:
    auth = []

    for j in range(h):
        k = floor(index / (2 ** j)) ^ 1
        auth.append(treeHash(SK, k * (2 ** j), j, address, w, length_all))
    return auth


def treeSig(message: bytearray, SK: XMSSPrivateKey, address: ADRS, w: int in {4, 16}, length_all: int, idx_sig: int, h: int) -> SigWithAuthPath:
    auth = buildAuth(SK, idx_sig, address, w, length_all, h)
    address.setType(0)
    address.setOTSAddress(idx_sig)
    sig_ots = WOTS_sign(message, SK.wots_private_keys[idx_sig], w, SK.SEED, address)
    Sig = SigWithAuthPath(sig_ots, auth)
    return Sig


def XMSS_sign(message: bytearray, SK: XMSSPrivateKey, w: int in {4, 16}, address: ADRS, h: int) -> SigXMSS:
    n = len(message) // 2
    len_1, len_2, length_all = compute_lengths(n, w)
    idx_sig = SK.idx
    SK.idx = idx_sig + 1
    r = PRF_XMSS(SK.SK_PRF, to_byte(idx_sig, 4), len_1)
    arrayOfBytes = bytearray()
    arrayOfBytes.extend(r)
    arrayOfBytes.extend(SK.root_value)
    arrayOfBytes.extend(bytearray(int_to_bytes(idx_sig, n)))
    M2 = H_msg(arrayOfBytes, message, len_1)

    value = treeSig(M2, SK, address, w, length_all, idx_sig, h)

    return SigXMSS(idx_sig, r, value, SK, M2)


def XMSS_rootFromSig(idx_sig: int, sig_ots, auth: List[bytearray], message: bytearray, h: int, w: int in {4, 16}, SEED, address: ADRS):
    n = len(message) // 2
    len_1, len_2, length_all = compute_lengths(n, w)

    address.setType(0)
    address.setOTSAddress(idx_sig)
    pk_ots = WOTS_pkFromSig(message, sig_ots, w, address, SEED)
    address.setType(1)
    address.setLTreeAddress(idx_sig)
    node = [bytearray, bytearray]
    node[0] = ltree(pk_ots, address, SEED, length_all)
    address.setType(2)
    address.setTreeIndex(idx_sig)

    for k in range(0, h):
        address.setTreeHeight(k)
        if floor(idx_sig / (2 ** k)) % 2 == 0:
            address.setTreeIndex(int.from_bytes(address.getTreeIndex(), byteorder='big') // 2)
            node[1] = RAND_HASH(node[0], auth[k], SEED, address)
        else:
            address.setTreeIndex((int.from_bytes(address.getTreeIndex(), byteorder='big') - 1) // 2)
            node[1] = RAND_HASH(auth[k], node[0], SEED, address)

        node[0] = node[1]

    return node[0]


def XMSS_verify(Sig: SigXMSS, M: bytearray, PK: XMSSPublicKey, w: int in {4, 16}, SEED, height: int):

    address = ADRS()

    n = len(M) // 2
    len_1, len_2, length_all = compute_lengths(n, w)

    arrayOfBytes = bytearray()
    arrayOfBytes.extend(Sig.r)
    arrayOfBytes.extend(PK.root_value)
    arrayOfBytes.extend(bytearray(int_to_bytes(Sig.idx_sig, n)))

    M2 = H_msg(arrayOfBytes, M, len_1)

    node = XMSS_rootFromSig(Sig.idx_sig, Sig.sig.sig_ots, Sig.sig.auth, M2, height, w, SEED, address)

    if node == PK.root_value:
        return True
    else:
        return False

