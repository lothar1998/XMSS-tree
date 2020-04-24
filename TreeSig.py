import copy
from math import floor
from XMSSPrivateKey import *
from ADRS import *
from treeHash import *
from WOTS_sign import *
from SigWithAuthPath import *


def buildAuth(SK: XMSSPrivateKey, index: int, ADRS: ADRS, w: int in {4, 16}, length_all: int) -> bytearray:
    """
    Function to build authentication path for corresponding signature
    :param SK: XMSS Secret Key
    :param index: WOTS+ key pair index
    :param ADRS: address structure
    :param w: the Winternitz parameter, it is a member of the set {4, 16}
    :param length_all: len parameter determined as len_1 + len_2
    :return: bytearray of hashes of sibling of nodes on the path
    """
    h = int.from_bytes(ADRS.getTreeHeight(), byteorder='big')
    auth = [bytearray] * h
    adrs = copy.deepcopy(ADRS)
    sk = copy.deepcopy(SK)
    for j in range(h):
        k = floor(index / (2 ** j)) ^ 1
        auth[j] = treeHash(sk, k * (2 ** j), j, adrs, w, length_all)
    return auth


def treeSig(message: bytes, SK: XMSSPrivateKey, ADRS: ADRS,w: int in {4, 16}, length_all: int, idx_sig: int):
    """
    Function to generate WOTS+ signature and authentication path for given message M with XMSS private key SK
    :param message: n-byte message
    :param SK: XMSS Secret Key
    :param ADRS: address structure
    :param w: the Winternitz parameter, it is a member of the set {4, 16}
    :param length_all: len parameter determined as len_1 + len_2
    :param idx_sig: signature index – default is None
    :return: Concatenation of WOTS+ signature sig_ots and authentication path auth
    """
    if idx_sig is None:
        idx_sig = SK.getIdx()
    auth = buildAuth(SK, idx_sig, ADRS, w, length_all)
    ADRS.setType(0)
    ADRS.setOTSAddress(idx_sig)
    sig_ots = WOTS_sign(message, SK.getWOTS_SK(idx_sig), w, SK.getSEED(), ADRS)
    Sig = SigWithAuthPath(sig_ots, auth)
    return Sig