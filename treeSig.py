import copy
from math import floor
from XMSSPrivateKey import *
from ADRS import *
from XMSS_keyGen import XMSS_keyGen
from treeHash import *
from WOTS_sign import *
from SigWithAuthPath import *


def buildAuth(SK: XMSSPrivateKey, index: int, adrs: ADRS, w: int in {4, 16}, length_all: int, h: int) -> List[bytearray]:
    """
    Function to build authentication path for corresponding signature
    :param SK: XMSS Secret Key
    :param index: WOTS+ key pair index
    :param ADRS: address structure
    :param w: the Winternitz parameter, it is a member of the set {4, 16}
    :param length_all: len parameter determined as len_1 + len_2
    :return: bytearray of hashes of sibling of nodes on the path
    """
    auth = []
    # adrs = copy.deepcopy(ADRS)
    # sk = copy.deepcopy(SK)
    for j in range(h):
        k = floor(index / (2 ** j)) ^ 1
        auth.append(treeHash(SK, k * (2 ** j), j, adrs, w, length_all))
    return auth


def treeSig(message: bytearray, SK: XMSSPrivateKey, adrs: ADRS, w: int in {4, 16}, length_all: int, idx_sig: int, h: int) -> SigWithAuthPath:
    """
    Function to generate WOTS+ signature and authentication path for given message M with XMSS private key SK
    :param message: n-byte message
    :param SK: XMSS Secret Key
    :param adrs: address structure
    :param w: the Winternitz parameter, it is a member of the set {4, 16}
    :param length_all: len parameter determined as len_1 + len_2
    :param idx_sig: signature index – default is None
    :param h: height of tree
    :return: Concatenation of WOTS+ signature sig_ots and authentication path auth
    """
    auth = buildAuth(SK, idx_sig, adrs, w, length_all, h)
    adrs.setType(0)
    adrs.setOTSAddress(idx_sig)
    sig_ots = WOTS_sign(message, SK.getWOTS_SK(idx_sig), w, SK.getSEED(), adrs)
    Sig = SigWithAuthPath(sig_ots, auth)
    return Sig


if __name__ == '__main__':
    KeyPair = XMSS_keyGen(2, 6, 16)
    len_1, len_2, len_all = lengths(6, 16)
    value = treeSig(bytearray(b'0e4575aa2c51'), KeyPair.getSK(), ADRS(), 16, len_all, 0, 2)
    print(value)