from basic_utilities import *
from generate_sk import *
from XMSSPrivateKey import *
from XMSSPublicKey import *
from XMSSKeyPair import *
from ADRS import ADRS
from treeHash import *


def set_random_values(n):
    seed = generate_seed(n)
    return seed


def XMSS_keyGen(height: int, n: int, w: int in {4, 16}) -> XMSSKeypair:
    """
    Structure of SK and PK
    SK = idx || wots_sk || SK_PRF || root || SEED;
    PK = OID || root || SEED;
    OID = object identifier
    :return: KeyPair
    """
    len_1, len_2, len_all = lengths(n, w)

    wots_sk = []
    for i in range(0, 2 ** height):
        wots_sk.append(generate_secret_key(len_all, n))

    SK = XMSSPrivateKey()
    PK = XMSSPublicKey()
    idx = 0

    SK.setSK_PRF(set_random_values(n))
    SEED = set_random_values(n)
    SK.setSEED(SEED)
    SK.setWOTS_SK(wots_sk)

    adrs = ADRS()

    root = treeHash(SK, 0, height, adrs, w, len_all)

    SK.setIdx(idx)
    SK.setRoot(root)

    PK.setOID(set_random_values(n))
    PK.setRoot(root)
    PK.setSEED(SEED)

    KeyPair = XMSSKeypair(SK, PK)
    return KeyPair


if __name__ == '__main__':
    value = XMSS_keyGen(2, 6, 16)
    print(value)
