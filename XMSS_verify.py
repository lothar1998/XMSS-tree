from ADRS import *
from XMSS_sign import *
from XMSS_rootFromSig import *


def XMSS_verify(Sig: SigXMSS, M: bytearray, PK: XMSSPublicKey, w: int in {4, 16}, SEED):

    adrs = ADRS()

    n = len(M) // 2
    len_1, len_2, length_all = lengths(n, w)

    arrayOfBytes = bytearray()
    arrayOfBytes.extend(Sig.r)
    arrayOfBytes.extend(PK.getRoot())
    arrayOfBytes.extend(bytearray(long_to_bytes(Sig.idx_sig, n)))

    M2 = H_msg(arrayOfBytes, M, len_1)

    node = XMSS_rootFromSig(Sig.idx_sig, Sig.sig.getSig_ots(), Sig.sig.getAuth(), M2, int.from_bytes(adrs.getTreeHeight(), byteorder='big'), w, SEED, adrs)

    if node == PK.getRoot():
        return True
    else:
        return False


if __name__ == '__main__':
    message = bytearray(b'0e4575aa2c51')
    KeyPair = XMSS_keyGen(2, 6, 16)
    len_1, len_2, len_all = lengths(6, 16)

    adrs = ADRS()

    signature1 = XMSS_sign(message, KeyPair.getSK(), 16, adrs, 2)
    signature2 = XMSS_sign(message, KeyPair.getSK(), 16, adrs, 2)
    signature3 = XMSS_sign(message, KeyPair.getSK(), 16, adrs, 2)
    signature4 = XMSS_sign(message, KeyPair.getSK(), 16, adrs, 2)

    output1 = XMSS_verify(signature1, message, KeyPair.getPK(), 16, KeyPair.getPK().getSEED())
    output2 = XMSS_verify(signature2, message, KeyPair.getPK(), 16, KeyPair.getPK().getSEED())
    output3 = XMSS_verify(signature3, message, KeyPair.getPK(), 16, KeyPair.getPK().getSEED())
    output4 = XMSS_verify(signature4, message, KeyPair.getPK(), 16, KeyPair.getPK().getSEED())
    print(output1, output2, output3, output4)
