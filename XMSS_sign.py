import hashlib

from XMSS_keyGen import *
from ADRS import *
from RAND_HASH import *
from treeSig import *
from SigXMSS import *


def XMSS_sign(message: bytearray, SK: XMSSPrivateKey, w: int in {4, 16}, adrs: ADRS, h: int) -> SigXMSS:
    n = len(message) // 2
    len_1, len_2, length_all = lengths(n, w)
    idx_sig = SK.getIdx()
    SK.setIdx(idx_sig + 1)
    r = PRF_XMSS(SK.getSK_PRF(), toByte(idx_sig, 4), len_1)
    arrayOfBytes = bytearray()
    arrayOfBytes.extend(r)
    arrayOfBytes.extend(SK.getRoot())
    arrayOfBytes.extend(bytearray(long_to_bytes(idx_sig, n)))
    M2 = H_msg(arrayOfBytes, message, len_1)

    value = treeSig(M2, SK, adrs, w, length_all, idx_sig, h)

    return SigXMSS(idx_sig, r, value, SK, M2)


def PRF_XMSS(KEY: str, M: bytearray, n: int) -> bytearray:
    # PRF: SHA2-256(toByte(3, 32) || KEY || M)
    toBytes = toByte(3, 4)
    KEY2 = bytearray()
    KEY2.extend(map(ord, KEY))
    help = hashlib.sha256(toBytes + KEY2 + M).hexdigest()[:n]
    out = bytearray()
    out.extend(map(ord, help))
    return out


def H_msg(KEY: bytearray, M: bytearray, n: int) -> bytearray:
    # H: SHA2-256(toByte(2, 32) || KEY || M)
    toBytes = toByte(2, 4)
    help_ = hashlib.sha256(toBytes + KEY + M).hexdigest()[:n]
    out = bytearray()
    out.extend(map(ord, help_))
    return out


if __name__ == '__main__':
    KeyPair = XMSS_keyGen(2, 6, 16)
    len_1, len_2, len_all = lengths(6, 16)
    value = XMSS_sign(bytearray(b'0e4575aa2c51'), KeyPair.getSK(), 16, ADRS(), 2)
    print(value)