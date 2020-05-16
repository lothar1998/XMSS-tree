from XMSS import *


def WOTS_demo(message: bytearray):
    msg_len = len(message) // 2
    w = 16
    len_1, len_2, length_all = compute_lengths(msg_len, w)

    SEED = generate_random_value(msg_len)
    addressWOTS_1 = ADRS()

    sk = WOTS_genSK(length_all, msg_len)
    pk = WOTS_genPK(sk, length_all, w, SEED, addressWOTS_1)

    signature = WOTS_sign(message, sk, w, SEED, addressWOTS_1)

    addressWOTS_2 = ADRS()

    pk_from_signature = WOTS_pkFromSig(message, signature, w, addressWOTS_2, SEED)

    ifProved = True

    for a, b in zip(pk, pk_from_signature):
        if a != b:
            ifProved = False
            break

    print("WOTS verification result:")
    print("Proved: " + str(ifProved))


def XMSS_demo(messages: List[bytearray]):

    height = int(log2(len(messages)))
    msg_len = len(messages[0]) // 2
    w = 16

    keyPair = XMSS_keyGen(height, msg_len, w)

    addressXMSS = ADRS()

    signatures = []

    for message in messages:
        signature = XMSS_sign(message, keyPair.SK, w, addressXMSS, height)
        signatures.append(signature)

    ifProved = True

    for signature, message in zip(signatures, messages):
        if not XMSS_verify(signature, message, keyPair.PK, w, keyPair.PK.SEED, height):
            ifProved = False
            break

    print("XMSS verification result:")
    print("Proved: " + str(ifProved))


if __name__ == '__main__':
    WOTS_demo(bytearray(b'0e4575aa2c51'))
    print("#" * 30)
    XMSS_demo([bytearray(b'0e4575aa2c51'), bytearray(b'0e4575aa2c51'), bytearray(b'0e4575aa2c51'), bytearray(b'0e4575aa2c51')])
