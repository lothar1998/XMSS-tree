from utils import *


def WOTS_genSK(length, n):
    secret_key = [bytes()] * length

    for i in range(length):
        SEED = generate_random_value(length)

        secret_key[i] = pseudorandom_function(SEED, n)

    return secret_key


def WOTS_genPK(private_key: [bytes], length: int, w: int in {4, 16}, SEED, address):
    public_key = [bytes()] * length
    for i in range(length):
        address.setChainAddress(i)
        public_key[i] = chain(private_key[i], 0, w - 1, SEED, address, w)

    return public_key


def WOTS_sign(message: bytes, private_key: [bytes], w: int in {4, 16}, SEED, address):
    checksum = 0

    n = len(message) // 2
    len_1, len_2, len_all = compute_lengths(n, w)

    msg = base_w(message, w, len_1)

    for i in range(0, len_1):
        checksum += w - 1 - msg[i]

    checksum = checksum << int(8 - ((len_2 * log2(w)) % 8))

    len_2_bytes = compute_needed_bytes(checksum)

    msg.extend(base_w(to_byte(checksum, len_2_bytes), w, len_2))

    signature = [bytes()] * len_all

    for i in range(0, len_all):
        address.setChainAddress(i)
        signature[i] = chain(private_key[i], 0, msg[i], SEED, address, w)

    return signature


def WOTS_pkFromSig(message: bytes, signature: [bytes], w: int in {4, 16}, address, SEED):
    checksum = 0

    n = len(message) // 2
    len_1, len_2, len_all = compute_lengths(n, w)

    msg = base_w(message, w, len_1)

    for i in range(0, len_1):
        checksum += w - 1 - msg[i]

    checksum = checksum << int(8 - ((len_2 * log2(w)) % 8))

    len_2_bytes = compute_needed_bytes(checksum)

    msg.extend(base_w(to_byte(checksum, len_2_bytes), w, len_2))

    tmp_pk = [bytes()] * len_all

    for i in range(0, len_all):
        address.setChainAddress(i)
        tmp_pk[i] = chain(signature[i], msg[i], w - 1 - msg[i], SEED, address, w)

    return tmp_pk
