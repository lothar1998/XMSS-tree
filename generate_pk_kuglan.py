from chain_miccu64 import chain


def generate_public_key(private_key: [bytes], length: int, w: int in {4, 16}, SEED, ADRS):
    public_key = [bytes()] * length  # declaring array of n-bytes strings

    for i in range(length):  # generating public key based on chain function with given private key
        ADRS.setChainAddress(i)
        public_key[i] = chain(private_key[i], 0, w - 1, SEED, ADRS)

    return public_key
