from math import log2


def base_w(byte_string: bytes, w: int in {4, 16}, out_len):
    in_ = 0
    total_ = 0
    bits_ = 0
    basew_ = []

    for i in range(0, out_len):
        if bits_ == 0:
            total_ = byte_string[in_]
            in_ += 1
            bits_ += 8

        bits_ -= log2(w)
        basew_.append((total_ >> int(bits_)) & (w - 1))
    return basew_
