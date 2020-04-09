import basic_utilities

msg_len = 25
length = basic_utilities.calc_len(msg_len, 16)
sk = basic_utilities.gen_sk(length)

print('Calculated length {0}'.format(length))
print('Private (Secure) key: {0}'.format(sk))
