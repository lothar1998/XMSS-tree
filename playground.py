import basic_utilities

msg_len = 25
length = basic_utilities.calculate_length(msg_len, 16)
sk = basic_utilities.generate_secret_key(length)

print('Calculated length {0}'.format(length))
print('Private (Secure) key: {0}'.format(sk))
