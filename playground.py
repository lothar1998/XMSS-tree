from generate_sk import generate_secret_key
from generate_pk_kuglan import generate_public_key
from basic_utilities import calculate_length

msg_len = 25
length = calculate_length(msg_len, 16)
sk = generate_secret_key(length)
pk = generate_public_key(sk, length, 4)


print('Calculated length {0}'.format(length))
print('Private (Secure) key: {0}'.format(sk))

