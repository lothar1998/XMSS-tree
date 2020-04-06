# XMSS-tree

"""
WOTS+ uses the parameters n and w; they both take positive integer
 values. These parameters are summarized as follows:
 
 n: the message length as well as the length of a private key,
 public key, or signature element in bytes.
 w: the Winternitz parameter; it is a member of the set {4, 16}.
 
 The parameters are used to compute values len, len_1, and len_2:
 len: the number of n-byte string elements in a WOTS+ private key,
 public key, and signature. It is computed as 
 
 len = len_1 + len_2,
 len_1 = ceil(8n / lg(w)) 
 len_2 = floor(lg(len_1 *(w - 1)) / lg(w)) + 1.
 
 The suggested method from [BDH11] can be described using
 PRF. 
 
 During key generation, a uniformly random n-byte string S is sampled from a secure source of randomness. 
 This string S is stored as private key. 
 The private key elements are computed as sk[i] = PRF(S, toByte(i, 32)) whenever needed. 
 
 Please note that this seed S MUST be different from the seed SEED used to randomize the hash
 function calls. Also, this seed S MUST be kept secret. The seed S
 MUST NOT be a low entropy, human-memorable value since private key
 elements are derived from S deterministically and their
 confidentiality is security-critical.
 
 """

	
