from Crypto.Cipher import AES
import base64
import random
import secrets
import itertools

split_into_chunks = lambda arr, n: [arr[i:i+n] for i in range(0,len(arr),n)]
# Challenge 9: Implement PKCS#7 padding
def pad(text, block_size):
	pad_length = (block_size - len(text)) % block_size
	if pad_length == 0: pad_length += block_size # Add extra block if len(text) is multiple of block size
	return text + bytes((chr(pad_length) * pad_length).encode())
def unpad(text):
	return text[:-text[-1]]
	
assert pad("YELLOW SUBMARINE".encode(), 20) == b"YELLOW SUBMARINE\x04\x04\x04\x04"
assert pad("YELLOW SUBMARINE".encode(), 16) == b"YELLOW SUBMARINE\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10"

# Challenge 10: Implement CBC mode
# Function that encrypts a 128-bit block with AES
def aes_encrypt(block, key):
	assert len(block) == 16 # Make sure the block has length 16
	block = bytes(block)
	cipher = AES.new(key, AES.MODE_ECB)
	return cipher.encrypt(block)
# Function that decrypts a 128-bit block with AES
def aes_decrypt(block, key):
	assert len(block) == 16 # Make sure the block has length 16
	block = bytes(block)
	cipher = AES.new(key, AES.MODE_ECB)
	return cipher.decrypt(block)
	
# Sanity check
# Example from https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf page 33
assert aes_encrypt(bytes.fromhex("3243f6a8885a308d313198a2e0370734"),bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")).hex()=="3925841d02dc09fbdc118597196a0b32"
assert aes_decrypt(bytes.fromhex("3925841d02dc09fbdc118597196a0b32"),bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")).hex()=="3243f6a8885a308d313198a2e0370734"

xor = lambda s1, s2: [s1[i] ^ s2[i] for i in range(len(s1))]

def aes_cbc_encrypt(plaintext, key, iv):
	# First, split up the plaintext into blocks
	plaintext = pad(plaintext, 16) # Pad the plaintext
	plaintext_blocks = [plaintext[i:i+16] for i in range(0,len(plaintext),16)] # Split into blocks
	# Now, we generate the ciphertext as follows
	# C = ciphertext, P = plaintext, IV = initialization vector
	# C_0 = IV
	# C_i = encrypt(P_{i-1} xor C_{i-1}, key)
	ciphertext_blocks = [iv]
	for block in plaintext_blocks:
		ciphertext_blocks.append(aes_encrypt(xor(block, ciphertext_blocks[-1]), key))
	return b''.join(ciphertext_blocks[1:]) # get rid of initialization vector

	
def aes_cbc_decrypt(ciphertext, key, iv):
	# First, split up the ciphertext into blocks
	ciphertext = pad(ciphertext, 16)
	ciphertext_blocks = [ciphertext[i:i+16] for i in range(0,len(ciphertext),16)]
	ciphertext_blocks = [iv] + ciphertext_blocks
	# Generate the plaintext in a similar way to encrypt
	plaintext_blocks = []
	for i in range(len(ciphertext_blocks)-2):
		plaintext_blocks.append(xor(ciphertext_blocks[i], aes_decrypt(ciphertext_blocks[i+1], key)))
	return unpad(b''.join([bytearray(i) for i in plaintext_blocks]))

# Sanity test
data = b"ABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFGHIJKLMNOPQRSTUVWXYZ"
key = b"YELLOW SUBMARINE"
iv = ('\x00'*16).encode()
cipher = AES.new(key, AES.MODE_CBC, iv)
ciphertext_expected = cipher.encrypt(pad(data,16))
ciphertext_actual = aes_cbc_encrypt(data, key, iv)
assert ciphertext_expected == ciphertext_actual
assert aes_cbc_decrypt(ciphertext_actual, key, iv) == data

def challenge10():
	f = open("challenge10.txt", "r")
	ciphertext = base64.b64decode("".join([i.strip() for i in f.readlines()]))
	key = b"YELLOW SUBMARINE"
	iv = ("\x00"*16).encode()
	print(aes_cbc_decrypt(ciphertext, key, iv))
	
# Challenge 11: An ECB/CBC detection oracle

def aes_ecb_encrypt(plaintext, key):
	cipher = AES.new(key, AES.MODE_ECB)
	return cipher.encrypt(pad(plaintext,16))
	
def aes_ecb_decrypt(ciphertext, key):
	cipher = AES.new(key, AES.MODE_ECB)
	return unpad(cipher.decrypt(ciphertext))

get_random_bytes = lambda n: secrets.token_bytes(n)

def encryption_oracle(plaintext):
	plaintext = get_random_bytes(random.randint(5,11)) + plaintext + get_random_bytes(random.randint(5,11))
	key = get_random_bytes(16)
	iv = get_random_bytes(16)
	cipher_type = random.choice(['ecb', 'cbc'])
	if cipher_type == 'ecb': return (aes_ecb_encrypt(plaintext, key), 'ecb')
	else: return (aes_cbc_encrypt(plaintext, key, iv), 'cbc')

# Similar to Challenge 8, we detect ECB mode by the repetition of 16 byte chunks
def guess_encryption_type_(ciphertext):
	ciphertext_chunks = [ciphertext[i:i+16] for i in range(0,len(ciphertext),16)]
	if len(set(ciphertext_chunks)) != len(ciphertext_chunks): return "ecb"
	return "cbc"

# Note that if we pass in a plaintext to our oracle with all the same byte, we will be able to detect ECB using the above method much more frequently
def challenge11():
	for k in range(1,50):
		plaintext = bytes(("A"*k).encode())
		successes = 0
		for i in range(10000):
			ciphertext, cipher_type = encryption_oracle(plaintext)
			if guess_encryption_type_(ciphertext) == cipher_type: successes += 1
		print(k, successes)

# Challenge 12: Byte-at-a-time ECB decryption (Simple)
challenge12_key = get_random_bytes(16)
def challenge12_oracle(plaintext, key = challenge12_key):
	return aes_ecb_encrypt(plaintext + base64.b64decode("Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK"), key)

# Guesses block size of AES, provided parameter is oracle function
def guess_block_size(oracle):
	guesses = [bytes()]
	for i in range(2,20):
		guesses.append(oracle(("A"*i).encode())[:i])
		if guesses[-1][:i-1] == guesses[-2][:i-1]:
			return i-1

# Guesses encryption type (like in challenge 11)
def guess_encryption_type(oracle):
	block_size = guess_block_size(oracle)
	# Plaintext is just 10 blocks of size 
	plaintext = ("A" * (10*block_size)).encode()
	ciphertext = oracle(plaintext)
	ciphertext_chunks = [ciphertext[i:i+block_size] for i in range(0,len(ciphertext),16)]
	return "ecb" if len(set(ciphertext_chunks)) != len(ciphertext_chunks) else "cbc"

# Guesses the length of the unknown padded string
def guess_string_length(oracle):
	encrypted_string = oracle(bytes())
	for i in itertools.count():
		new_encrypted = oracle(b'A'*i)
		if len(new_encrypted) != len(encrypted_string):
			return len(new_encrypted) - i - 1
			
# Get the first byte of unknown string
"""
first_block = b"A"*15
cipher_first_block = challenge12_oracle(first_block)
print(split_into_chunks(cipher_first_block,16))
for i in range(256):
	if challenge12_oracle(first_block + bytes([i]))[:16] == cipher_first_block[:16]:
		print("first character found!: " + chr(i))
"""
# Getting the first block of the unknown string
"""
first_block = b"A" * 15
secret = b''
for _ in range(16):
	print(first_block, secret)
	cipher_first_block = challenge12_oracle(first_block)
	for i in range(256):
		if challenge12_oracle(first_block + secret + bytes([i]))[:16] == cipher_first_block[:16]:
			secret += bytes([i])
			first_block = first_block[:-1]
"""
def challenge12():
	# Step 1: Guess block size
	block_size = guess_block_size(challenge12_oracle)
	print(block_size)
	# Step 2: Make sure oracle is ECB (not really necessary)
	assert guess_encryption_type(challenge12_oracle) == "ecb"
	first_block = b"A" * (block_size-1)
	secret = b''
	latest_block = 1
	# Keep looping while we have bytes
	while True:
		# print(first_block, secret, secret[-1] if len(secret)>1 else None)
		cipher_first_block = challenge12_oracle(first_block)
		# Check to see which byte leads to same cipher_first_block
		for i in range(256):
			if challenge12_oracle(first_block + secret + bytes([i]))[:block_size*latest_block] == cipher_first_block[:block_size*latest_block]:
				secret += bytes([i])
				first_block = first_block[:-1]
				# If we have a block of the secret already, we need some extra logic to reset things
				if len(secret) % block_size == 0 and len(secret) > 0: 
					first_block = b"A" * (block_size-1)
					latest_block += 1 
		if secret[-1] == 1: return secret[:-1]

# Challenge 13: ECB cut-and-paste

def str_to_dict(string):
	return dict([i.split("=") for i in string.split("&")])
	
assert str_to_dict("foo=bar&baz=qux&zap=zazzle") == {'foo': 'bar', 'baz': 'qux', 'zap': 'zazzle'}

def profile_for(email):
	if "&" in email or "=" in email:
		raise ValueError("email contains invalid character!")
	return "email="+email+"&uid=10&role=user"

assert str_to_dict(profile_for("foo@bar.com")) == {'email': 'foo@bar.com', 'uid': '10', 'role': 'user'}

challenge13_key = get_random_bytes(16)
# encrypt a profile (this function is accessible to the attacker)
def encrypt_profile(email, key=challenge13_key):
	return aes_ecb_encrypt(bytes(profile_for(email).encode()), key)
# decrypt a profile and print it (behind the scenes)
def decrypt_profile(ciphertext, key=challenge13_key):
	return str_to_dict(aes_ecb_decrypt(ciphertext, key).decode())
def challenge13():
	print("challenge 13 key: ", challenge13_key)
	# Now, we need to create an admin profile using only encrypt_profile
	# Let's try to create an email such that the plaintext blocks look like 
	# 0123456789ABCDEF 0123456789ABCDEF 0123456789ABCDEF
	# email=AAAAAAAAAA AAA&uid=10&role= user
	first_two_blocks = encrypt_profile("AAAAAAAAAAAAA")[:32]
	# The last block needs to be the AES encryption of 'admin'
	# We get this as follows
	# 0123456789ABCDEF 0123456789ABCDEF 0123456789ABCDEF
	# email=AAAAAAAAAA --pad('admin')-- &uid=10&role=user
	# The second block of this is the encryption of 'admin'
	encrypted_admin = encrypt_profile("AAAAAAAAAA" + pad(b'admin',16).decode())[16:32]
	# Put it all together and we'll get our encrypted account string
	encrypted_admin_account = first_two_blocks + encrypted_admin
	print("encrypted admin account: ", encrypted_admin_account)
	print(decrypt_profile(encrypted_admin_account))
	
# Challenge 14: Byte-at-a-time ECB decryption (Harder)
challenge14_key = b"YELLOW SUBMARINE"
random_prefix = b"random prefix"
unknown_string = b'This is a secret string, very secret string.'
def challenge14_oracle(plaintext, key = challenge14_key, prefix = random_prefix):
	return aes_ecb_encrypt(prefix + plaintext + unknown_string, key)
# To decrypt this is similar, except for the prefix - to deal with this, we pad thhe plaintext with the same byte until we get something like this
# 0123456789ABCDEF 0123456789ABCDEF 0123456789ABCDEF
# -prefix--padding plaintext/unknown string---------
padding = b'A' * (16 - len(random_prefix)) # NOTE: We need to know the length of the prefix for this to work
"""
first_block = b"A" * 15
secret = b''
for _ in range(16):
	print(first_block, secret)
	cipher_first_block = challenge12_oracle(first_block)
	for i in range(256):
		if challenge12_oracle(first_block + secret + bytes([i]))[:16] == cipher_first_block[:16]:
			secret += bytes([i])
			first_block = first_block[:-1]
"""
def challenge14():
	# Code is very similar to Challenge 12
	block_size = 16
	first_block = b"A" * (block_size-1)
	secret = b''
	end_pos = 32
	for _ in range(100):
		# print(first_block, secret)
		cipher_first_block = challenge14_oracle(padding + first_block)
		for i in range(256):
			if challenge14_oracle(padding + first_block + secret + bytes([i]))[16:end_pos] == cipher_first_block[16:end_pos]:
				secret += bytes([i])
				first_block = first_block[:-1]
				if len(secret) % block_size == 0 and len(secret) > 0: 
					first_block = b"A" * (block_size-1)
					end_pos += block_size
		if secret[-1] == 1: return secret[:-1]
		
# Challenge 15: PKCS#7 padding validation
def valid_pad(plaintext):
	pad_length = plaintext[-1]
	unpadded_text, padding = plaintext[:-pad_length], plaintext[-pad_length:]
	if len(set(padding)) == 1: return unpadded_text
	return None # return None instead of throwing exception
	
assert valid_pad(b"ICE ICE BABY\x04\x04\x04\x04") == b"ICE ICE BABY"
assert valid_pad(b"ICE ICE BABY\x05\x05\x05\x05") == None
assert valid_pad(b"ICE ICE BABY\x01\x02\x03\x04") == None

# Challenge 16: CBC bitflipping attacks





