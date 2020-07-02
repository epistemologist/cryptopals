# Challenge 1: hex to base64

import base64
from binascii import hexlify
from string import printable, ascii_letters, ascii_lowercase
from math import sqrt

string_to_bytes = lambda s: bytes(s.encode('utf8'))

words = [i.strip() for i in open("/usr/share/dict/words",'r').readlines()]

def hex_to_base64(s):
	# Input: hex string
	# Output: base 64 string
	return base64.b64encode(bytes.fromhex(s)).decode('utf8')

assert hex_to_base64("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d") == "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"

# Challenge 2: Fixed XOR
def xor(arr1, arr2):
	# Returns element-wise xor of arr1 and arr2
	# Assumes len(arr1) == len(arr2)
	assert len(arr1) == len(arr2)
	return bytearray([arr1[i] ^ arr2[i] for i in range(len(arr1))])
	
assert xor(bytes.fromhex("1c0111001f010100061a024b53535009181c"), bytes.fromhex("686974207468652062756c6c277320657965")) == bytearray(bytes.fromhex("746865206b696420646f6e277420706c6179"))

# Challenge 3: Single-byte XOR cipher
def prob_english(s, method = "chi_squared"):
	s = [chr(i) for i in s]
	if method != "freq":
		if any([char not in printable for char in s]): return -1e100 # If any character in the string is not printable, return 0
		# Check for english words
		potential_words = [i.lower() for i in "".join(s).split()]
		if len(set(potential_words).intersection(set(words))) > 2: # If we find more than 2 English words in the given string
			return 1e100
	letters = [i.lower() for i in s if i in ascii_letters] # Get all letters from string
	letter_freqs = [8.55, 1.60, 3.16, 3.87, 12.10, 2.18, 2.09, 4.96, 7.33, 0.22, 0.81, 4.21, 2.53, 7.17, 7.47, 2.07, 0.10, 6.33, 6.73, 8.94, 2.68, 1.06, 1.83, 0.19, 1.72, 0.11] # from http://practicalcryptography.com/cryptanalysis/letter-frequencies-various-languages/english-letter-frequencies/
	letter_counts = [letters.count(i) for i in ascii_lowercase]
	# Cosine similarity
	if method == "cosine":
		norm = lambda v: sqrt(sum([i*i for i in v])) # Function to return norm of vector
		dot = lambda u,v: sum([u[i]*v[i] for i in range(len(u))]) # Function to return the dot product of two vectors
		cosine = lambda u,v: dot(u,v) / (norm(u) * norm(v))
		return cosine(letter_counts, letter_freqs)
	
	# Chi squared similarity
	if method == "chi_squared":
		expected_frequencies = [i/100 * len(letters) for i in letter_freqs]
		chi_squared = lambda C, E: sum([(C[i]-E[i])**2 / E[i] for i in range(26)])
		return -chi_squared(letter_counts, expected_frequencies)
	if method == "freq":
		character_frequencies = {
		    'a': .08167, 'b': .01492, 'c': .02782, 'd': .04253,
		    'e': .12702, 'f': .02228, 'g': .02015, 'h': .06094,
		    'i': .06094, 'j': .00153, 'k': .00772, 'l': .04025,
		    'm': .02406, 'n': .06749, 'o': .07507, 'p': .01929,
		    'q': .00095, 'r': .05987, 's': .06327, 't': .09056,
		    'u': .02758, 'v': .00978, 'w': .02360, 'x': .00150,
		    'y': .01974, 'z': .00074, ' ': .13000
		}
		return sum([character_frequencies.get(i, 0) for i in s])
def xor_cipher(message, key):
	return bytes([message[i] ^ key[i%len(key)] for i in range(len(message))])
	
def challenge3():
	ciphertext = bytearray(bytes.fromhex("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"))
	print(ciphertext)
	return sorted([(chr(i),xor_cipher(ciphertext, bytearray([i]))) for i in range(256)], key = lambda b: prob_english(b[1])) # ('X', b"Cooking MC's like a pound of bacon")
	
# Challenge 4: Detect single-character XOR
def challenge4():
	f = open("challenge4.txt", "r")
	byte_strings = [bytes.fromhex(i.strip()) for i in f.readlines()]
	# potential_plaintexts = [[b] + list(sorted([(chr(i),xor_cipher(b, bytearray([i]))) for i in range(256)], key = lambda b: prob_english(b[1]))[-1]) for b in byte_strings] # List of potential plaintexts: [ciphertext, key, plaintext]
	potential_plaintexts = [[b, chr(i), xor_cipher(b, bytearray([i]))] for b in byte_strings for i in range(256)]
	print("top 10 most likely plaintexts found with cosine similarity: ", sorted(potential_plaintexts, key = lambda x: prob_english(x[2], method="cosine"))[-10:])
	print("top 10 most likely plaintexts found with chi-squared similarity: ", sorted(potential_plaintexts, key = lambda x: prob_english(x[2], method="chi_squared"))[-10:]) # [b'{ZB\x15A]TA\x15A]P\x15ETGAL\x15\\F\x15_@XE\\[R?', '5', b'Now that the party is jumping\n']

# Challenge 5: Implement repeating-key XOR	
assert xor_cipher(string_to_bytes("Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"), string_to_bytes("ICE")).hex() == "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"

# Challenge 6: Break repeating-key XOR
def hamming_distance(s1, s2):
	string_to_bits = lambda s: bin(int(hexlify(s),16))
	return sum([i[0]!=i[1] for i in zip(string_to_bits(s1), string_to_bits(s2))])

assert hamming_distance(string_to_bytes("this is a test"), string_to_bytes("wokka wokka!!!")) == 37

def challenge6():
	# Read the file 
	f = open("challenge6.txt")
	ciphertext = bytearray(base64.b64decode("".join([i.strip() for i in f.readlines()])))
	# Guess keysize
	avg = lambda arr: sum(arr)/len(arr)
	hamming_distances = dict()
	for k in range(2,40):
		cipher_chunks = [ciphertext[i:i+k] for i in range(0,len(ciphertext),k)][:4]
		hamming_distances[k] = avg([hamming_distance(cipher_chunks[i], cipher_chunks[i+1]) for i in range(len(cipher_chunks)-1)]) / k
	key_sizes = sorted(hamming_distances, key = lambda x: hamming_distances[x])
	print(key_sizes)
	for k in key_sizes[:5]: # Try the top 5 candidates
		# Split cipher text 
		cipher_chunks = [ciphertext[i:i+k] for i in range(0,len(ciphertext),k)]
		cipher_chunks = [i for i in cipher_chunks if len(i)==k]
		potential_key = bytearray()
		# Transpose the chunks and solve each block as a single char XOR
		for block in zip(*cipher_chunks):
			potential_key.append(max([(i,xor_cipher(block, bytearray([i]))) for i in range(0x20, 0x80)], key = lambda x: prob_english(x[1], method = "cosine"))[0])
		print(k, potential_key, xor_cipher(ciphertext, potential_key))
		print()

# Key is 'Terminator X: Bring the noise'

# Challenge 7: AES in ECB mode

from Crypto.Cipher import AES

def challenge7():
	f = open("challenge7.txt",'r')
	ciphertext = base64.b64decode("".join([i.strip() for i in f.readlines()]))
	cipher = AES.new("YELLOW SUBMARINE", AES.MODE_ECB)
	print(cipher.decrypt(ciphertext))
	
# Challenge 8: Detect AES in ECB mode
def challenge8():
	f = open("challenge8.txt")
	cipher_texts = [bytes.fromhex(i.strip()) for i in f.readlines()]
	# If ECB was used, then we can expect to find duplicated blocks of 16 bytes in the ciphertext
	ecb_used = [c for c in cipher_texts if len(set([c[j:j+16] for j in range(0,160,16)]))!=10]
	return ecb_used
