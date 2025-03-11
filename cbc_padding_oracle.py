#!/usr/bin/python3
import binascii as ba
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

key = b"this_is_the_key!"

iv = b"a"*16 # just for testing

example_data = \
    b"These are just random bytes used to test CBC padding oracle" + \
    b"attacks on AES with 128 bit keys and CBC mode   "

def encrypt(data, key, iv):
	cipher = AES.new(key, AES.MODE_CBC, iv)
	padded = pad(data, 16)
	print("\x1b[92mPadded:\x1b[0m")
	print(ba.hexlify(padded).decode())
	return iv + cipher.encrypt(padded)

def oracle(data):
	global key
	global iv
	cipher = AES.new(key, AES.MODE_CBC, iv)
	decrypted = cipher.decrypt(data)
	#print(ba.hexlify(decrypted).decode())
	result = None
	try:
		plaintext = unpad(decrypted, 16)
		#print("\x1b[95mPlaintext:\x1b[0m")
		#print(ba.hexlify(plaintext).decode())
		result = {"success":True, "decrypted":decrypted}
	except:
		result = {"success":False, "decrypted":decrypted}
	return result

# --------------------------------------------------------------------- #

ciphertext = encrypt(example_data, key, iv)
#print("\x1b[92mCiphertext:\x1b[0m")
#print(ba.hexlify(ciphertext).decode())

blocks = [ciphertext[i:i+16] for i in range(0, len(ciphertext), 16)]
#print("\x1b[93mBlocks:\x1b[0m")
#for b in range(len(blocks)):
#	print(str(b) + "\t" + ba.hexlify(blocks[b]).decode())
# --------------------------------------------------------------------- #

dec = b""
while (len(blocks) > 1):
	padding_found = b""

	print("="*30 + " \x1b[1;33m New Block \x1b[0m" + "="*30)

	for padding_value in range(1, 17):
		found = None

        # Setup the part of the padding already known 
		if (len(padding_found) > 0):
			attack = b""
			oldpad = padding_value-1
			newpad = padding_value
			padding_found = b"".join([(x ^ oldpad ^ newpad).to_bytes(1, "little") for x in padding_found])

		# Guessing step ...
		for guess in range(256):
			byte_guess = guess.to_bytes(1, "little")
            # Build a new block with known padding PLUS the guessed byte
			custom_block = blocks[-2][:16-padding_value] + byte_guess + padding_found
			# rebuild the full ciphertext
			modified = b"".join(blocks[:-2]) + custom_block + blocks[-1]
			# "Oracle" invokation
			oracle_result = oracle(modified)
			# test for success...
			if (oracle_result["success"]):
				print((byte_guess + padding_found).hex() + " ▶ \x1b[91m" + oracle_result["decrypted"][-padding_value:].hex() + "\x1b[0m")
                # Same byte?
				if (oracle_result["decrypted"][-padding_value] != padding_value):
					print(hex(oracle_result["decrypted"][-padding_value]))
					continue
				# The guess was good! Let's move on
				found = guess
				break
		if (found != None):
            # Retrieve the byte that generated the guess
			intermediate = found ^ padding_value
			# ...and the corresponding plaintext byte
			real = intermediate ^ blocks[-2][16-padding_value]
			# Append the plaintext byte to the rest
			dec = real.to_bytes(1, "little") + dec
			# update the padding for next iteration
			padding_found = ((padding_value) ^ intermediate).to_bytes(1, "little") + padding_found
		else:
			print("Not found")
			exit(-1)
	# Remove the processed block
	blocks.pop()
print("="*30 + " \x1b[1;32m Plaintext: \x1b[0m" + "="*30)
print(dec.decode())
print("="*30 + " \x1b[1;32m    End     \x1b[0m" + "="*30)
