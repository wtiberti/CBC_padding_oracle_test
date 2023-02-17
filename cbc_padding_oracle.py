#!/usr/bin/python3
import binascii as ba
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

key = b"chiave_d_esempio"
iv = b"a"*16
example_data = \
	b"Questa e' una prova di cifratura e decifratura con AES per " + \
	b"verificare che il padding oracle attack funzioni"

def cifra(data, key, iv):
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
	#print("\x1b[96mIntermezzo:\x1b[0m")
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

ciphertext = cifra(example_data, key, iv)
#print("\x1b[92mCiphertext:\x1b[0m")
#print(ba.hexlify(ciphertext).decode())

blocchi = [ciphertext[i:i+16] for i in range(0, len(ciphertext), 16)]
#print("\x1b[93mBlocchi:\x1b[0m")
#for b in range(len(blocchi)):
#	print(str(b) + "\t" + ba.hexlify(blocchi[b]).decode())
# --------------------------------------------------------------------- #

dec = b""
while (len(blocchi) > 1):
	padding_found = b""

	print("="*30 + " \x1b[1;33m Nuovo Blocco \x1b[0m" + "="*30)

	for padding_value in range(1, 17):
		found = None

		# preparo la parte di padding che conosco già
		if (len(padding_found) > 0):
			attack = b""
			oldpad = padding_value-1
			newpad = padding_value
			padding_found = b"".join([(x ^ oldpad ^ newpad).to_bytes(1, "little") for x in padding_found])

		# inizio guessing
		for guess in range(256):
			byte_guess = guess.to_bytes(1, "little")
			# costruisco un nuovo blocco che contenga i bytes trovati e il guess
			custom_block = blocchi[-2][:16-padding_value] + byte_guess + padding_found
			# ricostruisco il ciphertext
			modified = b"".join(blocchi[:-2]) + custom_block + blocchi[-1]
			# invoco l'oracolo
			oracle_result = oracle(modified)
			# Se ho successo...
			if (oracle_result["success"]):
				print((byte_guess + padding_found).hex() + " ▶ \x1b[91m" + oracle_result["decrypted"][-padding_value:].hex() + "\x1b[0m")
				# se ho pescato il byte che c'era già continuo la ricerca
				if (oracle_result["decrypted"][-padding_value] != padding_value):
					print(hex(oracle_result["decrypted"][-padding_value]))
					continue
				# il guess è buono: smetto di cercare
				found = guess
				break
		if (found != None):
			# calcolo il valore intermedio (risultato secco della decifratura)
			intermediate = found ^ padding_value
			# calcolo il "vero" byte del plaintext
			real = intermediate ^ blocchi[-2][16-padding_value]
			# push il byte del plaintext a quelli già trovati
			dec = real.to_bytes(1, "little") + dec
			# preparo il valore del padding per il prossimo giro
			padding_found = ((padding_value) ^ intermediate).to_bytes(1, "little") + padding_found
		else:
			print("Not found")
			exit(-1)
	# rimuovi blocco processato
	blocchi.pop()
print("="*30 + " \x1b[1;32m Plaintext: \x1b[0m" + "="*30)
print(dec.decode())
print("="*30 + " \x1b[1;32m    Fine    \x1b[0m" + "="*30)
