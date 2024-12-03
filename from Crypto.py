from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

# Define AES key
AES_KEY = b"R0chLi4uLi4uLi4="

# Case ID to encrypt
case_id = "23680b9172bfe11f5166bc0739816fb4"

def encrypt(value):
    cipher = AES.new(AES_KEY, AES.MODE_ECB)
    padded_value = pad(value.encode("utf-8"), 16)
    return cipher.encrypt(padded_value)

# Encrypt the case ID
encrypted_case_id = encrypt(case_id)

# Convert to hex
encrypted_case_id_hex = encrypted_case_id.hex()
print("Encrypted Case ID (hex):", encrypted_case_id_hex)
