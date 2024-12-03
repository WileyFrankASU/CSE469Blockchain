from ctypes.wintypes import BYTE
import hashlib
import os
import struct
import uuid
from datetime import datetime, timezone

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

AES_KEY = b"R0chLi4uLi4uLi4="



def encrypt16(value):
    # Encrypts values using AES and ensures input produces exactly 16 bytes of output
    cipher = AES.new(AES_KEY, AES.MODE_ECB)
    
    input_length = 16  # Desired length of the input
    padded_value = value.ljust(input_length, b'\0')  # Pad input to 16 bytes
    encrypted_value = cipher.encrypt(padded_value)
    
    return encrypted_value


def decrypt16(encrypted_value):
    """
    Decrypts the encrypted value using AES and returns the raw bytes after unpadding.

    Args:
        encrypted_value (bytes): Encrypted input to be decrypted.

    Returns:
        bytes: Decrypted and unpadded raw bytes.
    """
    cipher = AES.new(AES_KEY, AES.MODE_ECB)
    decrypted_padded = cipher.decrypt(encrypted_value)
    return decrypted_padded  # Remove padding and return raw bytes

def decrypt_item(encrypted_hex):
    encrypted_bytes = bytes.fromhex(encrypted_hex[:32])  # Remove padding
    cipher = AES.new(AES_KEY, AES.MODE_ECB)
    decrypted_bytes = cipher.decrypt(encrypted_bytes)
    unpadded_bytes = unpad(decrypted_bytes, 16)
    return unpadded_bytes.decode("utf-8")
def retrieve_item_id(encrypted_item_id):
    decrypted = decrypt16(encrypted_item_id)
    return int(decrypted.hex(), 16)  # Remove padding and decode
def encrypt(value):
    # encrypts values using AES
    cipher = AES.new(AES_KEY, AES.MODE_ECB)
    padded_value = pad(value.encode("utf-8"), 16)
    return cipher.encrypt(padded_value)

def hex_to_ascii_bytes(hex_str):
        return "".join(f"{ord(char):02x}" for char in hex_str).encode("ascii")

def main():
    number = 587541243 
    encrypted16 = encrypt16(number.to_bytes(16, byteorder="big")).hex()
    print(encrypted16)
    decrypted16 = retrieve_item_id(encrypted16)
    print(decrypted16)






    #decrypted = '96435d99-04f8-426f-a00d-b9c5e2fcce39'
    #print(decrypted)
    #uuid_value = uuid.UUID(decrypted)

    #reencrypt = encrypt16(uuid_value.bytes)
    #print(f'Encrypted: {reencrypt.hex()}')
    #print(f'Decrypted: {decrypt16(reencrypt).hex()}')
    
    


    


if __name__ == "__main__":
    main()