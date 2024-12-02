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


def retrieve_case_id(encrypted_case_id):
    # Decrypt the case_id
    decrypted_case_id = decrypt(bytes.fromhex(encrypted_case_id))
    # Format with dashes
    formatted_case_id = (
        decrypted_case_id[:8] + "-" +
        decrypted_case_id[8:12] + "-" +
        decrypted_case_id[12:16] + "-" +
        decrypted_case_id[16:20] + "-" +
        decrypted_case_id[20:]
    )
    return formatted_case_id


def retrieve_item_id(encrypted_item_id):
    decrypted = decrypt_item(encrypted_item_id)
    return decrypted  # Remove padding and decode


def main():
    case_id=b'\x1a\x8bp\x99\xba\xbc\xa7!Y\xb7_K}\xc09#\xfc\xeb\th\x1fFG(Jy\xf4y\xee\xb5^\xa0'

    flag = 'b83d796090e96a43d171257edf788329'
    
    encrypted = 'fde5e8e46bcfa3aced4d44f6e11c47b400000000000000000000000000000000'
    decrypted = decrypt16()
    print(decrypted.hex())
    #decrypted = '96435d99-04f8-426f-a00d-b9c5e2fcce39'
    #print(decrypted)
    #uuid_value = uuid.UUID(decrypted)

    #reencrypt = encrypt16(uuid_value.bytes)
    #print(f'Encrypted: {reencrypt.hex()}')
    #print(f'Decrypted: {decrypt16(reencrypt).hex()}')
    
    


    


if __name__ == "__main__":
    main()