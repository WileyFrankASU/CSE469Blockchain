from ctypes.wintypes import BYTE
import hashlib
import os
import struct
import uuid
from datetime import datetime, timezone

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

AES_KEY = b"R0chLi4uLi4uLi4="

from blockchain import Blockchain, Block



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
    decrypted = decrypt16(bytes.fromhex(encrypted_item_id.decode('utf-8')))
    return int(decrypted.hex(), 16)  # Remove padding and decode
def encrypt(value):
    # encrypts values using AES
    cipher = AES.new(AES_KEY, AES.MODE_ECB)
    padded_value = pad(value.encode("utf-8"), 16)
    return cipher.encrypt(padded_value)

def hex_to_ascii_bytes(hex_str):
        return "".join(f"{ord(char):02x}" for char in hex_str).encode("ascii")

def calculate_hash(block):
        # it takes a block object as input and packs its fields into a binary format

        case_id = block.case_id
        if not isinstance(block.case_id, bytes):
            case_id = bytes.fromhex(block.case_id)
            
        item_id = block.item_id
        if not isinstance(block.item_id, bytes):
            item_id = bytes.fromhex(block.item_id)
        
        cid = bytes.fromhex(block.case_id).ljust(32, b"\0") if isinstance(block.case_id, str) else block.case_id.ljust(32, b"\0")


        timestamp_data = block.timestamp
        case_id_data = case_id.ljust(32, b"\0") 
        item_id_data = item_id.ljust(32, b"\0")
        block_data = struct.pack(
            "32s d 32s 32s 12s 12s 12s I",
            block.prev_hash,
            block.timestamp,
            case_id_data,
            item_id_data,
            block.state.encode("utf-8").ljust(12, b"\0")
            if isinstance(block.state, str)
            else block.state.ljust(12, b"\0"),
            block.creator.encode("utf-8").ljust(12, b"\0")
            if isinstance(block.creator, str)
            else block.creator.ljust(12, b"\0"),
            block.owner.encode("utf-8").ljust(12, b"\0")
            if isinstance(block.owner, str)
            else block.owner.ljust(12, b"\0"),  # fields are padded to fixed sizes
            len(block.data),
        )
        
        #print(
        #    f"Previous Hash: \t\t{ block.prev_hash}\n" 
        #    f"Timestamp: \t\t{timestamp_data}\n"
        #    f"Case Id: \t\t{case_id_data}\n"
        #    f"Item Id: \t\t{item_id_data}\n"
        #    
        #     )

        # returns the resulting hash as a hexadecimal string
        return hashlib.sha256(block_data).hexdigest()

def ascii_to_cid(ascii_bytes):
    # Decode ASCII bytes to a string
    # Convert the hex string to bytes
    return ascii_bytes.decode('utf-8')


def stored_item_to_hashed_item():
    pass

def stored_case_to_hased_case():
    pass 


def main():
    blockchain_path = os.getenv("BCHOC_FILE_PATH", "blockchain.bin")
    
    
    base_hash = "a70b3312e5b6748af437660a56f7d9dff34dc7c45277f5fed36e5a52479dc00f"
    match_hash = "62ca860c4c58f5a96db9c01308d73660ff7cd6db5922cc11c570e05ef1049bf9"
    max_time = 1733450453.758627
    
    for i in range(0, 20000):
        genesis_block = Block(
                    prev_hash=b'\0'*32,
                    timestamp=max_time-(i*0.000001),  # Placeholder for timestamp
                    case_id=b'0'*32,  # 32 zero bytes
                    item_id=b'0'*32,  # 32 zero bytes
                    state=b'INITIAL\x00\x00\x00\x00\x00',  # Exactly 12 bytes
                    creator=b"\0"*12,  # 12 zero bytes
                    owner=b"\0"*12,  # 12 zero bytes
                    data= b'Initial block\x00',  # Explicit data
        )
        print(f"Time: {max_time-(i*0.000001)} Hash: {calculate_hash(genesis_block)}")
        if calculate_hash(genesis_block) == match_hash:
            print(f"SUCCESS!!!! {max_time-(i*0.000001)}") 
            print(f"SUCCESS!!!! {max_time-(i*0.000001)}") 
            print(f"SUCCESS!!!! {max_time-(i*0.000001)}") 
            print(f"SUCCESS!!!! {max_time-(i*0.000001)}") 
            print(f"SUCCESS!!!! {max_time-(i*0.000001)}") 
            print(f"SUCCESS!!!! {max_time-(i*0.000001)}") 
            quit()
         



    


if __name__ == "__main__":
    main()