import hashlib
import struct
import uuid
from datetime import datetime, timezone
from Crypto.Cipher import AES
import time
import os

AES_KEY = b"R0chLi4uLi4uLi4="

"""
Block Class:
Holds data for each block
Capable of hasing values via AES for the case and item ids
as well as the entire block using SHA256
Authors: Wiley Frank
"""

# Timestamp helper
def get_timestamp():
    # Generate UTC timestamp
    return datetime.now(timezone.utc).timestamp()


class Blockchain:
    def __init__(self, path):
        self.path = path  # Path to the blockchain file
        self.chain = []   # List to store blocks

        if os.path.exists(self.path):
            self.load_chain()  # Parse and load existing blockchain
        else:
            self.chain = []
            
    def load_chain(self):
            with open(self.path, "rb") as f:
                while True: #Read in data until eof
                    try:
                        block_data = f.read(112)  #the size of a block is 32 + 8 + 32 + 12 + 12 + 12 + 4 = 112
                        if not block_data:
                            break

                        # Unpack the block using struct
                        unpacked = struct.unpack("32s d 32s 32s 12s 12s 12s I", block_data)
                    
                        data_length = unpacked[-1]
                        additional_data = f.read(data_length) #reading in data for the length from the end of data length, as packed

                        # Reconstruct the block as a dictionary or object
                        block = {
                            "prev_hash": unpacked[0].decode().strip('\0'),
                            "timestamp": unpacked[1],
                            "case_id": unpacked[2],
                            "item_id": unpacked[3],
                            "state": unpacked[4].decode().strip('\0'),
                            "creator": unpacked[5].decode().strip('\0'),
                            "owner": unpacked[6].decode().strip('\0'),
                            "data_length": data_length,
                            "data": additional_data.decode()
                        }

                        # Append the reconstructed block to the chain
                        self.chain.append(block)

                    except struct.error:
                        print("Error parsing blockchain file. The file might be corrupted.")
                        break

    def add(self, case_id, item_ids, creator, password):
        """
        Add new evidence items to a case in the blockchain.
        """
        
        #check for invalid password
        if password != os.getenv("BCHOC_PASSWORD_CREATOR"):
            raise ValueError("Invalid creator password in add")
    
        for item_id in item_ids:
            # check for duplicate item ID
            if any(block["item_id"] == item_id for block in self.chain):
                raise ValueError(f"Item ID {item_id} already exists in the blockchain.")
        
            # create the new block or genesis block
            prev_hash = self.chain[-1].hash.encode() if self.chain else b"\x00" * 32
            block = self.create_block(
                prev_hash=prev_hash,
                case_id=case_id,
                item_id=item_id,
                state="CHECKEDIN",
                creator=creator,
                owner="",
                data=""
            )
            self.chain.append(block)  # Add to in-memory chain
            self.write_block(block)  # Persist to file
        print("Added items:", ", ".join(item_ids))
        
    def checkout(self, item_id, password):
        """
        Check out an evidence item.
        """
        if password not in self.get_owner_passwords():
            raise ValueError("Invalid password in checkout.")
    
        # Find the item in the blockchain
        block = next((b for b in reversed(self.chain) if b["item_id"] == item_id), None)
        if not block:
            raise ValueError(f"Item ID {item_id} not found.")
        if block["state"] != "CHECKEDIN":
            raise ValueError(f"Item ID {item_id} cannot be checked out as it is not CHECKEDIN.")
    
        # Add a new block for the checkout action
        new_block = self.create_block(
            prev_hash=self.chain[-1]["hash"],
            case_id=block["case_id"],
            item_id=item_id,
            state="CHECKEDOUT",
            creator="",
            owner="",
            data=""
        )
        self.chain.append(new_block)
        self.write_block(new_block)
        print(f"Item {item_id} checked out successfully.")
    
    def checkin(self, item_id, password):
        """
        Check in an evidence item.
        """
        if password not in self.get_owner_passwords():
            raise ValueError("Invalid password for checkin.")
    
        block = next((b for b in reversed(self.chain) if b["item_id"] == item_id), None)
        if not block:
            raise ValueError(f"Item ID {item_id} not found.")
        if block["state"] != "CHECKEDOUT":
            raise ValueError(f"Item ID {item_id} cannot be checked in as it is not CHECKEDOUT.")
    
        new_block = self.create_block(
            prev_hash=self.chain[-1]["hash"],
            case_id=block["case_id"],
            item_id=item_id,
            state="CHECKEDIN",
            creator="",
            owner="",
            data=""
        )
        self.chain.append(new_block)
        self.write_block(new_block)
        print(f"Item {item_id} checked in successfully.")

class Block:
    def __init__(self, prev_hash=b"\x00"*32, timestamp=None, case_id=None, evidence_id=None,
                 state=b"INITIAL\0\0\0\0\0", creator=b"\0"*12, owner=b"\0"*12, data=b"Initial block\0"):
        self.prev_hash = prev_hash
        self.timestamp = get_timestamp() if timestamp is None else timestamp
        self.case_id = case_id if case_id else uuid.uuid4().bytes  # 16-byte UUID (unpacked into 32 bytes)
        self.evidence_id = evidence_id if evidence_id else struct.pack('I', 0)  # 4-byte integer for ID
        self.case_id = self.encrypt(self.case_id)
        self.evidence_id = self.encrypt(str(evidence_id).zfill(4))
        self.state = state
        self.creator = creator
        self.owner = owner
        self.data = data.encode()
        self.data_length = len(self.data)
        self.hash = self.calculate_hash()
        
    def encrypt(self, value):
        cipher = AES.new(AES_KEY, AES.MODE_ECB)
        padded = value.ljust(16, '\0') 
        return cipher.encrypt(padded.encode())
    
    def pack(self):
        # Pack all fields using struct
        return struct.pack(
            "32s d 32s 32s 12s 12s I",
            self.prev_hash,
            self.timestamp,
            self.case_id,
            self.evidence_id,
            self.state.ljust(12, '\0').encode(),
            self.creator.ljust(12, '\0').encode(),
            self.owner.ljust(12, '\0').encode(),
            self.data_length
        ) + self.data
    
    # Timestamp helper
    def get_timestamp():
        # Generate UTC timestamp
        return datetime.now(timezone.utc).timestamp()
      
    #Returns the hash in a readable format for the block
    #I think the raw bytes may be necessary for hashing, but it can always be converted back
    #For output purposes, this should be sufficient 
    def calculate_hash(self):
        block_data = self.pack()
        return hashlib.sha256(block_data).hexdigest()
