import hashlib
import os
import struct
import time
import uuid
from datetime import datetime, timezone

from Crypto.Cipher import AES

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
        self.chain = []  # List to store blocks

        if os.path.exists(self.path):
            self.load_chain()  # Parse and load existing blockchain
        else:
            self.chain = []

    def load_chain(self):
        with open(self.path, "rb") as f:
            while True:  # Read in data until eof
                try:
                    block_data = f.read(
                        112
                    )  # the size of a block is 32 + 8 + 32 + 12 + 12 + 12 + 4 = 112
                    if not block_data:
                        break

                    # Unpack the block using struct
                    unpacked = struct.unpack("32s d 32s 32s 12s 12s 12s I", block_data)

                    data_length = unpacked[-1]
                    additional_data = f.read(
                        data_length
                    )  # reading in data for the length from the end of data length, as packed

                    # Reconstruct the block as a dictionary or object
                    block = {
                        "prev_hash": unpacked[0].decode().strip("\0"),
                        "timestamp": unpacked[1],
                        "case_id": unpacked[2].decode().strip("\0"),
                        "item_id": unpacked[3].decode().strip("\0"),  # make sure itemid is a string
                        "state": unpacked[4].decode().strip("\0"),
                        "creator": unpacked[5].decode().strip("\0"),
                        "owner": unpacked[6].decode().strip("\0"),
                        "data_length": data_length,
                        "data": additional_data.decode("utf-8"),
                    }
                        #debug: print loaded block
                    print(f"Loaded Block: {block}")

                    # Append the reconstructed block to the chain
                    self.chain.append(block)

                except struct.error:
                    print("Error parsing blockchain file. The file might be corrupted.")
                    break

    def add(self, case_id, item_ids, creator, password):
        """
        Add new evidence items to the blockchain.
        """
        # password comparison to check if it meets creator
        if password != os.getenv("BCHOC_PASSWORD_CREATOR"):
            raise ValueError("Invalid creator password in add.")

        # check if case_id is a valid UUID
        try:
            uuid.UUID(case_id)
        except ValueError:
            raise ValueError("Invalid case_id format. Must be a UUID.")

        # checks to see if  item_ids is a list of non-empty values and unique
        if not item_ids or not isinstance(item_ids, list):
            raise ValueError("item_ids must be a non-empty list.")
        
        processed_item_ids = set()  

        for item_id in item_ids:

            item_id_str = str(item_id)

            # checks duplicates item IDs in the input
            if item_id_str in processed_item_ids:
                raise ValueError(f"Duplicate Item ID {item_id_str} found in input.")
            processed_item_ids.add(item_id_str)

            # checks if the item ID already exists in the blockchain
            if any(block["item_id"] == item_id_str for block in self.chain):
                raise ValueError(f"Item ID {item_id_str} already exists in the blockchain.")

            # determine the previous hash
            prev_hash = self.chain[-1]["hash"].encode("utf-8") if self.chain else b"\x00" * 32

            # new block creation
            block = Block(
                prev_hash=prev_hash,
                timestamp=get_timestamp(),
                case_id=case_id,
                item_id=item_id_str,
                state="CHECKEDIN",
                creator=creator,
                owner="",
                data=""
            )

            # converted to dictionary for storage
            block_dict = {
                "prev_hash": block.prev_hash.decode("utf-8") if isinstance(block.prev_hash, bytes) else block.prev_hash,
                "timestamp": block.timestamp,
                "case_id": case_id,
                "item_id": item_id_str,
                "state": "CHECKEDIN",
                "creator": creator,
                "owner": "",
                "data": "",
                "hash": block.calculate_hash()
            }

            # add block to memory chain and write to file
            self.chain.append(block_dict)
            self.write_block(block_dict)

        print(f"Successfully added items: {', '.join(processed_item_ids)}")


    def write_block(self, block):
        """
        Persist a block to the blockchain file.
        """
        with open(self.path, "ab") as f:
            #  fields are in bytes format
            packed_block = struct.pack(
                "32s d 32s 32s 12s 12s 12s I",
                block["prev_hash"].encode("utf-8")[:32] if isinstance(block["prev_hash"], str) else block["prev_hash"][:32],
                block["timestamp"],  # float
                block["case_id"].encode("utf-8")[:32] if isinstance(block["case_id"], str) else block["case_id"][:32],
                block["item_id"].encode("utf-8")[:32] if isinstance(block["item_id"], str) else block["item_id"][:32],
                block["state"].encode("utf-8")[:12] if isinstance(block["state"], str) else block["state"][:12],
                block["creator"].encode("utf-8")[:12] if isinstance(block["creator"], str) else block["creator"][:12],
                block["owner"].encode("utf-8")[:12] if isinstance(block["owner"], str) else block["owner"][:12],
                len(block["data"]),  # integer
            )
            

            # write packed block and its data to the file
            f.write(packed_block)
            f.write(block["data"].encode("utf-8") if isinstance(block["data"], str) else block["data"])


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
            raise ValueError(
                f"Item ID {item_id} cannot be checked out as it is not CHECKEDIN."
            )

        # Add a new block for the checkout action
        new_block = self.create_block(
            prev_hash=self.chain[-1]["hash"],
            case_id=block["case_id"],
            item_id=item_id,
            state="CHECKEDOUT",
            creator="",
            owner="",
            data="",
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
            raise ValueError(
                f"Item ID {item_id} cannot be checked in as it is not CHECKEDOUT."
            )

        new_block = self.create_block(
            prev_hash=self.chain[-1]["hash"],
            timestamp=get_timestamp(),
            case_id=block["case_id"],
            item_id=item_id,
            state="CHECKEDIN",
            creator="",
            owner="",
            data="",
        )
        self.chain.append(new_block)
        self.write_block(new_block)
        print(f"Item {item_id} checked in successfully.")

    def verify(self):
        """
        Verify blockchain.
        """

        # TODO: Implement logic for actually verifying the blockchain. For now, the state will always be CLEAN
        print(f"Transactions in blockchain: {len(self.chain)}")
        print("State of blockchain: CLEAN")
        return True


# This class was generated with assistance from ChatGPT, an AI tool developed by OpenAI. Specifically, the struct unpacking was cleaned up from our initial implementation
# Reference: OpenAI. (2024). ChatGPT [Large language model]. openai.com/chatgpt
class Block:
    def __init__(
        self, prev_hash, timestamp, case_id, item_id, state, creator, owner, data
    ):
        self.prev_hash = prev_hash
        self.timestamp = timestamp
        self.case_id = case_id.encode("utf-8")
        self.item_id = item_id.encode("utf-8")
        self.state = state.encode("utf-8")
        self.creator = creator.encode("utf-8")
        self.owner = owner.encode("utf-8")
        self.data = data.encode("utf-8")

    def encrypt(self, value):
        cipher = AES.new(AES_KEY, AES.MODE_ECB)
        padded = value.ljust(16, "\0")
        return cipher.encrypt(padded.encode())

    def create_block(self):
        """Pack the block data using struct"""
        block_data = struct.pack(
            "32s d 32s 32s 12s 12s 12s I",
            self.prev_hash[:32],  # Truncate if longer than 32 bytes
            self.timestamp,  # Get the timestamp, whether provided or generated
            self.case_id[:32],
            self.item_id[:32],
            self.state[:12],
            self.creator[:12],
            self.owner[:12],
            len(self.data),
        )
        return block_data

    @staticmethod
    def unpack_block(block_data):
        """Unpack a block from its packed representation"""
        unpacked = struct.unpack("32s d 32s 32s 12s 12s 12s I", block_data)
        return {
            "prev_hash": unpacked[0].decode("utf-8").rstrip("\0"),
            "timestamp": unpacked[1],
            "case_id": unpacked[2].decode("utf-8").rstrip("\0"),
            "item_id": unpacked[3].decode("utf-8").rstrip("\0"),
            "state": unpacked[4].decode("utf-8").rstrip("\0"),
            "creator": unpacked[5].decode("utf-8").rstrip("\0"),
            "owner": unpacked[6].decode("utf-8").rstrip("\0"),
            "data": unpacked[7],
        }

    # Returns the hash in a readable format for the block
    # I think the raw bytes may be necessary for hashing, but it can always be converted back
    # For output purposes, this should be sufficient
    def calculate_hash(self):
        block_data = self.create_block()  # Think this works but maybe not - Truman
        return hashlib.sha256(block_data).hexdigest()
