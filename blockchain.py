import hashlib
import os
import struct
import uuid
from datetime import datetime, timezone

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

AES_KEY = b"R0chLi4uLi4uLi4="


# Timestamp helper
def get_timestamp():
    # Generate UTC timestamp
    return datetime.now(timezone.utc).timestamp()


def encrypt(value):
    # encrypts values using AES
    cipher = AES.new(AES_KEY, AES.MODE_ECB)
    padded_value = pad(value.encode("utf-8"), 16)
    return cipher.encrypt(padded_value)

def decrypt(encrypted_value):
    cipher = AES.new(AES_KEY, AES.MODE_ECB)
    decrypted_padded = cipher.decrypt(encrypted_value)
    return decrypted_padded.decode('utf-8')

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



class Blockchain:
    def __init__(self, path):
        self.path = path  # Path to the blockchain file
        self.chain = []  # List to store blocks

        if os.path.exists(self.path):
            self.load_chain()  # Parse and load existing blockchain
        else:
            self.chain = []

    def initialize(self):
        if not os.path.exists(self.path) and not self.chain:
            print("Blockchain file not found. Creating INITIAL block.")

            genesis_block = Block(
                prev_hash=b"\x00" * 32,  # 32 zero bytes
                timestamp=get_timestamp(),  # Placeholder for timestamp
                case_id=b"0" * 32,  # 32 zero bytes
                item_id=b"0" * 32,  # 32 zero bytes
                state=b"INITIAL\0\0\0\0\0",  # Exactly 12 bytes
                creator=b"\x00" * 12,  # 12 zero bytes
                owner=b"\x00" * 12,  # 12 zero bytes
                data=b"Initial block\0",  # Explicit data
            )
            genesis_block.hash = self.calculate_hash(genesis_block)
            self.chain.append(genesis_block)
            self.write_block(genesis_block)
        else:
            print("Blockchain file found with INITIAL block")

    # calculates the sha256 hash of a block
    def calculate_hash(self, block):
        # it takes a block object as input and packs its fields into a binary format

        block_data = struct.pack(
            "32s d 32s 32s 12s 12s 12s I",
            block.prev_hash.encode("utf-8").ljust(32, b"\0")
            if isinstance(block.prev_hash, str)
            else block.prev_hash.ljust(32, b"\0"),
            block.timestamp,
            bytes.fromhex(block.case_id).ljust(32, b"\0")
            if isinstance(block.case_id, str)
            else block.case_id.ljust(32, b"\0"),
            bytes.fromhex(block.item_id).ljust(32, b"\0")
            if isinstance(block.item_id, str)
            else block.item_id.ljust(32, b"\0"),
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
        # returns the resulting hash as a hexadecimal string
        return hashlib.sha256(block_data).hexdigest()

    def load_chain(self):
        with open(self.path, "rb") as f:
            while True:  # Read in data until eof
                try:
                    block_data = f.read(144)  # the size of a block is 144
                    if not block_data:
                        break

                    unpacked = struct.unpack("32s d 32s 32s 12s 12s 12s I", block_data)
                    data_length = unpacked[-1]
                    additional_data = f.read(data_length) if data_length > 0 else b""
                    # reading in data for the length from the end of data length, as packed
                    prev_hash = unpacked[0].hex()

                    # If the prev_hash is all zeros, don't strip the '\0' bytes
                    if prev_hash == "00" * len(unpacked[0]):
                        prev_hash = "00" * len(unpacked[0])
                    else:
                        prev_hash = prev_hash.rstrip("0")

                    block = Block(
                        prev_hash=prev_hash,
                        timestamp=unpacked[1],
                        case_id=unpacked[2].hex(),
                        item_id=unpacked[3].hex(),
                        state=unpacked[4].decode("utf-8").rstrip("\0"),
                        creator=unpacked[5].decode("utf-8").rstrip("\0"),
                        owner=unpacked[6].decode("utf-8").rstrip("\0"),
                        data=additional_data.decode("utf-8") if data_length > 0 else "",
                    )
                    block.hash = self.calculate_hash(block)
                    # Append the reconstructed block to the chain
                    self.chain.append(block)

                except struct.error:
                    print("Error parsing blockchain file. The file might be corrupted.")
                    raise SystemExit(1)

    # Print the chain for debugging purposes. Comment out when you don't need it/are submitting
    def print_chain(self):
        for index, block in enumerate(self.chain):
            print(f"Block hash: {block.hash}")
            print(f"Block {index}:")
            print(f"  prev_hash: {block.prev_hash}")
            print(f"  timestamp: {block.timestamp}")
            print(f"  case_id: {block.case_id}")
            print(f"  item_id: {block.item_id}")
            print(f"  state: {block.state}")
            print(f"  creator: {block.creator}")
            print(f"  owner: {block.owner}")
            print(f"  data: {block.data}")
            print("-" * 40)

    def add(self, case_id, item_ids, creator, password):
        """
        Add new evidence items to the blockchain.
        """

        # password comparison to check if it meets creator's password
        if password != os.getenv("BCHOC_PASSWORD_CREATOR"):
            raise ValueError("Invalid password")

        # check if case_id is a valid UUID
        try:
            uuid.UUID(case_id)
        except ValueError:
            raise ValueError("Invalid case_id format. Must be a UUID.")

        # checks to see if item_ids is a list of non-empty values and unique
        if not item_ids or not isinstance(item_ids, list):
            raise ValueError("item_ids must be a non-empty list.")

        processed_item_ids = set()

        # create the genesis block if the blockchain is empty
        if not os.path.exists(self.path) and not self.chain:
            print("Blockchain file not found. Creating INITIAL block.")
            genesis_block = Block(
                prev_hash="0",  # 32 zero bytes
                timestamp=0,  # Placeholder for timestamp
                case_id=b"0" * 32,  # 32 zero bytes
                item_id=b"0" * 32,  # 32 zero bytes
                state=b"INITIAL\0\0\0\0\0",  # Exactly 12 bytes
                creator=b"\x00" * 12,  # 12 zero bytes
                owner=b"\x00" * 12,  # 12 zero bytes
                data=b"Initial block\0",  # Explicit data
            )
            genesis_block.hash = self.calculate_hash(genesis_block)
            self.chain.append(genesis_block)
            self.write_block(genesis_block)

        # process all provided item_ids
        for item_id in item_ids:
            item_id_str = str(item_id).strip()
            if not item_id_str:
                raise ValueError("item_id cannot be empty.")

            # encrypt item_id for comparison
            encrypted_item_id = encrypt(item_id_str).hex()

            # check for duplicates in the blockchain
            for block in self.chain:
                # Since the INITIAL block is made as it is, have to check if the item_id is a string already
                if isinstance(block.item_id, bytes):
                    existing_item_id = (
                        block.item_id.decode("utf-8").rstrip("0").rstrip()
                    )  # strip padding or null bytes
                else:
                    existing_item_id = block.item_id.rstrip(
                        "0"
                    ).rstrip()  # strip padding or null bytes

                if encrypted_item_id == existing_item_id:
                    print(f"Duplicate found for item_id: {item_id_str}")
                    raise ValueError(
                        f"Duplicate Item ID {item_id_str} found or already exists."
                    )

            # check for duplicates in the current session
            if encrypted_item_id in processed_item_ids:
                print(f"Duplicate found in session for item_id: {item_id_str}")
                raise ValueError(
                    f"Duplicate Item ID {item_id_str} found in this session."
                )

            # add to the processed set to track during this call
            processed_item_ids.add(encrypted_item_id)

            # encrypt case_id
            encrypted_case_id = encrypt(case_id.replace("-","")).hex()

            # retrieve previous block hash
            prev_hash = self.chain[-1].hash

            # create a new block
            block = Block(
                prev_hash=prev_hash,
                timestamp=get_timestamp(),
                case_id=encrypted_case_id,
                item_id=encrypted_item_id,
                state="CHECKEDIN",
                creator=creator,
                owner="",
                data="",
            )

            # calculate the hash for the new block and append it to the chain
            block.hash = self.calculate_hash(block)
            self.chain.append(block)
            self.write_block(block)

            print(
                f"Added item: {item_id_str}\n"
                f"Adding item_id: {item_id}, Encrypted: {encrypted_item_id}"
                f"Status: CHECKEDIN\n"
                f"Time of action: {datetime.fromtimestamp(block.timestamp, timezone.utc).isoformat()}Z"
            )

    def remove(self, item_id, reason, password, owner=None):
        # password check broken -> always saying invalid password
        """
        if password != os.getenv("BCHOC_PASSWORD_CREATOR"):
            raise ValueError("Invalid password")
        """

        reasons = {"DISPOSED", "DESTROYED", "RELEASED"}
        if reason not in reasons:
            raise ValueError(f"Invalid reason '{reason}'. Must be one of {reasons}.")

        if reason == "RELEASED" and not owner:
            raise ValueError("Owner must be provided when reason is RELEASED.")

        e_item = encrypt(str(item_id).strip()).hex()

        # Find the block corresponding to the item_id
        block = next(
            (
                b
                for b in reversed(self.chain)
                if b.item_id.rstrip("0").rstrip() == e_item.rstrip("0").rstrip()
            ),
            None,
        )
        if not block:
            raise ValueError(f"Item ID {item_id} not found.")

        # check if the current state is ok for removal
        if block.state != "CHECKEDIN":
            raise ValueError(
                f"Item ID {item_id} cannot be removed as it is not CHECKEDIN."
            )

        # add  new block with the state set to the removal reason
        new_block = Block(
            prev_hash=self.chain[-1].hash,
            timestamp=get_timestamp(),
            case_id=block.case_id,
            item_id=block.item_id,
            state=reason,
            creator=block.creator,
            owner=owner or "",
            data="",
        )
        new_block.hash = self.calculate_hash(new_block)
        self.chain.append(new_block)
        self.write_block(new_block)

        print(f"Item {item_id} removed successfully with reason: {reason}.")

    def write_block(self, block):
        """
        Persist a block to the blockchain file.
        """

        with open(self.path, "ab") as f:
            # use struct.pack to align fields and convert them to binary format for writing to the file
            packed_block = struct.pack(
                #  fields are in bytes format
                "32s d 32s 32s 12s 12s 12s I",
                block.prev_hash.encode("utf-8").ljust(32, b"\0")
                if isinstance(block.prev_hash, str)
                else block.prev_hash.ljust(32, b"\0"),
                block.timestamp,
                bytes.fromhex(block.case_id).ljust(32, b"\0")
                if isinstance(block.case_id, str)
                else block.case_id.ljust(32, b"\0"),
                bytes.fromhex(block.item_id).ljust(32, b"\0")
                if isinstance(block.item_id, str)
                else block.item_id.ljust(32, b"\0"),
                block.state.encode("utf-8").ljust(12, b"\0")
                if isinstance(block.state, str)
                else block.state.ljust(12, b"\0"),
                block.creator.encode("utf-8").ljust(12, b"\0")
                if isinstance(block.creator, str)
                else block.creator.ljust(12, b"\0"),
                block.owner.encode("utf-8").ljust(12, b"\0")
                if isinstance(block.owner, str)
                else block.owner.ljust(12, b"\0"),
                len(block.data),
            )
            # write packed block and its data to the file
            f.write(packed_block)
            f.write(
                block.data.encode("utf-8")
                if isinstance(block.data, str)
                else block.data
            )

    def get_owner_passwords(self):
        """
        Retrieve valid passwords for the owners.
        """
        return [
            os.getenv("BCHOC_PASSWORD_POLICE"),
            os.getenv("BCHOC_PASSWORD_LAWYER"),
            os.getenv("BCHOC_PASSWORD_ANALYST"),
            os.getenv("BCHOC_PASSWORD_EXECUTIVE"),
        ]

    def checkout(self, item_id, password):
        """
        Check out an evidence item.
        """
        if password not in self.get_owner_passwords():
            raise ValueError("Invalid password for checkout.")

        encrypted_item_id = encrypt(str(item_id).strip()).hex()

        print(f"Checking out item_id: {item_id}, Encrypted: {encrypted_item_id}")
        block = next(
            (
                b
                for b in reversed(self.chain)
                if b.item_id.rstrip("0").rstrip()
                == encrypted_item_id.rstrip("0").rstrip()
            ),
            None,
        )
        if not block:
            raise ValueError(f"Item ID {item_id} not found.")

        if block.state not in {"CHECKEDIN", "INITIAL"}:
            raise ValueError(
                f"Item ID {item_id} cannot be checked out as it is not CHECKEDIN."
            )

        # add a new block
        new_block = Block(
            prev_hash=self.chain[-1].hash,
            timestamp=get_timestamp(),
            case_id=block.case_id,
            item_id=block.item_id,
            state="CHECKEDOUT",
            creator=block.creator,
            owner="",
            data="",
        )
        new_block.hash = self.calculate_hash(new_block)
        self.chain.append(new_block)
        self.write_block(new_block)

    def checkin(self, item_id, password):
        """
        Check in an evidence item.
        """

        if password not in self.get_owner_passwords():
            raise ValueError("Invalid password for checkin.")

        encrypted_item_id = encrypt(str(item_id).strip()).hex()

        block = next(
            (
                b
                for b in reversed(self.chain)
                if b.item_id.rstrip("0").rstrip()
                == encrypted_item_id.rstrip("0").rstrip()
            ),
            None,
        )
        if not block:
            raise ValueError(f"Item ID {item_id} not found.")

        if block.state != "CHECKEDOUT":
            raise ValueError(
                f"Item ID {item_id} cannot be checked in as it is not CHECKEDOUT."
            )

        new_block = Block(
            prev_hash=self.chain[-1].hash,
            timestamp=get_timestamp(),
            case_id=block.case_id,
            item_id=block.item_id,
            state="CHECKEDIN",
            creator=block.creator,
            owner="",
            data="",
        )
        new_block.hash = self.calculate_hash(new_block)
        self.chain.append(new_block)
        self.write_block(new_block)

    def verify(self):
        """
        Verify blockchain.
        """

        # TODO: Implement logic for actually verifying the blockchain. For now, the state will always be CLEAN
        print(f"Transactions in blockchain: {len(self.chain)}")
        print("State of blockchain: CLEAN")
        return True
    
    def show_cases(self, password):
        case_ids = set()
        for block in self.chain:
            case_id = block.case_id

                
            if case_id == "3030303030303030303030303030303030303030303030303030303030303030":
                continue
            
            decrypted_case_id = retrieve_case_id(case_id)
            
            
            case_ids.add(decrypted_case_id)
            

        if not case_ids:
            print("No cases found in the blockchain.")
        else:
            for case_id in case_ids:
                print(case_id)
                
    def show_items(self, case_id, password):
        """
        Display all item IDs in the blockchain for a specific case.
        """
        # Validate the provided password (if required for this operation)
        # if password not in self.get_owner_passwords() and password != os.getenv("BCHOC_PASSWORD_CREATOR"):
        #     raise ValueError("Invalid password for showing items.")

        # Encrypt the provided case_id for comparison

        # Collect unique item IDs for the given case
        item_ids = set()
        for block in self.chain:
            # Match blocks with the given case_id
            if block.case_id == "3030303030303030303030303030303030303030303030303030303030303030":
                continue
            if  retrieve_case_id(block.case_id) == case_id:
                # Decrypt the item_id
                decrypted_item_id = decrypt_item(block.item_id)
                item_ids.add(decrypted_item_id)

        # Display results
        if not item_ids:
            print(f"No items found for case ID {case_id}.")
        else:
            for item_id in item_ids:
                print(item_id)
                
    def show_history(self, case_id=None, item_id=None, num_entries=None, reverse=False, password=None):
        """
        Display the history of actions for a specific case or item.
        """
        # Validate the password if required
        if password not in self.get_owner_passwords():
            raise ValueError("Invalid password for showing history.")

        # Filter the blocks by case_id and/or item_id if provided
        matching_blocks = []
        for block in self.chain:
            if block.case_id == "3030303030303030303030303030303030303030303030303030303030303030":
                if not case_id and not item_id:
                    matching_blocks.append(block)
                continue

            # Apply filters
            case_match = not case_id or (retrieve_case_id(block.case_id) == case_id)
            item_match = not item_id or (retrieve_item_id(block.item_id) == item_id)

            if case_match and item_match:
                matching_blocks.append(block)

        # Sort blocks by timestamp
        matching_blocks.sort(key=lambda b: b.timestamp, reverse=reverse)

        # Limit the number of entries
        if num_entries:
            matching_blocks = matching_blocks[:num_entries]

        # Display the history
        if not matching_blocks:
            pass
        else:
            for block in matching_blocks:
                timestamp = datetime.fromtimestamp(block.timestamp, timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
                if block.case_id == "3030303030303030303030303030303030303030303030303030303030303030":
                    print(f"Case: 00000000-0000-0000-0000-000000000000")
                    print(f"Item: 0")
                    print(f"Action: INITIAL")
                    print(f"Time: {timestamp}")
                    print()
                    continue
                case_id_to_display = retrieve_case_id(block.case_id)
                item_id_to_display = retrieve_item_id(block.item_id)                      
                action = block.state

                print(f"Case: {case_id_to_display}")
                print(f"Item: {item_id_to_display}")
                print(f"Action: {action}")
                print(f"Time: {timestamp}")
                print()




# This class was generated with assistance from ChatGPT, an AI tool developed by OpenAI. Specifically, the struct unpacking was cleaned up from our initial implementation
# Reference: OpenAI. (2024). ChatGPT [Large language model]. openai.com/chatgpt


class Block:
    # initialize a block with prev_hash timestamp case_id item_id state creator owner and data here
    # stores the hash of the block initially set to none
    def __init__(
        self, prev_hash, timestamp, case_id, item_id, state, creator, owner, data
    ):
        self.prev_hash = prev_hash
        self.timestamp = timestamp
        self.case_id = case_id
        self.item_id = item_id
        self.state = state
        self.creator = creator
        self.owner = owner
        self.data = data
        self.hash = ""

    # the to_dict method converts the block attributes into a dictionary format so you can access or store it

    def to_dict(self):
        return {
            "prev_hash": self.prev_hash,
            "timestamp": self.timestamp,
            "case_id": self.case_id,
            "item_id": self.item_id,
            "state": self.state,
            "creator": self.creator,
            "owner": self.owner,
            "data": self.data,
            "hash": self.hash,
        }
