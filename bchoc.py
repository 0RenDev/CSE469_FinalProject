import argparse
import sys
import os
import hashlib
import time
import datetime
import struct
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import uuid
import ast

blockchain_file_path = os.getenv("BCHOC_FILE_PATH", "blockchain_file.bin")
AES_KEY = b"R0chLi4uLi4uLi4="
INITIAL_STATE = b'INITIAL\0\0\0\0\0'
passwords = {
    "P80P": b'POLICE',
    "L76L": b'LAWYER',
    "A65A": b'ANALYST',
    "E69E": b'EXECUTIVE',
    "C67C": b'CREATOR',
}
blockchain_path = os.getenv('BCHOC_FILE_PATH', 'blockchain.bin')
evidences = set()
BLOCK_SIZE = 16
# This function was generated with assistance from ChatGPT, an AI tool developed by OpenAI.
# Reference: OpenAI. (2024). ChatGPT [Large language model]. openai.com/chatgpt
def encrypt(data):
    cipher = AES.new(AES_KEY, AES.MODE_ECB)
    if(len(data) % BLOCK_SIZE != 0):
        data = pad(data, BLOCK_SIZE)
    encryped_data = "b'" + cipher.encrypt(data).hex() + "'"
    return ast.literal_eval(encryped_data)
# This function was generated with assistance from ChatGPT, an AI tool developed by OpenAI.
# Reference: OpenAI. (2024). ChatGPT [Large language model]. openai.com/chatgpt  
def decrypt(data):
    cipher = AES.new(AES_KEY, AES.MODE_ECB)
    decrypted_data_hex = data.decode('utf-8')
    decrypted_data = bytes.fromhex(decrypted_data_hex)
    decrypted_data = cipher.decrypt(decrypted_data)
    if(len(decrypted_data) % BLOCK_SIZE != 0):
        decrypted_data = unpad(decrypted_data, BLOCK_SIZE)
    return decrypted_data


def main():
    # This section has been added for reading multiple arguments
    if len(sys.argv) > 1 and sys.argv[1] == 'show' and len(sys.argv) > 2:
        if sys.argv[2] in ['items', 'cases', 'history']:
            sys.argv[1] = f"show {sys.argv[2]}"
            del sys.argv[2]
    parser = argparse.ArgumentParser(description="Blockchain Chain of Custody Management")
    parser.add_argument('command', choices=['add', 'checkout', 'checkin', 'show items', 'show cases','show history','owner','remove', 'init', 'verify'],
                        help="Command to execute")
    parser.add_argument('-c', '--case_id', type=str, action="append", help="Case identifier (UUID)")
    parser.add_argument('-i', '--item_id', type=int, action = "append", help="Item identifier (4-byte integer)")
    parser.add_argument('-g', '--creator', type=str, help="Creator of the evidence")
    parser.add_argument('-p', '--password', type=str, help="Password for authentication")
    parser.add_argument('-n', '--num_entries', type=int, help="Number of log entries to display")
    parser.add_argument('-r', '--reverse', action='store_true', help="Display history in reverse order")
    parser.add_argument('-y', '--why', choices=['DISPOSED', 'DESTROYED', 'RELEASED'], help="Reason for removal")
    parser.add_argument('-o', '--owner', type=str, help="Owner information for RELEASED reason")
    args = parser.parse_args()

    if args.command == 'init':
        init_blockchain()
    elif args.command == 'add':
        if(args.password!="C67C"):
            sys.exit(1)
        add(args.case_id, args.item_id, args.creator, args.password)
    elif args.command == 'checkin':
        checkin(args.item_id, args.password)
    elif args.command == 'checkout':
        checkout(args.item_id, args.password)
    elif args.command == 'remove':
        if(args.password!="C67C"):
            sys.exit(1)
        remove(args.item_id, args.why, args.password)
    elif args.command == 'show items':
        show_items(args.case_id)
    elif args.command == 'show cases':
        show_cases()
    elif args.command == 'show history':
        if (args.password not in passwords):
            sys.exit(1)
        show_history(args.case_id,args.item_id,args.num_entries,args.reverse)
    elif args.command == 'verify':
        verify()

#'init' function for initializing the blockchain
def init_blockchain():
    blockchain_path = os.getenv('BCHOC_FILE_PATH', 'blockchain.bin')

    if not os.path.exists(blockchain_path):
        prev_hash = b"\x00" * 32

        timestamp = time.time()

        case_id = b"0" * 32

        evidence_id = b"0" * 32

        state = b"INITIAL\0\0\0\0\0"

        creator = b"\0" * 12

        owner = b"\0" * 12

        data = b"Initial block\0"

        data_length = 14

        initial_block = struct.pack(
            "32s d 32s 32s 12s 12s 12s I",
            prev_hash,
            timestamp,
            case_id,
            evidence_id,
            state,
            creator,
            owner,
            data_length,
        )
        initial_block += data

        with open(blockchain_path, 'wb') as file:

            file.write(initial_block)

        print("Blockchain initialized.")
    else:
        with open(blockchain_path, 'rb') as file:
            block_data = file.read()

        if (block_data[:32] != b'\x00' * 32 or
                block_data[40:72] != b'0' * 32 or
                block_data[72:104] != b'0' * 32 or
                block_data[104:116] != b'INITIAL\0\0\0\0\0' or
                block_data[116:128] != b'\0' * 12 or
                block_data[128:140] != b'\0' * 12):
            print('Blockchain file invalid.')
            sys.exit(1)

        data_length = int.from_bytes(block_data[140:144], byteorder='big')
        if data_length != 14:
            print('Blockchain file invalid.')
            sys.exit(0)

        data = block_data[144:144 + data_length]
        if data != b'Initial block\0':
            print('Blockchain file invalid.')
            sys.exit(0)

        print("Blockchain file found with INITIAL block.")

# This function produces a set of all the item ids present in the file
def unique():
    with open(blockchain_file_path, "rb") as file:
        while True:
            header_data = file.read(144)
            if len(header_data) < 144:
                break  

            prev_hash, timestamp, case_id, evidence_id, state, creator, owner, data_length = struct.unpack(
                "32s d 32s 32s 12s 12s 12s I", header_data
            )
            data = file.read(data_length)
            if(data==b'Inital block\0'):
                continue
            try:
                evidence = int.from_bytes(decrypt(evidence_id),byteorder='big')
                evidences.add(evidence)
            except:
                print("Error reading blockchain.")
                continue


# Add function for adding blocks to the binary file
def add(case_id, item_id, creator, password):
    case_id = case_id[0]
    blockchain_path = os.getenv('BCHOC_FILE_PATH', 'blockchain.bin')
    if not os.path.exists(blockchain_path):
        init_blockchain()
    unique()
    for item in item_id:
        if(item in evidences):
            print(f"Duplicate item ID {item} for case ID {case_id}.")
            sys.exit(1)
    with open(blockchain_path, "rb") as file:
        file.seek(-144, os.SEEK_END)
        last_block = file.read(144)
    # This part take the writer to the end of the file
    block = None
    prev_block = None
    data = None
    with open(blockchain_path, 'rb') as file:
        while True:
            prev_block = block
            block = file.read(144)
            if(len(block) < 144):
                block = prev_block
                break
            _, _, _, _, _, _, _, data_length = struct.unpack('32s d 32s 32s 12s 12s 12s I', block[:144]) 
            data = file.read(int(data_length)) 
    prev_hash = hashlib.sha256(block+data).digest()
    timestamp = time.time()
    case_id = encrypt(uuid.UUID(case_id).int.to_bytes(16, byteorder='big'))
    if not isinstance(item_id, list):
        item_ids = [item_id]
    item_ids = [encrypt(int(item).to_bytes(16,byteorder='big')) for item in item_id]
    state = b'CHECKEDIN'
    creator = creator.encode('utf-8').ljust(12, b'\0')
    owner = b'\x00' * 12
    for m in item_ids:
        data_length = 0
        new_block = struct.pack("32s d 32s 32s 12s 12s 12s I", prev_hash, timestamp, case_id, m, state, creator, owner, data_length)
        with open(blockchain_path,"ab") as file:
            file.write(new_block)
        prev_hash = hashlib.sha256(new_block).digest()
        print(f'Added item: {decrypt(m)}')
        print('Status: CHECKEDIN')
        print(f'Time of action: {datetime.datetime.fromtimestamp(timestamp).isoformat()}Z')

#This function returns an array of block tuples with block header and block data
def getblocks():
    blockchain_path = os.getenv('BCHOC_FILE_PATH', 'blockchain.bin')
    blocks = []
    with open(blockchain_path, 'rb') as file:
        while True:
            block = file.read(144)
            if(len(block) < 144):
                if(len(block) != 0):
                    sys.exit(1)
                break
            _, _, _, _, _, _, _, data_length = struct.unpack('32s d 32s 32s 12s 12s 12s I', block[:144])
            data_length = int(data_length)
            data = b''
            if(data_length > 0):
                data = file.read(data_length)
            blocks.append((block, data))
    return blocks

# Remove function for discarding a certain block from the file
def remove(item_id,reason,password):
    item_id = item_id[0]
    blockchain_path = os.getenv('BCHOC_FILE_PATH', 'blockchain.bin')
    if not blockchain_path or not os.path.exists(blockchain_path):
        print("No blockchain file exists")
        sys.exit(1)
    if reason != 'DISPOSED' and reason != 'DESTROYED' and reason != 'RELEASED':
        print("Invalid reason for removal.")
        sys.exit(1)
    allblocks = getblocks()
    block = None
    data = None
    evidence_id_bytes = 0

    #Finding out the last block with the given item_id
    for tempBlock,tempData in allblocks:
        _, _, _, evidence_id, _, _, _, data_length = struct.unpack('32s d 32s 32s 12s 12s 12s I', tempBlock)
        data_length = int(data_length)
        data = tempData
        if(tempData == b'Initial block\0'):
            continue
        evidence_id_bytes = int.from_bytes(decrypt(evidence_id), byteorder='big')
        if(evidence_id_bytes == item_id):
            block = tempBlock
            data = tempData
    main_data = data
    if(block == None):
        print(f"Item {evidence_id_bytes} not found in the blockchain.")
        sys.exit(1)
    ################################################
    prev_hash, timestamp, case_id, evidence_id, state, creator,owner, data_length = struct.unpack('32s d 32s 32s 12s 12s 12s I',block[:144])
    decoded_state = state.decode('utf-8').rstrip('\0')
    if(decoded_state != "CHECKEDIN"):
        print(f"Item {evidence_id_bytes} is not in CHECKEDIN state.")
        sys.exit(1)
    #Details about the last block
    with open(blockchain_path, 'rb') as file:
        while True:
            prev_block = block
            block = file.read(144)
            if(len(block) < 144):
                block = prev_block
                break
            _, _, _, _, _, _, _, data_length = struct.unpack('32s d 32s 32s 12s 12s 12s I', block[:144]) 
            data = file.read(int(data_length)) 
    ############################################
    prev_hash = hashlib.sha256(block+data).digest()
    print(f"prev_hash: {prev_hash}")
    changed_state = reason.encode('utf-8').ljust(12, b'\0')      
    data = main_data
    data_length =len(data)
    timestamp = time.time()
    new_block = struct.pack('32s d 32s 32s 12s 12s 12s I', prev_hash, timestamp, case_id, evidence_id,changed_state, creator, owner, data_length) + main_data
    with open(blockchain_path, 'ab') as file:
        file.write(new_block)
        print(f' Removed item: {item_id}')
        print(' Status: REMOVED')
        print(f' Time of action: {datetime.datetime.fromtimestamp(timestamp).isoformat()}Z')

# Checkin function
def checkin(item_id,password):

    blockchain_path = os.getenv('BCHOC_FILE_PATH', 'blockchain.bin')
    item_id = item_id[0]
    if password in passwords:
        owner = passwords[password]
        allblocks = getblocks()
        #This portion searches through all the blocks to look for the one with the given item id
        block = None
        data = None
        evidence_id_bytes = 0
        for tempBlock,tempData in allblocks:
            _, _, _, evidence_id, _, _, _, data_length = struct.unpack('32s d 32s 32s 12s 12s 12s I', tempBlock)
            data_length = int(data_length)
            data = tempData
            if(tempData == b'Initial block\0'):
                continue
            evidence_id_bytes = int.from_bytes(decrypt(evidence_id), byteorder='big')
            if(evidence_id_bytes == item_id):
                block = tempBlock
                data = tempData
        if(block == None):
            print(f"Item {evidence_id_bytes} not found in the blockchain.")
            sys.exit(1)
        prev_hash, timestamp, case_id, evidence_id, state, creator, _, data_length = struct.unpack('32s d 32s 32s 12s 12s 12s I',block[:144])
        print(state)
        decoded_state = state.decode('utf-8').rstrip('\0')
        if(decoded_state != "CHECKEDOUT"):
            print(f"Item {evidence_id_bytes} is not in CHECKEDOUT state.")
            sys.exit(1)
        with open(blockchain_path, 'rb') as file:
            while True:
                prev_block = block
                block = file.read(144)
                if(len(block) < 144):
                    block = prev_block
                    break
                _, _, _, _, _, _, _, data_length = struct.unpack('32s d 32s 32s 12s 12s 12s I', block[:144]) 
                data = file.read(int(data_length)) 
        prev_hash = hashlib.sha256(block+data).digest()
        changed_state =  b'CHECKEDIN\0\0'
        data = data
        data_length =len(data)
        timestamp = time.time()
        new_block = struct.pack('32s d 32s 32s 12s 12s 12s I', prev_hash, timestamp, case_id, evidence_id,changed_state, creator, owner, data_length) + data
        with open(blockchain_path, 'ab') as file:
            file.write(new_block)
            print(f' Checked in item: {evidence_id}')
            print(' Status: CHECKEDIN')
            print(f' Time of action: {datetime.datetime.fromtimestamp(timestamp).isoformat()}Z')
    else:
        # print("Reached here in line 209 checkIN() ELSE ")
        print("Invalid Password")
        sys.exit(1)

# The checkout function is similar to the checkin function in a lot of aspects    
def checkout(item_id, password):

    blockchain_path = os.getenv('BCHOC_FILE_PATH', 'blockchain.bin')
    item_id = item_id[0]
    if password in passwords:
        owner = passwords[password]
        allblocks = getblocks()
        evidence_id_bytes = 0
        block = None
        data = None
        for tempBlock,tempData in allblocks:
            _, _, _, evidence_id, _, _, _, data_length = struct.unpack('32s d 32s 32s 12s 12s 12s I', tempBlock)
            data_length = int(data_length)
            data = tempData
            if(tempData == b'Initial block\0'):
                continue
            evidence_id_bytes = int.from_bytes(decrypt(evidence_id), byteorder='big')
            if(evidence_id_bytes==item_id):
                block = tempBlock
                data = tempData
        if(block == None):
            print(f"Item {evidence_id_bytes} not found in the blockchain.")
            sys.exit(1)
        prev_hash, timestamp, case_id, evidence_id, state, creator, _, data_length = struct.unpack('32s d 32s 32s 12s 12s 12s I',block[:144])
        print(state)
        decoded_state = state.decode('utf-8').rstrip('\0')
        if(decoded_state != "CHECKEDIN"):
            print(f"Item {evidence_id_bytes} is not in CHECKEDIN state.")
            sys.exit(1)
        with open(blockchain_path, 'rb') as file:
            while True:
                prev_block = block
                block = file.read(144)
                if(len(block) < 144):
                    block = prev_block
                    break
                _, _, _, _, _, _, _, data_length = struct.unpack('32s d 32s 32s 12s 12s 12s I', block[:144]) 
                data = file.read(int(data_length)) 
        prev_hash = hashlib.sha256(block+data).digest()
        changed_state =  b'CHECKEDOUT\0\0'
        data = data
        data_length =len(data)
        timestamp = time.time()
        new_block = struct.pack('32s d 32s 32s 12s 12s 12s I', prev_hash, timestamp, case_id, evidence_id,changed_state, creator, owner, data_length) + data
        with open(blockchain_path, 'ab') as file:
            file.write(new_block)
            print(f' Checked in item: {evidence_id}')
            print(' Status: CHECKEDOUT')
            print(f' Time of action: {datetime.datetime.fromtimestamp(timestamp).isoformat()}Z')
    else:
        print("Invalid Password")
        sys.exit(1)
# Shows all items with a certain case_id
def show_items(case_id):
    case_id = case_id[0]
    blockchain_path = os.getenv('BCHOC_FILE_PATH', 'blockchain.bin')
    if not os.path.exists(blockchain_path):
        print("Blockchain not found")
    tems = set()
    case = encrypt(uuid.UUID(case_id).int.to_bytes(16, byteorder='big'))
    allblocks = getblocks()
    block = None
    data = None
    for tempBlock,tempData in allblocks:
        _, _, case_id, evidence_id, _, _, _, data_length = struct.unpack('32s d 32s 32s 12s 12s 12s I', tempBlock)
        data_length = int(data_length)
        data = tempData
        if(tempData == b'Initial block\0'):
            continue
        if(case == case_id):
            evidence_id_bytes = int.from_bytes(decrypt(evidence_id), byteorder='big')
            tems.add(evidence_id_bytes)
    for item in tems:
        print(item)

# Shows all cases 
def show_cases():
    blockchain_path = os.getenv('BCHOC_FILE_PATH', 'blockchain.bin')
    if not os.path.exists(blockchain_path):
        print("Blockchain not found")
    allcases = set()
    allblocks = getblocks()
    block = None
    data = None
    for tempBlock,tempData in allblocks:
        _, _, case_id, evidence_id, _, _, _, data_length = struct.unpack('32s d 32s 32s 12s 12s 12s I', tempBlock)
        data_length = int(data_length)
        data = tempData
        if(tempData == b'Initial block\0'):
            continue
        case = uuid.UUID(bytes=decrypt(case_id))
        allcases.add(case)
    for case in allcases:
        print(case)

#Displays history of certain case ids and item ids
def show_history(case_id=None, item_id=None, num_entries=None, reverse=False):
    blockchain_path = os.getenv('BCHOC_FILE_PATH', 'blockchain.bin')
    if not os.path.exists(blockchain_path):
        print("Blockchain not found")
    if case_id:
        case_id = case_id[0]
        case_id_bytes = encrypt(uuid.UUID(case_id).int.to_bytes(16, byteorder='big'))
        if item_id:
            item_id = item_id[0]
            item_id_bytes = encrypt(int(item_id).to_bytes(16, byteorder='big'))
            allblocks = getblocks()
            if reverse:
                allblocks = allblocks[::-1][:num_entries]
            else:
                allblocks = allblocks[:num_entries]
            block = None
            data = None
            for tempBlock,tempData in allblocks:
                prev_hash, timestamp, case_id, evidence_id, state, creator, owner, data_length = struct.unpack('32s d 32s 32s 12s 12s 12s I', tempBlock)

                data_length = int(data_length)
                data = tempData
                action = state.replace(b'\x00',b'').decode('utf-8')
                evidence_id_bytes = int.from_bytes(decrypt(evidence_id), byteorder='big')    
                if(item_id_bytes==evidence_id and case_id==case_id_bytes):
                    case_id = uuid.UUID(bytes=decrypt(case_id))
                    print(f'Case: {case_id}')
                    print(f'Item: {evidence_id_bytes}')
                    print(f'Action: {action}')
                    print(f'Time: {datetime.datetime.fromtimestamp(timestamp).isoformat()}Z')
                    print()
        else:
            allblocks = getblocks()
            if reverse:
                allblocks = allblocks[::-1][:num_entries]
            else:
                allblocks = allblocks[:num_entries]
            block = None
            data = None
            for tempBlock,tempData in allblocks:
                prev_hash, timestamp, case_id, evidence_id, state, creator, owner, data_length = struct.unpack('32s d 32s 32s 12s 12s 12s I', tempBlock)
                data_length = int(data_length)
                data = tempData
                action = state.replace(b'\x00',b'').decode('utf-8')
                evidence_id_bytes = int.from_bytes(decrypt(evidence_id), byteorder='big')
                if(case_id==case_id_bytes):
                    case_id = uuid.UUID(bytes=decrypt(case_id))
                    print(f'Case: {case_id}')
                    print(f'Item: {evidence_id_bytes}')
                    print(f'Action: {action}')
                    print(f'Time: {datetime.datetime.fromtimestamp(timestamp).isoformat()}Z')
                    print()
    elif item_id:
        item_id = item_id[0]
        item_id_bytes = encrypt(int(item_id).to_bytes(16, byteorder='big'))
        allblocks = getblocks()
        if reverse:
            allblocks = allblocks[::-1][:num_entries]
        else:
            allblocks = allblocks[:num_entries]
        block = None
        data = None
        for tempBlock,tempData in allblocks:
            prev_hash, timestamp, case_id, evidence_id, state, creator, owner, data_length = struct.unpack('32s d 32s 32s 12s 12s 12s I', tempBlock)
            data_length = int(data_length)
            data = tempData
            action = state.replace(b'\x00',b'').decode('utf-8')
            evidence_id_bytes = int.from_bytes(decrypt(evidence_id), byteorder='big')
            case_id = uuid.UUID(bytes=decrypt(case_id))
            if(item_id_bytes==evidence_id):
                print(f'Case: {case_id}')
                print(f'Item: {evidence_id_bytes}')
                print(f'Action: {action}')
                print(f'Time: {datetime.datetime.fromtimestamp(timestamp).isoformat()}Z')
                print()
    else:
        allblocks = getblocks()
        if reverse:
            allblocks = allblocks[::-1][:num_entries]
        else:
            allblocks = allblocks[:num_entries]
        block = None
        data = None
        for tempBlock,tempData in allblocks:
                prev_hash, timestamp, case_id, evidence_id, state, creator, owner, data_length = struct.unpack('32s d 32s 32s 12s 12s 12s I', tempBlock)
                data_length = int(data_length)
                data = tempData
                action = state.replace(b'\x00',b'').decode('utf-8')
                evidence_id_bytes = int.from_bytes(decrypt(evidence_id), byteorder='big')
                case_id = uuid.UUID(bytes=decrypt(case_id))
                if(action=="INITIAL"):
                    print(f'Case: 00000000-0000-0000-0000-000000000000')
                    print(f'Item: 0')
                    print(f'Action: INITIAL')
                    print(f'Time: {datetime.datetime.fromtimestamp(timestamp).isoformat()}Z')
                    print()
                else:
                    print(f'Case: {case_id}')
                    print(f'Item: {evidence_id_bytes}')
                    print(f'Action: {action}')
                    print(f'Time: {datetime.datetime.fromtimestamp(timestamp).isoformat()}Z')
                    print()

#Verify function to verify if the chain is valid
def verify():
    blockchain_path = os.getenv('BCHOC_FILE_PATH', 'blockchain.bin')

    if not os.path.exists(blockchain_path):
        print("Blockchain file does not exist.")
        sys.exit(1)
    # blocks = []
    prev_block = None
    prev_data = None
    # with open(blockchain_path,"rb") as file: 
    #     while True: 
    #         block = file.read(144)
    #         if (block == None or len(block) < 144):
    #             print("Hello1")
    #             print("Blockchain file invalid.")
    #             sys.exit(1)
    #         if len(block) == 0:
    #             break
    #         blocks.append(block)

    allblocks = getblocks()
    for tempBlock,tempData in allblocks:
        # unpack each block to get the prev_hash for prev block
        if prev_block != None:
            prev_hash, timestamp, case_id, evidence_id,state, _, _, data_length = struct.unpack('32s d 32s 32s 12s 12s 12s I', tempBlock[:144])
            calculated_hash = hashlib.sha256(prev_block+prev_data).hexdigest()
            if (prev_hash.hex() != calculated_hash):
                print("Blockchain file invalid1.")
                sys.exit(1)

            _, prev_timestamp, prev_case_id, prev_evidence_id,prev_state, _, _, _ = struct.unpack('32s d 32s 32s 12s 12s 12s I', prev_block[:144]) # previous blocks unpacked.

            if (prev_case_id == case_id and prev_evidence_id == evidence_id and prev_state == state):
                print("Blockchain file invalid2.")
                sys.exit(1)
        else:
            prev_block = tempBlock
            prev_data = tempData

                    








if __name__ == "__main__":
    main()
