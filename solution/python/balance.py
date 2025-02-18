from decimal import Decimal
from email.mime import base
from itertools import chain
import re
from webbrowser import get
from ecdsa import SigningKey, SECP256k1
from subprocess import run
from typing import List, Tuple
import hashlib
import hmac
import json

# Provided by administrator
WALLET_NAME = "wallet_094"
EXTENDED_PRIVATE_KEY = "tprv8ZgxMBicQKsPeStJV5QkbdyjEzZPQaJo5ho3JDrSfx72YPRM5VSKxRRhgMM3ZtzcuyYydg1csc7SJVdBvDbprYSB3zEUuKbbdbaQevqY92W"

# Decode a base58 string into an array of bytes
def base58_decode(base58_string: str) -> bytes:
    base58_alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    # Convert Base58 string to a big integer
    n=0
    for c in base58_string:
        n = n * 58 + base58_alphabet.index(c)
    # Convert the integer to bytes
    base58_bytes = n.to_bytes((n.bit_length() + 7) // 8, 'big')
    # Chop off the 32 checksum bits and return
    return base58_bytes[:-4]
    # BONUS POINTS: Verify the checksum!


# Deserialize the extended key bytes and return a JSON object
# https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#serialization-format
# 4 byte: version bytes (mainnet: 0x0488B21E public, 0x0488ADE4 private; testnet: 0x043587CF public, 0x04358394 private)
# 1 byte: depth: 0x00 for master nodes, 0x01 for level-1 derived keys, ....
# 4 bytes: the fingerprint of the parent's key (0x00000000 if master key)
# 4 bytes: child number. This is ser32(i) for i in xi = xpar/i, with xi the key being serialized. (0x00000000 if master key)
# 32 bytes: the chain code
# 33 bytes: the public key or private key data (serP(K) for public keys, 0x00 || ser256(k) for private keys)
def deserialize_key(b: bytes) -> object:
    version = b[:4]
    depth = b[4]
    fingerprint = b[5:9]
    child_number = b[9:13]
    chain_code = b[13:45]
    key_data = b[45:78]

    data = {
        "version": version.hex(),
        "depth": depth,
        "fingerprint": fingerprint.hex(),
        "child_number": int.from_bytes(child_number, "big"),
        "chain_code": chain_code.hex(),
        "key_data": key_data.hex()
    }

    return data

# Derive the secp256k1 compressed public key from a given private key
# BONUS POINTS: Implement ECDSA yourself and multiply you key by the generator point!
def get_pub_from_priv(priv: bytes) -> bytes:
    
    #Check Input length
    if len(priv) != 32:
        raise ValueError("Invalid private key length")

    #Input validation 
    priv_int = int.from_bytes(priv, 'big')
    if priv_int <= 0 or priv_int >= SECP256k1.order:
        raise ValueError("Private key outside valid range")
    

    try:
        # Create signing key and get point
        sk = SigningKey.from_string(priv, curve=SECP256k1)
        vk = sk.get_verifying_key()
        point = vk.pubkey.point
        
        # Extract coordinates
        x_value = point.x()
        y_value = point.y()

        # Validate x coordinate
        if x_value.bit_length() > 256:
            raise ValueError("X coordinate too large")
        
        # Create compressed public key
        prefix = b'\x02' if y_value % 2 == 0 else b'\x03'
        x_bytes = x_value.to_bytes(32, 'big')

        return prefix + x_bytes
    
    except Exception as e:
        raise ValueError(f"Error deriving public key: {str(e)}")


# Perform a BIP32 parent private key -> child private key operation
# Return a JSON object with "key" and "chaincode" properties as bytes
# https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#user-content-Private_parent_key_rarr_private_child_key
def derive_priv_child(key: bytes, chaincode: bytes, index: int, hardened: bool) -> object:

    #Validate key & chaincode inputs 
    if len(key) != 32:
        raise ValueError("Parent private key must be 32 bytes")
    if len(chaincode) != 32:
        raise ValueError("Chain code must be 32 bytes")

    #Validate index
    key_int = int.from_bytes(key, 'big')
    if key_int <= 0 or key_int >= SECP256k1.order:
        raise ValueError("Parent private key outside valid range")
    
    #Check if hardened 
    if(hardened):
        #Validate index
        if index >= 0x80000000:
            raise ValueError("Index too large for hardened derivation")
        
        index += 0x80000000
        data = b'\x00' + key + index.to_bytes(4, 'big')

    else:
        try:
            parent_pub = get_pub_from_priv(key)
            data = parent_pub + index.to_bytes(4, 'big')
        except Exception as e:
            raise ValueError(f"Error getting parent public key: {str(e)}")

    try:
        hmac_output = hmac.new(chaincode, data, hashlib.sha512).digest()
        left, right = hmac_output[:32], hmac_output[32:] #split the output into left and right - L32 bytes keys R32 Chaincode
    except Exception as e:
        raise ValueError(f"Error computing HMAC: {str(e)}")


    #Left 32 bytes for derive child key
    left_int = int.from_bytes(left, 'big')
    #Validation of left_int
    if left_int >= SECP256k1.order:
        raise ValueError("Derive key is too large")
    
    #Calculate the child private key
    child_key = (left_int + key_int) % SECP256k1.order

    #Validate child key
    if child_key == 0:
        raise ValueError("Derived zero private key")
    
    try:
        child_key_bytes = child_key.to_bytes(32, 'big')
    except Exception as e:
        raise ValueError(f"Error converting child key to bytes: {str(e)}")
    
    return{
        "key": child_key_bytes,
        "chaincode": right
    }

# Given an extended private key and a BIP32 derivation path,
# compute the first 2000 child private keys.
# Return an array of keys encoded as bytes.
# The derivation path is formatted as an array of (index: int, hardened: bool) tuples.
def get_wallet_privs(key: bytes, chaincode: bytes, path: List[Tuple[int, bool]]) -> List[bytes]:
    
     # Validate inputs
    if len(key) != 32:
        raise ValueError("Master private key must be 32 bytes")
    if len(chaincode) != 32:
        raise ValueError("Master chain code must be 32 bytes")
    if not path:
        raise ValueError("Derivation path cannot be empty")

    current_key = key
    current_chaincode = chaincode

    #print("Deriving base path...")
    for level, (index, hardened) in enumerate(path):
        try:
            result = derive_priv_child(current_key, current_chaincode, index, hardened)
            current_key = result["key"]
            current_chaincode = result["chaincode"]
        except Exception as e:
            raise ValueError(f"Error deriving key at level {level}: {str(e)}")
        
    # Derive the first 2000 child keys 
    derived_keys = []
    base_key = current_key
    base_chaincode = current_chaincode

    #print("\nDeriving 2000 addresses...") 
    for i in range(2000):
        #if i > 0 and i % 500 == 0:
            #print(f"Derived {i} addresses")
        
        try:
            #Derive child key
            result = derive_priv_child(base_key, base_chaincode, i, False)
            derived_keys.append(result["key"])

        except Exception as e:
            print(f"Warning: Failed to derive key at index {i}: {str(e)}")
            continue
    
    return derived_keys


# Derive the p2wpkh witness program (aka scriptPubKey) for a given compressed public key.
# Return a bytes array to be compared with the JSON output of Bitcoin Core RPC getblock
# so we can find our received transactions in blocks.
# These are segwit version 0 pay-to-public-key-hash witness programs.
# https://github.com/bitcoin/bips/blob/master/bip-0141.mediawiki#user-content-P2WPKH
def get_p2wpkh_program(pubkey: bytes, version: int=0) -> bytes:

    sha256_hash = hashlib.sha256(pubkey).digest()
    ripemd160Hash = hashlib.new("ripemd160", sha256_hash).digest()

    segwit_version = bytes([version])
    pk_hash_version = bytes([len(ripemd160Hash)])

    script_pub_key = segwit_version + pk_hash_version + ripemd160Hash

    return script_pub_key


# Assuming Bitcoin Core is running and connected to signet using default datadir,
# execute an RPC and return its value or error message.
# https://github.com/bitcoin/bitcoin/blob/master/doc/bitcoin-conf.md#configuration-file-path
# Examples: bcli("getblockcount")
#           bcli("getblockhash 100")
def bcli(cmd: str):
    res = run(
            ["bitcoin-cli", "-signet"] + cmd.split(" "),
            capture_output=True,
            encoding="utf-8")
    print(f"Executing command: bitcoin-cli -signet {cmd}")
    if res.returncode == 0:
        return res.stdout.strip()
    else:
        print(f"Error executing command: {cmd}")
        raise Exception(res.stderr.strip())
        


# Recover the wallet state from the blockchain:
# - Parse tprv and path from descriptor and derive 2000 key pairs and witness programs
# - Request blocks 0-310 from Bitcoin Core via RPC and scan all transactions
# - Return a state object with all the derived keys and total wallet balance
def recover_wallet_state(tprv: str):
    # Key derivation remains the same
    decoded_key = base58_decode(tprv)
    key_data = deserialize_key(decoded_key)
    master_key = bytes.fromhex(key_data["key_data"][2:])
    chain_code = bytes.fromhex(key_data["chain_code"])
    
    path = [
        (84, True),    
        (1, True),     
        (0, True),     
        (0, False),    
    ]
    
    privs = get_wallet_privs(master_key, chain_code, path)

    pubs = [get_pub_from_priv(priv) for priv in privs]

    programs = [get_p2wpkh_program(pub) for pub in pubs]
    
    # Initialize state with balance as float - we'll format it at the end
    state = {
        "utxo": {},        
        "balance": 0.0,    # Using float instead of Decimal
        "privs": privs,
        "pubs": pubs,
        "programs": programs
    }
    
    height = 300
    
    for h in range(height + 1):
        try:
            block_hash = bcli(f"getblockhash {h}")
            # Parse JSON normally, without Decimal
            block_data = json.loads(bcli(f"getblock {block_hash} 2"))
            txs = block_data["tx"]
            
            for tx in txs:
                tx_id = tx["txid"]
                
                # Handle spends
                for inp in tx["vin"]:
                    if "txinwitness" in inp and len(inp["txinwitness"]) >= 2:
                        witness_pubkey = bytes.fromhex(inp["txinwitness"][1])
                        
                        if witness_pubkey in pubs:
                            outpoint = f"{inp['txid']}:{inp['vout']}"
                            if outpoint in state["utxo"]:
                                spent_amount = state["utxo"][outpoint]
                                state["balance"] -= spent_amount
                                del state["utxo"][outpoint]
                
                # Handle receives
                for out_idx, out in enumerate(tx["vout"]):
                    if "scriptPubKey" in out and "hex" in out["scriptPubKey"]:
                        script = bytes.fromhex(out["scriptPubKey"]["hex"])
                        
                        if script in programs:
                            # Store the BTC amount directly
                            amount = float(out["value"])
                            outpoint = f"{tx_id}:{out_idx}"
                            state["utxo"][outpoint] = amount
                            state["balance"] += amount
                            
        except Exception as e:
            print(f"\nError scanning block {h}: {str(e)}")
            continue
    
    return state


if __name__ == "__main__":
    state = recover_wallet_state(EXTENDED_PRIVATE_KEY)
    format_balance = f"{state['balance']:.8f}"

    print(f"{WALLET_NAME} {format_balance}")