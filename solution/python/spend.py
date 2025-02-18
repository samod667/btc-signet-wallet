import hashlib
import json
import sys
import subprocess
from ecdsa import SigningKey, SECP256k1, util
from ecdsa.util import sigencode_der
from typing import List, Tuple

from balance import (
    EXTENDED_PRIVATE_KEY,
    bcli,
    get_pub_from_priv,
    get_p2wpkh_program,
    recover_wallet_state
)

def create_multisig_script(keys: List[bytes]) -> bytes:
    """
    Create a 2-of-2 multisig output script from compressed public keys.
    Script format: OP_2 <pubkey1> <pubkey2> OP_2 OP_CHECKMULTISIG
    Keys are sorted for deterministic script creation.
    """
    if len(keys) != 2:
        raise ValueError("Must provide exactly 2 keys")
        
    script = bytearray()
    script.append(0x52)  # OP_2
    
    for key in sorted(keys):
        if len(key) != 33:
            raise ValueError("Invalid public key length")
        script.append(0x21)  # Push 33 bytes
        script.extend(key)
    
    script.append(0x52)  # OP_2
    script.append(0xae)  # OP_CHECKMULTISIG
    
    return bytes(script)

def get_p2wsh_program(script: bytes, version: int = 0) -> bytes:
    """
    Compute P2WSH witness program from a script.
    Returns: version byte + 0x20 + SHA256(script)
    """
    if version != 0:
        raise ValueError(f"Unsupported witness version: {version}")
    
    if not script:
        raise ValueError("Empty script provided")
        
    if len(script) > 3600:
        raise ValueError("Script too long")
        
    script_hash = hashlib.sha256(script).digest()
    
    if len(script_hash) != 32:
        raise ValueError(f"Invalid script hash length: {len(script_hash)}")
    
    return bytes([version]) + bytes([0x20]) + script_hash

def input_from_utxo(txid: bytes, index: int) -> bytes:
    """
    Create a transaction input from txid and index.
    Returns: serialized input with empty scriptSig and SEQUENCE_FINAL
    """
    if len(txid) != 32:
        raise ValueError(f"Invalid txid length: {len(txid)}")
    
    if not isinstance(index, int):
        raise ValueError("Index must be integer")
        
    if index < 0 or index > 0xffffffff:
        raise ValueError(f"Index out of range: {index}")
    
    input_bytes = bytearray()
    input_bytes.extend(txid)
    input_bytes.extend(index.to_bytes(4, "little"))
    input_bytes.append(0x00)  # Empty scriptSig
    input_bytes.extend(0xffffffff.to_bytes(4, "little"))  # SEQUENCE_FINAL
    
    return bytes(input_bytes)

def output_from_options(script: bytes, value: int) -> bytes:
    """
    Create a transaction output from script and value.
    Returns: serialized output with 8-byte value and script
    """
    if value < 0:
        raise ValueError("Value must be positive")
    if value > 21000000 * 100000000:
        raise ValueError("Value exceeds maximum supply")
    if not script:
        raise ValueError("Script cannot be empty")
    
    output = bytearray()
    output.extend(value.to_bytes(8, "little"))
    output.append(len(script))
    output.extend(script)
    
    return bytes(output)

def get_p2wpkh_scriptcode(utxo: object) -> bytes:
    """
    Create P2WPKH scriptcode from UTXO.
    Returns: script with DUP HASH160 <pubkeyhash> EQUALVERIFY CHECKSIG
    """
    if not isinstance(utxo, dict) or "scriptPubKey" not in utxo or "hex" not in utxo["scriptPubKey"]:
        raise ValueError("Invalid UTXO object structure.")
    
    script_hex = utxo["scriptPubKey"]["hex"]
    witness_program = bytes.fromhex(script_hex)

    if len(witness_program) != 22:
        raise ValueError("Invalid P2WPKH witness program length")
    if witness_program[0] != 0x00:
        raise ValueError("Invalid witness version")
    if witness_program[1] != 0x14:
        raise ValueError("Invalid P2WPKH length marker")
    
    pub_key_hash = witness_program[2:]

    scriptcode = bytearray([
        0x19,  # Total script length
        0x76,  # OP_DUP
        0xa9,  # OP_HASH160
        0x14,  # Push 20 bytes
    ])
    scriptcode.extend(pub_key_hash)
    scriptcode.extend([
        0x88,  # OP_EQUALVERIFY
        0xac   # OP_CHECKSIG
    ])

    return bytes(scriptcode)

def get_commitment_hash(outpoint: bytes, scriptcode: bytes, value: int, outputs: List[bytes]) -> bytes:
    """
    Compute BIP143 transaction digest for segwit signature hashing.
    """
    def dsha256(data: bytes) -> bytes:
        return hashlib.sha256(hashlib.sha256(data).digest()).digest()

    preimage = bytearray()

    # Version
    preimage.extend((2).to_bytes(4, "little"))
    
    # Prevouts hash
    preimage.extend(dsha256(outpoint))
    
    # Sequence hash
    sequence = 0xffffffff.to_bytes(4, "little")
    preimage.extend(dsha256(sequence))
    
    # Outpoint
    preimage.extend(outpoint)
    
    # Scriptcode
    preimage.extend(scriptcode)
    
    # Value
    preimage.extend(value.to_bytes(8, "little"))
    
    # Sequence
    preimage.extend(sequence)
    
    # Outputs hash
    preimage.extend(dsha256(b''.join(outputs)))
    
    # Locktime
    preimage.extend((0).to_bytes(4, "little"))
    
    # Sighash type
    preimage.extend((1).to_bytes(4, "little"))

    return dsha256(preimage)

def sign(priv: bytes, msg: bytes) -> bytes:
    """
    Create Bitcoin-compatible ECDSA signature.
    Returns: DER-encoded signature with low S value and SIGHASH_ALL byte
    """
    if not isinstance(priv, bytes) or len(priv) != 32:
        raise ValueError("Invalid private key")
    if len(msg) != 32:
        raise ValueError("Invalid message digest")

    signing_key = SigningKey.from_string(priv, curve=SECP256k1)
    signature = signing_key.sign_digest(msg, sigencode=sigencode_der)
    
    # Parse DER signature
    pos = 2
    r_len = signature[pos + 1]
    pos += 2
    r = int.from_bytes(signature[pos:pos + r_len], 'big')
    
    pos += r_len
    s_len = signature[pos + 1]
    pos += 2
    s = int.from_bytes(signature[pos:pos + s_len], 'big')

    # Enforce low S value
    half_order = SECP256k1.order // 2
    if s > half_order:
        s = SECP256k1.order - s

    # Reconstruct DER signature
    def der_encode_integer(value: int) -> bytes:
        value_bytes = value.to_bytes((value.bit_length() + 7) // 8, 'big')
        if value_bytes[0] & 0x80:
            value_bytes = b'\x00' + value_bytes
        return bytes([0x02, len(value_bytes)]) + value_bytes

    r_encoded = der_encode_integer(r)
    s_encoded = der_encode_integer(s)
    
    der_sig = bytes([0x30, len(r_encoded) + len(s_encoded)]) + r_encoded + s_encoded
    
    return der_sig + bytes([0x01])  # Append SIGHASH_ALL

def get_p2wpkh_witness(priv: bytes, msg: bytes) -> bytes:
    """
    Create P2WPKH witness stack with signature and pubkey.
    """
    pubkey = get_pub_from_priv(priv)
    if len(pubkey) != 33:
        raise ValueError("Invalid public key length")
    
    witness = bytearray()
    witness.append(0x02)  # Two witness elements
    
    signature = sign(priv, msg)
    witness.append(len(signature))
    witness.extend(signature)
    
    witness.append(0x21)  # 33 bytes for compressed pubkey
    witness.extend(pubkey)
    
    return bytes(witness)

def get_p2wsh_witness(privs: List[bytes], msg: bytes) -> bytes:
    """
    Create P2WSH witness stack for 2-of-2 multisig.
    Returns: 0x00 byte + signatures + redeem script
    """
    if len(privs) != 2:
        raise ValueError("Need exactly 2 private keys")
    for priv in privs:
        if len(priv) != 32:
            raise ValueError("Invalid private key length")
    if len(msg) != 32:
        raise ValueError("Invalid message digest")

    witness = bytearray()
    
    # Get and sort pubkeys with corresponding privkeys
    pubkeys = [get_pub_from_priv(priv) for priv in privs]
    sorted_pairs = sorted(zip(pubkeys, privs), key=lambda x: x[0])
    sorted_privs = [pair[1] for pair in sorted_pairs]
    
    witness.append(0x04)  # Four witness elements
    witness.append(0x00)  # CHECKMULTISIG bug
    
    # Add signatures in sorted order
    for priv in sorted_privs:
        signature = sign(priv, msg)
        witness.append(len(signature))
        witness.extend(signature)
    
    # Add redeem script
    redeem_script = create_multisig_script(pubkeys)
    witness.append(len(redeem_script))
    witness.extend(redeem_script)
    
    return bytes(witness)

def assemble_transaction(inputs: List[bytes], outputs: List[bytes], witnesses: List[bytes]) -> str:
    """
    Assemble complete segwit transaction.
    Returns: hex-encoded transaction ready for broadcast
    """
    tx = bytearray()
    
    tx.extend((2).to_bytes(4, "little"))  # Version
    tx.append(0x00)  # Segwit marker
    tx.append(0x01)  # Segwit flag
    
    tx.append(len(inputs))
    for input_data in inputs:
        tx.extend(input_data)
    
    tx.append(len(outputs))
    for output_data in outputs:
        tx.extend(output_data)
    
    for witness_data in witnesses:
        tx.extend(witness_data)
    
    tx.extend((0).to_bytes(4, "little"))  # Locktime
    
    return tx.hex()

def get_txid(inputs: List[bytes], outputs: List[bytes]) -> str:
    """
    Compute transaction ID (double SHA256 of non-witness data).
    Returns: reversed hex string of txid
    """
    def dsha256(data: bytes) -> bytes:
        return hashlib.sha256(hashlib.sha256(data).digest()).digest()

    def encode_varint(n: int) -> bytes:
        if n < 253:
            return bytes([n])
        elif n < 0x10000:
            return bytes([253]) + n.to_bytes(2, "little")
        elif n < 0x100000000:
            return bytes([254]) + n.to_bytes(4, "little")
        else:
            return bytes([255]) + n.to_bytes(8, "little")
    
    if not inputs or not outputs:
        raise ValueError("Empty inputs or outputs")
    
    tx_for_hash = bytearray()
    tx_for_hash.extend((2).to_bytes(4, "little"))  # Version
    tx_for_hash.extend(encode_varint(len(inputs)))
    
    for input_data in inputs:
        if len(input_data) < 41:
            raise ValueError("Invalid input data size")
        tx_for_hash.extend(input_data)
    
    tx_for_hash.extend(encode_varint(len(outputs)))
    
    for output_data in outputs:
        if len(output_data) < 9:
            raise ValueError("Invalid output data size")
        tx_for_hash.extend(output_data)
    
    tx_for_hash.extend((0).to_bytes(4, "little"))  # Locktime
    
    hashit = dsha256(tx_for_hash)
    return hashit[::-1].hex()

def verify_utxo(txid: str, vout: int) -> tuple[bool, dict]:
    """
    Verify if UTXO exists and is spendable.
    Returns: (is_spendable, utxo_info)
    """
    try:
        result = subprocess.run(
            ['bitcoin-cli', '-signet', 'gettxout', txid, str(vout)],
            capture_output=True,
            text=True
        )
        
        if result.returncode != 0 or not result.stdout.strip():
            return False, None
            
        return True, json.loads(result.stdout)
        
    except Exception:
        return False, None
    

def spend_p2wpkh(state: object) -> tuple[str, str, List[bytes], List[int]]:
    """
    Creates a transaction spending from p2wpkh to p2wsh multisig.
    The transaction structure will have:
    - Input: P2WPKH UTXO
    - Output 0: Destination P2WSH multisig (1,000,000 satoshis)
    - Output 1: Change back to P2WPKH using same key as input
    
    Args:
        state: Wallet state containing UTXOs, keys, and programs
        
    Returns:
        tuple: (txid, raw_transaction, [pubkey1, pubkey2], [key_index1, key_index2])
    """
    FEE = 1000
    AMT = 1000000  # 0.01 BTC

    # Sort UTXOs by amount in descending order to try largest first
    sorted_utxos = sorted(state["utxo"].items(),
                         key=lambda x: float(x[1]),
                         reverse=True)

    def find_key_for_utxo(utxo_info: dict) -> tuple[bytes, bytes, bytes, int]:
        """
        Find the matching private key, public key, program, and index for a UTXO.
        Returns (private_key, public_key, witness_program, key_index) or raises if not found.
        """
        script_hex = utxo_info["scriptPubKey"]["hex"]
        utxo_program = bytes.fromhex(script_hex)
        
        for i, program in enumerate(state["programs"]):
            if program == utxo_program:
                return state["privs"][i], state["pubs"][i], program, i
                
        raise ValueError("No matching key found for UTXO")

    for outpoint, amount in sorted_utxos:
        try:
            txid_str, vout_str = outpoint.split(":")
            vout = int(vout_str)
            
            # Verify UTXO is spendable and get its details
            is_spendable, utxo_info = verify_utxo(txid_str, vout)
            if not is_spendable:
                continue
            
            # Find the correct key pair and index for this UTXO
            try:
                privkey, pubkey, program, input_key_index = find_key_for_utxo(utxo_info)
            except ValueError:
                continue
            
            # Convert amount from BTC to satoshis
            amount_sats = int(float(amount) * 100_000_000)
            
            if amount_sats <= (AMT + FEE):
                continue

            # Create transaction input
            txid_bytes = bytes.fromhex(txid_str)[::-1]  # Reverse for internal use
            input_data = input_from_utxo(txid_bytes, vout)
            outpoint_bytes = txid_bytes + vout.to_bytes(4, "little")

            # Select keys for multisig based on input key index
            # Use the next two consecutive keys after our input key
            multisig_key1_index = (input_key_index + 1) % len(state["privs"])
            multisig_key2_index = (input_key_index + 2) % len(state["privs"])
            
            pubkey1 = get_pub_from_priv(state["privs"][multisig_key1_index])
            pubkey2 = get_pub_from_priv(state["privs"][multisig_key2_index])
            
            # Create P2WSH multisig script and program
            multisig_script = create_multisig_script([pubkey1, pubkey2])
            witness_program = get_p2wsh_program(multisig_script)

            # Create outputs in order (destination first, then change)
            destination_output = output_from_options(
                witness_program,  # P2WSH program for multisig
                AMT
            )

            change_amount = amount_sats - AMT - FEE
            change_output = output_from_options(
                program,  # Use same program as input for change
                change_amount
            )

            # Create scriptcode and commitment hash
            scriptcode = get_p2wpkh_scriptcode({
                "scriptPubKey": {"hex": program.hex()}
            })

            commitment = get_commitment_hash(
                outpoint_bytes,
                scriptcode,
                amount_sats,
                [destination_output, change_output]
            )

            # Create witness and assemble transaction
            witness = get_p2wpkh_witness(privkey, commitment)
            
            tx = assemble_transaction(
                [input_data],
                [destination_output, change_output],
                [witness]
            )

            # Calculate TXID from non-witness data
            txid = get_txid(
                [input_data],
                [destination_output, change_output]
            )

            return txid, tx, [pubkey1, pubkey2], [multisig_key1_index, multisig_key2_index]

        except Exception:
            continue

    raise ValueError("No spendable UTXOs found")

def spend_p2wsh(state: object, txid: str, used_pubkeys: List[bytes], key_indexes: List[int]) -> str:
    """
    Create and sign transaction spending from P2WSH multisig to OP_RETURN.
    
    Args:
        state: Wallet state with keys and programs
        txid: TXID of the P2WSH output to spend
        used_pubkeys: Public keys used in the multisig script
        key_indexes: Indexes of private keys for signing
    
    Returns:
        str: Raw transaction hex
    """
    COIN_VALUE = 1000000  # 0.01 BTC from first tx
    FEE = 1000
    
    # Create input from first transaction's output
    txid_bytes = bytes.fromhex(txid)[::-1]  # Reverse for internal byte order
    outpoint = txid_bytes + (0).to_bytes(4, "little")
    input_data = input_from_utxo(txid_bytes, 0)
    
    # Create OP_RETURN output
    name = "SIGNET CHALLENGE BY SAMOD"
    name_bytes = name.encode('ascii')
    op_return_script = bytes([0x6a, len(name_bytes)]) + name_bytes
    op_return_output = output_from_options(op_return_script, 0)
    
    # Create change output
    change_amount = COIN_VALUE - FEE
    change_output = output_from_options(state["programs"][0], change_amount)
    
    # Recreate multisig script and create scriptcode (with length prefix)
    multisig_script = create_multisig_script(used_pubkeys)
    scriptcode = bytes([len(multisig_script)]) + multisig_script

    # Create commitment hash for signing
    commitment = get_commitment_hash(
        outpoint,
        scriptcode,
        COIN_VALUE,
        [op_return_output, change_output]
    )

    # Create witness stack with signatures in correct order
    witness = get_p2wsh_witness(
        [state["privs"][key_indexes[0]], state["privs"][key_indexes[1]]],
        commitment
    )
    
    # Assemble and return complete transaction
    return assemble_transaction(
        [input_data],
        [op_return_output, change_output],
        [witness]
    )

if __name__ == "__main__":
    try:
        state = recover_wallet_state(EXTENDED_PRIVATE_KEY)
        
        # Create first transaction (P2WPKH to P2WSH)
        txid1, tx1, used_pubkeys, key_indexes = spend_p2wpkh(state)
        
        # Create second transaction (P2WSH to OP_RETURN)
        tx2 = spend_p2wsh(state, txid1, used_pubkeys, key_indexes)
        
        # Output hex-encoded transactions
        print(tx1)
        print(tx2)
        
    except Exception:
        sys.exit(1)