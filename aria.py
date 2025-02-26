import os
import secrets
from typing import List, Tuple

# ---------------------------
# Conversion Utilities
# ---------------------------
def to_int(byte_array: List[int]) -> int:
    """
    Convert a 4-byte array to a 32-bit integer.
    """
    if len(byte_array) != 4:
        raise ValueError(f"to_int: la longueur de byte_array doit être 4, obtenu {len(byte_array)}")
    return (byte_array[0] << 24) | (byte_array[1] << 16) | (byte_array[2] << 8) | byte_array[3]

def to_byte_array(integer: int) -> List[int]:
    """
    Convert a 32-bit integer to a 4-byte array.
    """
    return [(integer >> 24) & 0xff, (integer >> 16) & 0xff, (integer >> 8) & 0xff, integer & 0xff]

# ---------------------------
# ARIA Core Functions
# ---------------------------
def m(t: int) -> int:
    """
    Perform the multiplication function for ARIA.
    """
    return (0x00010101 * ((t >> 24) & 0xff) ^
            0x01000101 * ((t >> 16) & 0xff) ^
            0x01010001 * ((t >> 8) & 0xff) ^
            0x01010100 * (t & 0xff))

def badc(t: int) -> int:
    """
    Swap adjacent bytes.
    """
    return ((t << 8) & 0xff00ff00) ^ ((t >> 8) & 0x00ff00ff)

def cdab(t: int) -> int:
    """
    Swap pairs of bytes.
    """
    return ((t << 16) & 0xffff0000) ^ ((t >> 16) & 0x0000ffff)

def dcba(t: int) -> int:
    """
    Reverse the byte order.
    """
    return ((t & 0x000000ff) << 24) ^ ((t & 0x0000ff00) << 8) ^ ((t & 0x00ff0000) >> 8) ^ ((t & 0xff000000) >> 24)

def gsrk(x: List[int], y: List[int], rot: int) -> List[int]:
    """
    Generate subkeys using a rotation and mix function.
    """
    if len(x) != 4 or len(y) != 4:
        raise ValueError(f"gsrk: la taille des entrées doit être 4, obtenu x={len(x)}, y={len(y)}")
    q = 4 - (rot // 32)
    r = rot % 32
    s = 32 - r

    return [
        x[0] ^ ((y[q % 4] >> r) & 0xffffffff) ^ ((y[(q + 3) % 4] << s) & 0xffffffff),
        x[1] ^ ((y[(q + 1) % 4] >> r) & 0xffffffff) ^ ((y[q % 4] << s) & 0xffffffff),
        x[2] ^ ((y[(q + 2) % 4] >> r) & 0xffffffff) ^ ((y[(q + 1) % 4] << s) & 0xffffffff),
        x[3] ^ ((y[(q + 3) % 4] >> r) & 0xffffffff) ^ ((y[(q + 2) % 4] << s) & 0xffffffff)
    ]

def diff(i: List[int]) -> List[int]:
    """
    Apply the diffusion function to a block represented as a list of four 32-bit integers.
    """
    if len(i) != 4:
        raise ValueError(f"diff: la taille d'entrée doit être 4, obtenu {len(i)}")
    t0, t1, t2, t3 = m(i[0]), m(i[1]), m(i[2]), m(i[3])

    # First round of mixing
    t1 ^= t2
    t2 ^= t3
    t0 ^= t1
    t3 ^= t1
    t2 ^= t0
    t1 ^= t2

    # Apply byte reordering functions
    t1 = badc(t1)
    t2 = cdab(t2)
    t3 = dcba(t3)

    # Second round of mixing
    t1 ^= t2
    t2 ^= t3
    t0 ^= t1
    t3 ^= t1
    t2 ^= t0
    t1 ^= t2

    return [t0, t1, t2, t3]

def do_enc_key_setup(mk: List[int], key_bits: int) -> Tuple[List[int], List[int], List[int]]:
    """
    Set up the encryption keys using the master key.
    """
    # Key rotation constants for different key sizes
    krk = [
        [0x517cc1b7, 0x27220a94, 0xfe13abe8, 0xfa9a6ee0],
        [0x6db14acc, 0x9e21c820, 0xff28b1d5, 0xef5de2b0],
        [0xdb92371d, 0x2126e970, 0x03249775, 0x04e8c90e]
    ]
    # Convert master key bytes to 32-bit words
    w = [to_int(mk[i:i+4]) for i in range(0, len(mk), 4)]
    q = (key_bits - 128) // 64
    t = [w[i] ^ krk[q][i] for i in range(4)]

    k0 = t
    k1 = diff(t)
    k2 = diff(diff(t))

    # Key mixing steps
    k1 = [k1[i] ^ k0[i] for i in range(4)]
    k2 = [k2[i] ^ k1[i] for i in range(4)]
    return k0, k1, k2

def do_crypt(in_blk: List[int], key: Tuple[List[int], List[int], List[int]], rounds: int) -> List[int]:
    """
    Encrypt or decrypt a 16-byte block using the provided key schedule.
    """
    if len(in_blk) != 16:
        raise ValueError(f"do_crypt: la taille du bloc d'entrée doit être 16, obtenu {len(in_blk)}")
    k0, k1, k2 = key

    # Initial key addition
    x = [
        to_int(in_blk[0:4]) ^ k0[0],
        to_int(in_blk[4:8]) ^ k0[1],
        to_int(in_blk[8:12]) ^ k0[2],
        to_int(in_blk[12:16]) ^ k0[3]
    ]

    # Rounds of diffusion and subkey mixing
    for _ in range(rounds - 1):
        x = diff(gsrk(diff(x), k1, 19))
        x = diff(gsrk(diff(x), k2, 31))
    x = diff(gsrk(diff(x), k1, 19))

    # Convert result back to a byte array
    out_blk: List[int] = []
    for num in x:
        out_blk.extend(to_byte_array(num))
    return out_blk

# ---------------------------
# Padding and Block Size Validation
# ---------------------------
def pkcs7_pad(data: bytes, block_size: int = 16) -> bytes:
    """
    Apply PKCS#7 padding to data.
    """
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len] * pad_len)

def pkcs7_unpad(padded_data: bytes) -> bytes:
    """
    Remove PKCS#7 padding.
    """
    pad_len = padded_data[-1]
    if pad_len < 1 or pad_len > len(padded_data):
        raise ValueError("Padding invalide")
    if not all(p == pad_len for p in padded_data[-pad_len:]):
        raise ValueError("Structure de padding invalide")
    return padded_data[:-pad_len]

def validate_block_size(data: bytes, block_size: int = 16) -> None:
    """
    Validate that data length is a multiple of the block size.
    """
    if len(data) % block_size != 0:
        raise ValueError("Les données ne sont pas alignées sur la taille du bloc")

# ---------------------------
# Key Generation
# ---------------------------
def generate_key(key_bits: int = 128) -> List[int]:
    """
    Generate a cryptographically secure random key.
    """
    if key_bits not in [128, 192, 256]:
        raise ValueError("La taille de clé doit être 128, 192 ou 256 bits")
    key_length = key_bits // 8
    return list(secrets.token_bytes(key_length))

# ---------------------------
# Encryption and Decryption Functions
# ---------------------------
def aria_encrypt(plain_text: str, master_key: List[int], key_bits: int = 128, rounds: int = 16) -> bytes:
    """
    Encrypt a plaintext string using ARIA.
    """
    expected_key_length = key_bits // 8
    if len(master_key) != expected_key_length:
        raise ValueError(f"La longueur de master_key doit être {expected_key_length}, obtenu {len(master_key)}")
    
    # Encode if input is string and pad
    if isinstance(plain_text, str):
        plain_text = plain_text.encode('utf-8')
    plain_text = pkcs7_pad(plain_text)

    key_schedule = do_enc_key_setup(master_key, key_bits)
    blocks = [plain_text[i:i+16] for i in range(0, len(plain_text), 16)]
    encrypted_blocks = [bytes(do_crypt(list(block), key_schedule, rounds)) for block in blocks]
    return b''.join(encrypted_blocks)

def aria_decrypt(cipher_text: bytes, master_key: List[int], key_bits: int = 128, rounds: int = 16) -> str:
    """
    Decrypt a ciphertext (in bytes) using ARIA.
    """
    validate_block_size(cipher_text)
    key_schedule = do_enc_key_setup(master_key, key_bits)
    blocks = [cipher_text[i:i+16] for i in range(0, len(cipher_text), 16)]
    decrypted_blocks = [bytes(do_crypt(list(block), key_schedule, rounds)) for block in blocks]
    decrypted_data = b''.join(decrypted_blocks)
    return pkcs7_unpad(decrypted_data).decode('utf-8')

def encrypt_file(input_file: str, output_file: str, master_key: List[int], key_bits: int = 128, rounds: int = 16) -> bool:
    """
    Encrypt a file using ARIA.
    """
    try:
        with open(input_file, "rb") as f:
            data = f.read()
        padded_data = pkcs7_pad(data)
        key_schedule = do_enc_key_setup(master_key, key_bits)
        blocks = [padded_data[i:i+16] for i in range(0, len(padded_data), 16)]
        encrypted_blocks = [bytes(do_crypt(list(block), key_schedule, rounds)) for block in blocks]

        with open(output_file, "wb") as f:
            f.write(b''.join(encrypted_blocks))
        return True
    except Exception as e:
        raise RuntimeError(f"Échec de l'encryption du fichier : {e}")

def decrypt_file(input_file: str, output_file: str, master_key: List[int], key_bits: int = 128, rounds: int = 16) -> bool:
    """
    Decrypt a file using ARIA.
    """
    try:
        with open(input_file, "rb") as f:
            data = f.read()
        validate_block_size(data)
        key_schedule = do_enc_key_setup(master_key, key_bits)
        blocks = [data[i:i+16] for i in range(0, len(data), 16)]
        decrypted_blocks = [bytes(do_crypt(list(block), key_schedule, rounds)) for block in blocks]
        decrypted_data = b''.join(decrypted_blocks)
        unpadded_data = pkcs7_unpad(decrypted_data)

        with open(output_file, "wb") as f:
            f.write(unpadded_data)
        return True
    except Exception as e:
        raise RuntimeError(f"Échec du déchiffrement du fichier : {e}")

# ---------------------------
# Command-Line Interface
# ---------------------------
def main() -> None:
    print("===== Système d'encryption ARIA =====")
    print("Crédits : Inspiré par les auteurs du cipher ARIA (2003)")
    print("======================================\n")

    # Key selection or generation
    print("Choisissez l'option pour la clé :")
    print("1. Générer une clé (128 bits)")
    print("2. Générer une clé (192 bits)")
    print("3. Générer une clé (256 bits)")
    print("4. Saisir une clé (hexadécimal)")
    choice = input("Votre choix (1-4) : ").strip()
    key_bits = 128
    master_key: List[int] = []

    if choice in ['1', '2', '3']:
        key_bits = [128, 192, 256][int(choice) - 1]
        master_key = generate_key(key_bits)
        print(f"Clé générée ({key_bits} bits) : {bytes(master_key).hex()}\n")
    elif choice == '4':
        key_hex = input("Entrez votre clé en format hexadécimal : ").strip()
        master_key = list(bytes.fromhex(key_hex))
        key_bits = len(master_key) * 8
        print(f"Clé saisie ({key_bits} bits) : {key_hex}\n")
    else:
        print("Choix invalide.")
        return

    # Choose the number of rounds
    rounds_input = input("Entrez le nombre de tours à utiliser (entre 1 et 16, par défaut 16) : ").strip()
    rounds = 16
    if rounds_input:
        try:
            rounds = int(rounds_input)
            if rounds < 1 or rounds > 16:
                print("Le nombre de tours doit être compris entre 1 et 16. Utilisation de 16 par défaut.")
                rounds = 16
        except ValueError:
            print("Nombre de tours invalide, utilisation de 16 par défaut.")

    # Choose action
    print("\nQue souhaitez-vous faire ?")
    print("1. Chiffrer")
    print("2. Déchiffrer")
    action = input("Votre choix (1-2) : ").strip()

    # Choose target: text or file
    print("Sélectionnez la cible :")
    print("1. Texte")
    print("2. Fichier")
    target = input("Votre choix (1-2) : ").strip()

    if action == '1' and target == '1':  # Encrypt text
        plain_text = input("Entrez le texte à chiffrer : ")
        try:
            encrypted = aria_encrypt(plain_text, master_key, key_bits, rounds)
            print(f"Texte chiffré (hex) : {encrypted.hex()}")
        except Exception as e:
            print(f"Erreur lors de l'encryption : {e}")

    elif action == '2' and target == '1':  # Decrypt text
        cipher_hex = input("Entrez le texte chiffré (en hex) : ")
        key_hex = input("Entrez la clé de déchiffrement (en hex) : ")
        try:
            key_bytes = list(bytes.fromhex(key_hex))
            if len(key_bytes) * 8 != key_bits:
                raise ValueError(f"La clé doit être de {key_bits} bits, obtenu {len(key_bytes) * 8} bits.")
            decrypted = aria_decrypt(bytes.fromhex(cipher_hex), key_bytes, key_bits, rounds)
            print(f"Texte déchiffré : {decrypted}")
        except Exception as e:
            print(f"Erreur lors du déchiffrement : {e}")

    elif action == '1' and target == '2':  # Encrypt file
        input_file = input("Entrez le chemin du fichier source : ").strip()
        output_file = input("Entrez le chemin du fichier de destination : ").strip()
        try:
            if encrypt_file(input_file, output_file, master_key, key_bits, rounds):
                print("Fichier chiffré avec succès.")
        except Exception as e:
            print(f"Erreur lors de l'encryption du fichier : {e}")

    elif action == '2' and target == '2':  # Decrypt file
        input_file = input("Entrez le chemin du fichier source : ").strip()
        output_file = input("Entrez le chemin du fichier de destination : ").strip()
        key_hex = input("Entrez la clé de déchiffrement (en hex) : ").strip()
        try:
            key_bytes = list(bytes.fromhex(key_hex))
            if len(key_bytes) * 8 != key_bits:
                raise ValueError(f"La clé doit être de {key_bits} bits, obtenu {len(key_bytes) * 8} bits.")
            if decrypt_file(input_file, output_file, key_bytes, key_bits, rounds):
                print("Fichier déchiffré avec succès.")
        except Exception as e:
            print(f"Erreur lors du déchiffrement : {e}")
    else:
        print("Option invalide.")

if __name__ == "__main__":
    main()