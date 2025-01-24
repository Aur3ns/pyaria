import curses
import os
import random
from curses import wrapper
from curses.textpad import Textbox, rectangle
import time

# Cypher Functions
def to_int(byte_array):
    assert len(byte_array) == 4, f"to_int: byte_array length must be 4, got {len(byte_array)}"
    return (byte_array[0] << 24) | (byte_array[1] << 16) | (byte_array[2] << 8) | byte_array[3]

def to_byte_array(integer):
    return [(integer >> 24) & 0xff, (integer >> 16) & 0xff, (integer >> 8) & 0xff, integer & 0xff]

# Functions ARIA
def m(t):
    return 0x00010101 * ((t >> 24) & 0xff) ^ 0x01000101 * ((t >> 16) & 0xff) ^ \
           0x01010001 * ((t >> 8) & 0xff) ^ 0x01010100 * (t & 0xff)

def badc(t):
    return ((t << 8) & 0xff00ff00) ^ ((t >> 8) & 0x00ff00ff)

def cdab(t):
    return ((t << 16) & 0xffff0000) ^ ((t >> 16) & 0x0000ffff)

def dcba(t):
    return (t & 0x000000ff) << 24 ^ (t & 0x0000ff00) << 8 ^ (t & 0x00ff0000) >> 8 ^ (t & 0xff000000) >> 24

def gsrk(x, y, rot):
    assert len(x) == 4 and len(y) == 4, f"gsrk: Input sizes must be 4, got x={len(x)}, y={len(y)}"
    q = 4 - (rot // 32)
    r = rot % 32
    s = 32 - r

    print(f"gsrk: before x={x}, y={y}, q={q}, r={r}, s={s}")

    result = [
        x[0] ^ (y[(q) % 4] >> r) ^ (y[(q + 3) % 4] << s),
        x[1] ^ (y[(q + 1) % 4] >> r) ^ (y[(q) % 4] << s),
        x[2] ^ (y[(q + 2) % 4] >> r) ^ (y[(q + 1) % 4] << s),
        x[3] ^ (y[(q + 3) % 4] >> r) ^ (y[(q + 2) % 4] << s)
    ]

    print(f"gsrk: after = {result}")
    return result

def diff(i):
    assert len(i) == 4, f"diff: Input size must be 4, got {len(i)}"
    t0, t1, t2, t3 = m(i[0]), m(i[1]), m(i[2]), m(i[3])
    print(f"diff: After m = {[t0, t1, t2, t3]}")

    t1 ^= t2
    t2 ^= t3
    t0 ^= t1
    t3 ^= t1
    t2 ^= t0
    t1 ^= t2

    t1, t2, t3 = badc(t1), cdab(t2), dcba(t3)

    t1 ^= t2
    t2 ^= t3
    t0 ^= t1
    t3 ^= t1
    t2 ^= t0
    t1 ^= t2

    result = [t0, t1, t2, t3]
    assert len(result) == 4, f"diff: Output size must be 4, got {len(result)}"
    print(f"diff: Final result = {result}")
    return result

def do_enc_key_setup(mk, key_bits):
    krk = [
        [0x517cc1b7, 0x27220a94, 0xfe13abe8, 0xfa9a6ee0],
        [0x6db14acc, 0x9e21c820, 0xff28b1d5, 0xef5de2b0],
        [0xdb92371d, 0x2126e970, 0x03249775, 0x04e8c90e]
    ]

    # Master key in blocks of 32 bits
    w = [to_int(mk[i:i+4]) for i in range(0, len(mk), 4)]
    print(f"do_enc_key_setup: w = {w}")

    q = (key_bits - 128) // 64
    t = [w[i] ^ krk[q][i] for i in range(4)]
    print(f"do_enc_key_setup: t = {t}")

    # Intermediate key generation
    k0 = t
    k1 = diff(t)
    k2 = diff(diff(t))

    assert len(k1) == 4, f"do_enc_key_setup: k1 length must be 4, got {len(k1)}"
    assert len(k2) == 4, f"do_enc_key_setup: k2 length must be 4, got {len(k2)}"

    k1 = [k1[i] ^ k0[i] for i in range(4)]
    k2 = [k2[i] ^ k1[i] for i in range(4)]

    print(f"do_enc_key_setup: k0 = {k0}, k1 = {k1}, k2 = {k2}")
    return k0, k1, k2


def do_crypt(in_blk, key, rounds):
    assert len(in_blk) == 16, f"do_crypt: Input block size must be 16, got {len(in_blk)}"
    k0, k1, k2 = key

    print(f"do_crypt: in_blk = {in_blk}")
    print(f"do_crypt: k1 = {k1}, k2 = {k2}")

    assert len(k1) == 4, f"do_crypt: k1 length must be 4, got {len(k1)}"
    assert len(k2) == 4, f"do_crypt: k2 length must be 4, got {len(k2)}"

    x = [
        to_int(in_blk[0:4]) ^ k0[0],
        to_int(in_blk[4:8]) ^ k0[1],
        to_int(in_blk[8:12]) ^ k0[2],
        to_int(in_blk[12:16]) ^ k0[3]
    ]

    print(f"do_crypt: x after initial xor = {x}")

    for r in range(rounds - 1):
        x = diff(gsrk(diff(x), k1, 19))
        x = diff(gsrk(diff(x), k2, 31))

    x = diff(gsrk(diff(x), k1, 19))

    out_blk = [
        (x[0] >> 24) & 0xff, (x[0] >> 16) & 0xff, (x[0] >> 8) & 0xff, x[0] & 0xff,
        (x[1] >> 24) & 0xff, (x[1] >> 16) & 0xff, (x[1] >> 8) & 0xff, x[1] & 0xff,
        (x[2] >> 24) & 0xff, (x[2] >> 16) & 0xff, (x[2] >> 8) & 0xff, x[2] & 0xff,
        (x[3] >> 24) & 0xff, (x[3] >> 16) & 0xff, (x[3] >> 8) & 0xff, x[3] & 0xff
    ]

    print(f"do_crypt: out_blk = {out_blk}")
    return out_blk

# Padding and validation utilities
def pkcs7_pad(data, block_size=16):
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len] * pad_len)

def pkcs7_unpad(padded_data):
    pad_len = padded_data[-1]
    if pad_len < 1 or pad_len > len(padded_data):
        raise ValueError("Invalid padding")
    if not all(p == pad_len for p in padded_data[-pad_len:]):
        raise ValueError("Invalid padding structure")
    return padded_data[:-pad_len]

def validate_block_size(data, block_size=16):
    if len(data) % block_size != 0:
        raise ValueError("Data is not properly aligned to block size")

# Key generation utility
def generate_key(key_bits=128):
    if key_bits not in [128, 192, 256]:
        raise ValueError("Key size must be 128, 192, or 256 bits")
    return [random.randint(0, 255) for _ in range(key_bits // 8)]

def aria_encrypt(plain_text, master_key, key_bits=128):
    try:
        expected_key_length = key_bits // 8
        assert len(master_key) == expected_key_length, f"aria_encrypt: master_key length must be {expected_key_length}, got {len(master_key)}"

        if isinstance(plain_text, str):
            plain_text = plain_text.encode('utf-8')
        plain_text = pkcs7_pad(plain_text)

        key_schedule = do_enc_key_setup(master_key, key_bits)
        blocks = [plain_text[i:i+16] for i in range(0, len(plain_text), 16)]

        encrypted_blocks = []
        for block in blocks:
            assert len(block) == 16
            encrypted_block = bytes(do_crypt(list(block), key_schedule, 16))
            encrypted_blocks.append(encrypted_block)

        return b''.join(encrypted_blocks)
    except Exception as e:
        raise RuntimeError(f"Encryption failed: {e}")

def aria_decrypt(cipher_text, master_key, key_bits=128):
    try:
        validate_block_size(cipher_text)
        key_schedule = do_enc_key_setup(master_key, key_bits)
        blocks = [cipher_text[i:i+16] for i in range(0, len(cipher_text), 16)]

        decrypted_blocks = []
        for block in blocks:
            assert len(block) == 16
            decrypted_block = bytes(do_crypt(list(block), key_schedule, 16))
            decrypted_blocks.append(decrypted_block)

        decrypted_data = b''.join(decrypted_blocks)
        return pkcs7_unpad(decrypted_data).decode('utf-8')
    except Exception as e:
        raise RuntimeError(f"Decryption failed: {e}")

def encrypt_file(input_file, output_file, master_key, key_bits=128):
    try:
        with open(input_file, "rb") as f:
            data = f.read()

        padded_data = pkcs7_pad(data)
        key_schedule = do_enc_key_setup(master_key, key_bits)
        blocks = [padded_data[i:i+16] for i in range(0, len(padded_data), 16)]
        encrypted_blocks = [bytes(do_crypt(list(block), key_schedule, 16)) for block in blocks]

        with open(output_file, "wb") as f:
            f.write(b''.join(encrypted_blocks))
        return True
    except Exception as e:
        raise RuntimeError(f"File encryption failed: {e}")


def decrypt_file(input_file, output_file, master_key, key_bits=128):
    try:
        with open(input_file, "rb") as f:
            data = f.read()

        validate_block_size(data)
        key_schedule = do_enc_key_setup(master_key, key_bits)
        blocks = [data[i:i+16] for i in range(0, len(data), 16)]
        decrypted_blocks = [bytes(do_crypt(list(block), key_schedule, 16)) for block in blocks]
        decrypted_data = b''.join(decrypted_blocks)

        unpadded_data = pkcs7_unpad(decrypted_data)
        with open(output_file, "wb") as f:
            f.write(unpadded_data)
        return True
    except Exception as e:
        raise RuntimeError(f"File decryption failed: {e}")


def display_credits(stdscr):
    # Première page : TheBlackBird
    page_one = r"""
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣀⣀⣀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣴⣿⣿⡟⠋⢻⣷⣄⡀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣤⣾⣿⣷⣿⣿⣿⣿⣿⣶⣾⣿⣿⠿⠿⠿⠶⠄⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠉⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡇⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡟⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠃⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠃⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⣿⣿⣿⣿⣿⣿⣿⡟⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⣿⣿⣿⣿⣿⣿⠟⠻⣧⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⣼⣿⣿⣿⣿⣿⣿⣆⣤⠿⢶⣦⡀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⢰⣿⣿⣿⣿⣿⣿⣿⣿⡀⠀⠀⠀⠑⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⣿⣿⣿⣿⣿⣿⣿⣿⣿⣇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠸⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠉⠙⠛⠋⠉⠉⠀⠀⠀

Done by TheBlackBird
"""
    # Deuxième page : Inspired by...
    page_two = r"""

ARIA Encryption System

Inspired by the authors of the ARIA cipher:
Daesung Kwon, Jaesung Kim, Sangwoo Park, Soo Hak Sung,
Yaekwon Sohn, Jung Hwan Song, Yongjin Yeom, E-Joong Yoon, 
Sangjin Lee, Jaewon Lee, Seongtaek Chee, Daewan Han, Jin Hong
KISA, Korean National Security Research Institute

New Block Cipher : ARIA , 2003

"""

    # Afficher la première page
    stdscr.clear()
    curses.start_color()
    curses.init_pair(1, curses.COLOR_GREEN, curses.COLOR_BLACK)
    GREEN = curses.color_pair(1)

    for i, line in enumerate(page_one.split("\n")):
        stdscr.addstr(5 + i, (curses.COLS - len(line)) // 2, line, GREEN)
    stdscr.addstr(curses.LINES - 2, (curses.COLS - len("Press any key to continue...")) // 2, "Press any key to continue...", GREEN)
    stdscr.refresh()
    stdscr.getch()

    # Afficher la deuxième page
    stdscr.clear()
    for i, line in enumerate(page_two.split("\n")):
        stdscr.addstr(5 + i, (curses.COLS - len(line)) // 2, line, GREEN)
    stdscr.addstr(curses.LINES - 2, (curses.COLS - len("Press any key to continue...")) // 2, "Press any key to continue...", GREEN)
    stdscr.refresh()
    stdscr.getch()


class AriaInterface:
    def __init__(self, stdscr):
        self.stdscr = stdscr
        self.height, self.width = stdscr.getmaxyx()
        curses.start_color()
        curses.init_pair(1, curses.COLOR_GREEN, curses.COLOR_BLACK)
        curses.init_pair(2, curses.COLOR_BLACK, curses.COLOR_GREEN)
        curses.init_pair(3, curses.COLOR_RED, curses.COLOR_BLACK)

        self.GREEN = curses.color_pair(1)
        self.SELECTED = curses.color_pair(2)
        self.ERROR = curses.color_pair(3)
        curses.curs_set(0)

        self.logs = []
        self.key = None  # Stocker la clé
        self.key_bits = 128  # Par défaut 128 bits

        # Création de fenêtres
        self.menu_win = curses.newwin(self.height // 2, self.width, 0, 0)
        self.logs_win = curses.newwin(self.height // 2 - 2, self.width, self.height // 2, 0)
        self.status_win = curses.newwin(1, self.width, self.height - 1, 0)

    def add_log(self, message, error=False):
        prefix = "[ERROR]" if error else "[INFO]"
        self.logs.append(f"{prefix} {message}")
        if len(self.logs) > self.logs_win.getmaxyx()[0] - 2:
            self.logs.pop(0)

    def draw_logs(self):
        self.logs_win.clear()
        self.logs_win.border(0)
        
        # Titre centré
        title = "LOGS"
        max_width = self.logs_win.getmaxyx()[1] - 2
        centered_x = (max_width - len(title)) // 2
        self.logs_win.addstr(0, centered_x, title, self.GREEN)
    
        for i, log in enumerate(self.logs):
            color = self.ERROR if "[ERROR]" in log else self.GREEN
            self.logs_win.addstr(1 + i, 2, log[:max_width - 4], color)
    
        self.logs_win.refresh()

    def draw_menu(self, options, current_option):
        self.menu_win.clear()
        self.menu_win.border(0)
        title = [
            "╔══════════════════════════════════════╗",
            "║        ARIA ENCRYPTION SYSTEM        ║",
            "║               [¬º-°]¬                ║",
            "╚══════════════════════════════════════╝"
        ]
        for i, line in enumerate(title):
            self.menu_win.addstr(i + 1, (self.width - len(line)) // 2, line, self.GREEN)

        menu_y = 6
        for i, option in enumerate(options):
            x = (self.width - len(option)) // 2
            style = self.SELECTED if i == current_option else self.GREEN
            self.menu_win.addstr(menu_y + i * 2, x, option, style)
        self.menu_win.refresh()

    def set_status(self, status):
        self.status_win.clear()
        self.status_win.addstr(0, 2, f"Status: {status}".ljust(self.width - 4), self.GREEN)
        self.status_win.refresh()

    def select_key(self):
        """Menu pour choisir ou générer la clé."""
        key_options = ["Generate Key (128 bits)", "Generate Key (192 bits)", "Generate Key (256 bits)", "Enter Key (Hexadecimal)"]
        current_option = 0

        while True:
            self.draw_menu(key_options, current_option)
            self.set_status("Use UP/DOWN to navigate, ENTER to select.")

            key = self.stdscr.getch()
            if key == curses.KEY_UP and current_option > 0:
                current_option -= 1
            elif key == curses.KEY_DOWN and current_option < len(key_options) - 1:
                current_option += 1
            elif key == 10:  # Enter
                if current_option < 3:  # Générer une clé
                    self.key_bits = [128, 192, 256][current_option]
                    self.key = generate_key(self.key_bits)
                    self.add_log(f"Generated key ({self.key_bits} bits): {bytes(self.key).hex()}")
                else:  # Saisir une clé manuellement
                    self.set_status("Enter your key in hexadecimal format.")
                    curses.curs_set(1)
                    editwin = curses.newwin(1, self.width - 4, self.height // 2, 2)
                    box = Textbox(editwin)
                    box.edit()
                    curses.curs_set(0)

                    key_hex = box.gather().strip()
                    self.key = bytes.fromhex(key_hex)
                    self.key_bits = len(self.key) * 8
                    self.add_log(f"Entered key ({self.key_bits} bits): {key_hex}")
                break

    def choose_action(self):
        """Menu pour choisir entre chiffrement ou déchiffrement."""
        options = ["Encrypt", "Decrypt"]
        current_option = 0

        while True:
            self.draw_menu(options, current_option)
            self.set_status("Use UP/DOWN to navigate, ENTER to select.")

            key = self.stdscr.getch()
            if key == curses.KEY_UP and current_option > 0:
                current_option -= 1
            elif key == curses.KEY_DOWN and current_option < len(options) - 1:
                current_option += 1
            elif key == 10:  # Enter
                return options[current_option]

    def choose_target(self):
        """Menu pour choisir texte ou fichier."""
        options = ["Text", "File"]
        current_option = 0

        while True:
            self.draw_menu(options, current_option)
            self.set_status("Use UP/DOWN to navigate, ENTER to select.")

            key = self.stdscr.getch()
            if key == curses.KEY_UP and current_option > 0:
                current_option -= 1
            elif key == curses.KEY_DOWN and current_option < len(options) - 1:
                current_option += 1
            elif key == 10:  # Enter
                return options[current_option]

    def main_loop(self):
        while True:
            self.select_key()  # Étape 1 : Choisir/générer une clé
            action = self.choose_action()  # Étape 2 : Encrypt/Decrypt
            target = self.choose_target()  # Étape 3 : Text/File

            if action == "Encrypt" and target == "Text":
                self.encrypt_text()
            elif action == "Decrypt" and target == "Text":
                self.decrypt_text()
            elif action == "Encrypt" and target == "File":
                self.encrypt_file()
            elif action == "Decrypt" and target == "File":
                self.decrypt_file()
            else:
                break

    def encrypt_text(self):
        self.set_status("Enter text to encrypt.")
        curses.curs_set(1)
        editwin = curses.newwin(1, self.width - 4, self.height // 2, 2)
        box = Textbox(editwin)
        box.edit()
        curses.curs_set(0)

        text = box.gather().strip()
        self.add_log(f"Encrypting text: {text}")

        try:
            if self.key is None:  # Générer une nouvelle clé si elle n'existe pas
                self.key = generate_key(self.key_bits)
                self.add_log(f"Key generated ({self.key_bits} bits): {bytes(self.key).hex()}")

            encrypted = aria_encrypt(text, self.key, self.key_bits)
            self.add_log(f"Encrypted text (hex): {encrypted.hex()}")
        except Exception as e:
            self.add_log(f"Error during encryption: {e}", error=True)

    def decrypt_text(self):
        self.set_status("Enter text to decrypt (hex).")
        curses.curs_set(1)
        editwin = curses.newwin(1, self.width - 4, self.height // 2, 2)
        box = Textbox(editwin)
        box.edit()
        curses.curs_set(0)

        text = box.gather().strip()
        self.add_log(f"Decrypting text (hex): {text}")

        self.set_status("Enter decryption key (hex).")
        keywin = curses.newwin(1, self.width - 4, self.height // 2 + 2, 2)
        keybox = Textbox(keywin)
        keybox.edit()
        curses.curs_set(0)

        key_hex = keybox.gather().strip()
        self.add_log(f"Key entered (hex): {key_hex}")

        try:
            key = bytes.fromhex(key_hex)
            if len(key) * 8 != self.key_bits:
                raise ValueError(f"Invalid key length: Expected {self.key_bits} bits, got {len(key) * 8} bits.")

            encrypted_bytes = bytes.fromhex(text)
            decrypted = aria_decrypt(encrypted_bytes, list(key), self.key_bits)
            self.add_log(f"Decrypted text: {decrypted}")
        except Exception as e:
            self.add_log(f"Error during decryption: {e}", error=True)

    def encrypt_file(self):
        """Chiffrer un fichier."""
        self.set_status("Enter input file path.")
        curses.curs_set(1)
        editwin = curses.newwin(1, self.width - 4, self.height // 2, 2)
        box = Textbox(editwin)
        box.edit()
        curses.curs_set(0)

        input_path = box.gather().strip()
        self.add_log(f"Input file: {input_path}")

        self.set_status("Enter output file path.")
        editwin = curses.newwin(1, self.width - 4, self.height // 2 + 2, 2)
        box = Textbox(editwin)
        box.edit()
        curses.curs_set(0)

        output_path = box.gather().strip()
        self.add_log(f"Output file: {output_path}")

        try:
            if self.key is None:
                self.key = generate_key(self.key_bits)
                self.add_log(f"Key generated ({self.key_bits} bits): {bytes(self.key).hex()}")

            encrypt_file(input_path, output_path, self.key, self.key_bits)
            self.add_log(f"File encrypted successfully.")
        except Exception as e:
            self.add_log(f"Error during file encryption: {e}", error=True)

    def decrypt_file(self):
        """Déchiffrer un fichier."""
        self.set_status("Enter input file path.")
        curses.curs_set(1)
        editwin = curses.newwin(1, self.width - 4, self.height // 2, 2)
        box = Textbox(editwin)
        box.edit()
        curses.curs_set(0)

        input_path = box.gather().strip()
        self.add_log(f"Input file: {input_path}")

        self.set_status("Enter output file path.")
        editwin = curses.newwin(1, self.width - 4, self.height // 2 + 2, 2)
        box = Textbox(editwin)
        box.edit()
        curses.curs_set(0)

        output_path = box.gather().strip()
        self.add_log(f"Output file: {output_path}")

        self.set_status("Enter decryption key (hex).")
        keywin = curses.newwin(1, self.width - 4, self.height // 2 + 4, 2)
        keybox = Textbox(keywin)
        keybox.edit()
        curses.curs_set(0)

        key_hex = keybox.gather().strip()
        self.add_log(f"Key entered (hex): {key_hex}")

        try:
            key = bytes.fromhex(key_hex)
            if len(key) * 8 != self.key_bits:
                raise ValueError(f"Invalid key length: Expected {self.key_bits} bits, got {len(key) * 8} bits.")

            decrypt_file(input_path, output_path, list(key), self.key_bits)
            self.add_log(f"File decrypted successfully.")
        except Exception as e:
            self.add_log(f"Error during file decryption: {e}", error=True)


def main(stdscr):
    display_credits(stdscr)  # Affichage de la page de crédits
    interface = AriaInterface(stdscr)
    interface.main_loop()

if __name__ == "__main__":
    curses.wrapper(main)
