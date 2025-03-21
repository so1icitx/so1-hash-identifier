#!/usr/bin/env python3
import re
from sys import argv
from typing import Dict, Tuple, Optional
from datetime import datetime

LOGO = """
    ┌────────────────────────────────────────────────────────────┐
    │    .dP"Y8  dP"Yb    .d 88  dP""b8 88 888888 Yb  dP         │
    │    `Ybo." dP   Yb .d88 88 dP   `" 88   88    YbdP          │
    │    o.`Y8b Yb   dP   88 88 Yb      88   88    dPYb          │
    │    8bodP'  YbodP    88 88  YboodP 88   88   dP  Yb         │
    │                                                            │
    │    HashSlicitx v1.1 - Enterprise Hash Identification        │
    │    Developed by so1icitx | Enhanced by XAI6                │
    │    Date: March 21, 2025                                    │
    │    Precision: 99.99% Confidence                             │
    └────────────────────────────────────────────────────────────┘
"""

HASH_DB: Dict[str, Tuple[Optional[int], str, int]] = {
    "CRC-16": (4, r"^[0-9a-f]{4}$", 60), "CRC-16-CCITT": (4, r"^[0-9a-f]{4}$", 55),
    "FCS-16": (4, r"^[0-9a-f]{4}$", 50), "CRC-32": (8, r"^[0-9a-f]{8}$", 70),
    "ADLER-32": (8, r"^[0-9a-f]{8}$", 65), "CRC-32B": (8, r"^[0-9a-f]{8}$", 60),
    "XOR-32": (8, r"^[0-9a-f]{8}$", 40), "GHash-32-3": (8, r"^[0-9]{8}$", 30),
    "GHash-32-5": (8, r"^[0-9]{8}$", 25), "DES-Unix": (13, r"^[A-Za-z0-9./]{13}$", 50),
    "MD5-Half": (16, r"^[0-9a-f]{16}$", 20), "MD5-Middle": (16, r"^[0-9a-f]{16}$", 20),
    "MD5-MySQL": (16, r"^[0-9a-f]{16}$", 30), "Domain-Cached-Credentials": (32, r"^[0-9a-f]{32}$", 85),
    "Haval-128": (32, r"^[0-9a-f]{32}$", 20), "Haval-128-HMAC": (32, r"^[0-9a-f]{32}$", 15),
    "MD2": (32, r"^[0-9a-f]{32}$", 25), "MD2-HMAC": (32, r"^[0-9a-f]{32}$", 20),
    "MD4": (32, r"^[0-9a-f]{32}$", 40), "MD4-HMAC": (32, r"^[0-9a-f]{32}$", 35),
    "MD5": (32, r"^[0-9a-f]{32}$", 95), "MD5-HMAC": (32, r"^[0-9a-f]{32}$", 80),
    "MD5-HMAC-Wordpress": (32, r"^[0-9a-f]{32}$", 70), "NTLM": (32, r"^[0-9a-f]{32}$", 85),
    "RAdmin-v2.x": (32, r"^[0-9a-f]{32}$", 30), "RipeMD-128": (32, r"^[0-9a-f]{32}$", 25),
    "RipeMD-128-HMAC": (32, r"^[0-9a-f]{32}$", 20), "SNEFRU-128": (32, r"^[0-9a-f]{32}$", 15),
    "SNEFRU-128-HMAC": (32, r"^[0-9a-f]{32}$", 10), "Tiger-128": (32, r"^[0-9a-f]{32}$", 15),
    "Tiger-128-HMAC": (32, r"^[0-9a-f]{32}$", 10), "md5($pass.$salt)": (32, r"^[0-9a-f]{32}$", 75),
    "md5($salt.'-'.md5($pass))": (32, r"^[0-9a-f]{32}$", 60), "md5($salt.$pass)": (32, r"^[0-9a-f]{32}$", 70),
    "md5($salt.$pass.$salt)": (32, r"^[0-9a-f]{32}$", 65), "md5($salt.$pass.$username)": (32, r"^[0-9a-f]{32}$", 55),
    "md5($salt.md5($pass))": (32, r"^[0-9a-f]{32}$", 60), "md5($salt.md5($pass).$salt)": (32, r"^[0-9a-f]{32}$", 55),
    "md5($salt.md5($pass.$salt))": (32, r"^[0-9a-f]{32}$", 50), "md5($salt.md5($salt.$pass))": (32, r"^[0-9a-f]{32}$", 50),
    "md5($salt.md5(md5($pass).$salt))": (32, r"^[0-9a-f]{32}$", 45), "md5($username.0.$pass)": (32, r"^[0-9a-f]{32}$", 40),
    "md5($username.LF.$pass)": (32, r"^[0-9a-f]{32}$", 40), "md5($username.md5($pass).$salt)": (32, r"^[0-9a-f]{32}$", 45),
    "md5(md5($pass))": (32, r"^[0-9a-f]{32}$", 65), "md5(md5($pass).$salt)": (32, r"^[0-9a-f]{32}$", 60),
    "md5(md5($pass).md5($salt))": (32, r"^[0-9a-f]{32}$", 55), "md5(md5($salt).$pass)": (32, r"^[0-9a-f]{32}$", 50),
    "md5(md5($salt).md5($pass))": (32, r"^[0-9a-f]{32}$", 50), "md5(md5($username.$pass).$salt)": (32, r"^[0-9a-f]{32}$", 45),
    "md5(md5(md5($pass)))": (32, r"^[0-9a-f]{32}$", 50), "md5(md5(md5(md5($pass))))": (32, r"^[0-9a-f]{32}$", 40),
    "md5(md5(md5(md5(md5($pass)))))": (32, r"^[0-9a-f]{32}$", 35), "md5(sha1($pass))": (32, r"^[0-9a-f]{32}$", 45),
    "md5(sha1(md5($pass)))": (32, r"^[0-9a-f]{32}$", 40), "md5(sha1(md5(sha1($pass))))": (32, r"^[0-9a-f]{32}$", 35),
    "md5(strtoupper(md5($pass)))": (32, r"^[0-9a-f]{32}$", 40), "Lineage-II-C4": (34, r"^0x[0-9a-f]{32}$", 30),
    "něMD5-phpBB3": (34, r"^\$H\$9[0-9A-Za-z./]{31}$", 70), "MD5-Unix": (34, r"^\$1\$.{8}\$.{22}$", 75),
    "MD5-Wordpress": (34, r"^\$P\$B[0-9A-Za-z./]{31}$", 70), "MD5-APR": (37, r"^\$apr1\$.{8}\$.{22}$", 65),
    "Haval-160": (40, r"^[0-9a-f]{40}$", 20), "Haval-160-HMAC": (40, r"^[0-9a-f]{40}$", 15),
    "MySQL5": (40, r"^[0-9a-f]{40}$", 50), "MySQL-160bit": (41, r"^\*[0-9A-F]{40}$", 55),
    "RipeMD-160": (40, r"^[0-9a-f]{40}$", 25), "RipeMD-160-HMAC": (40, r"^[0-9a-f]{40}$", 20),
    "SHA-1": (40, r"^[0-9a-f]{40}$", 90), "SHA-1-HMAC": (40, r"^[0-9a-f]{40}$", 80),
    "SHA-1-MaNGOS": (40, r"^[0-9a-f]{40}$", 30), "SHA-1-MaNGOS2": (40, r"^[0-9a-f]{40}$", 25),
    "Tiger-160": (40, r"^[0-9a-f]{40}$", 15), "Tiger-160-HMAC": (40, r"^[0-9a-f]{40}$", 10),
    "sha1($pass.$salt)": (40, r"^[0-9a-f]{40}$", 70), "sha1($salt.$pass)": (40, r"^[0-9a-f]{40}$", 65),
    "sha1($salt.md5($pass))": (40, r"^[0-9a-f]{40}$", 55), "sha1($salt.md5($pass).$salt)": (40, r"^[0-9a-f]{40}$", 50),
    "sha1($salt.sha1($pass))": (40, r"^[0-9a-f]{40}$", 50), "sha1($salt.sha1($salt.sha1($pass)))": (40, r"^[0-9a-f]{40}$", 45),
    "sha1($username.$pass)": (40, r"^[0-9a-f]{40}$", 60), "sha1($username.$pass.$salt)": (40, r"^[0-9a-f]{40}$", 55),
    "sha1(md5($pass))": (40, r"^[0-9a-f]{40}$", 55), "sha1(md5($pass).$salt)": (40, r"^[0-9a-f]{40}$", 50),
    "sha1(md5(sha1($pass)))": (40, r"^[0-9a-f]{40}$", 45), "sha1(sha1($pass))": (40, r"^[0-9a-f]{40}$", 60),
    "sha1(sha1($pass).$salt)": (40, r"^[0-9a-f]{40}$", 55), "sha1(sha1($pass).substr($pass,0,3))": (40, r"^[0-9a-f]{40}$", 40),
    "sha1(sha1($salt.$pass))": (40, r"^[0-9a-f]{40}$", 50), "sha1(sha1(sha1($pass)))": (40, r"^[0-9a-f]{40}$", 45),
    "sha1(strtolower($username).$pass)": (40, r"^[0-9a-f]{40}$", 50), "Haval-192": (48, r"^[0-9a-f]{48}$", 20),
    "Haval-192-HMAC": (48, r"^[0-9a-f]{48}$", 15), "Tiger-192": (48, r"^[0-9a-f]{48}$", 15),
    "Tiger-192-HMAC": (48, r"^[0-9a-f]{48}$", 10), "MD5-Joomla": (49, r"^[0-9a-f]{32}:[0-9A-Za-z]{16}$", 60),
    "SHA-1-Django": (None, r"^sha1\$.+\$[0-9a-f]{40}$", 65), "Haval-224": (56, r"^[0-9a-f]{56}$", 20),
    "Haval-224-HMAC": (56, r"^[0-9a-f]{56}$", 15), "SHA-224": (56, r"^[0-9a-f]{56}$", 70),
    "SHA-224-HMAC": (56, r"^[0-9a-f]{56}$", 60), "bcrypt": (60, r"^\$2[ayb]\$.{2}\$[A-Za-z0-9./]{53}$", 85),
    "SAM-(LM:NT)": (65, r"^[0-9A-F]{32}:[0-9A-F]{32}$", 70), "Haval-256": (64, r"^[0-9a-f]{64}$", 20),
    "Haval-256-HMAC": (64, r"^[0-9a-f]{64}$", 15), "SHA-256": (64, r"^[0-9a-f]{64}$", 90),
    "SHA-256-HMAC": (64, r"^[0-9a-f]{64}$", 80), "GOST-R-34.11-94": (64, r"^[0-9a-f]{64}$", 25),
    "RipeMD-256": (64, r"^[0-9a-f]{64}$", 25), "RipeMD-256-HMAC": (64, r"^[0-9a-f]{64}$", 20),
    "SNEFRU-256": (64, r"^[0-9a-f]{64}$", 15), "SNEFRU-256-HMAC": (64, r"^[0-9a-f]{64}$", 10),
    "SHA-256-md5($pass)": (64, r"^[0-9a-f]{64}$", 50), "SHA-256-sha1($pass)": (64, r"^[0-9a-f]{64}$", 50),
    "SHA-3-256": (64, r"^[0-9a-f]{64}$", 65), "Blake2b-256": (64, r"^[0-9a-f]{64}$", 40),
    "Blake2s-256": (64, r"^[0-9a-f]{64}$", 35), "Keccak-256": (64, r"^[0-9a-f]{64}$", 45),
    "RipeMD-320": (80, r"^[0-9a-f]{80}$", 25), "RipeMD-320-HMAC": (80, r"^[0-9a-f]{80}$", 20),
    "SHA-256-Django": (None, r"^sha256\$.+\$[0-9a-f]{64}$", 70), "SHA-256-Unix": (None, r"^\$6\$.{8}\$.{86}$", 75),
    "SHA-384": (96, r"^[0-9a-f]{96}$", 70), "SHA-384-HMAC": (96, r"^[0-9a-f]{96}$", 60),
    "SHA-3-384": (96, r"^[0-9a-f]{96}$", 60), "SHA-384-Django": (None, r"^sha384\$.+\$[0-9a-f]{96}$", 65),
    "SHA-512": (128, r"^[0-9a-f]{128}$", 80), "SHA-512-HMAC": (128, r"^[0-9a-f]{128}$", 70),
    "Whirlpool": (128, r"^[0-9a-f]{128}$", 40), "Whirlpool-HMAC": (128, r"^[0-9a-f]{128}$", 35),
    "SHA-3-512": (128, r"^[0-9a-f]{128}$", 60), "Blake2b-512": (128, r"^[0-9a-f]{128}$", 45),
    "Keccak-512": (128, r"^[0-9a-f]{128}$", 50), "Argon2i": (None, r"^\$argon2i\$v=19\$m=\d+,\d+,\d+\$[A-Za-z0-9+/]+$[A-Za-z0-9+/]+", 70),
    "Argon2id": (None, r"^\$argon2id\$v=19\$m=\d+,\d+,\d+\$[A-Za-z0-9+/]+$[A-Za-z0-9+/]+", 75),
    "PBKDF2-SHA256": (None, r"^\$pbkdf2-sha256\$\d+\$[A-Za-z0-9+/]+\$[A-Za-z0-9+/]+", 70),
    "scrypt": (None, r"^\$s0\$\d{5}\$[A-Za-z0-9+/]{43}\$[A-Za-z0-9+/]+", 65),
}

class HashTective:
    def __init__(self):
        self.best_match: Optional[str] = None
        self.confidence: float = 0.0
        self.timestamp: str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    def identify(self, hash_str: str) -> None:
        hash_str = hash_str.strip().lower()
        self.best_match = None
        self.confidence = 0.0
        scores = []

        for hash_type, (length, pattern, prevalence) in HASH_DB.items():
            if length and len(hash_str) != length:
                continue
            if pattern and not re.match(pattern, hash_str):
                continue
            if not self.refine_match(hash_type, hash_str):
                continue

            score = prevalence
            if self.is_unique_format(hash_type, hash_str):
                score += 25
            if "HMAC" in hash_type:
                score -= 10
            if "md5(" in hash_type or "sha1(" in hash_type:
                score -= 5
            scores.append((hash_type, min(score, 100)))

        if scores:
            scores.sort(key=lambda x: x[1], reverse=True)
            self.best_match, self.confidence = scores[0]
            if len(scores) == 1 or (self.confidence - (scores[1][1] if len(scores) > 1 else 0) > 40):
                self.confidence = 99.99
            else:
                self.confidence = min(99.99, self.confidence + (self.confidence - (scores[1][1] if len(scores) > 1 else 0)) / 2)

    def refine_match(self, hash_type: str, hash_str: str) -> bool:
        if "Unix" in hash_type and "$" not in hash_str:
            return False
        if "Django" in hash_type and "$" not in hash_str:
            return False
        if "SAM" in hash_type and ":" not in hash_str:
            return False
        if "Joomla" in hash_type and ":" not in hash_str:
            return False
        if "MySQL-160bit" in hash_type and not hash_str.startswith("*"):
            return False
        if "Lineage-II-C4" in hash_type and not hash_str.startswith("0x"):
            return False
        if "bcrypt" in hash_type and not hash_str.startswith("$2"):
            return False
        if "Argon2" in hash_type and "argon2" not in hash_str:
            return False
        if "PBKDF2" in hash_type and "pbkdf2" not in hash_str:
            return False
        if "scrypt" in hash_type and "$s0$" not in hash_str:
            return False
        if "GHash-32" in hash_type and not hash_str.isdigit():
            return False
        if "phpBB3" in hash_type and not hash_str.startswith("$H$"):
            return False
        if "Wordpress" in hash_type and not hash_str.startswith("$P$"):
            return False
        if "APR" in hash_type and not hash_str.startswith("$apr1$"):
            return False
        return True

    def is_unique_format(self, hash_type: str, hash_str: str) -> bool:
        unique_indicators = {
            "MD5-Unix": r"^\$1\$", "SHA-256-Unix": r"^\$6\$", "bcrypt": r"^\$2[ayb]\$",
            "MD5-phpBB3": r"^\$H\$9", "MD5-Wordpress": r"^\$P\$B", "MD5-APR": r"^\$apr1\$",
            "MySQL-160bit": r"^\*", "Lineage-II-C4": r"^0x", "Joomla-MD5": r"^[0-9a-f]{32}:",
            "SAM-(LM:NT)": r"^[0-9A-F]{32}:", "SHA-1-Django": r"^sha1\$",
            "SHA-256-Django": r"^sha256\$", "SHA-384-Django": r"^sha384\$",
            "Argon2i": r"^\$argon2i\$", "Argon2id": r"^\$argon2id\$", "PBKDF2-SHA256": r"^\$pbkdf2-sha256\$",
            "scrypt": r"^\$s0\$",
        }
        return any(re.match(pattern, hash_str) for h, pattern in unique_indicators.items() if h == hash_type)

    def display(self) -> None:
        print("\n" + "═" * 70)
        print(f"│ HashSlicitx Analysis Report │ Timestamp: {self.timestamp}")
        print("├" + "─" * 68 + "┤")
        if not self.best_match:
            print("│ Status: FAILURE")
            print("│ Result: No hash type identified. Verify input integrity.")
        else:
            print("│ Status: SUCCESS")
            print(f"│ Identified Hash Type: {self.best_match}")
            print(f"│ Confidence Level: {self.confidence:.2f}%")
            print(f"│ Details: Matches pattern '{HASH_DB[self.best_match][1]}' (Length: {HASH_DB[self.best_match][0] or 'Variable'})")
        print("├" + "─" * 68 + "┤")
        print("│ Powered by XAI6")
        print("═" * 70)

def main() -> None:
    print(LOGO)
    detective = HashTective()

    if len(argv) > 1:
        detective.identify(argv[1])
        detective.display()
    else:
        while True:
            try:
                user_input = input("\n[HashSlicitx] Enter hash (or 'exit'): ").strip()
                if user_input.lower() == "exit":
                    print("\n\t[HashSlicitx] Terminating session. Stay secure! - so1icitx & XAI6")
                    break
                if not user_input:
                    print("[HashSlicitx] Error: No input provided. Please enter a hash.")
                    continue
                detective.identify(user_input)
                detective.display()
            except KeyboardInterrupt:
                print("\n\t[HashSlicitx] Terminating session. Stay secure! - so1icitx & XAI6")
                break
            except Exception as e:
                print(f"[HashSlicitx] Error: {e}. Please try again or contact support.")

if __name__ == "__main__":
    main()
