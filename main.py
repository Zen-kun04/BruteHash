import os
import re
import json
import time
from hashlib import md5, sha1, sha256, sha512

with open("config.json", 'r') as f:
    config = json.load(f)

wl_passwords = []
WORDLIST_PATH = config["wordlist"]
RESULT = None

def get_hash_salt(content: str) -> tuple:
    if '$' in content:
        if result := re.findall("[^$SHA]\w{31,127}", content):
            if len(result) > 1:  # Found salt + hash
                return (result[1], result[0]) if len(result[1]) > len(result[0]) else (result[0], result[1])
            splitted = re.findall("[^$SHA]\w+", content)
            salt = ''.join(x for x in splitted if x != result[0])
            if salt != '':
                return (result[0], salt)
            return (result[0], None)
        return (None, None)
    elif ':' in content:
        splitted = content.split(':')
        return (splitted[0], splitted[1]) if len(splitted[0]) > len(splitted[1]) else (splitted[1], splitted[0])
    return (None, None)

def load_wordlist(file: str):
    global wl_passwords
    with open(file, 'r', encoding='latin-1') as f:
        wl_passwords = [password.strip() for password in f]

def start_brute(password: str, hash_str: str, salt: str or None = None):
    global RESULT
    if len(hash_str) == 32:  # MD5
        if salt:
            if md5(password.encode() + salt.encode()).hexdigest() == hash_str or \
                md5(salt.encode() + password.encode()).hexdigest() == hash_str or \
                    md5(md5(password.encode()).hexdigest().encode() + salt.encode()).hexdigest() == hash_str:
                RESULT = password
        else:
            if md5(password.encode()).hexdigest() == hash_str:
                RESULT = password
    elif len(hash_str) == 40:  # SHA1
        if salt:
            if sha1(password.encode() + salt.encode()).hexdigest() == hash_str or \
                sha1(salt.encode() + password.encode()).hexdigest() == hash_str or \
                    sha1(sha1(password.encode()).hexdigest().encode() + salt.encode()).hexdigest() == hash_str:
                RESULT = password
        else:
            if sha1(password.encode()).hexdigest() == hash_str:
                RESULT = password
    elif len(hash_str) == 64:  # SHA256
        if salt:
            if sha256(password.encode() + salt.encode()).hexdigest() == hash_str or \
                sha256(salt.encode() + password.encode()).hexdigest() == hash_str or \
                    sha256(sha256(password.encode()).hexdigest().encode() + salt.encode()).hexdigest() == hash_str:
                RESULT = password
        else:
            if sha256(password.encode()).hexdigest() == hash_str:
                RESULT = password
    elif len(hash_str) == 128:  # SHA512
        if salt:
            if sha512(password.encode() + salt.encode()).hexdigest() == hash_str or \
                sha512(salt.encode() + password.encode()).hexdigest() == hash_str or \
                    sha512(sha512(password.encode()).hexdigest().encode() + salt.encode()).hexdigest() == hash_str:
                RESULT = password
        else:
            if sha512(password.encode()).hexdigest() == hash_str:
                RESULT = password

def main_brute(hash_str: str, salt: str):
    print("Imported wordlist done, starting bruteforce...")
    start = time.time()
    for password in wl_passwords:
        if RESULT is not None:
            break
        start_brute(password, hash_str, salt)
    end = time.time()
    if RESULT is not None:
        print(f"Found in {end - start} => {RESULT}")
    else:
        print(f"No results found, finished in {end - start}")

def from_raw_hash():
    raw_hash = input("Raw hash > ")
    hash_str, salt = get_hash_salt(raw_hash)
    main_brute(hash_str, salt)

def hash_x_salt():
    hash_str = input("Hash > ")
    salt = input("Salt > ")
    main_brute(hash_str, salt)

def main():
    global WORDLIST_PATH
    if WORDLIST_PATH is None:
        WORDLIST_PATH = input("Wordlist > ")
        if not os.path.isfile(WORDLIST_PATH):
            exit()
        load_wordlist(WORDLIST_PATH)
    else:
        load_wordlist(WORDLIST_PATH)
        with open("config.json", 'w') as f:
            f.write(json.dumps({
                "wordlist": WORDLIST_PATH
            }, indent=4))
    print("1) From raw hash")
    print("2) Hash x Salt")
    opt = input("> ")
    if opt == "1":
        from_raw_hash()
    elif opt == "2":
        hash_x_salt()


if __name__ == "__main__":
    main()