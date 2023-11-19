# BruteHash
An easy and fast hash bruteforce.

## Setup
```
git clone https://github.com/Zen-kun04/BruteHash.git
cd BruteHash
pip install -r requirements.txt
python main.py
```

## Supported hashes
- MD5
- SHA1
- SHA256
- SHA512

## Supported hashing methods:
- HASH_TYPE(password)
- HASH_TYPE(password + salt)
- HASH_TYPE(salt + password)
- HASH_TYPE(HASH_TYPE(password) + salt)

## Advice por developers
I already tried to use the library threading, ThreadPoolExecutor (from concurrent.futures) and multiprocessing and it made everything slower af.
So unless I'm a freaking retarded dev, adding threads in a bruteforcing script for hashes might not be a good idea.