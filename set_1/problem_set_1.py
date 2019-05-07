import codecs
import csv
from operator import xor
import pdb


#decode hex and encode it into base64
def problem_1(hex):
    str = codecs.decode(hex, 'hex')
    b64 = codecs.encode(str, 'base64')
    return b64


# produce xor combination of two strings
def xor(str1, str2):
    b1 = bytes(str1, 'utf-8') if type(str1) == str else str1
    b2 = bytes(str2, 'utf-8') if type(str1) == str else str2
    xor = bytearray(len(b1))
    for i in range(len(b1)):
        xor[i] = b1[i] ^ b2[i]
    return xor


def score(s):
    freq = {}
    string = ' etaoinshrdlucmfwgypbvkxjqz'
    rank = len(string)
    for char in string:
        freq[char] = rank
        rank -= 1
    score = 0
    for c in s.lower():
        if chr(c) in freq:
            score += freq[chr(c)]
    return score


#cesar cipher
def xor_cipher(string):
    max_score = None
    english_plaintext = None
    key = None

    for i in range(256):
        s2 = str(i) * len(string)
        try:
            plaintext = bytes(xor(string, s2))
            pscore = score(plaintext)
            if not max_score or pscore > max_score:
                max_score = pscore
                english_plaintext = plaintext
                key = chr(i)
        except UnicodeError:
            continue
    return key, english_plaintext, max_score


def multi_xor_cipher():
    ans = None
    with open('strings.txt', 'r') as f:
        csv_r = list(csv.reader(f))
        for line in csv_r:
            val = xor_cipher(line[0])
            if not ans or val[2] > ans[2]:
                ans = val
    return ans


#vigenere cipher
def repeating_key_xor(strings: 'list', key) -> list:
    ans = []
    key = bytes(key, 'utf-8')
    for string in strings:
        string = bytes(string, 'utf-8')
        new = bytearray(len(string))
        for i in range(len(string)):
            new[i] = string[i] ^ key[i % len(key)]
        ans.append(codecs.encode(new, 'hex'))

    return ans


def hamming_distance(str1, str2):
    combined = xor(str1, str2)
    diff = 0
    for byte in combined:
        diff += bin(byte).count('1')
    return diff


import heapq


def decrypt_r_key_xor():
    lines = []
    with open("r_key_strings.txt", 'r') as f:
        lines.extend([line for line in f])
        lines = bytearray("".join(lines), 'utf-8')
        lines = codecs.decode(lines, "base64")

    distances = []
    for key_size in range(2, 40):
        block1 = lines[:key_size]
        block2 = lines[key_size:key_size * 2]
        distance = hamming_distance(block1, block2) / key_size
        distances.append((distance, key_size))
    distances = heapq.nsmallest(5, distances)

    for _, key_size in distances:
        block_bytes = [[] for _ in range(key_size)]
        for i, byte in enumerate(lines):
            block_bytes[i % key_size].append(byte)

        keys = ''
        for bbytes in block_bytes:
            k_bytes = "".join([chr(asci) for asci in bbytes])
            keys += xor_cipher(k_bytes)[0]
        key = bytearray(keys * len(lines), 'utf-8')
        plaintext = "".join(map(chr, xor(lines, key)))
        print(keys, key_size, plaintext)


from Crypto.Cipher import AES


#AES = advanced encryption Standard, a spec for the encryption of electronic data
def ecb():
    obj = AES.new("YELLOW SUBMARINE", AES.MODE_ECB)
    ciphertext = codecs.decode(
        bytes("".join(list(open("ecb.txt", 'r'))), 'utf-8'), "base64")
    plaintext = obj.decrypt(ciphertext)
    return ciphertext, plaintext


from collections import defaultdict


def repeated_blocks(buffer, block_l=16):
    # set default to -1 so that any two matching results in positive 1 onward
    reps = defaultdict(lambda: -1)
    for i in range(0, len(buffer), block_l):
        block = bytes(buffer[i:i + block_l])
        reps[block] += 1
    return sum(reps.values())


def ecb_2():
    max_reps = 0
    ecb_ciphertext = None

    for c_txt in list(open("ecb_2.txt", 'r')):
        c_txt = c_txt.rstrip()
        reps = repeated_blocks(bytearray(c_txt, 'utf-8'))
        if reps > max_reps:
            max_reps = reps
            ecb_ciphertext = c_txt
    return ecb_ciphertext


print(ecb_2())
