# !/usr/bin/env python3
# -*- coding: utf-8 -*-

import string
from pathlib import Path
import random
from hashlib import sha256,sha3_512

SALT_LENGTH = 8
CHARS = '2346789BCDFGHJKMPQRTVWXY'


def get_random_string(length: int = 32, chars: string = CHARS) -> str:
    return ''.join(random.choice(chars) for i in range(length))


def encode(num, alphabet=CHARS):
    """Encode a positive number into Base X and return the string.

    Arguments:
    - `num`: The number to encode
    - `alphabet`: The alphabet to use for encoding
    """
    if num == 0:
        return alphabet[0]
    arr = []
    arr_append = arr.append  # Extract bound-method for faster access.
    _divmod = divmod  # Access to locals is faster.
    base = len(alphabet)
    while num:
        num, rem = _divmod(num, base)
        arr_append(alphabet[rem])
    arr.reverse()
    return ''.join(arr)


def decode(string, alphabet=CHARS):
    """Decode a Base X encoded string into the number

    Arguments:
    - `string`: The encoded string
    - `alphabet`: The alphabet to use for decoding
    """
    base = len(alphabet)
    strlen = len(string)
    num = 0

    idx = 0
    for char in string:
        power = (strlen - (idx + 1))
        num += alphabet.index(char) * (base ** power)
        idx += 1

    return num


def dddd(x):
    q = sha256(x.encode())
    w = q.hexdigest()
    print(w)
    e = int(w, 16)
    print(e)
    r = encode(e)
    print(r)
    t = str(r)
    print(t)
    y = t[:10]
    print(y)


def test():
    this_file = Path(__file__)
    print(this_file)
    f = this_file.read_bytes()
    q = sha3_512(this_file.read_bytes())
    w = q.digest()
    print(w)
    print(len(w))
    print


test()
