import pathlib
from cipher import encrypt2file_b, decrypt2file_b

if __name__ == '__main__':
    a = b"Across the Great Wall we can reach every corner of the world."
    encrypt2file_b(a, pathlib.Path("file.tmp"))
    b = decrypt2file_b(pathlib.Path("file.tmp"))
    print(b)
