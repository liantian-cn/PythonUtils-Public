import pathlib

BASE_DIR = pathlib.Path("E:/temp_av/")
ALLOW_EXT = [".mp4", ".wmv"]
DEBUG = True


def remove_non_ascii(text):
    return (''.join([i if ord(i) < 128 else '' for i in text])).strip()


for file in BASE_DIR.glob('*.*'):
    if file.suffix in ALLOW_EXT:
        print(remove_non_ascii(file.stem)+file.suffix)
