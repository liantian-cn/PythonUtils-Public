import pathlib

BASE_DIR = pathlib.Path("E:/temp_q/")
ALLOW_EXT = [".mp4", ".wmv"]
DEBUG = False

for file in BASE_DIR.glob('*.*'):
    if file.suffix in ALLOW_EXT:
        new_file_path = BASE_DIR.joinpath(file.stem.split(" ")[0] + file.suffix)
        print("{}  ====>  {} ".format(file, new_file_path))
        if not DEBUG:
            file.rename(new_file_path)
