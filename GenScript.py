import pathlib
import os

INPUT_DIR = pathlib.Path("G:/temp_q/")
OUTPUT_DIR = pathlib.Path("G:/temp_out/")
ALLOW_EXT = [".mp4", ".wmv", ".mkv", ".avi"]
SCRIPT_FILE = pathlib.Path("G:/run.bat")

template = """

ffmpeg.exe -y -hwaccel auto -i "{s_file}" -c:v libx265  -preset medium -crf 23 -x265-params "crf=23" -pix_fmt yuv420p  -profile:v main -level 3.1 -movflags +faststart -r 24000/1001  -vf "scale=trunc(iw/2)*2:trunc(ih/2)*2" -map 0:v:0? -c:a aac -b:a 192k -map 0:a? -c:s mov_text -map 0:s? -map_chapters 0 -map_metadata 0 -vsync 2 -f matroska -v quiet -stats -threads 1 "{d_file}"

"""

s_list = []

for file in sorted(INPUT_DIR.glob('*.*'), key=os.path.getsize, reverse=True):
    if file.suffix in ALLOW_EXT:
        new_file_path = OUTPUT_DIR.joinpath(file.stem + ".mkv")
        script = template.format(s_file=file, d_file=new_file_path).strip() + "\n\n"
        s_list.append(script)

with open(SCRIPT_FILE, "w", encoding="utf-8") as f:
    f.write("""
cd /d D:\Programs\\ffmpeg


IF "%~1" == "1" GOTO Call1
IF "%~1" == "2" GOTO Call2
IF "%~1" == "3" GOTO Call3

exit 0

:Call1

exit 0

:Call2

exit 0

:Call3

exit 0
    \n""")
    f.writelines(s_list)
