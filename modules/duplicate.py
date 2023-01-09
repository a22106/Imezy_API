# duplicate files in the two directories
from pathlib import Path
from shutil import copyfile
import argparse

parser = argparse.ArgumentParser()
parser.add_argument('--dir1', '-d1', help='directory 1', default='/data/StableDiffusion/stable-diffusion-webui-test/generated', required=True, type=str)
parser.add_argument('--dir2', '-d2', help='directory 2', default='/data/StableDiffusion/stable-diffusion-webui-pius/generated', required=True, type=str)
args = parser.parse_args()

# make whole files in the directories to be equal. even if the files are not in the same directory and in the subdirectory
# copy files from dir1 to dir2 and vice versa
def copy_files(dir1, dir2):
    for file in dir1.glob('**/*'):
        if file.is_file():
            
            file2 = dir2 / file.relative_to(dir1)
            if file2.exists() == False:
                file2.parent.mkdir(parents=True, exist_ok=True)
                copyfile(file, file2)
                print(f'copied {file} to {file2}')
            else:
                continue
                
DIR1 = Path(args.dir1)
DIR2 = Path(args.dir2)
copy_files(DIR1, DIR2)
copy_files(DIR2, DIR1)