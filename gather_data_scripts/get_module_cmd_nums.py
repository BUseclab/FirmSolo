#!/usr/bin/env python3


import os, sys
currentdir = os.path.dirname(os.path.realpath(__file__))
parentdir = os.path.dirname(currentdir)
sys.path.append(parentdir)
from custom_utils import *
import subprocess as sb
import traceback as tb


def get_ghidra_cmd(module,image):
    mod = module.split("/")[-1].replace(".ko","")
    extracted_fs_dir = f"{result_dir_path}/{image}/extracted_fs/"

    cmd = f"{ghidra_dir}support/analyzeHeadless {script_dir}ghidra Project{image} -import \"{extracted_fs_dir}{module}\" -postScript ioctl_cmds.py \"{container_data_path}/fuzzer_data/{image}/{mod}_cmds.out\" -readOnly -scriptlog \"{script_dir}ghidra/\""

    return cmd
    
def get_cmd_nums(image, mod):
    
    
    info = None
    try:
        which_info = ["modules"]
        info = get_image_info(image,which_info)
        modules = info[0]
    except:
        print("Image",image,"does not have any info about modules...aborting")
        print(tb.format_exc())
        return None
    ### Create the data directory
    fuz_data_path = "{}/fuzzer_data/{}".format(container_data_path, image)
    if not os.path.exists(fuz_data_path):
        try:
            mkdir = "mkdir {}".format(fuz_data_path)
            sb.run(mkdir,shell=True)
        except:
            print("Could not create dir",fuz_data_path)
            return None
    if '' in modules:
        modules.remove('')
    
    for module in modules:
        if mod not in module:
            continue
        ghidra_cmd = get_ghidra_cmd(module,image)
        try:
            ret = sb.run(ghidra_cmd,cwd =f"{script_dir}ghidra",shell=True)
        except:
            print(tb.format_exc())
            return None
    return "Success"

def main(image,module):

    get_cmd_nums(image,module)


if __name__ == "__main__":
    image = sys.argv[1]
    module = sys.argv[2]
    main(image,module)
