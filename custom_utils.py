import os
import sys
import pickle
import getpass
import subprocess
import traceback as tb
from collections import defaultdict

user = getpass.getuser()
hostname = os.uname()[1]
############### Absolute Paths ######################

#Change this path to your experiment directory
abs_path = "/output/"
# Change this path where FirmSolo is installed
script_dir =  "/FirmSolo/"
# Change this to where Ghidra is installed
ghidra_dir = "/ghidra/ghidra_10.2.3_PUBLIC/"
# Change this to where TriforceLinuxSyscallFuzzer is installed
tafl_lsf_dir = "/TriforceLinuxSyscallFuzzer/"
#Change this to where TriforceAFL is installed
tafl_dir = "/TriforceAFL/"


#Change this based on your machine threads
num_of_threads = 4

img_info_path = abs_path + "Image_Info/"

loaded_mods_path = abs_path + "Loaded_Modules/"

container_data_path = abs_path + "Data/"

exploit_dir = abs_path + "Exploits/"

result_dir_path = abs_path + "results/"

log_path = abs_path + "logs/"

fdyne_data = script_dir + "firmadyne_data/"

openwrt_patch_dir = script_dir + "openwrt_patches/"

kernel_prefix = "linux-"

kern_dir = abs_path + "kernel_dirs/"
kern_sources = abs_path + "/kernel_sources/"

### The dictionaries are used to cache information about the 
### symbols exported/implemented by the kernels
kern_dicts = abs_path + "kernel_dicts/"
ksyms_dir = abs_path + "kernel_ksyms_confs/"

tar_dir = abs_path + "kernel_tars/"

fs_dir = abs_path + "Filesystems/"

extracted_fs_and_kern_dir = abs_path + "images/"

kernel_configs = script_dir + "kernel_configs/"

buildroot_fs_dir = script_dir + "buildroot_fs/"
#####################################################

################## Useful Methods ###################

# Read the lines from a file
def read_file(file_path):
    with open(file_path,"r",errors="ignore") as f:
        lines = f.readlines()

    #lines = lines.replace("\n\n\n","").split("\n")
    
    # Remove the new line
    result = list(map(lambda x:x.strip("\n").rstrip(), lines))
    
    return result

# Read the lines from a file with carriage return
def read_file_cr(file_path):
    with open(file_path,"r",errors="ignore") as f:
        lines = f.read()

    lines = lines.replace("\n\n\n","").split("\n")
    
    # Remove the new line
    result = list(map(lambda x:x.strip("\n").rstrip(), lines))
    
    return result

# Write a file
def write_file(file_path,lines, mode):
    with open(file_path,mode) as f:
        f.writelines(lines)


# Read a pickle file
def read_pickle(file_path):
    with open(file_path, "rb") as f:
        result = pickle.load(f)

    return result
# Read a pickle file
def multi_read_pickle(file_path, how_many):
    result = []
    with open(file_path, "rb") as f:
        for i in range(how_many-1):
            temp = pickle.load(f)
            result.append(temp)

    return result


#Write a pickle object to a file
def write_pickle(file_path,obj):
    sys.setrecursionlimit(200000)
    with open(file_path,"wb") as f:
        pickle.dump(obj,f)

def multi_write_pickle(file_path,obj):
    sys.setrecursionlimit(200000)
    with open(file_path,"wb") as f:
        for objct in obj:
            pickle.dump(obj,f)

def check_if_numeric(inpt):
    if inpt.isnumeric():
        return True
    else:
        return False

def get_image_info(image,which_info):
    # The pickle object containing the image data
    pkl_obj = img_info_path + image + ".pkl"
    
    info = read_pickle(pkl_obj)

    out = []
    if which_info == "all":
        return info
    else:
        for i in which_info:
            out.append(info[i])
        return out

def save_image_info(image, info):
    pkl_obj = img_info_path + image + ".pkl"

    write_pickle(pkl_obj, info)

def get_vendor(image,arch,ds_recovery,new_kern_dir,*args):
    if ds_recovery:
        defconfig = "{}/.config".format(new_kern_dir)
        return defconfig

    if arch == "mips":
        defconfig = "{}/config.malta".format(kernel_configs)
    elif arch == "arm":
        print("ARGS",args[0])
        if args[0] == "armv5":
            ### Versatile board
            defconfig = "{}/config.arm_versatile".format(kernel_configs)
        elif args[0] == "armv6":
            defconfig = "{}/config.arm_realview_v6".format(kernel_configs)
        else:
            defconfig = "{}/config.arm_realview_v7".format(kernel_configs)
            

    return defconfig

def get_toolchain(kernel, arch, endian):
    if arch == "mips":
        if kernel < "linux-2.6.23":
            if endian == "big endian":
                cross = "/opt/mips_gcc-3.4/usr/bin/mips-linux-gnu-"
            else:
                cross = "/opt/mipsel_gcc-3.4/usr/bin/mipsel-linux-gnu-"
        elif kernel < "linux-4.4.198":
            if endian == "big endian":
                cross = "/opt/mips_gcc-4.3/usr/bin/mips-linux-gnu-"
            else:
                cross = "/opt/mipsel_gcc-4.3/usr/bin/mipsel-linux-gnu-"
        ### GCC 5.5 installed on /usr
        else:
            if endian == "big endian":
                cross = "mips-linux-gnu-"
            else:
                cross = "mipsel-linux-gnu-"
    elif arch == "arm":
        cross = "/opt/arm_gcc-4.3/usr/bin/arm-linux-gnueabi-"
    else:
        cross = None

    return cross

def create_dict(elems):
    out = {}

    for elem in elems:
        key = elem.split("/")[-1].strip("\n")
        out[key] = elem.strip("\n")

    return out
def create_dict_key_vals(keys,values):
    out = {}
    for i,key in enumerate(keys):
        out[key] = values[i]

    return out


def clean_kernel_source(kernel,container, arch):
    ### Clean kernel source directory
    try:
        if container == "ubuntu":
            image_dir = kern_dir + kernel
        else:
            image_dir = kern_dir2 + kernel
        
        if arch == "mips":
            mrproper = subprocess.run(['make','mrproper','ARCH=arm'],\
                    cwd=image_dir,stderr=subprocess.PIPE,stdout=subprocess.PIPE)
            print("Cleaning kernel source")
            print(mrproper.stdout.decode("utf-8"))
            
            mrproper = subprocess.run(['make','mrproper','ARCH=mips'],\
                    cwd=image_dir,stderr=subprocess.PIPE,stdout=subprocess.PIPE)
            print("Cleaning kernel source")
            print(mrproper.stdout.decode("utf-8"))
        elif arch == "arm":
            mrproper = subprocess.run(['make','mrproper','ARCH=mips'],\
                    cwd=image_dir,stderr=subprocess.PIPE,stdout=subprocess.PIPE)
            print("Cleaning kernel source")
            print(mrproper.stdout.decode("utf-8"))
            
            mrproper = subprocess.run(['make','mrproper','ARCH=arm'],\
                    cwd=image_dir,stderr=subprocess.PIPE,stdout=subprocess.PIPE)
            print("Cleaning kernel source")
            print(mrproper.stdout.decode("utf-8"))
    except:
        print(tb.format_exc())
        print("Something went wrong with cleaning the kernel")


#####################################################
