#!/usr/bin/env python3


import os, sys
sys.path.append("/firmsolo")
from custom_utils import *


def find_char_devs(image):
    
    print("Checking image", image)
    image_info = loaded_mods_path + "{0}/dmesg_ups_subs.out".format(image)
    loaded_mods_fl = loaded_mods_path + "{0}/{0}_ups_subs.pkl".format(image)
    
    try:
        lines = read_file(image_info)
    except:
        print("Dmesg file for image",image,"does not exist")
        return None
    
    try:
        info = read_pickle(loaded_mods_fl)
        loaded_modules = info[0]
    except:
        print("Loaded modules info for image",image,"does not exist")
        return None
    
    print("Loaded modules\n", loaded_modules)
    ### First filter out the noise
    dmesg = []
    for line in lines:
        if "insmod " in line:
            dmesg.append(line)
        #if "insmod:" in line:
            #dmesg = dmesg[]
        #if "Module_name:" in line:
            #dmesg.append(line)
        elif "Registering device" in line:
            dmesg.append(line)
    
    devices = []
    indx = 0
    while indx < len(dmesg):
        line = dmesg[indx]
        if "insmod " in line:
            device = []
            mod_name = line.split("/")[-1].replace(".ko","")
            indx += 1
            if indx == len(dmesg):
                break
            line = dmesg[indx]

            while "insmod " not in line:
                dev_tokens = line.split()[-1].split(":")
                dev_name, major, minor = dev_tokens[0], dev_tokens[1], dev_tokens[2]
                if [dev_name,major,minor] not in device:
                    device.append([dev_name,major,minor])
                indx += 1
                if indx >= len(dmesg):
                    break
                line = dmesg[indx]
            devices.append([mod_name,device])
            continue
        indx += 1
    
    candidates = []
    if devices != []:
        for dev in devices:
            if dev[1] != [] and dev[0] in loaded_modules:
                    temp = list(map(lambda x:":".join(x),dev[1]))
                    what_to_write = [image,dev[0]] + temp
                    candidates.append(what_to_write)
    
    return candidates

if __name__ == "__main__":
    image = sys.argv[1]

    find_char_devs(image)



