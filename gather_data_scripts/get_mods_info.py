#!/usr/bin/env python3


import os, sys
currentdir = os.path.dirname(os.path.realpath(__file__))
parentdir = os.path.dirname(currentdir)
sys.path.append(parentdir)
from custom_utils import *

def get_image_data(image):
    shipped_mods_file = f"{loaded_mods_path}{image}/{image}_ups_subs.pkl"
    mods = []

    try:
        data = read_pickle(shipped_mods_file)
        mods = data[0]
        subs = data[1]
        core_subs = data[2]
        emulated = data[3]
    except Exception as e:
        print(traceback.format_exc())
        return
    
    loaded = ""
    sub_num = 0
    core_sub_num = 0
    try:
        if emulated == 0:
            loaded = "Not emulated"
        else:
            if "" in mods:
                loaded = len(mods) -1
            else:
                loaded = len(mods)
            sub_num = len(subs)
            core_sub_num = len(core_subs)
    except:
        pass

    crashed_mods_file = f"{loaded_mods_path}{image}/crashed_modules_ups_subs.pkl"
    
    crashed_mods = []

    try:
        crashed_mods = read_pickle(crashed_mods_file)
    except Exception as e:
        pass
    
    crashed_mod_num = 0
    if len(crashed_mods) > 0:
        crashed_mod_num = len(crashed_mods)

    image_info = img_info_path + "{0}.pkl".format(image)
    info = []
    
    which_info = ["modules"]
    try:
        info = get_image_info(image,which_info)
    except Exception as e:
        print(e)
        pass
    
    total_modules = 0
    if len(info) > 0:
        if "" in info[0]:
            total_modules = len(info[0]) -1
        else:
            total_modules = len(info[0])
    
    all_modules = list(map(lambda x:x.split("/")[-1].replace(".ko",""), info[0]))
    all_subs = list(map(lambda x:x[2].replace(".ko",""), subs))
    all_crashed = list(map(lambda x:x.replace(".ko",""), crashed_mods))
    

    print("Image:", image, "Total Modules:", str(total_modules), "Loaded Modules:", str(loaded), "Crashing Modules:", str(crashed_mod_num), "Substitutions:", str(sub_num), "\n")
    print("All Modules:\n", all_modules,"\n")
    print("Loaded Modules:\n", mods,"\n")
    print("Crashing Modules:\n", all_crashed,"\n")
    print("Substitutions:\n", all_subs,"\n")

