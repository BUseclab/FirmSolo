#!/usr/bin/env python3



import os
import sys
import pickle
currentdir = os.path.dirname(os.path.realpath(__file__))
parentdir = os.path.dirname(currentdir)
sys.path.append(parentdir)
import ast
import traceback as tb

import custom_utils as cu

image_dslc = {}


def find_mod_data():

    for img in image_dslc:
        #which_info = ["modules"]
        #info = cu.get_image_info(img,which_info)
        
        #loaded_mods_fl = cu.loaded_mods_path + "{}/{}_ups.pkl".format(img,img)
        img_info_fl = cu.img_info_path + "{}.pkl".format(img)
        try:
            data = cu.read_pickle(img_info_fl)
        except:
            print(tb.format_exc())
        
        #data['dslc'] = image_dslc[img]
        data['firma_dslc'] = list(set(image_dslc[img] + data['firma_dslc']))
        print("Image", img, data['firma_dslc'])
        
        cu.write_pickle(img_info_fl, data)

if __name__ == "__main__":

    infile = sys.argv[1]
    #infile2 = sys.argv[2]

    lines = cu.read_file(infile)
    #need_fix = cu.read_file(infile2)
    for line in lines:
        if "[" not in line:
            print(line)
            continue
        #if "Bad_struct_Offsets" in line:
            #continue
        tokens = line.split(":")
        image = tokens[0].split()[1]
        #if image not in need_fix:
            #continue
        sol_opts = ast.literal_eval(tokens[-1])
        if image not in image_dslc:
            image_dslc[image] = sol_opts
        else:
            image_dslc[image] = list(set(image_dslc[image] + sol_opts))

    print(image_dslc)
    find_mod_data()
