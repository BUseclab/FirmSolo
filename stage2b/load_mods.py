#!/usr/bin/env python3
#How to make the multiprocessing pool non daemonic
#https://stackoverflow.com/questions/6974695/python-process-pool-non-daemonic

import os
import sys
currentdir = os.path.dirname(os.path.realpath(__file__))
parentdir = os.path.dirname(currentdir)
sys.path.append(parentdir)
sys.path.append(currentdir)
import custom_utils as cu
from get_order import fix_order
import time
import multiprocessing
from multiprocessing import Process,Pipe,Pool
import pickle
import create_fs as fs
import argparse
from random import randint
import traceback
import subprocess
from control_qemu import do_run

compilation_error = []

results = []
not_loaded = []
dirs = []

total = 0
tot_loaded = 0
tot_bad_mods = 0
cont_instances = []     # Actual container instances


def extract_loaded(order,subs,core_subs,proc_mod):
    mods_to_test = [] 
    loaded_mods = []
    start_addresses = []
    module_sizes = []
    loaded = 0
    which_mods = []
    which_size = []
    which_addr = []
    subed_modules = []
    
    try:
        path1,path2,subed_mods = zip(*subs)
        subed_modules = list(map (lambda x:x.replace(".ko",""),list(subed_mods)))
        print("Subed modules",subed_modules)
    except:
        print(traceback.format_exc())
    
    print("Core subs",core_subs)
    core_subz = list(map (lambda x:x.replace(".ko",""),list(core_subs)))
    
        
    try:
        for path in order:
            module = path.split("/")[-1].split(".")[0]
            if module not in mods_to_test:
                mods_to_test.append(module.replace("-","_"))
        
        for module in proc_mod:
            if module == '' or module == '~ ':
                continue
            info = module.split()
            if "cat" in info:
                continue
            if "firmadyne" in info:
                continue
 #           print(info)
            mod = info[0].replace("-","_")
            size = info[1]
            address = info[5]


            loaded_mods.append(mod)
            module_sizes.append(size)
            start_addresses.append(address)
        
        indx = 0
        for module in loaded_mods:
            if module in subed_modules or module in core_subz:
                indx+=1
                continue
            ### Substituted module so we do not count it
            
            if module in mods_to_test:
                loaded += 1
                which_mods.append(module)
                which_size.append(module_sizes[indx])
                which_addr.append(start_addresses[indx])
            indx += 1
    except:
        print(traceback.format_exc())
        sys.exit(0)

    print("Modules",which_mods)
    print("Sizes",which_size)
    print("Addresses",which_addr)

    return loaded, which_mods, which_size, which_addr, loaded_mods, module_sizes, start_addresses

def get_modprobe(image,cust_module_paths):
    # Go the result directory where the modprobe modules are kept -> Isolate the name of each module
    #modprobe = []
    resultdir = cu.result_dir_path
    image_dir = resultdir + image + "/"
    vanilla_modules = []
    vanilla_order = []

    dirs = os.listdir(image_dir)                                                                                                     
    for f in dirs:                                                                                                                   
        if os.path.isdir(image_dir + f):
            kernel = f
            mod_dir = os.listdir(image_dir + f +"/lib/modules/")[0]                                                                                                               

    lib_dir = image_dir + kernel + "/lib/modules/" + mod_dir
    mod_dep = image_dir + kernel + "/lib/modules/" + mod_dir +"/modules.dep"
    
    ################## Get the necessary vanilla modules #############
    which_info = ["final_files"]
    info = cu.get_image_info(image,which_info)
    temp = info[0]
    #with open(image_dir + "vanilla_mods.out","r") as f:
        #temp = f.readlines()
    vanilla_modules = list(map(lambda x : x.split("/")[-1].strip(".c\n") + ".ko", temp))
       
    #cust_modules = list(map(lambda x : x.split("/")[-1].strip("\n"), cust_module_paths))
    #vanilla_modules = list(set(vanilla_modules + cust_modules))
    

    print("Vanilla_modules",vanilla_modules)
    ####################################################################
    
    exist = []
    paramz = {}
    try:
        with open(mod_dep,"r") as f:
            line = f.readline()
            while line:
                #modprobe.append(line.split()[0].split(":")[0].split("/")[-1])
                #modprobe.append("/tmp/native/" + mod_dir+ "/" + line.split()[0].split(":")[0])
                van_module = line.split(":")[0].split("/")[-1].strip("\n")
                for vmod in vanilla_modules:
                    if vmod == van_module:
                        exist.append(van_module)
                        #modprobe.append("/lib/modules/" + mod_dir+ "/" + line.strip("\n"))
                line = f.readline()
    except:
        print("File",mod_dep,"does not exist")

    #print("Modprobe modules",exist)
    if exist != []:
        vanilla_order,paramz = fix_order(image,exist,mod_dep,lib_dir)
    
    return vanilla_order,paramz


def fix_filesystem(cmd,cmd2,cmd3):
        
    try:
        os.system(cmd)
    except Exception as e:
        print(e)

    try:
        os.system(cmd2)
    except Exception as e:
        print(e)
    
    try:
        os.system(cmd3)
    except Exception as e:
        print(e)


###################### Write data to a pickle file ###########################################
def write_to_pickle(loaded,sizes,addr,mod_file,*args):
    with open(mod_file,"wb") as f:
        pickle.dump(loaded,f)
        pickle.dump(sizes,f)
        pickle.dump(addr,f)
        ######### If there are modules subs drop to the pickle as well ###################
        print(args)
        if args != ():
            for arg in args:
                pickle.dump(arg,f)
            #pickle.dump(args[1],f)
##############################################################################################

############# Check if we only have one image or multiple ######################################
def check_if_numeric(infile,img_id):
    
    images = []

    if img_id.isnumeric():
        img_id = int(img_id)
        print ("Image ID",img_id)


    dirs = []
    if img_id == "-1":
        with open(infile,"r") as f:
            line = f.readline()
            while line:
                img = line.split("/")[-1].strip("\n")
                images.append(img)
                line = f.readline()
    else:
        images.append(str(img_id))

    return images
#################################################################################################

################# Get modules that cause a segmentation fault #################################
def get_bad_mods(image,mode):
    bad_modules = []
    native_bad_modules = []
    try:
        with open(cu.loaded_mods_path + image + "/bad_modules_{0}.pkl".format(mode),"rb") as f:
            bad_modules = pickle.load(f)
    except Exception as e:
        print(e)
        print("Image",image,"has not any bad modules yet")

    try:
        with open(cu.loaded_mods_path + image + "/bad_modules_native_{0}.pkl".format(mode),"rb") as f:
            native_bad_modules = pickle.load(f)
    except Exception as e:
        print(e)
        print("Image",image,"has not any native bad modules yet")

    print ("Bad modules",bad_modules)

    print ("Native bad modules", native_bad_modules)


    return bad_modules, native_bad_modules
##############################################################################################

################## Delete filesystem to save space #################################
def delete_fs(image,endianess):

    if endianess == "little endian":
        rootfs = cu.fs_path + image + "/rootfs_mipsel.qcow2"
    else:
        rootfs = cu.fs_path + image +"/rootfs_mips.qcow2"

    try:
        print("Removing filesystem for image",image)
        os.system("rm " + rootfs)
    except Exception as e:
        print("Could not remove the filesystem for image",image)

####################################################################################

def setup_emul(data):
    
    image = data[0]
    cnt = data[1]
    mode = data[2]
    socket_dir = data[3]
    upstream_params = {}
    
    print("Creating filesystem......")
    ##################### Fix Fs first ####################
    fs.create_img_fs(image, cnt, "qcow2")
    ######################################################
    time.sleep(2)
    
    image_fs_dir = cu.fs_dir + image
    
    do_run(image, mode)
    return

    ###################################################################################################################################


def save_to_output(outfile,results):

    total = 0
    tot_loaded = 0
    tot_bad_mods = 0
    with open(outfile,"w") as f:
        for res in results:
            total += res[1]
            tot_loaded += res[2]
            if res[4] == 1:
                loaded = str(res[2])
            else:
                loaded = "Not emulated"
            tot_bad_mods += res[3]
            bad = str(res[3])
            subs = str(res[5])
            core_subs = str(res[6])

            f.write("Image " + res[0] + " Total " + str(res[1]) + " Loaded " + loaded + " Bad Modules " + bad + " Substitutions " + subs + " Core substitutions " + core_subs +"\n")
        f.write("\n")
        f.write("Total " + str(total) + " Total Loaded " + str(tot_loaded) + " Total Bad Modules " + str(tot_bad_mods) + "\n")

    print("Images that were not compiled:")
    for img in compilation_error:
        print(img)

################ Create a filesystem for each image and also load all its modules ################
def log_e(e):
    print(e)

def filter_images(images):
    filtered = []
    for image in images:
        mod_fl = "{}/{}/{}_ups.pkl".format(cu.loaded_mods_path, image, image)
        try:
            res = cu.multi_read_pickle(mod_fl, 8)
        except:
            pass
        print ("Image", image, res[-1])
    return images

def do_qemu(images, socket_dir, img_cnt, outfile, mode):
    
    wanted_imgs = []
    res = []
    for j,image in enumerate(images):
        if j >= img_cnt:
            break
        wanted_imgs.append([image,j,mode,socket_dir])

    for img in wanted_imgs:
        print("Emulating image",img)
        result = setup_emul(img)
        print("Done with image",img)
        res.append(result)
    
#################################################################################################

############# Call this function when imported as a module ####################
def load_mods(infile,outfile,img_cnt,img_id,socket_dir,mode):
    
        images = check_if_numeric(infile,img_id) 

        do_qemu(images, socket_dir, img_cnt, outfile, mode)

###############################################################################


if __name__ == "__main__":
        #################### Read all the arguments and set them to the directory #############################
        parser = argparse.ArgumentParser(description='Create Filesystems and QEMU snapshots for Images')
        parser.add_argument('-f', '--infile',help='The file to get the list of images from', default=None)
        parser.add_argument('-o', '--outfile',help='The file to store statistics to', default=None)
        parser.add_argument('-n', '--cnt',type=int,help='The number of images to process from the input file', default=1)
        parser.add_argument('-i', '--img_id',help='Either the number -1 or a single image ID for single processing')
        parser.add_argument('-m', '--mode',help='Mode for loading kernel modules {noup,upns,ups_subs}', default="ups_subs")
        parser.add_argument('-s', '--socket_dir',help='The directory were the results are', default="./")
        
        res = parser.parse_args()
        infile = res.infile
        outfile = res.outfile
        img_cnt = res.cnt
        img_id = res.img_id
        mode = res.mode
        socket_dir = res.socket_dir
        #######################################################################################################
        
        images = check_if_numeric(infile,img_id) 

        do_qemu(images,socket_dir,img_cnt,outfile,mode)
