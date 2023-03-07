#!/usr/bin/env python3


import os
import sys
currentdir = os.path.dirname(os.path.realpath(__file__))
parentdir = os.path.dirname(currentdir)
sys.path.append(parentdir)
import custom_utils as cu
import pickle
from multiprocessing import Pool
import subprocess

def create_tmp_dir(image,cnt):
    try:
        cmd = "mkdir /tmp/{}_{}".format(image,cnt)
        #cmd = "mkdir /tmp/" + image + str(cnt)
        os.system(cmd)
        cmd2 = "mkdir /tmp/{}_{}_2".format(image,cnt)
        #cmd2 = "mkdir /tmp/" + image + "_2"
        os.system(cmd2)
    except Exception as e:
        print(e)
        print("Directory /tmp"+image+" already exists")


def fix_filesystems(batch):
    
    images = cu.read_file(batch)
    
    return images

def delete_old_files(image,cnt):

    cwd = os.getcwd()
    os.chdir("/tmp/" + image + "_{}".format(cnt))
    
    cmd = "rm -rf /tmp/" + image + "_{}_2/*".format(cnt)
    os.system(cmd)

    #cmd2 = " rm -rf ./native"

    #os.system(cmd2)

    os.chdir(cwd)


def copy_rootfs(output_dir, image, rootfs,temp):

    try:
        cmd = "mkdir " + output_dir + image
        os.system(cmd)
    except:
        print("The directory " + output_dir + image, "already exists")

    # Copy the individual root filesystem to its directory

    cmd2 = "cp {}{} {}{}/{}".format(cu.abs_path,temp,output_dir,image,rootfs)
    os.system(cmd2)


def cleanup(temp,output_dir, image,rootfs,cnt):
    
    try:
        cmd = "rm {}{}".format(cu.abs_path,temp)
        os.system(cmd)
    except:
        print("Filesystem",temp, "does not exist")
    
    try:
        cmd = "rmdir /tmp/" +  image + "_{}".format(cnt)
        os.system(cmd)
    except:
        print("Directory","/tmp/" + image, "does not exist")
    
    try:
        cmd = "rmdir /tmp/" +  image + "_{}_2".format(cnt)
        os.system(cmd)
    except:
        print("Directory","/tmp/" + image + "_2", "does not exist")
    
    try:
        cmd = "rm " + output_dir + image + "/" + rootfs
        os.system(cmd)
    except:
        print(" Copy Filesystem",rootfs, "does not exist")
############# Convert the image from ext2 to qcow2 ####################

def convert_to_qcow(output_dir,image,rootfs,unique_fs,cnt,module,dev_name):
    cwd = os.getcwd()
    root_dir = output_dir + image
    os.chdir(root_dir)
    core = rootfs.split(".")[0]
    
    mod = module.replace(".ko","")
    if unique_fs:
        if not os.path.exists("./fuzzer/"):
            os.mkdir("./fuzzer")
        cmd = "qemu-img convert -O qcow2 {} ./fuzzer/rootfs_{}_{}.qcow2".format(rootfs,mod,dev_name)
    else:
        cmd = "qemu-img convert -O qcow2 " + rootfs + " " + core + ".qcow2"

 #   cmd = " qemu-img convert -O qcow2 rootfs2.ext2 rootfs2.qcow2"
    
    print("Converting rootfs to qcow2 format")
    print(cmd)
    os.system(cmd)
    print(root_dir)
    os.chdir(cwd)
#######################################################################

################################################################################
################## Create Image FS Function ##############################

# To be called from outside of the script
def create_img_fs(image,cnt,fs_type,*args):
    

    image_dir = cu.result_dir_path
    shipped_mod_dir = f"{cu.result_dir_path}/{image}/extracted_fs/"
    exploit_dir = cu.exploit_dir
    
    output_dir = cu.fs_dir
    
    which_info = ["kernel","arch","endian", "modules"]
    info = cu.get_image_info(image,which_info)

    endianess = info[2]
    arch = info[1]
    kernel = info[0]
    modules = info[3]

    
    #Select the correct driver executable {gcc/endianess}
    if kernel >= "2.6.32":
        if arch == "mips":
            distro = "mips_new"
        else:
            distro = "arm_new"
    else:
        if arch == "mips":
            distro = "mips_old"
        else:
            distro = "arm_old"
    ################ Create a filesystem based on the type we want: qcow2 or cpio ########################
    if arch == "mips":
        if endianess == "little endian":
            if fs_type == "qcow2":
                rootfs = "rootfs_mipsel.ext2"
                temp = "rootfs_mipsel" +  str(cnt) + ".ext2"
            else:
                rootfs = "rootfs_cpio.ext2"
                temp = "rootfs_cpio" + str(cnt) + ".ext2"
            mount_cmd = "mount {}".format(cu.abs_path) + temp + " /tmp/" + image + "_{}/".format(cnt)
            end = "le"

        else:
            if fs_type == "qcow2":
                rootfs = "rootfs_mips.ext2"
                temp = "rootfs_mips" +  str(cnt) + ".ext2"
            else:
                rootfs = "rootfs_mips_cpio.ext2"
                temp = "rootfs_mips_cpio" + str(cnt) + ".ext2"
            mount_cmd = "mount {}".format(cu.abs_path) + temp + " /tmp/" + image + "_{}/".format(cnt)
            end = "be"
    elif arch == "arm":
        if endianess == "little endian":
            end = "le"
        else:
            end = "be"
        if fs_type == "qcow2":
            rootfs = "rootfs_arm.ext2"
            temp = "rootfs" + str(cnt) + ".ext2"
        else:
            rootfs = "rootfs_arm_cpio.ext2"
            temp = "rootfs_arm_cpio" + str(cnt) + ".ext2"
        mount_cmd = "mount {}".format(cu.abs_path) + temp + " /tmp/" + image + "_{}/".format(cnt)

    #### First find all the 
    #native_mods_temp = "modules" + str(cnt) + ".ext2"
    #mount_native = "mount {} /tmp/{}_2".format(native_mods_temp,image)

    print("Creating a temporary filesystem for",rootfs)
    create_tmp_cmd = " cp {}{} {}{}".format(cu.buildroot_fs_dir,rootfs,cu.abs_path,temp)
    os.system(create_tmp_cmd)
    
    print("Creating a tmp directory for mounting the filesystem....")
    create_tmp_dir(image,cnt)

    print("Using filesystem",temp)
    os.system(mount_cmd)

    delete_old_files(image,cnt)

    #cmd = "cp -r " + shipped_mod_dir + image + " /tmp/" + image + "_{}/root/".format(cnt)

    cmd2 = "cp -r " + image_dir + image + "/linux-" + kernel + "/lib/modules/ " + "/tmp/" + image + "_{}/root/native/".format(cnt)
    
    cmd3 = "cp  " + image_dir + image + "/linux-" + kernel + "/System.map " + "/tmp/" + image + "_{}/".format(cnt)
    os.system(cmd3)
    
    if arch == "mips":
        cmd4 = "cp /TriforceLinuxSyscallFuzzer/" + distro + "/" + end + "/driver" + " /tmp/" + image + "_{}/home/".format(cnt)
    elif arch == "arm":
        cmd4 = "cp /TriforceLinuxSyscallFuzzer/" + distro + "/driver" + " /tmp/" + image + "_{}/home/".format(cnt)
    
    print("Copying fuzzer user agent to filesystem")
    os.system(cmd4)

    #### If we are calling from the fuzzer then create an init script
    create_unique_fs = False
    fuzz_mod = ""
    dev_name = ""
    if args:
        init_template = args[0]
        fl = "/tmp/{}_{}/init".format(image,cnt)
        create_unique_fs = True
        with open(fl,"w") as f:
            f.write(init_template)
        cmd5 = "chmod +x {}".format(fl)
        os.system(cmd5)
        fuzz_mod = args[1]
        dev_name = args[2]

    print("Copying shipped modules")
    distrib_mod_dir_create = f"mkdir -p /tmp/{image}_{cnt}/root/{image}"
    subprocess.run(distrib_mod_dir_create, shell = True)
    
    for module in modules:
        x = module.split("/")
        if x[1] == image:
            sub_dir = "/".join(x[2:-1])
        else:
            sub_dir = "/".join(x[1:-1])
        mkdir_cmd = f"mkdir -p /tmp/{image}_{cnt}/root/{image}/{sub_dir}"
        print("Creating dir", mkdir_cmd)
        try:
            subprocess.run(mkdir_cmd, shell = True)
        except:
            print(traceback.format_exc())
            pass

        cp_cmd = f"cp {shipped_mod_dir}/{module} /tmp/{image}_{cnt}/root/{image}/{sub_dir}"
        try:
            subprocess.run(cp_cmd, shell = True)
        except:
            print(traceback.format_exc())
            pass

    #os.system(cmd)
    if fs_type == "qcow2":
        print("Copying native modules")
        os.system(cmd2)

    if fs_type == "qcow2":
        umount_cmd = "umount /tmp/" + image + "_{}".format(cnt)
        os.system(umount_cmd)
        copy_rootfs(output_dir,image,rootfs,temp)
        convert_to_qcow(output_dir,image,rootfs,create_unique_fs,cnt,fuzz_mod,dev_name)
    else:
        print("Please set fs_type to qcow2")
    
    cleanup(temp,output_dir, image,rootfs,cnt)
##########################################################################


def multi_proc(data):
    image = data[0]
    offset = data[1]
    fs_type = data[2]

    create_img_fs(image,offset,fs_type)


if __name__ == "__main__":
    
    img_id = sys.argv[1]
    fs_type = sys.argv[2]
    
    ###### Check if the ID is a number or the alphanumeric hash ########
    if img_id.isnumeric():
        print("Image ID",img_id)
    else:
        print("Invalid Image ID")
    ####################################################################
    ############################### Create the filesystems ########################################
        
    res = multi_proc([img_id, 0 , fs_type])

    ##############################################################################################
    

        


