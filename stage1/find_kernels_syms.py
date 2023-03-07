#!/usr/bin/env python3


import os
import sys
import pickle
import subprocess
from multiprocessing import Pool
currentdir = os.path.dirname(os.path.realpath(__file__))
parentdir = os.path.dirname(currentdir)
sys.path.append(parentdir)
sys.path.append(currentdir)
import custom_utils as cu


class Image_kernel:
    def __init__(self,image,kern,out_dir):
        self.image = image
        self.kern = kern
        self.out_dir = out_dir
        self.vmlnx_to_elf = f"{cu.script_dir}vmlinux-to-elf/vmlinux-to-elf"
        self.kallsym_finder = f"{cu.script_dir}vmlinux-to-elf/kallsyms-finder"
        self.config_finder = f"{cu.script_dir}stage1/config_extr.sh"

    def make_dir(self):
        cmd = f"mkdir {self.out_dir}/"        
        try:
            res = subprocess.call(cmd, shell=True)
        except:
            print("The directory for image",self.image,"is already created")
            pass

    def extract_kernel(self):
        cmd = f"{self.vmlnx_to_elf} --e-machine 1 --bit-size 32 {self.kern} {self.out_dir}/vmlinux"
        
        success = False
        try:
            res = subprocess.call(cmd,stderr=subprocess.PIPE, shell=True)
            success= True
        except:
            print("Could not extract kernel",self.kern)

        return success
    
    def extract_kallsyms(self,success):
        cmd = f"{self.kallsym_finder} {self.out_dir}/vmlinux"
        
        #We have not extracted the kernel
        if not success:
            return

        res = ""
        try:
            res = subprocess.check_output(cmd,shell=True).decode("utf-8")
        except:
            print("Could not retrieve kallsyms information for image",self.image)

        if res != "":
            with open(f"{self.out_dir}/kallsyms", "w") as f:
                f.write(res+"\n")
        
        return
    
    def extract_config(self,success):
        if success:
            cmd = f"{self.config_finder} {self.out_dir}vmlinux"
        else:
            cmd = f"{self.config_finder} {self.kern}"
        
        retrieved = False
        res = ""
        try:
            res = subprocess.check_output(cmd, shell=True).decode("utf-8")
            retrieved = True
        except:
            print("Could not retrieve the config file for image",self.image)

        
        if res != "":
            with open(f"{self.out_dir}/config", "w") as f:
                f.write(res + "\n")

        return retrieved


def extract_kernel_ksym_entry(image):
    out_dir = f"{cu.result_dir_path}/{image}/original_kernel/"
    target_kernel = f"{cu.extracted_fs_and_kern_dir}/{image}.kernel"

    obj = Image_kernel(image, target_kernel, out_dir)
    obj.make_dir()
    success = obj.extract_kernel()
    if success:
        obj.extract_kallsyms(success)
    
    retrieved = obj.extract_config(success)

def main():
    
    image = sys.argv[1]
    extract_kernel_ksym_entry(image)

if __name__ == "__main__":
    main()
