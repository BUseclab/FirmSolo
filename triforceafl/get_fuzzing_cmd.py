#!/usr/bin/env python3


import os
import sys
currentdir = os.path.dirname(os.path.realpath(__file__))
parentdir = os.path.dirname(currentdir)
sys.path.append(parentdir)
sys.path.append("{}/fs_and_snap_scripts/".format(parentdir))
import subprocess
from dataclasses import dataclass
import traceback
import custom_utils as cu

delimeter = "\xa5\xc9"
calldelim = "\xb7\xe3"


########### Read all the device file names for the images in our set #############
def get_entry(image):
    cmd = f"find {cu.abs_path}/Fuzz_Results_Cur/{image} -name \"fuzzer_stats\""

    out = None
    try:
        out = subprocess.check_output(cmd,shell=True).decode("utf-8").split("\n")
    except:
        pass
    
    return out

def get_cmd(entry,image):
    lines = cu.read_file(entry)

    fuzz_cmd = lines[-1].split(": ")[1]

    tokens = fuzz_cmd.split(" ")
    qemu= tokens[13]
    kernel = tokens[17]
    rootfs = tokens[19]
    machine = tokens[33]
    if qemu == "qemu-system-arm":
        panic = tokens[35]
        die = tokens[37]
        testfile = tokens[39]
    else:
        panic = tokens[37]
        die = tokens[39]
        testfile = tokens[41]
    #### Now get the crash inputs
    if machine == "malta":
        console = "ttyS0"
        storage = "hda"
        cpu = "\"-cpu 34Kf\""
    else:
        console = "ttyAMA0"
        storage = "sda"
        cpu = ""

    module_fuzz_dir = entry.replace("fuzzer_stats","")
    module = module_fuzz_dir.split("/")[-3]

    crash_dir = module_fuzz_dir + "crashes/"
    crashes = os.listdir(crash_dir)
    try:
        crashes.remove("README.txt")
    except:
        pass
    hang_dir = module_fuzz_dir + "hangs/"
    hangs = os.listdir(hang_dir)

    return qemu,kernel,rootfs,machine,panic,die,testfile,console,storage,cpu,crash_dir,crashes,hang_dir,hangs



###############################################################

if __name__ == "__main__":
    
    image = sys.argv[1]
   # Create a pool with 8 workers
    entries = get_entry(image)
    
    for entry in entries:
        if not entry:
            continue
        qemu,kernel,rootfs,machine,panic,die,testfile,console,storage,cpu,crash_dir,crashes,hang_dir,hangs = get_cmd(entry,image)
        
        print("Entry:", entry)
        print("CRASHES:")
        for crash in crashes:
            crash_fl = crash_dir + crash
            cmd = f"{cu.tafl_lsf_dir}/runTest " + " ".join([testfile,crash_fl,kernel,rootfs,storage,panic,die,machine,qemu,console,cpu])
            print(cmd)
            print()
        print("HANGS:")
        for hang in hangs:
            hang_fl = hang_dir + hang
            cmd = f"{cu.tafl_lsf_dir}/runTest " + " ".join([testfile,hang_fl,kernel,rootfs,storage,panic,die,machine,qemu,console,cpu])
            print(cmd)
            print()

