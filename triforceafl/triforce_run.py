#!/usr/bin/env python3



import os
import sys
currentdir = os.path.dirname(os.path.realpath(__file__))
parentdir = os.path.dirname(currentdir)
sys.path.append(parentdir)
from stage2b.get_order import Module_Order, get_dictionary 
from stage2b.create_fs import create_img_fs
import subprocess as sb
from multiprocessing import Pool
from dataclasses import dataclass
import pickle
import shlex
import signal
import time as tm
import struct
import traceback
import custom_utils as cu
import csv
import threading
from gather_data_scripts.get_module_cmd_nums import get_cmd_nums
import argparse
from gather_data_scripts.get_image_char_devs import find_char_devs


delimeter = "\xa5\xc9"
calldelim = "\xb7\xe3"

init_template = """#!/bin/sh                                                                                                                              
mount -t proc proc /proc                                                                                                               
#mount -t sysfs none /sys                                                                                                              
mount -t debugfs none /sys/kernel/debug                                                                                                
mount -t devtmpfs none /dev                                                                                                            
#mount -t tmpfs none /tmp                                                                                                              
#chmod 777 / /tmp                                                                                                                      
mkdir -p /dev/pts                                                                                                                      
mkdir -p /dev/shm                                                                                                                      
mount -a                                                                                                                               
hostname -F /etc/hostname                                                                                                              
/etc/init.d/rcS                                                                                                                        
%(MODULES)s
%(MKNOD)s

exec /home/driver -v

"""

entry_dict = {}

class TriforceAFL:
    def __init__(self, image, module, entry, cnt, out_fuzz_dir, timeout):
        self.image = image
        self.module = module
        self.entry = entry
        self.cnt = str(cnt)
        self.out_fuzz_dir = out_fuzz_dir
        self.timeout = timeout
        self.test_case = "0"   ### Case with char device
        self.have_mknod = True
        ### Setup functions
        self.__get_major_minor()
        self.__get_image_info()
        self.cust_module_dict = cu.create_dict(self.modules)
        self.__set_trace_addresses()
        self.__create_fuzz_dirs()
        self.extracted_fs_dir = f"{cu.result_dir_path}{image}/extracted_fs/"

    ### Setup the major, minor, the device name or net device
    def __get_major_minor(self):
        data_tokens = self.entry.split(":")
        self.major = data_tokens[1]
        self.minor = data_tokens[2]
        self.dev_name = data_tokens[0]
        if data_tokens[0] == "tun":
            self.dev_name_path = "/dev/net/tun"
        else:
            self.dev_name_path = "/dev/" + data_tokens[0]

        if int(self.major) == 0 and int(self.minor) == 0:
            self.have_mknod = False
            self.dev_name_path = data_tokens[0]
            self.test_case = "1"   ### Case with net device

    def __get_image_info(self):
        self.kernel, self.arch, self.endian, self.modules, \
                     self.vermagic = get_module_info(self.image)

    def __set_trace_addresses(self):
        if self.arch == "mips":
            self.start_addr = "c0000000"
            self.end_addr = "c2000000"
        elif self.arch == "arm":
            self.start_addr = "bf000000"
            self.end_addr = "c0000000"
        else:
            self.start_addr = "0"
            self.end_addr = "0"

    def __create_fuzz_dirs(self):
        create_output_dirs(self.out_fuzz_dir, self.module)
        self.target_dir = f"{self.out_fuzz_dir}{self.module}/"
        create_output_dirs(self.target_dir, self.dev_name)
        self.target_dir += f"{self.dev_name}"
        self.copy_data_file = f"{self.target_dir}/fuzz_data{self.cnt}"

    def __get_module_data(self):
        ### First get the panic and die address for the Kfs kernel
        self.panic, self.die = get_panic_die(self.image, self.kernel)

        cust_mod_subs = []
        mod_load_info_fl = f"{cu.loaded_mods_path}{self.image}/{self.image}_ups_subs.pkl"
        try:
            mod_load_info = cu.read_pickle(mod_load_info_fl)
            self.cust_mod_subs = mod_load_info[1]
            self.core_subs = mod_load_info[2]
            print("Core subs", self.core_subs)
            self.qemu_opts = mod_load_info[-1]
        except:
            print("Image {} does not have any load information yet...Run"
                  "stage 3 first".format(self.image))
            return False

        return True


    def __get_module_deps(self):
        try:
            module_path = self.cust_module_dict[self.module + ".ko"]
        except:
            tmp_mod = self.module.replace("-","_")
            try:
                module_path = self.cust_module_dict[tmp_mod + ".ko"]
                self.module = tmp_mod
            except:
                tmp_mod = self.module.replace("_","-")
                module_path = self.cust_module_dict[tmp_mod + ".ko"]
                self.module = tmp_mod


        all_modules_order = Module_Order(self.modules, "shipped", self.extracted_fs_dir)
        
        cust_order = []
        all_modules_order.get_order_recursive(module_path)
        cust_order = all_modules_order.order

        #cust_order,paramz = get_mod_order(module_path,self.modules,cust_order,
                                          #"shipped", paramz)
        
        success = self.__get_module_data()
        if not success:
            return success

        ### Apply any substitutions if needed
        if len(cust_order) > 1:
            for indx, mod_path in enumerate(cust_order[:-1]):
                for sub in self.cust_mod_subs:
                    if mod_path.split("/")[-1] == sub[2]:
                        cust_order[indx] = sub[1].replace("/upstream",
                                                          "./native")

        self.deps = cust_order
        return True
    
    def __setup_qemu(self):
        self.fuzz_cmd = None
        if self.arch == "mips":
            if self.endian == "little endian":
                qemu = "qemu-system-mipsel"
            else:
                qemu = "qemu-system-mips"
            self.kernel_path = \
                    f"{cu.result_dir_path}{self.image}/{self.kernel}/vmlinux"
        elif self.arch == "arm":
            qemu = "qemu-system-arm"
            self.kernel_path = \
                    f"{cu.result_dir_path}{self.image}/{self.kernel}/zImage"
        else:
            return False

        machine = self.qemu_opts["machine"]
        if self.qemu_opts["cpu"] != "":
            cpu = self.qemu_opts["cpu"].split()[1]
        else:
            cpu = ""
        
        print("CPU", cpu)
        iface = self.qemu_opts["iface"]
        if iface == "":
            iface = "if=ide"

        blk_dev = self.qemu_opts["blk_dev"]
        tty = self.qemu_opts["tty"]

        fuzzer_args = \
                f"-t 200 -m 6144 -i {self.input_dir} -o {self.input_dir_min} -QQ -- {qemu} -L /TriforceAFL/qemu_mode/qemu/pc-bios -kernel {self.kernel_path} -drive file=privmem:{self.fs_path},{iface} -m 256M -nographic -append \"root={blk_dev} rw init=/init console={tty} fdyne_execute=0 firmadyne.procfs=0 firmadyne.devfs=0 mem=256M\" -M {machine} -cpu {cpu} -aflPanicAddr {self.panic} -aflDmesgAddr {self.die} -aflFile2 {self.copy_data_file} -aflFile @@"

        self.minimizer = f"timeout --foreground -k 10 300 /TriforceAFL/afl-cmin {fuzzer_args}"
        print("Minimizing cmd", self.minimizer)
        
        #self.input_dir_min = self.input_dir
        if self.input_dir != "-":
            self.run_minimizer()
        
        if not os.listdir(self.input_dir_min):
            self.input_dir_min = self.input_dir

        if cpu != "":
            temp = cpu
            cpu = "\"" + "-cpu " + temp + "\""
            
        self.fuzz_cmd = \
                f"timeout -k 10 {self.timeout} /TriforceLinuxSyscallFuzzer/Fuzz -M {self.banner} {self.kernel_path} {self.image} {self.target_dir} {self.fs_path},{iface} {machine} {self.panic} {self.copy_data_file} {qemu} {self.die} {blk_dev} {self.input_dir_min} {tty} {cpu}"
        
        print("Fuzzer cmd is", self.fuzz_cmd)
        return True

    def run_minimizer(self):
        try:
            minimize = sb.run(self.minimizer, cwd="/TriforceAFL/", shell = True)
            if int(minimize) == 124 and os.listdir(self.input_dir_min) == []:
                print("Minimizing had no effect going back to default input dir")
                self.input_dir_min = self.input_dir
        except:
            print("Unsuccessful minimizing for", self.image, self.banner)

    def fix_fs(self):
        
        rootfs = "rootfs_{}_{}.qcow2".format(self.module, self.dev_name)
        self.fs_path = "{}/{}/fuzzer/{}".format(cu.fs_dir, self.image, rootfs)

        if os.path.exists(self.fs_path):
            return

        insmod = []
        for path in self.deps:
            if self.image in path:
                insmod.append(f"insmod /root/{path}")
            else:
                insmod.append(f"insmod /root/{self.image}/{path}")

        modules_load = "\n".join(insmod)

        if self.have_mknod:
            dev_create = "mknod {} c {} {}".format(self.dev_name_path,
                                                   self.major, self.minor)
            template_init = init_template % dict(MODULES = modules_load,
                                                 MKNOD = dev_create)
        else:
            dev_create = "ifconfig {} up".format(self.dev_name_path)
            template_init = init_template % dict(MODULES = modules_load,
                                                 MKNOD = dev_create)

        print("Template\n",template_init)

        ### Create the filesystem
        print ("MODULE IS", self.module)
        create_img_fs(self.image, self.cnt, "qcow2", template_init, self.module,
                      self.dev_name)

    def copy_fuzz_data(self):
        the_start_addr = str(int(self.start_addr, 16))
        the_end_addr = str(int(self.end_addr, 16))
        cp_cmd = ["python2", f"{cu.script_dir}/triforceafl/copy_fuzz_data.py",
                the_start_addr, the_end_addr, self.dev_name_path,
                self.copy_data_file, self.test_case]
        try:
            sb.run(cp_cmd)
        except:
            print(traceback.format_exc())
            return False

        return True

    def get_module_data(self):
        success = self.__get_module_deps()
        return success

    def setup_afl(self):
        self.banner = f"{self.dev_name}_{self.image}"

        ### Get the module data: Dependencies, Substitutions, etc
        success = self.get_module_data()
        if not success:
            print("Could not get module info for image", self.image)
            return success

        ### Tracing data for the fuzzer
        success = self.copy_fuzz_data()
        if not success:
            print("Could print the tracing data for the fuzzer...Exiting")
            return success
        ### The filesystem to be used
        self.fix_fs()
        
        ### AFL arguments
        self.fuzzer_path = f"TriforceAFL/"
        self.input_dir_min = f"{self.out_fuzz_dir}{self.module}/inputs_min/"
        ### Either we continue a fuzzing run or create a new one
        if os.path.exists(f"{self.target_dir}/{self.banner}"):
            check_cont = check_if_cont(self.target_dir, self.banner)
            if check_cont:
                self.input_dir = "-"
            elif check_cont == False:
                print("The fuzzer did not make progress for 2 hours...Exiting")
                return False
            else:
                self.input_dir = fix_inputs(self.image, self.module,
                                            self.out_fuzz_dir)
        else:
            self.input_dir = fix_inputs(self.image, self.module,
                                        self.out_fuzz_dir)
        ### Triforce QEMU setup
        success = self.__setup_qemu()
        if not success:
            print("Could setup QEMU for image", self.image)
            return success

        return True
    def run_the_fuzzer(self):
        success = self.setup_afl()
        if not success:
            print(f"Something went wrong when setting up TriforceAFL for image {self.image} and banner {self.banner}")
            return
        ### Main fuzzer run
        if not self.fuzz_cmd:
            print(f"Something went wrong when setting up TriforceAFL for image {self.image} and banner {self.banner}")

        curr_cwd = os.getcwd()
        try:
            fuzzer = sb.Popen(self.fuzz_cmd, cwd=curr_cwd, shell=True)
        except:
            print(traceback.format_exc())

        try:
            fuzzer.wait(timeout = self.timeout)
        except:
            print("Timeout expired for process", str(fuzzer.pid))

#########################################################################

def filter_entries(entries):
    which_info = ["kernel"]
    for tokens in entries:
        image, module = tokens[0], tokens[1]
        
        data = [image]
        for dev in tokens[2:]:
            data.append(dev)
        info = cu.get_image_info(image,which_info)
        kernel = "linux-" + info[0]
        temp = frozenset([kernel,module])
        if temp not in entry_dict.keys():
            entry_dict[temp]= [data]
        else:
            entry_dict[temp].append(data)

########### Get candidate kmods to be fuzzed for an image #############
def get_entries(image):
    entries = find_char_devs(image)

    return entries
###############################################################

####################### Get panic and die addresses for the image ###############
def get_panic_die(image,kernel):
    system_map = "{}{}/{}/System.map".format(cu.result_dir_path,image,kernel)
    
    symbols = cu.read_file(system_map)
    
    for line in symbols:
        tokens = line.split()
        if tokens[2] == "panic":
            panic = tokens[0].replace("ffffffff","")
        if tokens[2] == "die":
            die = tokens[0].replace("ffffffff","")
    return panic,die
#################################################################################

##################### Fix inputs for the fuzzer ########################
def fix_inputs(image, module, out_fuzz_dir):
    ioctl_cmd_fl = \
            f"{cu.container_data_path}fuzzer_data/{image}/{module}_cmds.out"
    inpt_dir = f"{out_fuzz_dir}{module}/inputs/"

    #if os.path.exists(inpt_dir):
        #return inpt_dir

    mkdir = ["mkdir", inpt_dir]
    ### Create the dir if it does not exist
    try:
        sb.run(mkdir)
    except:
        print(traceback.format_exc())
        pass
    ### Create the inputs for the fuzzer
    create_inpt = "python2 /TriforceLinuxSyscallFuzzer/gen.py {} {}".format(ioctl_cmd_fl,inpt_dir)
    
    print("Running", create_inpt)
    try:
        sb.run(create_inpt, shell = True)
    except:
        print(traceback.format_exc())
        print("Could not create the input seeds for image",image,"and module",
              module)

    return inpt_dir

#########################################################################
def check_if_fs_exists(image,path):
    if os.path.exists(path):
        return True
    else:
        return False
########################################################################

def check_if_cont(out_dir, banner):
    try:
        fl = f"{out_dir}/{banner}/fuzzer_stats"
        lines = cu.read_file(fl)
    except:
        return None

    path_num = 0
    last_path_time = 0
    last_update_time = 0
    for line in lines:
        if "paths_total" in line:
            tokens = line.split()
            path_num = int(tokens[2])
        if "last_path" in line:
            tokens = line.split()
            last_path_time = int(tokens[2])
        if "last_update" in line:
            tokens = line.split()
            last_update_time = int(tokens[2])
    last_path_discovered = last_update_time - last_path_time

    if path_num > 1 and last_path_time >0  and last_path_discovered < 7200:
        return True
    else:
        return False

################### Data class for passing input to workers ################

@dataclass
class FuzzData:
    img_name: str
    module:str
    entry: str
    out_fuzz_dir: str
    counter: int               #Needed for creating a temp file
    timeout: int
###########################################################################

def create_output_dirs(out_fuzz_dir,subdir):
    try:
        os.mkdir(out_fuzz_dir + subdir)
    except:
        print("Directory",out_fuzz_dir + subdir,"already exists")
        #print(traceback.format_exc())


def create_directories(image):
    out_fuzz_dir = cu.abs_path + "Fuzz_Results_Cur/" + image + "/"

    try:
        cmd = ["mkdir", "-p", out_fuzz_dir]
        sb.run(cmd)   
    except:
        print("Directory",out_fuzz_dir,"already exists")

    return out_fuzz_dir

###################### Essential Info about the module ###########################

def get_module_info(image):
    
    which_info = ["kernel","arch","endian","modules","vermagic"]
    
    info = cu.get_image_info(image, which_info)

    kernel = "linux-" + info[0]
    arch = info[1]
    endianess = info[2]
    modules = info[3]
    vermagic = info[4]

    return kernel,arch,endianess, modules,vermagic

##################################################################################

def save_bad_testcase(out_fuzz_dir,bad_cmd):
    outfile = out_fuzz_dir + "bad_testcases"
    with open(outfile,"a") as f:
        f.write(bad_cmd + "\n")

def cleanup(data_fname):
    try:
        res = sb.run(["rm","-rf",data_fname],shell=False)
    except Exception as e:
        print(e)
        print(traceback.format_exc())

#################### Function for every worker #######################
def start_fuzz(fuzz_data):
    image = fuzz_data.img_name
    module = fuzz_data.module
    entry = fuzz_data.entry
    cnt = fuzz_data.counter
    #print("Inside worker",cnt)
    out_fuzz_dir = fuzz_data.out_fuzz_dir
    
    timeout = fuzz_data.timeout

    triforce = TriforceAFL(image, module, entry, cnt, out_fuzz_dir, timeout)
    try:
        triforce.run_the_fuzzer()
    except:
        print(traceback.format_exc())

######################################################################

#################### Generic Fuzzing #################################

def data_append(image,kernel,arch,endianess,image_num,out_fuzz_dir):

    data = []
    data.append(image)
    data.append(kernel)
    data.append(arch)
    data.append(endianess)
    data.append(image_num)
    data.append(out_fuzz_dir)

    return data
######################################################################



if __name__ == "__main__":
    
    parser = argparse.ArgumentParser(description='Fuzz IoT kernel modules with TriforceAFL')
    parser.add_argument('-i', '--image', help = 'An image whose kernel modules will be fuzzed', default = None)
    parser.add_argument('-t', '--time', type = str, help = 'How much time each kenrel module should be fuzzed. Along with the time specify if seconds, minutes or hours [s,m,h] (e.g., -t 10s)', default = None)

    args = parser.parse_args()
    image = args.image
    time = args.time

    if not time or not image:
        print("Please specify a correct image ID or time to fuzz")
        sys.exit(1)

    if "m" in time:
        timeout = int("".join(filter(str.isdigit, time))) * 60
    elif "h" in time:
        timeout = int("".join(filter(str.isdigit, time))) * 3600
    else:
        timeout = int("".join(filter(str.isdigit, time)))
    
    print(f"Will fuzz for {timeout} seconds")
   # Create a pool of python workers
    #p = Pool(cu.num_of_threads)

    entries = get_entries(image)

    all_data = []
    
    cnt = 0
    for entry in entries:
        
        module = entry[1]
        image = entry[0]

        devices = entry[2:]
        devs = []
        for dev in devices:
            tokens = dev.split(":")
            if tokens[0].isnumeric():
                continue
            else:
                devs.append(dev)

        print("Getting the IOCTL cmd numbers for image",image,"and module",module)
        get_cmd_nums(image, module + ".ko")
        
        # Create the result directory
        out_fuzz_dir = create_directories(image)
        
        for dev in devs:
            fuzz_data = FuzzData(image, module, dev, out_fuzz_dir, cnt, timeout)
            instance = "Image:{} Module:{} Dev:{}\n".format(image,module,dev)
            print(instance)
            all_data.append(fuzz_data)
            cnt += 1
        # Map each entry to a worker
    
    for data in all_data:
        start_fuzz(data)
        #print("Data", data)
    #res = p.map(start_fuzz, all_data)
