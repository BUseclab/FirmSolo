#!/usr/bin/env python3

import os
import pexpect
import sys
currentdir = os.path.dirname(os.path.realpath(__file__))
parentdir = os.path.dirname(currentdir)
sys.path.append(parentdir)
import custom_utils as cu
import pickle
import time
import subprocess
from multiprocessing import Pipe
import traceback
import signal
import argparse
from get_order import fix_order
import re
#import qmp
#import qmp_shell as qmps


class Emulate():
    def __init__(self, image, subs, core_subs, crashed_modules,
                 crashed_modules_upstream, timed_out_modules,
                 timed_out_modules_upstream, mode, cnt,
                 segfaulted = True, emulated = False, last_module = None):

        self.image = image
        self.segfaulted = segfaulted
        self.subs = subs
        self.core_subs = core_subs
        self.crashed_modules = crashed_modules
        self.crashed_modules_upstream = crashed_modules_upstream
        self.timed_out_modules = timed_out_modules
        self.timed_out_modules_upstream = timed_out_modules_upstream
        self.emulated = emulated
        self.last_module = last_module
        self.mode = mode
        self.cnt = cnt
        self.dmesg_file = cu.loaded_mods_path + self.image + "/dmesg_{0}.out".format(self.mode)
        self.error_fl = "{}{}/{}_faults.out".format(cu.loaded_mods_path, self.image, self.mode)
        self.get_info()
        self.get_qemu_cmd()
        self.get_upstream()
        self.create_dirs()
        self.order = []
        self.loaded_module_types = {}

    def static_find_crashing_mod(self, module_data, error_addr):
        if "mips" in self.arch:
            kernel_addr = int(0x80000000)
        elif "arm" in self.arch:
            kernel_addr = int(0xc0000000)

        min_dif_err = 5000000000
        where_err = ""
        err_addr = int(error_addr[0], 16)

        diff_a1 = err_addr - kernel_addr
        if diff_a1 > 0:
            if diff_a1 < min_dif_err:
                min_dif_err = diff_a1
                where_err = "kernel"

        for data in module_data:
            mod = data[0]
            addr = int(data[1], 16)
            size = data[2]

            diff_a1 = err_addr - addr 

            if diff_a1 > 0: 
                if diff_a1 < min_dif_err:
                    min_dif_err = diff_a1
                    where_err = mod

        return where_err

    def get_static_crash_mod_info(self, crashing_module = None):
        crashing_mods = [] 
        module_data = [] 
        error_data = [] 
        err_addr = []
        serial_output = cu.read_file(self.dmesg_file)

        error_found = False

        for line in serial_output:
            if "Module_name" in line:
                error_found = False
                tk = line.split("Module_name:")[1]
                tokens = tk.split()
                module_data.append([tokens[0], tokens[2], tokens[4]])
                current_module = tokens[0]
            if "epc   :" in line:
                tokens = line.split()
                err_addr.append("0x" + tokens[2])
                error_found = True 
                error_data.append(line)
                continue
            if "pc :" in line:
                tokens = line.split()
                addr = "0x" + tokens[2].replace("[<", "").replace(">]", "")
                err_addr.append(addr)
                print("Error address")
                error_found = True 
                error_data.append(line)
                continue
            if error_found == True:
                #func_addresses = re.findall("(\[\<.*\>\])", line)
                #if func_addresses:
                error_data.append(line)
        try:
            crashing_module = self.static_find_crashing_mod(module_data, err_addr)
        except:
            print("Something went bad")
            return None
        #if crashing_module == "kernel":
            #for ln in error_data:
                #func_addresses = re.findall("(\[\<.*\>\])", ln)
                #if func_addresses:
                    #address = ["0x" + ln.split()[0].strip("[<>]")]
                    #crashing_module = self.static_find_crashing_mod(module_data, address)
                    #if crashing_module != "kernel":
                        #break
        
        if crashing_module and crashing_module != "kernel" and crashing_module != current_module:
            return crashing_module
        else:
            return None

    def create_dirs(self):
        cmd = ["mkdir", "{}{}".format(cu.loaded_mods_path, self.image)]
        try:
            subprocess.call(cmd)
        except:
            print("Directory for image",self.image,"already exists")
        
        cmd = ["rm","-rf", "{}{}/errors/".format(cu.loaded_mods_path, self.image)]
        try:
            subprocess.call(cmd)
        except:
            print(traceback.format_exc())
        
        cmd = ["mkdir", "{}{}/errors/".format(cu.loaded_mods_path, self.image)]
        try:
            subprocess.call(cmd)
        except:
            print(traceback.format_exc())

        cmd = ["rm", self.error_fl]
        try:
            subprocess.call(cmd)
        except:
            print(traceback.format_exc())

    def get_info(self):
        ### get some important info about the image
        which_info = ["kernel","arch","endian","vermagic", "modules"]
        info = cu.get_image_info(self.image,which_info)
        
        self.kernel, self.arch, self.endian, self.vermagic, self.modules = \
                                    info[0], info[1], info[2], info[3], info[4]
        
        ###### Get the order for loading the shipped modules and vanilla modules as well as other data ######
        self.compiled = True
        try:
            modprb = get_modprobe(self.image, self.modules)
            self.modprobe = []
            for mod in modprb:
                tokens = mod.split("/lib/")
                if len(tokens) > 2:
                    mod_path = "/lib/" + tokens[1]
                    tmp = ""
                    for tkn in tokens[2:]:
                        tmp += "/lib/{0}".format(tkn)
                    mod_path = "/lib/" + tokens[1] + tmp
                else:
                    mod_path = "/lib/" + tokens[1]
                self.modprobe.append(mod_path)
        except Exception as e:
            print(traceback.format_exc())
            self.compiled = False

    def save_faults(self, module, msg, mod_origin):
        with open(self.error_fl,"a") as f:
            f.write(module + " " + mod_origin +"\n")
            f.write(str(msg) + "\n")

        ### Now also save the dmesg for DSLC
        error_dmesg = "{}{}/errors/dmesg_{}_{}".format(cu.loaded_mods_path,
                                                       self.image, module,
                                                       mod_origin)
        
        #self.child.logfile_read.close()
        cmd = ["cp", self.dmesg_file, error_dmesg]
        try:
            subprocess.call(cmd)
        except:
            print("In save_faults:")
            print(traceback.format_exc())

    def init_qemu(self, dmesg):
        user = "root"
        # Spawn the qemu process and log to stdout
        try:
            self.child = pexpect.spawn(self.cmd)
            self.child.logfile_read = dmesg
            # Now wait for the login
            self.child.expect('(?i)login:',timeout=60)
            result = self.child.before.decode("utf-8")
        except:
            result = self.child.before.decode("utf-8")
            stop_child(self.child, self.image)
            if "ARMv7" in self.vermagic:
                self.child = pexpect.spawn(self.backup_cmd)
                self.child.logfile_read = dmesg
                # Now wait for the login
                self.child.expect('(?i)login:',timeout=60)
                self.cmd = self.backup_cmd
                self.qemu_opts[0] = self.qemu_opts[-1]
                self.qemu_opt_dict['machine'] = self.qemu_opts[-1]
            else:
                raise

        # And login with the credentials from above
        self.child.sendline(user)
        self.child.expect('# ',timeout=60)
        
        # Successful emulation
        self.emulated = True


        self.child.sendline("cd /root")
        self.child.expect('# ')

    ######################## Get all the upstream modules ###############################

    def get_upstream(self):
        res = ""
        try:
            res = subprocess.check_output('find {} -name "*.ko"'.format(self.resultdir),shell=True)
        except:
            print(traceback.format_exc())
            self.upstream_paths, self.upstream_modules = [], []

        self.upstream_paths = res.decode("utf-8").split("\n")

        self.upstream_modules = list(map(lambda x:x.split("/")[-1],self.upstream_paths))

    def check_if_crashed(self, is_upstream, module):
        last_module = None
        case = 0
        count = 0
        if not is_upstream:
            for modules in [self.crashed_modules,
                    self.crashed_modules_upstream, self.timed_out_modules,
                    self.timed_out_modules_upstream]:
                if module not in modules:
                    count += 1
            if count == 4:
                last_module = module
                load = False
                case = 0
            elif count == 3 and module in self.crashed_modules:
                last_module = module
                if self.mode == "no_subs":
                    load = False
                else:
                    load = True
                case = 1
            else:
                load = False
                case = 2
        else:
            for modules in [self.crashed_modules_upstream,
                    self.timed_out_modules_upstream]:
                if module not in modules:
                    count += 1
            if count == 2:
                last_module = module
                load = True
                case = 3
            else:
                load = False
                case = 4

        return load, last_module, case

    def load_one(self, cmd):
        try:
            self.child.sendline(cmd)
            self.child.expect(['# ',pexpect.EOF], timeout=60)
            result = self.child.before.decode("utf-8")
            #print(result)
        except:
            #### We had a timeout which means the module caused something bad
            #### So lets remove it
            result = self.child.before.decode("utf-8")
            if not "Oops" in result and not "Kernel panic" in result:
                result = "ModuleTimedOut"

        return result

    #### Function to load the modules. If a module needs a substitution
    #### this function does it
    def load_modules(self, insmod, mod, module, mod_origin, case):

        result = ""
        flag = False
        if mod_origin == "upstream":
            load_cmd = insmod.replace("/lib/modules/","/upstream/")
        else:
            load_cmd = insmod
        # Case one module causes a lot of problems 
        # We have to check if we are going to insert a custom bad module
        # If the module is a bad custom module we are now trying to load
        # its upstream counterpart
        if case != 1 or mod_origin == "upstream":
            print("Load_cmd", load_cmd)
            result = self.load_one(insmod)

        ### Check if the module crashed
        for error in ["Segmentation fault", "Oops", "Kernel panic", "ModuleTimedOut"]:
            if error in result:
                if error == "ModuleTimedOut":
                    reason = "timeout"
                else:
                    reason = "segfault"
                return reason, mod_origin, load_cmd, result

        if mod_origin == "distributed" and self.mode == "ups_subs" and case < 2:   # Substitutions enabled
            dict_indx = mod.replace(".ko","").strip("\n")
            ### Do we need a substitution?
            if "insmod:" in result or case == 1:
                try:
                    #### Find if there is an upstream counterpart
                    indx = self.upstream_modules.index(mod)
                    modl = self.upstream_paths[indx]
                    print("Sub module", modl)
                except Exception as e:
                    print("Could not load the upstream version of",mod)
                    return "no_load", mod_origin, load_cmd, result

                print("Substituting {0} with its native counter part".format(mod))
                mod_origin = "upstream"  # We have to change the mod origin in case smth happens

                cmd = "insmod /lib/modules/" + modl.split("/lib/modules/")[1]
                ### Keep old and new load_cmd for substitutions
                a_sub = [load_cmd.split(" ")[1]]
                load_cmd = cmd.replace("/lib/modules/","/upstream/")
                print("New load_cmd", load_cmd)
                a_sub.append(load_cmd.split(" ")[1])

                result = self.load_one(cmd)
                ### Check if the module crashed
                for error in ["Segmentation fault", "Oops", "Kernel panic", "ModuleTimedOut"]:
                    if error in result:
                        if error == "ModuleTimedOut":
                            reason = "timeout"
                        else:
                            reason = "segfault"
                            self.save_faults(mod, result, mod_origin)
                        return reason, mod_origin, load_cmd, result

                # We know that the substitution was a success (module was loaded) so save it
                if "insmod:" not in result:
                    a_sub.append(mod)
                    self.subs.append(a_sub)

        # The module is not loading prob due to some symbol missing
        # so dont add it to the order
        if "insmod:" in result:
            return "no_load", mod_origin, load_cmd, result

        ### The module got loaded yay!
        return "no_segfault", mod_origin, load_cmd, result

    ################### Load Upstream Kernel Modules ###################

    #TODO: A lot of code reuse here with the shipped modules function
    ###### Merge them

    def load_upstream_modules(self):
        already_loaded = []
        proc_mod = []
        last_module = None
        mod_origin = None
        distributed = False
        self.core_subs = []
        self.subs = []
        self.order = []

        try:
            for modl in self.modprobe:
                mod = modl.split("/")[-1]
                dict_indx = mod.replace(".ko", "")
                ### Check if the module is a troublesome one then if it is in native modules load it
                is_upstream_only, module = only_modprobe(mod, self.modules)

                ### Check if the module is pure upstream or there is a custom module aliasing
                load, last_module, case = self.check_if_crashed(is_upstream_only, module)

                ### A bad module probably
                if not load:
                    continue

                load_cmd = ""
                if load:
                    ### We have a custom module with an alias conflict that segfaulted
                    ### So we are substituting with the original upstream module
                    ### Count these case cause the subs list does not reflect them
                    if case == 1:
                        self.core_subs.append(mod)

                    cmd = "insmod {0}".format(modl)
                    mod_origin = "upstream"
                else:
                    if self.image in module:
                        cmd = f"insmod {module}".replace(f"./{self.image}/", f"{self.image}/")
                    else:
                        cmd = f"insmod {self.image}/{module}"
                    mod_origin = "distributed"
                    distributed = True                         # Flag to know if we are dealing with a ditributed module

                segfault,mod_origin,load_cmd, result = self.load_modules(cmd, mod,
                                                                 module,
                                                                 mod_origin,
                                                                 case)

                if segfault == "segfault" or segfault == "timeout":
                    self.segfaulted = True
                    if sefault == "segfault":
                        crash_module = self.get_static_crash_mod_info()
                        if crash_module:
                            crash_module += ".ko"
                            if crash_module in self.loaded_module_types:
                                new_origin = self.loaded_module_types[crash_module]
                                if new_origin == "distributed":
                                    mod_origin = new_origin
                                    last_module = crash_module
                            elif crash_module.replace("_","-") in self.loaded_module_types:
                                new_origin = self.loaded_module_types[crash_module.replace("_","-")]
                                if new_origin == "distributed":
                                    mod_origin = new_origin
                                    last_module = crash_module.replace("_","-")
                            elif crash_module.replace("-","_") in self.loaded_module_types:
                                new_origin = self.loaded_module_types[crash_module.replace("-","_")]
                                if new_origin == "distributed":
                                    mod_origin = new_origin
                                    last_module = crash_module.replace("-","_")
                        self.save_faults(last_module, result, mod_origin)
                    return already_loaded, last_module, mod_origin, segfault  # Send already_loaded, last_module,mod_origin,emulation, segfaulted, panic

                ### Second check if the module corrupts the slab
                self.child.sendline("cat /proc/modules")
                self.child.expect('# ',timeout=10)
                proc_mod = self.child.before.decode("utf-8")

                if "Segmentation fault" in proc_mod or "Oops" in proc_mod or "Kernel panic" in proc_mod:
                    crash_module = self.get_static_crash_mod_info()
                    if crash_module:
                        crash_module += ".ko"
                        if crash_module in self.loaded_module_types:
                            new_origin = self.loaded_module_types[crash_module]
                            if new_origin == "distributed":
                                mod_origin = new_origin
                                last_module = crash_module
                        elif crash_module.replace("_","-") in self.loaded_module_types:
                            new_origin = self.loaded_module_types[crash_module.replace("_","-")]
                            if new_origin == "distributed":
                                mod_origin = new_origin
                                last_module = crash_module.replace("_","-")
                        elif crash_module.replace("-","_") in self.loaded_module_types:
                            new_origin = self.loaded_module_types[crash_module.replace("-","_")]
                            if new_origin == "distributed":
                                mod_origin = new_origin
                                last_module = crash_module.replace("-","_")
                    self.segfaulted = True
                    self.save_faults(last_module, proc_mod, mod_origin)
                    return already_loaded, last_module, mod_origin, "segfault"  # Send already_loaded, last_module,mod_origin,emulation, segfaulted, panic
                if segfault != "no_load":
                    self.order.append(load_cmd)
                    self.loaded_module_types[mod] = mod_origin
                
                if distributed:
                    already_loaded.append(module)
                    
        except Exception as e:
                print("Exception happened in native_modules")
                print (traceback.format_exc())
                #if self.child.logfile_read != None:
                    #self.child.logfile_read.close()
                self.segfaulted = True
                return already_loaded, last_module, mod_origin, "segfault"  # Send already_loaded, last_module,mod_origin,emulation, segfaulted, panic
        
        self.segfaulted = False
        # All the modules were loaded or not normally
        return already_loaded, last_module, mod_origin, None

    ################# Load Shipped Kernel Modules #####################

    def load_distributed_modules(self, already_loaded):
        
        mod_origin = None
        for module in self.modules:
            print("Loading module",module)
            if module in already_loaded:
                continue
            module_name = module.split("/")[-1].strip("\n")
            dict_indx = module_name.replace(".ko","")

            ### Check if the module is pure upstream or there is a custom module aliasing
            load, last_module, case = self.check_if_crashed(False, module_name)
            
            #Case of a very bad module and no module subs 
            if case > 0 and (self.mode == "no_upstream" or self.mode == "no_subs"):
                continue
            
            ### Very bad module case helps with ups mode
            if not load and case != 0:
                continue
            
            load_cmd = ""
            mod_origin = "distributed"
            try:
                if self.image in module:
                    cmd = f"insmod {module}".replace(f"./{self.image}/", f"{self.image}/")
                else:
                    cmd = f"insmod {self.image}/{module}"

                
                segfault,mod_origin,load_cmd, result = self.load_modules(cmd, module_name,
                                                                 module,
                                                                 mod_origin,
                                                                 case)

                if segfault == "segfault" or segfault == "timeout":
                    self.segfaulted = True
                    if segfault == "segfault":
                        crash_module = self.get_static_crash_mod_info()
                        if crash_module:
                            print("Module", last_module, "will be replaced with", crash_module)
                            crash_module += ".ko"
                            if crash_module in self.loaded_module_types:
                                new_origin = self.loaded_module_types[crash_module]
                                if new_origin == "distributed":
                                    mod_origin = new_origin
                                    last_module = crash_module
                            elif crash_module.replace("_","-") in self.loaded_module_types:
                                new_origin = self.loaded_module_types[crash_module.replace("_","-")]
                                if new_origin == "distributed":
                                    mod_origin = new_origin
                                    last_module = crash_module.replace("_","-")
                            elif crash_module.replace("-","_") in self.loaded_module_types:
                                new_origin = self.loaded_module_types[crash_module.replace("-","_")]
                                if new_origin == "distributed":
                                    mod_origin = new_origin
                                    last_module = crash_module.replace("-","_")
                        self.save_faults(last_module, result, mod_origin)
                    return last_module, mod_origin, segfault  # Send last_module,mod_origin,emulation, segfaulted, panic
                
                if segfault == "no_load":
                    continue

                self.child.sendline("cat /proc/modules")
                self.child.expect('# ', timeout=10)
                proc_mod = self.child.before.decode("utf-8")

                if "Segmentation fault" in proc_mod or "Oops" in proc_mod or "Kernel panic" in proc_mod:
                    self.segfaulted = True
                    crash_module = self.get_static_crash_mod_info()
                    if crash_module:
                        crash_module += ".ko"
                        if crash_module in self.loaded_module_types:
                            new_origin = self.loaded_module_types[crash_module]
                            if new_origin == "distributed":
                                mod_origin = new_origin
                                last_module = crash_module
                        elif crash_module.replace("_","-") in self.loaded_module_types:
                            new_origin = self.loaded_module_types[crash_module.replace("_","-")]
                            if new_origin == "distributed":
                                mod_origin = new_origin
                                last_module = crash_module.replace("_","-")
                        elif crash_module.replace("-","_") in self.loaded_module_types:
                            new_origin = self.loaded_module_types[crash_module.replace("-","_")]
                            if new_origin == "distributed":
                                mod_origin = new_origin
                                last_module = crash_module.replace("-","_")
                    self.save_faults(last_module, proc_mod, mod_origin)
                    return last_module, mod_origin, "segfault"  # Send last_module,mod_origin,emulation, segfaulted, panic

                if segfault != "no_load":
                    self.order.append(load_cmd)
                    self.loaded_module_types[module_name] = mod_origin

            except Exception as e:
                print("Exception happened in shipped_modules")
                print (traceback.format_exc())
                #if self.child.logfile_read != None:
                    #self.child.logfile_read.close()
                self.segfaulted = True
                return last_module, mod_origin, "segfault"  # Send last_module,mod_origin,emulation, segfaulted, panic
        
        self.segfaulted = False
        return last_module, mod_origin, None

###################################################################
    ####################### Main Function/Emulate the Image and load its modules #############################
    def run_qemu(self):
        
        print("Emulating image",self.image)
        self.segaulted = False
        self.emulated = False
        self.loaded_module_types = {}
        proc_mod = []
        lsmod = []
        final_order = []
        already_loaded = []
        order = []
        upstream = []
        upstream_paths = []
        core_subs = []
        qemu_opt_dict = None
        last_module = None

        # Open the dmesg file to save serial log from the child
        dmesg = open(self.dmesg_file,"wb")

        ### Emulation begins
        try:
            self.init_qemu(dmesg)
            ### Now we are logged in
            ### Load the native modules first

            if self.mode != "no_upstream":
                already_loaded, last_module, mod_origin, reason = \
                            self.load_upstream_modules()

                #### If there is a problem return immediately
                if not self.emulated or self.segfaulted:
                    stop_child(self.child, self.image)
                    return last_module, mod_origin, reason
            
            save_order(self.image, self.order, self.mode, "core")

            # Then load the shipped modules
            last_module, mod_origin, reason = \
                    self.load_distributed_modules(already_loaded)

            #### If there is a problem return immediately
            if not self.emulated or self.segfaulted:
                stop_child(self.child, self.image)
                return last_module, mod_origin, reason

            save_order(self.image, self.order, self.mode, "final")

    ############## See what modules are loaded in the end ###########################################################
            #self.child.sendline("cat /proc/modules")
            #self.child.expect('# ')
            #proc_mod = self.child.before.decode("utf-8")
            
            stop_child(self.child,self.image)

        except Exception as e:
            print("A serious error happened during emulation")
            #self.child.logfile_read.close()
            print (traceback.format_exc())
        
        print("QEMU CMD", self.cmd)
        print("Returning safely")
        self.segfaulted = False
        #if self.child.logfile_read != None:
            #self.child.logfile_read.close()
        return last_module, mod_origin, None

############ Fix the Qemu command based on the image #############
    def get_qemu_cmd(self):
        
        # The socket might be used if you want QMP support
        # Not currently used 

        kernel = cu.kernel_prefix + self.kernel
        
        # Define the qemu cmd to run
        # The important bit is to redirect the serial to stdio
        
        self.resultdir = cu.result_dir_path + self.image + "/" + kernel + "/"
        
        bak_machine = ""
        if self.arch == "mips":
            if self.endian == "little endian":
                qemu = "qemu-system-mipsel"
                rootfs = cu.fs_dir + self.image + "/rootfs_mipsel.qcow2"
            else:
                qemu = "qemu-system-mips"
                rootfs = cu.fs_dir + self.image + "/rootfs_mips.qcow2"
            machine = "malta"
            cpu = "-cpu 34Kf"
            iface = ""
            blk_dev = "/dev/hda"
            tty = "ttyS0"
        elif self.arch == "arm":
            qemu = "qemu-system-arm"
            rootfs = cu.fs_dir + self.image + "/rootfs_arm.qcow2"
            if "ARMv5" in self.vermagic:
                machine = "versatilepb"
                cpu = ""
                iface = "if=scsi"
                blk_dev = "/dev/sda"
            elif "ARMv6" in self.vermagic:
                machine = "realview-eb-mpcore"
                cpu = "-cpu arm11mpcore"
                iface = "if=sd"
                blk_dev = "/dev/mmcblk0"
            else:
                machine = "realview-pbx-a9"
                cpu = "-cpu cortex-a9"
                bak_machine = "realview-pb-a8"
                iface = "if=sd"
                blk_dev = "/dev/mmcblk0"
            tty = "ttyAMA0"
        
        print("Rootfs used is", rootfs)
        
        self.backup_cmd = None
        if self.arch == "mips":
            #cmd = qemu + " -kernel " + resultdir  + "vmlinux -drive file=" + rootfs + ",file.locking=off,index=0,media=disk  -append \"root=/dev/hda rw console=ttyS0 log_buf_len=100M firmadyne.reboot=0 firmadyne.devfs=0 firmadyne.execute=0 firmadyne.procfs=0 firmadyne.syscall=0 \" -cpu 34Kf -nographic -M malta -m 256M"
            self.cmd = qemu + " -kernel " + self.resultdir  + "vmlinux -drive file=" + rootfs + ",index=0,media=disk,file.locking=off  -append \"root=/dev/hda rootwait rw console=ttyS0 log_buf_len=100M fdyne_reboot=0 fdyne_devfs=0 fdyne_execute=0 firmadyne.procfs=0 fdyne_syscall=0 firmsolo=1 \" -cpu 34Kf -nographic -M malta -m 256M"
        elif self.arch == "arm" and "ARMv5" in self.vermagic:
            self.cmd = "{} -kernel {}zImage -drive file={},if=scsi,file.locking=off -append \"root=/dev/sda rootwait rw console=ttyAMA0 log_buf_len=10M fdyne_reboot=0 firmadyne.devfs=0 fdyne_execute=0 firmadyne.procfs=0 fdyne_syscall=0 firmsolo=1 mem=256M \" -M {} -m 256M -nographic".format(qemu,self.resultdir,rootfs,machine)
        elif self.arch == "arm" and "ARMv6" in self.vermagic:
            self.cmd = "{} -kernel {}zImage -drive file={},if=sd,file.locking=off -append \"root=/dev/mmcblk0 rootwait rw console=ttyAMA0 log_buf_len=10M fdyne_reboot=0 firmadyne.devfs=0 fdyne_execute=0 firmadyne.procfs=0 fdyne_syscall=0 firmsolo=1 mem=256M\" -M {} -cpu arm11mpcore -m 256M -nographic".format(qemu,self.resultdir,rootfs,machine)
        else:
            self.cmd = "{} -kernel {}zImage -drive file={},if=sd,file.locking=off -append \"root=/dev/mmcblk0 rootwait rw console=ttyAMA0 log_buf_len=10M fdyne_reboot=0 firmadyne.devfs=1 fdyne_execute=0 firmadyne.procfs=1 fdyne_syscall=0 firmsolo=1 mem=256M\" -M {} -cpu cortex-a9 -m 256M -nographic".format(qemu,self.resultdir,rootfs,machine)
            self.backup_cmd = "{} -kernel {}zImage -drive file={},if=sd,file.locking=off -append \"root=/dev/mmcblk0 rootwait rw console=ttyAMA0 log_buf_len=10M fdyne_reboot=0 firmadyne.devfs=0 fdyne_execute=0 firmadyne.procfs=0 fdyne_syscall=0 firmsolo=1 mem=256M\" -M realview-pb-a8 -cpu cortex-a9 -m 256M -nographic".format(qemu,self.resultdir,rootfs,machine)
            
        print("QEMU CMD", self.cmd)   
        
        self.qemu_opts = [machine, cpu, iface, blk_dev, tty, bak_machine]

        self.qemu_opt_dict = {"machine": self.qemu_opts[0],
                "cpu" : self.qemu_opts[1], "iface" : self.qemu_opts[2],
                "blk_dev" : self.qemu_opts[3], "tty" : self.qemu_opts[4]}

#####################################################################
def only_modprobe(mod,modules):
    for path in modules:
        module = path.split("/")[-1]
        if mod == module:
            return False,path
    return True, None

############ Function to stop the child from running ##############
def stop_child(child,image):

    if child.isalive():
        child.delayafterclose = 1.0
        child.delayafterterminate = 1.0
        child.sendline('init 0')

    if child.isalive():
        print('Child did not exit gracefully.',"Killing forcefully the child with pid",str(child.pid))

    res = ""
    try:
        pid_to_kill = "ps ax | grep \"/{0}/\"".format(image)
        res = subprocess.check_output(pid_to_kill, shell=True)
    except Exception as e:
        print(e)

    res = str(res)
    if res != "":
        results = res.split("\n")
        for rs in results:
            if "grep" not in rs:
                pid = int(rs.split()[0])
                print("Killing pid",pid)
                break
        try:
            os.kill(pid,signal.SIGINT)
        except Exception as e:
            print(e)
        time.sleep(2)

    print("Child exited gracefully.")
###################################################################

################## Save the order of loading modules ################################
def save_order(image,order,mode,what):
    if what == "core":
        fname = cu.loaded_mods_path + image + "/" + image + "_{0}.order".format(mode)
    elif what == "final":
        fname = cu.loaded_mods_path + image + "/" + image + "_final_{0}.order".format(mode)
    with open(fname,"w") as f:
        f.write("#!/bin/sh\n")
        for cmd in order:
            f.write(cmd + "\n")

#####################################################################################


#####################################################################################

def get_fault_info(msg):
    call_trace = []
    flag = False
    lines = msg.split("\n")
    for line in lines:
        ln = line.strip("\r\r")
        if "Call Trace:" in line or "Backtrace" in ln:   # Call Trace -> MIPS, Backtrace ->  ARM
            flag = True
            continue
        if flag == True and ("stack_done" not in ln and "Code" not in ln and ln != ''):
            func_addresses = re.findall("(\[\<.*\>\])",ln)
            if not func_addresses:
                continue
            call_trace.append(ln)
        if flag ==True and ("stack_done" in ln or "Code" in ln or ln == ''):
            flag = False
            break
    return call_trace

def get_section_and_mod_info(msg):
    section_info = []
    lines = msg.split("\n")
    module_info = ""
    for line in lines:
        if "Module_name" in line:
            module_info = line.strip("\r\r")
        elif ".text" in line:
            tmp_line = line.strip("\t").strip("\r\r")
            section_info.append(tmp_line)

    return module_info, section_info




def get_params(abs_path):
    parms = []
    try:
        param_out = subprocess.check_output("strings {0} | grep parm=".format(abs_path), shell=True).split("\n")
        if len(param_out) > 0:
            paramtype_out = subprocess.check_output("strings {0} | grep parmtype=".format(abs_path), shell=True).split("\n")
            
        for indx,parm in enumerate(param_out[:-1]):
            tokens1 = parm.replace("parm=","").split(" ")
            if "(default " in parm:
                continue
            else:
                tokens2 = paramtype_out[indx].replace("parmtype=","").split(":")
                param_name = tokens2[0]
                param_type = tokens2[1]
                parms.append([param_name,param_type])
    except:
        #print("Error in finding the params")
        #print(traceback.format_exc())
        pass
    
    return parms




def do_snapshot(socket_dir,snap_name):
    try:
        cmd = "{}scripts/fs_and_snap_scripts/qmp_shell.py " + socket_dir + " " + snap_name
        qmp_out = os.popen(cmd).read()
        print("QMP OUTPUT",qmp_out)

    except Exception as e:
        print("There was error with snapshoting")
        print(e)



def cleanup_tmp(socket):

    try:
        cmd = "rm /tmp/" + socket
        os.system(cmd)
    
    except Exception as e:
        print(e)



def save_dmesg(dmesg,image,mode):
    out_dmesg = cu.loaded_mods_path + image + "/dmesg_{0}.out".format(mode)
    with open(out_dmesg,"w") as f:
        f.write(dmesg)



##################################################################################################################

###################### Write data to a pickle file ###########################################                                                        
def write_to_pickle(loaded, mod_file,*args):
    with open(mod_file,"wb") as f:
        pickle.dump(loaded,f)
        ######### If there are modules subs drop to the pickle as well ###################
       # print(args)
        if args != ():
            for arg in args:
                pickle.dump(arg,f)
            #pickle.dump(args[1],f)                                                                                                                   
############################################################################################## 
def extract_loaded(image_emul):
    which_mods = []
    subed_mods = []
    try:
        d_paths, u_paths, subs = zip(*image_emul.subs)
        subed_mods = list(map(lambda x:x.replace(".ko","").replace("-","_"), list(subs)))
    except:
        pass

    try:
        for path in image_emul.order:
            module = path.split("/")[-1].replace(".ko", "")
            if "upstream" not in path:
                which_mods.append(module)
    except:
        print(traceback.format_exc())
        sys.exit(0)

    print("Subs", subed_mods)
    print("Core subs", image_emul.core_subs)
    print("Modules", which_mods)
    return which_mods


def get_modprobe(image, cust_module_paths):
    ### Go to the result directory where the modprobe modules are kept 
    ### Isolate the name of each module
    resultdir = cu.result_dir_path
    image_dir  = resultdir + image + "/"
    vanilla_modules  = []
    vanilla_order = []

    dirs = os.listdir(image_dir)
    for f in dirs:
        if os.path.isdir(image_dir + f) and "linux" in f:
            kernel = f
            mod_dir = os.listdir(image_dir +f +"/lib/modules/")[0]
    
    print("Mod dir", mod_dir)
    lib_dir = image_dir + kernel + "/lib/modules/" + mod_dir
    mod_dep = image_dir + kernel + "/lib/modules/" + mod_dir + "/modules.dep"

    ########################## Get the necessary vanilla modules #########################
    which_info = ["final_files"]
    info = cu.get_image_info(image,which_info)
    temp = info[0]

    vanilla_modules = list(map(lambda x : x.split("/")[-1].strip(".c\n")+ ".ko",temp))

    exist = []
    try:
        with open(mod_dep,"r") as f:
            line = f.readline()
            while line:
                van_module = line.split(":")[0].split("/")[-1].strip("\n")
                for vmod in vanilla_modules:
                    if vmod == van_module:
                        exist.append(van_module)

                line = f.readline()
    except:
        print("File",mod_dep,"does not exist")

    if exist != []:
        vanilla_order = fix_order(image, exist, mod_dep,lib_dir,image_dir + kernel)

    return vanilla_order

############################ Get modules that cause a segmentation fault ########################################
def get_bad_mods(image,mode):
    bad_modules = []
    native_bad_modules = []
    try:
        bad_modules = cu.read_pickle(cu.loaded_mods_path + image + "/bad_modules_{0}.pkl".format(mode))
    except Exception as e:
        print(e)
        print("Image",image,"has not nay bad modules yet")
    
    try:
        native_bad_modules =cu.read_pickle(cu.loaded_mods_path + image + "/bad_modules_native_{0}.pkl".format(mode))
    except Exception as e:
        print(e)
        print("Image",image,"has not any native bad modules yet")

    print ("Bad modules",bad_modules)
    print("Native bad modules",native_bad_modules)

    return bad_modules, native_bad_modules
#################################################################################################################


####################################################### The actual emulation #########################################################
def run_the_emulation(image, mode):

    ############################ Run the Qemu emulaton -> every time we segfault we discard the moduel and start again #########################
    segfaulted = True
    cnt = 0
    proc_mod = []
    subs = []
    core_subs = []
    crashed_modules = []
    crashed_modules_upstream = []
    timed_out_modules = []
    timed_out_modules_upstream = []
    emulated = True
    print("Abs_dir",cu.abs_path)
    
    image_emul = Emulate(image, subs, core_subs, crashed_modules,
                         crashed_modules_upstream, timed_out_modules,
                         timed_out_modules_upstream, mode, cnt, segfaulted, emulated)
    
    ### Image is not compiled so return
    if not image_emul.compiled:
        return image_emul

    ############### Get the existing bad modules for the image if they exist #################
    #bad_modules, native_bad_modules = get_bad_mods(image,mode)
    ##########################################################################################
    try:
        while image_emul.segfaulted:
            last_module, mod_origin, reason = image_emul.run_qemu()

            ######## Get info from the child ########
            print("Segfaulted", image_emul.segfaulted)
            if image_emul.segfaulted and reason == "segfault":
                if mod_origin == "distributed":
                    image_emul.crashed_modules.append(last_module)
                elif mod_origin == "upstream":
                    image_emul.crashed_modules_upstream.append(last_module)
            elif image_emul.segfaulted and reason == "timeout":
                if mod_origin == "distributed":
                    image_emul.timed_out_modules.append(last_module)
                elif mod_origin == "upstream":
                    image_emul.timed_out_modules_upstream.append(last_module)

            print("Bad modules", image_emul.crashed_modules)
            print("Native bad modules",image_emul.crashed_modules_upstream)
            print("Timed out", image_emul.timed_out_modules)
            print("Time out native",image_emul.timed_out_modules_upstream)
            
            time.sleep(2)
            ############################################
    except Exception as e:
        print(e)
        print("Process could not be instantiated for",image)
    
    return image_emul
#########################################################################################################################################

def do_run(image, mode):
    
    ### Emulate the image ###
    image_emul = run_the_emulation(image, mode)

    if not image_emul.compiled:
        print("Image not compiled", image)
        return [image, len(image_emul.modules), 0,0,0,0,0]
    
    if len(image_emul.crashed_modules) > 0:
        cu.write_pickle(cu.loaded_mods_path + image + "/crashed_modules_{0}.pkl".format(mode), image_emul.crashed_modules)
    else:
        cmd = ["rm", "{}/{}/crashed_modules_{}.pkl".format(cu.loaded_mods_path, image, mode)]
        try:
            subprocess.call(cmd, stdout= subprocess.PIPE)
        except:
            ### The file is not there anyway
            pass

    if len(image_emul.crashed_modules_upstream) > 0:
        cu.write_pickle(cu.loaded_mods_path + image + "/crashed_modules_upstream_{0}.pkl".format(mode), image_emul.crashed_modules_upstream)
    
    if len(image_emul.timed_out_modules) > 0:
        cu.write_pickle(cu.loaded_mods_path + image + "/timed_out.pkl", image_emul.timed_out_modules)
    else:
        cmd = ["rm", "{}/{}/timed_out.pkl".format(cu.loaded_mods_path, image)]
        try:
            subprocess.call(cmd, stdout= subprocess.PIPE)
        except:
            ### The file is not there anyway
            pass

    if len(image_emul.timed_out_modules_upstream) > 0:
        cu.write_pickle(cu.loaded_mods_path + image + "/timed_out_upstream.pkl", image_emul.timed_out_modules_upstream)
    
    loaded = 0
    ### Get info about all the loaded modules and the loaded shipped modules ###
    which_mods = extract_loaded(image_emul)
    loaded = len(which_mods)
    if not image_emul.emulated:
        print("Image",image,"was not emulated at all")

    if loaded >= 0:
        mod_file =  cu.loaded_mods_path + image + "/"+ image +"_{0}.pkl".format(mode)
        cu.multi_write_pickle(mod_file, [which_mods, image_emul.subs, image_emul.core_subs, image_emul.emulated, image_emul.qemu_opt_dict])
    
    print("Image " + image + " Total " + str(len(image_emul.modules)) + " Loaded " + str(loaded) + " Bad Modules " + str(len(image_emul.crashed_modules)) + " Substitutions " + str(len(image_emul.subs)) + " Core substitutions " + str(len(image_emul.core_subs)) )

    
    return

def main():
    parser = argparse.ArgumentParser(description='Create Filesystems and QEMU snapshots for Images')                                              
    parser.add_argument('img_id',help='Id of the image')                                          
    parser.add_argument('mode',help='Mode for loading kernel modules {noup,upns,ups}')                                                            
     
    res = parser.parse_args()
    image = res.img_id                                                                                                                           
    mode = res.mode
    cnt = res.cnt

    do_run(image, mode)

    return

if __name__ == "__main__":
    main()
