#!/usr/bin/env python3
import os
import sys
currentdir = os.path.dirname(os.path.realpath(__file__))
parentdir = os.path.dirname(currentdir)
sys.path.append(parentdir)
import string
import pickle
import time
import subprocess
from multiprocessing import Pool
import custom_utils as cu
from stage1 import get_symbol_info as gsi
from stage1 import parse_kernel_source as pks
import re
import argparse as argp
import traceback
import requests as req
import tarfile
from pathlib import Path
from requests.packages.urllib3.exceptions import InsecureRequestWarning
req.packages.urllib3.disable_warnings(InsecureRequestWarning)
from stage2b.get_order import Module_Order
from stage1.find_kernels_syms import extract_kernel_ksym_entry


done = []
kernel_org = "https://mirrors.edge.kernel.org/pub/linux/kernel/"

vermagic_opts = {
                "CONFIG_MODULE_UNLOAD" : "mod_unload",
                "CONFIG_PREEMPT"       : "preempt",
                "CONFIG_MODVERSIONS"   : "modversions",
                "CONFIG_SMP"           : "SMP",
                "CONFIG_ARM_PATCH_PHYS_VIRT" : "p2v8",
        }

######################## Class for the Image info gathering ################################

class Image():
    def __init__(self,img):
        #temp_img = img.replace(" ","\ ").replace("(","\(").replace(")","\)")
        self.extracted_fs_dir = f"{cu.result_dir_path}/{img}/extracted_fs/"
        
        ### In case there is weird image name
        #if os.path.exists(self.extracted_fs_dir):
            #self.img = temp
        #### Case where the name of the image is too long so we have to truncate
        #### one character
        #else:
            #self.img = temp[:-1]
    
        self.img = img
        self.undef_syms = []
        self.global_syms = []
        self.unknown_syms = []
        self.ksyms = []
        self.vermagic = None
        self.modules = []
        self.kernel = None
        self.extravers = None
        self.final_files = []
        self.arch = None
        self.endian = None
        self.cross = None
        self.isa = None
        self.symbols = []
    
    ### Extract the ksyms from the orginal kernel if that is possible
    def extract_kallsyms(self):
        extract_kernel_ksym_entry(self.img)


    def check_kern_exists(self):
        kernel_dir = cu.kern_sources + cu.kernel_prefix + self.kernel
        kernel = cu.kernel_prefix + self.kernel
        if "linux-2.6" in kernel:
            subdir = "v2.6"
        elif "linux-3." in kernel:
            subdir = "v3.x"
        elif "linux-4." in kernel:
            subdir = "v4.x"
        elif "linux-5." in kernel:
            subdir = "v5.x"
        else:
            vers = self.kernel.split(".")[0]
            subdir = f"v{vers}.x"

        path = Path(kernel_dir)

        if not (path.exists()):
            remote_tar_file = "{}{}/{}.tar.gz".format(kernel_org, subdir,
                                                      kernel)
            local_tar_file = "{}/{}.tar.gz".format(cu.tar_dir, kernel)
            cmd = "wget {} -O {}".format(remote_tar_file, local_tar_file)
            print("Kernel", self.kernel, "does not exist in local repository...")
            print ("Downloading kernel from url:", remote_tar_file)
            try:
                res = subprocess.check_output(cmd, shell = True)
            except:
                print(traceback.format_exc())
                return False

        return True

    ### Function to get the kernel version and the extraversion used by
    ### the image
    def get_kernel_info(self,kernel):
        kern = None
        extravers = None
        if kernel == "2.6.2219":
            kern ="2.6.22.19"
            extravers = ""
        else:
            res = re.search("(\d+\.){2}(\d+){1}(\.\d+){0,}", kernel)
            if res == None:
                return
            else:
                kern = res.group()
            if kern and "/" not in kernel:
                extravers = kernel.replace(kern,"")
            else:
                extravers = ""
        
        self.kernel = kern
        self.extravers = extravers

    def get_vermagic_info(self, module):
        ### First find the vermagic
        modinfo = None
        output = None

        if self.vermagic and self.kernel:
            return

        try:
            output = subprocess.check_output("strings {}".format(module),
                                             shell = True).decode("utf-8")
        except:
            print("Running string on {}s module {} was "
                  "unsuccessful".format(self.img,module))
            return
        ### Now get the vermagic
        vermagic = []
        
        if output:
            for line in output.split("\n"):
                if "vermagic=" in line:
                    modinfo = line
                    break
            if modinfo:
                vermagic = modinfo.replace("vermagic=","").split()
            if not self.vermagic and vermagic != []:
                self.vermagic = vermagic
                ### Also extract the kernel
                if not self.kernel:
                    self.get_kernel_info(vermagic[0])
            else:
                if self.arch == "arm":
                    self.vermagic = ["ARM" + self.isa]
                elif self.arch == "mips":
                    self.vermagic = ["MIPS" + self.isa]
        ### Now even though the vermagic is absent we might get the kernel version from the module
        ### path. Luckily the regex work for the path
        else:
            if self.arch == "arm":
                self.vermagic = ["ARM" + self.isa]
            elif self.arch == "mips":
                self.vermagic = ["MIPS" + self.isa]
        if not self.kernel:
            self.get_kernel_info(module)

    ### Function to get the undefined and global symbols for a module
    ### We invoke string instead of modinfo, since it is more effective
    def get_module_symbols(self,module):

        self.get_vermagic_info(module)
        ### If the kernel does not exist in our available kernels we
        ### cannot compile it anyway so abort checking the image
        #if self.kernel == None or not self.check_kern_exists() or self.kernel == "2.6.24.111":
            #if self.kernel == None:
                #print("FS could not find a kernel for this image")
            #return True
        ### Now get the symbols of the module
        ### We run nm for this purpose
        nm = None
        try:
            nm = subprocess.check_output("nm -a {}".format(module),
                                         shell=True).decode("utf-8").split("\n")
        except:
            print("Running nm on {}s module {} was unsuccessful".format(self.img,module))
    
        if nm:
            for sym in nm:
                tokens = sym.split()
                if tokens == []:
                    continue
                ### We remove the offset of the symbol for convenience
                if len(tokens) > 2:
                    del tokens[0]
                ### Find the global and the undefined symbols and save them
                ### First Undefined
                if tokens[0] == "U" and tokens[1] not in self.undef_syms:
                    self.undef_syms.append(tokens[1])
                ### Next Global
                elif tokens[0] != "U" and tokens[0].isupper() and tokens[1] not in self.global_syms:
                    self.global_syms.append(tokens[1])
        #return False

    ### This is for the case where the vermagic is not available in the modules
    ### Thus we might come across some of the vermagic options inside the
    ### option and guard set we created using the module symbols
    def populate_vermagic(self, options, guards):
        
        print("Image", self.img)
        if len(self.vermagic) > 1:
            return options

        for opt in options:
            if opt in vermagic_opts and vermagic_opts[opt] not in self.vermagic:
                self.vermagic.append(vermagic_opts[opt])

        for opt in guards:
            if opt in vermagic_opts and vermagic_opts[opt] not in self.vermagic:
                self.vermagic.append(vermagic_opts[opt])

        options.append("CONFIG_MODULE_FORCE_LOAD")
        return options

    ### Filter the symbols both in the Undefined and Global symbol set
    def filter_mod_syms(self):

        for sym in self.undef_syms:
            if sym not in self.global_syms:
                self.unknown_syms.append(sym)
        print("Unknown symbols:",len(self.unknown_syms))
        #print("Unknown :",self.unknown_syms)
        #print("GLOBAL :\n",self.global_syms)
    
    def filter_kallsyms(self):
        temp = []
        for sym in self.ksyms:
            if "." in sym:
                sm = sym.split(".")[0]
            else:
                sm = sym
            if sm not in self.global_syms:
                temp.append(sm)
        print("Unknown symbols:",len(temp))
        self.ksyms = temp

    ### Function to get the information about the modules in the image
    ### First we find all the modules in the filesystem
    def get_module_info(self):
        os.chdir(self.extracted_fs_dir)
        ### First get the modules
        result = None
        error = None
        try:
            result = subprocess.check_output("find . -name \"*.ko\"",shell=True).decode("utf-8")
        except:
            print("Finding the modules of {} failed".format(self.img))

        result = result.replace(" ","\\ ")
        if result:
            self.modules = result.split("\n")
            ### Now that we have the modules get the arch and
            ### endianness
            self.get_arch_endian_cross()
            for module in self.modules:
                if module == '':
                    continue
                self.get_module_symbols(module)

        os.chdir(currentdir)
        
        if self.kernel == None:
            print("FS could not find a kernel for this image")
            return True
        if not self.check_kern_exists() or self.kernel == "2.6.24.111":
            print("The kernel version for this image is not available")
            return True

        print("Kernel",self.kernel)
        ### Now remove the duplicate syms in Undefined and Global symbols
        self.filter_mod_syms()
        #print(self.unknown_syms)


    def get_arch_endian_cross(self):
        cwd = os.getcwd()
        os.chdir(self.extracted_fs_dir)
        elf_header = []
        output = None
        arch, endianess, cross, isa = None, None, None, None
        
        for module in self.modules:
            #print("readelf",module)
            try:
                output = subprocess.check_output("readelf -Ah ./{}".format(module),
                                                 shell=True).decode("utf-8").split("\n")
            except:
                print("Running readelf for {}s module: {} was unsuccessful".format(self.img,module))
            
            if output:
                for line in output:
                    if "Machine" in line or "Data" in line:
                        elf_header.append(line)
                    if "Tag_CPU_arch:" in line:
                        isa = re.search("v(\d)",
                                        line).group()

                if "little endian" in elf_header[0]:
                    endianess = "little endian"
                    if "MIPS" in elf_header[1]:
                        arch = "mips"
                        cross = "mipsel-linux-gnu-"
                        ### Even if this is wrong it is the safest
                        ### option to set the isa to R2 due to
                        ### backwards compatibility
                        isa = "32_R2"
                    elif "ARM" in elf_header[1]:
                        arch = "arm"
                        cross = "arm-linux-gnueabi-"
                else:
                    endianess = "big endian"
                    if "MIPS" in elf_header[1]:
                        arch = "mips"
                        cross = "mips-linux-gnu-"
                        isa = "32_R2"
                    elif "ARM" in elf_header[1]:
                        arch = "arm"
                        cross = "arm-linux-gnueabi-"
                break
        
        self.arch, self.endian, self.cross, self.isa = arch, endianess, cross, isa
        os.chdir(cwd)
    ### Get the kallsyms symbols from the original kernel
    ### if they exist...
    
    def get_ksyms(self):
        self.extract_kallsyms()
        ksyms_file = f"{cu.result_dir_path}/{self.img}/original_kernel/kallsyms"
        ksyms = None

        try:
            ksyms = cu.read_file(ksyms_file)
        except:
            print("Image {} does not have kallsyms information".format(self.img))
        ### Skip the first 12 lines which are irrelevant info generated by the tool
        if ksyms:
            self.ksyms = list(map(lambda x:x.split(" ")[2].strip("\n"),ksyms[12:-1]))
            self.filter_kallsyms()
            print("Kallsyms:",len(self.ksyms))

    
    ### Merge kallsym files and module files together
    def merge_files(self,mod_sym_files,ksym_files):
        self.all_files = mod_sym_files
        ### We have to remove the information about SLAB memory allocator introduced from 
        ### the kallsyms files because it introduces uncertainty
        for files in ksym_files:
            if "slab.c" not in files and "slub.c" not in files and "slob.c" not in files:
                self.all_files.append(files)
        #self.symbols = self.unknown_syms
        self.symbols = self.unknown_syms + self.ksyms

    ### For each file get how many times it is referenced and also the groups of files
    ### that export a symbol...the symbol doent matter for now
    def get_file_freqs_and_groups(self):
        syms_fl_dict, syms_fl_groups = {}, []
        for files in self.all_files:
            syms_fl_dict, syms_fl_groups = gsi.find_file_freqs(files,syms_fl_dict,syms_fl_groups)

        return syms_fl_dict, syms_fl_groups
    
    ### Break the arbitration when a symbol is exported by multiple files
    ### The file with the most references wins
    def break_arbitration(self):
        syms_fl_dict, syms_fl_groups = self.get_file_freqs_and_groups()

        final_files = []
        for group in syms_fl_groups:
            dominant = group[0]
            max_freq = syms_fl_dict[dominant]
            for fl in group:
                freq = syms_fl_dict[fl]
                if freq > max_freq:
                    dominant = fl
                    max_freq = freq
            final_files.append(dominant)
        
        ### These are the main files that export our symbols in the kernel
        self.final_files = final_files

    ### Save the information about the image in a dictionary format
    ### to a pickle so that it can be used by the other stages of
    ### FirmSolo
    def save_image_info(self, seen_options, additional_guards, module_options):
        image_file = "{}{}.pkl".format(cu.img_info_path,self.img)

        dict_to_save = {
                "kernel":self.kernel,
                "extraversion":self.extravers,
                "modules":self.modules,
                "vermagic":self.vermagic,
                "unknown_mod_syms" : self.unknown_syms,
                "symbols":self.symbols,
                "ksyms":self.ksyms,
                "arch":self.arch,
                "endian":self.endian,
                "cross":self.cross,
                "sym_files":self.all_files,
                "final_files":self.final_files,
                "options":seen_options,
                "guards": additional_guards,
                "module_options" : module_options
                }

        cu.write_pickle(image_file,dict_to_save)

############################################################################################


####################### Class for getting info from kernel source ############################ 
class Kernel():
    def __init__(self,kernel):
        self.kernel = cu.kernel_prefix + kernel
        self.kern_dict = None
        self.guard_dict = None
        self.kernel_dir = cu.kern_sources + self.kernel
    
    def create_dict_dir(self):
        cmd = "mkdir {}{}".format(cu.kern_dicts,self.kernel)
        try:
            res= subprocess.call(cmd,shell=True)
        except:
            print("Directory {}{} is already created".format(cu.kern_dicts,
                                                             self.kernel))

    ### First try to get the dictionary for the kernel
    ### if it exists else create a new one
    def read_sym_dictionary(self,arch):
        kernel_dict_file = "{}/{}/{}_{}_sym_dict.pkl".format(cu.kern_dicts,
                                                             self.kernel,
                                                             self.kernel,arch)
        try:
            self.kern_dict = cu.read_pickle(kernel_dict_file)
        except:
            self.kern_dict = {}
    
    ### Cache the result for symbols in a dictionary for future use
    def save_sym_dictionary(self,arch):
        kernel_dict_file = "{}/{}/{}_{}_sym_dict.pkl".format(cu.kern_dicts,
                                                             self.kernel,
                                                             self.kernel,arch)
        try:
            cu.write_pickle(kernel_dict_file,self.kern_dict)
        except:
            print("Saving the symbol dictionary for kernel {} failed".format(self.kernel))
            print(traceback.format_exc())
    
    def check_if_kernel_src_exists(self):
        kernel_tar_path = "{}/{}.tar.gz".format(cu.tar_dir, self.kernel)

        path = Path(self.kernel_dir)

        if not (path.exists()):
            try:
                untar = tarfile.open(kernel_tar_path)
            except:
                print(traceback.format_exc())
                print("Could not untar kernel", self.kernel)
                return False

            try:
                untar.extractall(self.kernel_dir)
                untar.close()
            except:
                print("Error when extracting the kernel", self.kernel)
                return False

        return True

    ### Function to run Cscope on the kernel directory
    ### This is useful to search for the exporting files
    ### of the symbols
    def find_and_cscope(self, arch = "arm"):

        tar_exists = self.check_if_kernel_src_exists()
        if not tar_exists:
            return tar_exists

        find_cmd = "find . -path \"./arch/*\" ! -path \"./arch/{}*\" -prune -o -path \"./Documentation*\" -prune -o \\( -name \"*.[chxsS]\" -o -name \"Makefile\" \\) -print >./cscope.files".format(arch)

        ### First run the find command
        os.chdir(self.kernel_dir)
        try:
            res = subprocess.call(find_cmd, shell=True)
        except:
            print("Find command on {} was unsuccessful".format(self.kernel_dir))
            print(traceback.format_exc())

        try:
            cscope = subprocess.call("cscope -q -b",shell=True)
        except:
            print("Cscope in directory {} failed".format(self.kernel_dir))
            print(traceback.format_exc())
        os.chdir(currentdir)
    
        return tar_exists

    ### Function to find the definitions of each symbol in the kernel source
    ### The results are cached in a dictionary for each kernel

    def find_sym_export_files(self,symbols,arch,p):
        ### Run cscope first
        #self.find_and_cscope(kernel_dir,arch)
        export_files = []
        

        ### Ok now this process will use more than one threads so we need to 
        ### create first the data to feed them (kern_dict, kernel_dir, symbol)
        dict_list = [self.kern_dict for i in range(len(symbols))]
        k_dir = [self.kernel_dir for i in range(len(symbols))]
        data = [list(x) for x in zip(symbols,dict_list,k_dir)]
       
        res = p.map(gsi.find_definition,data)        
        
        ### Now update the dictionary with new entries
        for i,sym in enumerate(symbols):
            if sym not in self.kern_dict.keys():
                self.kern_dict[sym] = res[i]
        
        ### Now filter out all the empty files
        export_files = list(filter(None,res))
                
        return export_files
    
    ### Now this is a dictionary holding the inlined conditional guards for some symbols
    ### We cannot find these conditionals by just looking at the Makefiles
    def read_guard_dictionary(self):
        guard_dict_file = "{}/{}/{}_guard_dict.pkl".format(cu.kern_dicts,self.kernel,self.kernel)
        try:
            self.guard_dict = cu.read_pickle(guard_dict_file)
        except:
            self.guard_dict = {}

    ### Cache the result for guards in a dictionary for future use
    def save_guard_dictionary(self):
        guard_dict_file = "{}/{}/{}_guard_dict.pkl".format(cu.kern_dicts,self.kernel,self.kernel)
        try:
            cu.write_pickle(guard_dict_file,self.kern_dict)
        except:
            print("Saving the guard dictionary for kernel {} failed".format(self.kernel))
    
    ### Finally find the configuration options for the symbols as well their additional
    ### guards if they exist
    def find_sym_and_guard_conds(self,final_files,symbols):
       # kernel_dir = cu.kernel_sources + self.kernel
        os.chdir(self.kernel_dir)
        
        filenames = list(map(lambda x:x.split("/")[-1],final_files))
        seen_options , additional_guards = [], []
        for i,fl in enumerate(filenames):
            ### Now check the file for additional guards and modify the dict
            if final_files[i] not in self.guard_dict.keys():
                print("Final file",final_files[i])
                self.guard_dict[final_files[i]] = create_dictionary(final_files[i])
                #print("Final file",fl,self.guard_dict[final_files[i]])

            ### Now find the configuration option that is responsible for compiling
            ### the file either within the kernel proper or as a module
            conf_opt,Makefile = gsi.find_conf_opt(final_files[i],fl)
            if conf_opt and conf_opt != 'y' and conf_opt != "obj" and \
                                            conf_opt not in seen_options:
                seen_options.append(conf_opt)

            ### Now find the additional guards for each symbol
            for sym in symbols:
                for dictn in self.guard_dict.values():
                    if sym in dictn.keys():
                        if dictn[sym] not in additional_guards:
                            additional_guards.append(dictn[sym])
        
        os.chdir(currentdir)
        return seen_options, additional_guards

	### Find the configuration options related to the modules that have an upstream counterpart
    def find_module_options(self, order):
        cwd = os.getcwd()
        os.chdir(self.kernel_dir)
        print("Finding the config options pertaining to the counterpart upstream modules of the distributed modules")
        #run cscope -> take the first file with definition -> return the whole path + file
        module_options = []
        for mod in order:
            module = mod.split("/")[-1].replace(".ko",".o")
            option = ""
            cscope = 'cscope -d -L6"{0}"'.format(module)
            try:
                option = subprocess.check_output(cscope, stderr=subprocess.PIPE, shell=True).decode("utf-8")
            except:
                print("The module",module,"does not exist in the upstream kernel source")
                continue

            opt = ""
            options = option.split("\n")
            print("Checking module", module)
            found = False
            for line in options:
                tokens = line.split()
                for token in tokens:
                    if token == module:
                #token = line.split(" ")[-1]
                        if "CONFIG_" in line:
                            opt = line
                            found = True
                            print("OPT", line)
                            break
                if found:
                    break

            if opt != "":
                if "subst" in opt:
                    opt_temp =opt.replace("obj-$(subst y,","")
                    opt_temp =opt_temp.replace("$(subst m,y,","")
                    match = re.findall('\$\(.*?\)',opt_temp)
                    #print("MATCH",match)
                    for m in match:
                        conf_opt = m.strip("$()")
                        if conf_opt not in module_options:
                            module_options.append(conf_opt)

                else:
                    #conf_opt = opt.split("-")[1].split(")")[0].strip("$(")
                    conf_opt = opt.split("$(")[1].split(")")[0]
                #if module not in vanilla_modules:
                    #vanilla_modules.append(module)
                    if conf_opt not in module_options:
                        module_options.append(conf_opt)
        return module_options

##############################################################################################

### Create a dictionary for symbols containing additional guards that protect them in the
### file that contains their definition
def create_dictionary(fl):
    #infile = "{0}linux-{1}/{2}".format(kern_dir,linux,fl)
    obj = pks.Parse(fl)
    obj.parse_input()
    obj.parse_conditionals()
    obj.create_dict(obj.tree,obj.tree.cond)
    return obj.mapping

def filter_options(opts):
    filt_ops = []
    for opt in opts:
        if "CONFIG_" not in opt:
            continue
        filt_ops.append(opt.strip("+=-:"))
    return filt_ops

def get_image_info(image):
    
    img=None
    img = Image(image)
    error = img.get_module_info()
    if error:
        return
    
    img.get_ksyms()
    kern = Kernel(img.kernel)
    kern.create_dict_dir()
    kern.read_sym_dictionary(img.arch)
    kern.read_guard_dictionary()
    tar_exists = kern.find_and_cscope(img.arch)
    if not tar_exists or img.arch == None:
        outf.write(image+"\n")
        print("Tar does not exist")
        return
    
    ### Use multiple threads because the static analysis will be faster
    p = Pool(cu.num_of_threads)

    sym_files = kern.find_sym_export_files(img.unknown_syms,img.arch,p)
    ksym_files = kern.find_sym_export_files(img.ksyms,img.arch,p)
    kern.save_sym_dictionary(img.arch)
    img.merge_files(sym_files,ksym_files)
    img.break_arbitration()
    seen_options, additional_guards = kern.find_sym_and_guard_conds(img.final_files,img.symbols)
    seen_options = filter_options(seen_options)
    seen_options = img.populate_vermagic(seen_options, additional_guards)
    mod_order = Module_Order(img.modules, "shipped", img.extracted_fs_dir)
    mod_order.get_mod_order()
    order = mod_order.order
    module_options = kern.find_module_options(order)
    img.modules = order

    print("Checked image",image)
    print("\nVermagic", img.vermagic)
    print("Seen_options\n",seen_options)
    print("\nAdditional guards\n",additional_guards)
    print("Module_options\n", module_options)

    img.save_image_info(seen_options,additional_guards, module_options)

def main():
    
    parser = argp.ArgumentParser(description='Extract metadata information from firmware images')
    parser.add_argument('-f','--infile',help='A file containing the images to do the search for',default=None)
    parser.add_argument('-i','--image',help='A single image ID to get the information from',default=None)
    parser.add_argument('-n','--cnt',type=int,help='How many images should we anlayze...To be used with -f option',default=0)

    res = parser.parse_args()
    infile = res.infile
    image = res.image
    cnt = res.cnt

    if not infile and not image:
        print("You must provide one file or one image id")
        sys.exit(0)
    
    if image:
        images = [image]
        cnt = 1
    else:
        images = cu.read_file(infile)
    
    indx = 0
    for image in images:
        if indx == cnt:
            break
        print("Checking image",image)
        get_image_info(image)
        time.sleep(2)
        indx +=1
    
if __name__ == '__main__':
    main()
