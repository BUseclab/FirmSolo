#!/usr/bin/env python3

import os
import sys
currentdir = os.path.dirname(os.path.realpath(__file__))
parentdir = os.path.dirname(currentdir)
sys.path.append(parentdir)
import custom_utils as cu
import subprocess as sb
import pickle
import traceback

################## Module Path Dictionary ###################
# Create a dictionary containing the module path in the 
# fielsystem for each module (upstream)
#############################################################
def get_dictionary(f_mod_order,lib_dir,img_kernel_dir):
    #print("FMOD_ORDER", f_mod_order)
    try:
        paths = cu.read_file(f_mod_order)
    except:
        print("File",f_mod_order,"does not exist")
    
    actual_paths = []
    for path in paths:
        if "lib/modules" in path.split(":")[0]:
            pth = img_kernel_dir + "/" +path.split(":")[0].strip(":")
        else:
            pth = lib_dir + "/" +path.split(":")[0].strip(":")
        actual_paths.append(pth)

    mod_dict = {}
    for indx,path in enumerate(actual_paths):
        module = path.split("/")[-1]
        mod_dict[module] = indx
    
    return mod_dict,actual_paths



class Module_Order():
    def __init__(self, modules, module_type, extracted_fs_dir, mod_dict=None, mod_order=None):
        self.modules = modules
        self.module_type = module_type
        self.mod_dict = mod_dict
        self.mod_order = mod_order
        self.extracted_fs_dir = extracted_fs_dir
        self.order = []
        self.seen = []

################## Module loading order #######################
# Recursive function to get the module loading order for both
# the custom and upstream modules
###############################################################
    def get_order_recursive(self, module):
        if self.module_type == "shipped":
            path = module
            module_name = module.split("/")[-1].replace(".ko", "")
            absol_module_path = "{}{}".format(self.extracted_fs_dir, module)
        elif self.module_type == "vanilla":
            module_name = module.replace(".ko", "")
            print(type(self.mod_dict))
            print ("Module", module)
            index = self.mod_dict[module]
            path = self.mod_order[index]
            absol_module_path = path
        
        if module_name == "":
            return

        try:
            cmd = "strings {} | grep depends=".format(absol_module_path)
            modinfo = sb.check_output(cmd, shell=True).decode("utf-8").split("\n")

            for i in modinfo:
                if i.startswith("depends="):
                    tokens = i.replace("depends=","").strip(" ").split(",")
                    if tokens == ['']:
                        if path not in self.order:
                            self.order.append(path)
                            self.seen.append(path)
                    else:       
                        for dep in tokens:
                            if self.module_type == "vanilla":
                                mod = "{}.ko".format(dep)
                                indx2 = self.mod_dict[mod]
                                path2 = self.mod_order[indx2]
                                if path2 in self.seen:
                                    continue
                                else:
                                    self.get_order_recursive(mod)
                            else:
                                for mod in self.modules:
                                    if (dep.replace("mod-","") +".ko") == mod.split("/")[-1]:
               #                         print("Dep path",mod)
                                        if mod in self.seen:
                                            continue
                                        else:
                                            self.get_order_recursive(mod)

            if path not in self.order:
                self.order.append(path)

        except Exception as e:
            print(traceback.format_exc())
            print("There was an error with modinfo")

    def get_mod_order(self):
        for module in self.modules:
            self.get_order_recursive(module)

def fix_order(image, *args):
        extracted_fs_dir = f"{cu.result_dir_path}{image}/extracted_fs/"
        if len(args) == 0:
            which_info = ["kernel","modules"]
            info = cu.get_image_info(image,which_info)
            
            modules = info[1]
            kern = info[0]
            module_type = "shipped"
            kernel = cu.kernel_prefix + kern
            mod_order = Module_Order(modules, module_type, extracted_fs_dir)
            mod_order.get_mod_order()

            return len(mod_order.order), mod_order.order
        else:
            if len(args) < 2:
                print("Wrong number of arguments to fix_order")
                raise Exception('arguments')
                
            vanilla_modules = args[0]
            f_mod_order = args[1]
            lib_dir = args[2]
            if len(args) > 3:
                img_kernel_dir = args[3]
            else:
                img_kernel_dir = ""

            mod_dict,mod_order = get_dictionary(f_mod_order,lib_dir,img_kernel_dir)
            module_type = "vanilla"
            mod_order = Module_Order(vanilla_modules, module_type, extracted_fs_dir, mod_dict, mod_order)
            mod_order.get_mod_order()

            return mod_order.order
