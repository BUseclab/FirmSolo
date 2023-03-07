#!/usr/bin/env python3


import os
import sys
currentdir = os.path.dirname(os.path.realpath(__file__))
parentdir = os.path.dirname(currentdir)
sys.path.append(parentdir)
sys.path.append(currentdir)
sys.path.append("{}/stage2a/".format(parentdir))
sys.path.append("{}/stage2b/".format(parentdir))
from kcre import Image as Img, find_custom_module_options                           ### We also have an image class here
from load_mods import load_mods
from kconfiglib import Kconfig
from get_order import Module_Order, get_dictionary
from pprint import pprint
import pexpect as pe
import pickle
import traceback
import custom_utils as cu
import subprocess
import multiprocessing as mp
import signal
import argparse
import time
import re
from itertools import combinations
from anytree import NodeMixin,RenderTree
from collections import deque
import json
import get_ds_conds
import csv
from collections import OrderedDict
from sympy.logic import simplify_logic
from sympy.logic.boolalg import to_cnf
from scipy import spatial

all_the_instructions = {}

class AST(NodeMixin):
    def __init__(self, cond, members = None, end_block = -1, next_node = None,
                 parent = None, children = []):
        self.cond = cond
        self.members = members
        self.end_block = end_block
        self.next_node = next_node
        self.parent = parent
        self.children = children

    def set_root(self, root):
        self.root = root

class Image():
    def __init__(self, img, kernel, arch, endian, vermagic, cust_modules,
                final_files, conf_opts, guard_opts, module_options, serial_out, struct_mod_ok, fi_opts):
        self.img = img
        self.bad_mod_file = "{}{}/crashed_modules_ups_subs.pkl".format(
                            cu.loaded_mods_path, img)
        self.mod_errors_path = "{}{}/errors/".format(
                            cu.loaded_mods_path, img)
        self.mod_load_info_file = "{}{}/{}_ups_subs.pkl".format(
                            cu.loaded_mods_path, img, img)
        self.final_order_file = "{}/{}/{}_final_ups_subs.order".format(
                            cu.loaded_mods_path, img, img)
        self.kernel = cu.kernel_prefix + kernel
        self.extracted_fs_dir = f"{cu.result_dir_path}/{img}/extracted_fs/"
        self.arch = arch
        self.endian = endian
        self.vermagic = vermagic
        self.options = conf_opts
        self.guards = guard_opts
        self.module_options = module_options
        self.solution = []
        self.indx = 0
        self.cust_modules = cust_modules
        self.img_kern_dir = "{}{}/{}/".format(cu.result_dir_path,
                            self.img, self.kernel)
        self.kern_dir = cu.kern_dir + self.kernel + "/"
        self.__get_kernel_syms()
        self.final_files = final_files
        self.serial_out = serial_out
        self.struct_mod_ok = struct_mod_ok
        self.bad_solutions = []
        self.bad_struct_module_solutions = []
        self.fi_opts = fi_opts

        self.__get_module_info()
        ### Refresh the custom fs in case of modifications
        #self.__create_fs()


    ################################ Private #####################################
    ############## Function to get the upstream module order file #################
    def __get_ups_order_fl(self):
        module_dir = "{}{}/{}/lib/modules/".format(cu.result_dir_path,self.img,self.kernel)
        mod_dir = os.listdir(module_dir)[0]
        self.mod_dir = "{}{}/".format(module_dir,mod_dir)
        # Get the actual file
        if self.kernel < "linux-2.6.25":
            mod_dep = "{}{}/modules.dep".format(module_dir,mod_dir)
        else:
            mod_dep = "{}{}/modules.order".format(module_dir,mod_dir)

        lib_dir = "{}{}".format(module_dir,mod_dir)

        return mod_dep, lib_dir
    
    ################# Info about the custom modules ##################
    def __get_bad_mods(self):
        bad_cust_mods = []
        try:
            bad_cust_mods = cu.read_pickle(self.bad_mod_file)
        except:
            print("Image",self.img,"does not have any bad modules")
        
        self.bad_cust_mods = bad_cust_mods
    
    ################ Get the subs for the deps of the crasing module ##############
    def __get_modules_subs(self):
        cust_mod_subs = []
        core_subs = []
        try:
            mod_load_info = cu.read_pickle(self.mod_load_info_file)
            cust_mod_subs = mod_load_info[1]
            core_subs = mod_load_info[2]
            qemu_opts = mod_load_info[-1]
        except:
            print("Image {} does not have any load information yet...Run stage 3 first".format(self.img))
        
        self.cust_mod_subs = cust_mod_subs
        self.core_subs = core_subs
        self.qemu_opts = qemu_opts

    def __get_cust_mod_info(self):
        self.cust_mod_dict = cu.create_dict(self.cust_modules)
        self.__get_bad_mods()
        self.__get_modules_subs()

    def __check_if_upstream_exists(self,module):
        if module in self.ups_mod_dict.keys():
            return True
        else:
            return False

    # Keep in mind that even though we have the order of the upstream modules
    # we compiled with FS, in the end we do not need all of them so we 
    # need to find the dependencies of only the modules we actually need
    def __get_ups_mod_info(self):
        # This is for upstream modules
        mod_dep, lib_dir = self.__get_ups_order_fl()
        ups_mod_dict, ups_mod_order = get_dictionary(mod_dep,lib_dir,self.img_kern_dir)
        
        self.ups_mod_dict = ups_mod_dict
        self.ups_mod_order = ups_mod_order
        #self.ups_mod_order = list(map(lambda x: self.mod_dir + x,ups_mod_order))
    
    ### Function to get all the addresses and the symbols defined in the kernel
    ### Since not all kernels are compiled with KALLSYMS it is better to read 
    ### the System.map
    def __get_kernel_syms(self):
        system_map_fl = self.img_kern_dir + "System.map"
        system_map_data = cu.read_file(system_map_fl)
        self.system_map = dict()
        for line in system_map_data:
            tokens = line.split()
            addr = tokens[0].replace("ffffffff","0x")
            ### key:address value:function name
            self.system_map[addr] = tokens[2]


    def __parse_and_get_structs(self,c_file,start,end,global_structs):
        lines = cu.read_file(c_file)
        
        present_structs = []
        ### Only check in the function body
        for line in lines[int(start)-1:int(end)]:
            for struct in global_structs:
                s_name = re.sub("\[\w+\]","",struct[-1])
                if s_name in line:
                    if struct not in present_structs:
                        present_structs.append(struct)

        return present_structs

    def __get_module_info(self):
        # Get important information about the craching custom modules
        # and the existing upstream modules for the image
        self.__get_cust_mod_info()
        self.__get_ups_mod_info()
    
    def __create_fs(self):
        ### Create the Filesystem for that new image
        cmd = "{}stage2b/create_fs.py {} qcow2".format(
            cu.script_dir,self.img)
        try:
            res = subprocess.call(cmd,shell=True)
        except:
            print(traceback.format_exc())
    ############################################################################
    def create_fs(self):
        self.__create_fs()

    ### We need to create the cscope DB since we have to search for the functions
    ### during the errors. We do not need to run cscope to all the files in the 
    ### kernel tree but only the files that FS found
    def create_cscope_db(self,ups_deps):
        cscope_fl = self.kern_dir + "cscope.files"
        cwd = os.getcwd()
        os.chdir(self.kern_dir)
        with open(cscope_fl,"w") as f:
            ### First files related to the main kernel
            for fl in self.final_files:
                f.write("./" + fl + "\n")
            ### Second files related to the kernel modules
            module_related_files = []
            for mod in ups_deps:
                module = mod.split("/")[-1]
                module_subdir = mod.split("/kernel/")[1].replace(module,"")
                res = ""
                try:
                    res = subprocess.check_output('find {} -name "*.[ch]"'.format(module_subdir),cwd=self.kern_dir,shell=True).decode("utf-8")
                except:
                    print(traceback.format_exc())
                    print("Find failed")
                for result in res.split("\n"):
                    if result not in module_related_files and result != "./":
                        module_related_files.append(result)
            
            for result in module_related_files:
                f.write("./" + result + "\n")

        try:
            res = subprocess.run("cscope -q -b",cwd=self.kern_dir, stderr=subprocess.PIPE, stdout=subprocess.PIPE, shell=True)
        except:
            print("Creating the cscope database failed")
        os.chdir(cwd)
    
    ### Check for a specific symbol with cscope
    ### We are interested in the file that contains the implementation of the symbol
    def run_cscope_cmd(self,func):
        res = ""
        try:
            res = subprocess.check_output('cscope -q -d -L1"{0}"'.format(func),cwd=self.kern_dir,shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE,timeout=30).decode("utf-8")
            print("RES",res)
        except:
            print(traceback.format_exc())
            print("Cscope searching for func",func,"failed")
        return res

    def get_struct_info(self):
        struct_file = "{}struct_info/{}_{}_struct_options.pkl".format(\
                      cu.container_data_path, self.kernel, self.arch)
        if os.path.exists(struct_file):
            with open(struct_file,"rb") as f:
                self.struct_dict_conds = pickle.load(f)
                self.struct_dict_members = pickle.load(f)
        else:
            self.struct_dict_conds, self.struct_dict_members = \
                                    get_ds_conds.main(self.kernel, self.arch)

        #self.struct_dict = cu.read_pickle(struct_file)

    def get_crashing_module(self):
        # Get the next craching module with an upstream counterpart
        module = None
        exists = False
        while self.indx < len(self.bad_cust_mods):
            mod = self.bad_cust_mods[self.indx]
            if self.__check_if_upstream_exists(mod):
                exists = True
            module = mod
            self.indx += 1
            return module,exists
            #self.indx += 1
        return None,exists
        

    def get_dependencies(self, module, ups_mod_exists):
        module_path = self.cust_mod_dict[module]

        ### Custom module order (Only for the bad module)
        cust_order = []
        cust_mod_order = Module_Order(self.cust_modules, "shipped", self.extracted_fs_dir)
        cust_mod_order.get_order_recursive(module_path)
        cust_order = cust_mod_order.order
        #cust_order = get_mod_order(module_path, self.cust_modules,
                            #cust_order, "shipped", paramz)

        ### Upstream module order (The corresponding upstream module)
        ups_order = []
        ups_mod_order = Module_Order([module], "vanilla", self.extracted_fs_dir,
                                     self.ups_mod_dict, self.ups_mod_order)
        try:
            ups_mod_order.get_mod_order()
            ups_order = ups_mod_order.order
        except:
            pass
        #ups_order = get_mod_order(module, self.ups_mod_dict,
                                #self.ups_mod_order, ups_order, "vanilla",
                                #ups_paramz)

        ### The final module load order found in the emulation phase
        module_load_order = cu.read_file(self.final_order_file)
        the_core_subs = []
        for insmod in module_load_order:
            for core_sub in self.core_subs:
                if core_sub in insmod:
                    the_core_subs.append(insmod.split()[1].replace("/upstream",
                                                                   "./native/"))

        ### Save the path to the upstream module in the filesystem 
        ### so that we can use it afterwards...It is going to be the last one
        print("Cust_order",cust_order)
        print("UPS_order",ups_order)
        if ups_mod_exists:
            self.ups_mod_path = ups_order[-1]

        full_path_ups_order = list(ups_order)
        print("Full path UPS_order",ups_order)

        ups_order = list(map(lambda x: "./native/" + x.split(
                                    "/lib/modules/")[1], ups_order))

        ### Now if the dependencies for the custom module were substituted
        ### we need to use their upstream counterpart
        sub_mappings = []
        if len(cust_order) > 1:
            for indx,mod_path in enumerate(cust_order[:-1]):
                for sub in self.cust_mod_subs:
                    module_name = mod_path.split("/")[-1]
                    if module_name == sub[2]:
                        cust_order[indx] = sub[1].replace("/upstream/",
                                                          "./native/")
                        sub_mappings.append([cust_order[indx], mod_path])

        cust_order = the_core_subs + cust_order

        print("Sub mappings", sub_mappings)
        return cust_order, ups_order, full_path_ups_order, sub_mappings

    def get_global_structs(self,path,dep):
        ### Get the global structs used by the upstream module
        ### We assume that the corresponding custom module is 
        ### using the same structs. Also even if the error happened
        ### due to a function called in a dependency module, our 
        ### target module should still know about the unaligned global
        ### struct
        global_structs = []
        res = None
        cmd = "pglobal -v {} | grep \"struct\|union\|enum\"".format(path)
        try:
            res = subprocess.check_output(cmd,shell=True).decode("utf-8")
        except:
            print(traceback.format_exc())
        
        ### For every result we get back we isolate the struct instance
        ### and its type
        if res != None:
            lines = res.split("\n")
            for line in lines:
                #if "extern" not in line and dep == False:
                #    continue
                #if "extern" in line and dep == True:
                #    continue
                match = re.search("(struct|union|enum)(\s+)(.?)(\s*)(.?)*[^\)]\;\;",line)
                if match != None:
                    tokens = list(filter(None,match.group().split(" ")))
                    struct = tokens[-1].strip(";;")
                    d_type = tokens[0]
                    if "*" in tokens:
                        d_name = tokens[-3] 
                        pointer = ""
                    else:
                        d_name = tokens[-2]
                        pointer = "&"
                    global_structs.append([d_type,d_name,pointer,struct])

        return global_structs
    
    def check_if_kernel_func(self,function):
        if function in self.system_map.values():
            return True
        return False

    def get_function_with_error(self,address,section_info):
        address = int(address,0)
        func_name = ""
        min_diff = 10000000
        
        error_loc = None
        ### First check the functions within the module or its
        ### dependencies
        for module_section in section_info:
            ### Section information captured for each module
            for section in module_section[1]:
                info = section
                tokens = info.split()
                f_name = tokens[1].replace(".text.","").replace(".text","")
                f_addr = int(tokens[0].replace("\\t",""),0)
                diff = address - f_addr
                if diff >= 0 and diff < min_diff:
                    min_diff = diff
                    func_name = f_name
                    error_loc = module_section[0]
        
        ## Then check with the kernel functions
        for func_addr in self.system_map.keys():
            if "0x" not in func_addr:
                temp = "0x" + func_addr
            else:
                temp = func_addr
            f_addr = int(temp,0)
            diff = address - f_addr
            if diff >= 0  and diff < min_diff:
                min_diff = diff
                func_name = self.system_map[func_addr]
                error_loc = "kernel"

        return func_name, error_loc


    ### This is a function that will find us the function where the error
    ### actually happened
    def find_funcs(self, module, section_info, call_trace):

        #print("Error file",self.mod_errors_file)
        stack_trace, function, functions = [], "", []

        for line in call_trace:
            ### Stupid heuristics
            if "psr:" in line or "Not" in line:
                continue

            tokens = line.split()
            error_addr = tokens[0].strip("[<>]")
            ### Call trace is of type "Function entered at..."
            if error_addr == "Function":
                error_addr = tokens[3].strip("[<>]")
            addr_name = None
            stack_trace.append([error_addr, addr_name])
            ### This means that the function name is available
            if len(tokens) >= 2:
                ### Case we have the address name
                if "+" in tokens[1]:
                    addr_name = tokens[1].split("+")[0].replace("(", "")
                    is_kernel_func = self.check_if_kernel_func(addr_name)
                elif "(" in tokens[1]:
                    addr_name = tokens[1].replace("(", "")
                    is_kernel_func = self.check_if_kernel_func(addr_name)
                # if not is_kernel_func and addr_name and stack_trace[-1][1] == None:
                #     stack_trace[-1][1] = addr_name

            found = False
            for indx, elem in enumerate(stack_trace):
                ### The Call Trace line only contains the address of the
                ### function and not the name. So if the name is available
                ### from EPC/PC save that instead
                call_trace_addr = elem[0]
                call_trace_func = elem[1]
                if error_addr == call_trace_addr and call_trace_func == None:
                    if call_trace_func != addr_name:
                        found = True
                        stack_trace[indx] = [call_trace_addr, addr_name]
                    else:
                        found = True

            ### Else save whatever we have for this specific address
            if not found:
                stack_trace.append([error_addr, addr_name])

        for trace in stack_trace:
            address, function = trace[0], trace[1]
            if "0x" not in address:
                address = "0x" + address

            ### This means that KALLSYMS is disabled so we only have an address
            ### Search for the function
            if function == None:
                function, error_loc = self.get_function_with_error(address,
                                    section_info)
            ### We know the name, however we also need the module that has that
            ### function
            else:
                temp,error_loc = self.get_function_with_error(address,
                                                            section_info)
            try:
                if function == ".init":
                    function = "init_module"
                if function and [function, error_loc, address] not in functions:
                    functions.append([function, error_loc, address])

            except:
                print(traceback.format_exc())

        return functions


    def fix_offsets(self,members,opts,struct,mem0_offset):

        for indx,mem in enumerate(members):
            members[indx][1] = mem[1] - mem0_offset

        all_members = members

        if struct in opts.keys():
            opts[struct] = list(map(list,opts[struct]))
            for indx,cond in enumerate(opts[struct]):
                opts[struct][indx][1] = int(cond[1]) - mem0_offset
                opts[struct][indx][2] = int(cond[2]) - mem0_offset

            all_members += opts[struct]
            all_members = [list(i) for i in set(map(tuple, all_members))]

        all_members = sorted(all_members,key = lambda x:x[1])

        return members,opts,all_members

    def add_members(self,struct,module,members,option_list,parent,block):
        for indx,elem in enumerate(members):
            ### This means we have a conditional
            ### So we have to create a new node
            member = elem[0]
            line = elem[1]
            variable = elem[2]
            if block.end_block != -1 and block.end_block < line:
               # print("We are outside of block",block.cond,"for struct",struct,"Returning to parent")
                new_block = AST(parent.cond,[],-1)
                new_block.parent = parent
                option_list = self.add_members(struct,module,members[indx:],option_list,parent,new_block)
                return option_list
            
            if cu.check_if_numeric(str(elem[2])):
          #      print("Hit conditional {}...Creating new block".format(elem[0]))
                ### Overwrite current block if its empty
                if block.members == [] and not block.children:
                    block.cond = elem[0]
                    block.end_block = elem[2]
                    #option_list = self.add_members(struct,module,members[indx+1:],option_list,parent,block)
                    continue
                else:
                    new_block = AST(elem[0],[],elem[2])
                    new_block.parent = parent
                    option_list = self.add_members(struct,module,members[indx+1:],option_list,parent,new_block)
                return option_list
            
           # print("MEMBER",member,"of struct",struct,"in line",line)
            ### The block for the conditional has ended so return to its parent
            
            if "*" in member:
                block.members.append([member,variable])
                continue
            else:
                if member not in self.struct_dict_conds.keys():
                    block.members.append([member,variable])
                    continue
                opts = self.struct_dict_conds[member]["conds"]
                if member not in option_list.keys() and opts != []:
                    option_list[member] = sorted(opts,key = lambda x:x[1])
                #option_list.append(self.struct_dict_conds[member]["conds"])
            #    print("Member",member,"is a DS...Initiating recursion")
                #if "union" in member or "enum" in member:
                    #new_block = AST(member,[],-1)
                    #new_block.parent = block
                #else:
                if block.cond == "root" and block.members == [] and not block.children:
                    block.cond =  "{} {}".format(member,variable)
                    option_list  = self.find_struct_options(member,module,option_list,parent,block)
                else:
                    new_block = AST("{} {}".format(member,variable),[],-1)
                    new_block.parent = block
                    option_list  = self.find_struct_options(member,module,option_list,block,new_block)
                
                if indx + 1 < len(members):
                    new_block = AST(parent.cond,[],-1)
                    new_block.parent = parent
                    option_list = self.add_members(struct,module,members[indx+1:],option_list,parent,new_block)
                    break

        
        return option_list

    def find_struct_options(self,struct,module,option_list,parent,block):
      #  print("Finding members for struct",struct)
        members = self.find_members(module,struct)
       # print("MEMBERS\n",members)

        if members:
            member0_ofst = int(members[0][1])
            members,option_list,all_members = self.fix_offsets(members,option_list,struct,member0_ofst)
        #    print("MEMBERS with conditionals\n",all_members)
            option_list = self.add_members(struct,module,all_members,option_list,parent,block)

        return option_list

    def find_members(self,module,struct):
        #index = self.ups_mod_dict[module]
        #ups_module_path = self.ups_mod_order[index]
        ### We also need to keep the rest of the members of the
        ### struct since they can contribute to the total number
        ### of options we have to enable
        members = []
        for s_dict in self.struct_dict_members:
            ### Now check if we have the struct and if the struct is defined
            ### in a file that is included by the module. This tries to catch
            ### multiple definitions of a struct with the same name
            if struct in s_dict.keys():
                struct_file = s_dict[struct][1].replace(self.kernel +"/","")
         #       print("Struct",struct,"file",struct_file)
                #if struct_file == declared_in_fl:
                members += s_dict[struct][0]
        
        #members[0] = list(map(list,members[0]))
       # print(members[0])
        ### Find if a member is actually an alias
        for indx,elem in enumerate(members):
            if not elem:
                continue
            for dt_name in self.struct_dict_conds.keys():
                if self.struct_dict_conds[dt_name]["alias"] == []:
                    continue
                try:
                    aliases,line_nums = map(list,zip(*self.struct_dict_conds[dt_name]["alias"]))
                except:
        #            print (self.struct_dict_conds[dt_name]["alias"])
                    raise
                if elem[0] in aliases:
                    #print("ALIAS",elem,"OF",dt_name)
                    members[indx][0] = dt_name
                    break
        
        return members


    def find_module_members(self,struct,module_path):
        ds_tokens = struct.split()

        cmd = "pahole -C {} -E {}".format(ds_tokens[1], module_path)
        res = ""
        try:
            print("Pahole", cmd)
            res = subprocess.check_output(cmd, shell=True).decode("utf-8")
        except:
            print(traceback.format_exc())
            return []
        
        #declared_in_fl = ""
        #try:
            #declared_in_fl = res.split("\n")[1].split()[2].split(":")[0]
        #except:
            #print(ros)
            ##print(res.split("\n")[1])
            #raise
        
        #print("Declared in ", declared_in_fl)
        members = res.split("\n")[1:]
        return members
    
    def update_config_file(self,arch,options,kconf):
        #config_tree_file = img_kern_dir + "config.pkl"
        #config_tree = cu.read_pickle(config_tree_file)

        cwd = os.getcwd()
        os.chdir(self.kern_dir)
        #module_configs = find_custom_module_options(self.cust_modules)
        img_obj = Img(kconf,self.img, self.module_options, arch)
        
        if arch == "mips" and "CONFIG_SMP" in options:
            opts = ["CONFIG_MIPS_MT_SMP","!CONFIG_MIPS_MT_DISABLED", "CONFIG_SYS_SUPPORTS_MULTITHREADING"] + options 
        elif arch == "mips" and "!CONFIG_SMP" in options:
            opts = ["!CONFIG_MIPS_MT_SMP","CONFIG_MIPS_MT_DISABLED", "!CONFIG_SYS_SUPPORTS_MULTITHREADING"] + options
        else:
            opts = options
        ### Enable the options in the config file ###
        for opt in opts:
            img_obj.filename = None
            img_obj.kconf._tokens = img_obj.kconf._tokenize("if " + opt.replace("CONFIG_",""))
            img_obj.kconf._line = opt.replace("CONFIG_","")
            img_obj.kconf._tokens_i = 1
            expression = img_obj.kconf._expect_expr_and_eol()
            img_obj._split_expr_info(expression,expression)
            try:
                print("Value of opt ", opt , "is", img_obj.kconf.syms[opt.replace("CONFIG_","").strip("!")].tri_value)
            except:
                pass

        try:
            ### Write to .config in the kernel source tree
            print("Writing config file to", self.kern_dir)
            img_obj.kconf.write_config(filename=self.kern_dir + ".config")
        except:
            print("Config write failed")

        os.chdir(cwd)


    def do_compile(self, ds_recovery,s_mod_dir,arch,options,kconf, save_config = False, *args):
        ### Compile the FS kernel also adding the argument options
        what_to_remove = []
        for opt in options:
            if "!" in opt:
                temp = negate_options([opt])
                if temp[0] in options:
                    what_to_remove.append(opt)
        
        print("WHAT TO REMOVE", what_to_remove)
        for opt in what_to_remove:
            options.remove(opt)
        ### If we want to compile a standalone module
        ### Get the .config file from the result directory of the image
        ### and just enable the additional options
        if ds_recovery:
            self.update_config_file(arch,options,kconf)

        if args:
            vermagic_override = "-o"
        else:
            vermagic_override = ""
        
        if save_config:
            s_config = "yes"
        else:
            s_config = "no"

        print("Preparing to compile for the solution", options,"\n")
        compile_cmd = f"python3 {cu.script_dir}stage2a/firm_kern_comp.py {self.img} -d {ds_recovery} -m {s_mod_dir} -s {s_config} {vermagic_override} {self.fi_opts} -l"

        for option in options:
            compile_cmd += " " + "\"{}\"".format(option)

        print("Compilation Command",compile_cmd)

        try:
            res = subprocess.run(compile_cmd,stdout=subprocess.PIPE, stderr=subprocess.PIPE,shell=True, timeout = 300)
        except:
            print(traceback.format_exc())
            pass


    ### Find the member that was accessed incorrectly
    def find_accessed_members(self, struct, offsets, module_path):
        members = self.find_module_members(struct, module_path)
        
        if members == []:
            return [], {}
        ### A bit of black magic
        members_accessed = []
        seen_offsets = []
        member_pos = {}
        ### There might be two members with the same name
        ### We need to know which one is the correct
        member_seen_freq = {}
        for line in members:

            tokens = list(filter(None, line.split(" ")))
            if tokens == [] or "{" in line or "}" in line:
                continue
            print("TOKENZ",tokens)
            if "cacheline" in tokens or "cachelines:" in tokens \
                    or "padding:" in tokens or "padding" in tokens \
                    or "holes:" in tokens or "XXX" in tokens \
                    or "paddings:" in tokens or "cacheline:" in tokens or "Bitfield" in tokens or "bits" in tokens or "bitfield" in tokens:
                continue
            if ";" in tokens[-1]:
                continue
            if len(tokens) < 4:
                continue
            if tokens[-4] == "/*":
                if ":" in tokens[-3]:
                    offset_token = int(tokens[-3].split(":")[0])
                else:
                    offset_token = int(tokens[-3])
            else:
                offset_token = int(tokens[-4].split(":")[0])
            member = list(filter(None,line.split(" ")))[-5].strip(";")
            if ")" in member:
                for token in tokens:
                    if "(*" in token:
                        member = token.split(")")[0].strip("(*")
            if member == "/*":
                member = list(filter(None,line.split(" ")))[-6].strip(";")
            if member not in member_seen_freq:
                member_seen_freq[member] = 1
            else:
                member_seen_freq[member] += 1
            if offset_token in offsets:
                if offset_token in seen_offsets:
                    continue
                members_accessed.append(member)
                member_pos[member] = member_seen_freq[member]
                seen_offsets.append(offset_token)

        return members_accessed, member_pos

    

    def get_offsets(self, module_path, struct, members_accessed, member_pos, negate):
        members = self.find_module_members(struct,module_path)
        if members == []:
            return {}

        new_offsets = {}
        struct_size = 0
        ### A bit of black magic
        for i,member in enumerate(members_accessed):
            member_seen_freq = {}
            for line in members:
                #print("Member",line)
                #pattern = re.search('\*(.?)*\*',line)
                #if pattern == None:
                    #continue
                #tokens = list(filter(None, pattern.group().split(" ")))
                tokens = list(filter(None, line.split(" ")))
                #print("Tokens",tokens)
                if tokens == [] or "{" in line or "}" in line:
                    continue
                if "cacheline" in tokens or "cachelines:" in tokens:
                    continue
                if (member + ";") in tokens or f"(*{member})" in line:
                    print("Member",member)
                    if member not in member_seen_freq:
                        member_seen_freq[member] = 1
                    else:
                        member_seen_freq[member] += 1
                    if tokens[-4] == "/*":
                        if ":" in tokens[-3]:
                            offset = int(tokens[-3].split(":")[0])
                        else:
                            offset = int(tokens[-3])
                        print("Member seen",member_seen_freq, "Member pos", member_pos)
                        if member_pos[member] != member_seen_freq[member]:
                            continue
                        #if not negate:
                            #if offset < first_offsets[member]:
                                #continue
                        #else:
                            #if offset > first_offsets[member]:
                                #continue
                        print("Here",member, offset)
                        new_offsets[member] = offset
                    else:
                        print("Member seen",member_seen_freq, "Member pos", member_pos)
                        if member_pos[member] != member_seen_freq[member]:
                            continue
                        offset = int(tokens[-4].split(":")[0])
                        #if not negate:
                            #if offset < first_offsets[member]:
                                #continue
                        #else:
                            #if offset > first_offsets[member]:
                                #continue
                        print("Here",member, offset)
                        new_offsets[member] = offset

                    break
        for line in members:
            #print("Member",line)
            #pattern = re.search('\*(.?)*\*',line)
            #if pattern == None:
                #continue
            #tokens = list(filter(None, pattern.group().split(" ")))
            if "size:" in line:
                tokens = list(filter(None, line.split(" ")))
                struct_size = int(tokens[2].strip(","))
                #print(line)
                break

        return new_offsets, struct_size
    
    ### In the case where the vermagic was not known and we have
    ### an option in the solution that belongs to the vermagic
    ### we need to update it
    def update_vermagic(self):
        image_data_fs = f"{cu.img_info_path}{self.img}.pkl"
        image_data = cu.read_pickle(image_data_fs)
        for option in self.solution:
            if option == "CONFIG_SMP":
                image_data["vermagic"].append("SMP")
            if option == "CONFIG_MODULE_UNLOAD":
                image_data["vermagic"].append("mod_unload")
            try:
                if option == "!CONFIG_SMP":
                    image_data["vermagic"].remove("SMP")
                if option == "!CONFIG_MODULE_UNLOAD":
                    image_data["vermagic"].remove("mod_unload")
            except:
                pass

        cu.write_pickle(image_data_fs, image_data)

    def fix_struct_module(self, crashing_mod_deps):
        ### Get the path of the crashing module, we will analyze
        ### it with Ghidra to find out the struct module's layout
        crashing_mod_path = crashing_mod_deps[-1]
        ### Now get a random upstream module to experiment upon
        ### Any will do because struct module is common to all
        ### modules
        for random_mod in self.ups_mod_order:
            if "net" in random_mod:
                continue
            random_module = random_mod
            break

        ghidra_cmd = f"{cu.ghidra_dir}support/analyzeHeadless {cu.script_dir}ghidra Project{self.img}" \
            f" -import \"{self.extracted_fs_dir}{crashing_mod_path}\" -postScript get_struct_mod_layout.py -readOnly" \
            f" -scriptlog \"{cu.script_dir}ghidra/\""
        
        print("Ghidra cmd", ghidra_cmd)
        ### Analyze the crashing module (Maybe it might have been replaced with
        ### one of its dependencies) with ghidra
        ghidra_dir = "{}ghidra/".format(cu.script_dir)
        try:
            output = subprocess.check_output(ghidra_cmd, cwd = ghidra_dir,stderr = subprocess.PIPE,
                        shell = True).decode("utf-8").split("\n")
        except:
            print(traceback.format_exc())
            print("Could not analyze the upstream kernel module", random_module)
        
        for i, line in enumerate(output):
            if line == "Module Layout":
                struct_module_layout = json.loads(output[i+1],
                                object_pairs_hook = OrderedDict)
        
        target_size = int(struct_module_layout["size"])
        del struct_module_layout["size"]
        
        ### Now get the size of struct module in the KFs kernel
        members_accessed = ["(*init)(void)", "(*exit)(void)"]
        member_pos = {"(*init)(void)" : 1, "(*exit)(void)": 1}
        actual_offsets, struct_size = self.get_offsets(random_module, "struct module",\
                members_accessed, {"(*init)(void)" : 1, "(*exit)(void)" : 1}, False)
        
        ### Case where struct module is correctly aligned just return
        if int(actual_offsets["(*init)(void)"]) == int(struct_module_layout["init_module"]) and \
                int(actual_offsets["(*exit)(void)"]) == int(struct_module_layout["cleanup_module"]) and \
                struct_size == target_size:
                    print("Struct module for", self.img, "is already aligned")
                    return None
        target_offsets = {"(*init)(void)" : struct_module_layout["init_module"], "(*exit)(void)": struct_module_layout["cleanup_module"]}
        ### First get which options are not enabled
        not_enabled_opts, extra_opts = \
                          get_struct_conditionals(self, None,
                                                  "struct module")
        
        if "CONFIG_LOCK_STAT" in not_enabled_opts:
            not_enabled_opts.remove("CONFIG_LOCK_STAT")
        if "CONFIG_LOCKDEP" in not_enabled_opts:
            not_enabled_opts.remove("CONFIG_LOCKDEP")

        negated = negate_options(extra_opts)
        all_opts = negated + not_enabled_opts

        print("Struct module FIX")
        print("Not enabled", not_enabled_opts)
        print("Extra options", extra_opts)

        print("Upstream offsets and size", actual_offsets, struct_size)
        print("Custom offsets and size", struct_module_layout, target_size)
        
        random_module_name = random_module.split("/")[-1]
        module_subdir = random_module.split("/kernel/")[1].replace(random_module_name,"")
        in_tree_module = cu.kern_dir + "{}{}/{}{}".format(cu.kernel_prefix,
                                                          self.kernel.replace("linux-",""),
                                                          module_subdir, random_module_name)

        print("In tree module", in_tree_module)
        solution = []
        if int(actual_offsets["(*exit)(void)"]) > int(struct_module_layout["cleanup_module"]):
            negate = True
        else:
            negate = False

        prev_size = 0
        override_vermagic = True
        try:
            found = self.solution_finder_recursive(all_opts, {}, actual_offsets, target_offsets, in_tree_module, "struct module", members_accessed, self, module_subdir, 0, negate, member_pos, [], struct_size, target_size, prev_size, override_vermagic)
        except:
            print(traceback.format_exc())
            with open(cu.log_path + "dslc_results.out","a") as f:
                msg = f"Image {self.img}:struct_module:Solution_error\n"
                f.write(msg)

        if found and self.solution != []:
            with open(cu.log_path + "dslc_results.out","a") as f:
                msg = "Image {}:{}:{}\n".format(self.img, "struct_module", self.solution)
                f.write(msg)
            print("Solution is", self.solution)
            self.update_vermagic()
            return self.solution
        else:
            with open(cu.log_path + "dslc_results.out","a") as f:
                msg = "Image {}:{}:No_solution\n".format(self.img, "struct_module")
                f.write(msg)
            return None

    def create_kconfig(self):

        ### First creat the kconfig
        cwd = os.getcwd()
        os.chdir(self.kern_dir)
        ### Create the new kconf object
        kconf = Kconfig("./arch/{}/Kconfig".format(self.arch), warn = False, warn_to_stderr = False)
        ### Load the .config file created by FS
        kconf.load_config(filename = self.img_kern_dir + ".config")
        os.chdir(cwd)

        return kconf

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

    def get_static_crash_mod_info(self, serial_output, in_firmadyne = False, crashing_module = None):
        module_info = {}
        crashing_mods = []
        module_data = []
        error_data = []
        err_addr = []
        #module_info[crashing_module +".ko"] = []

        error_found = False
        ### This is to avoid errors in user space apps
        ### FirmSolo does not have this problem since
        ### it is using its custom file-system
        if in_firmadyne:
            oops_seen = False
        else:
            oops_seen = True

        for line in serial_output:
            if "Module_name" in line:
                if error_found == True:
                    break
                error_found = False
                tk = line.split("Module_name:")[1]
                tokens = tk.split()
                module_data.append([tokens[0], tokens[2], tokens[4]])
                current_module = tokens[0]
                module_info[current_module + ".ko"] = []
            if "Oops" in line or "Kernel bug detected" in line or "BUG:" in line:
                oops_seen = True
            if "------------[ cut here ]------------" in line:
                oops_seen = True
                error_found = True
                continue
            ### ARM dmesg messes up the below
            try:
                if ".text" in line and current_module != "":
                    module_info[current_module + ".ko"].append(line)
            except:
                pass
            try:
                if ".init" in line and current_module != "":
                    module_info[current_module + ".ko"].append(line)
            except:
                pass
            if "epc   :" in line and oops_seen:
                tokens = line.split()
                err_addr.append("0x" + tokens[2])
                error_found = True
                error_data.append(line)
                continue
            if "pc :" in line and oops_seen:
                tokens = line.split()
                addr = "0x" + tokens[2].replace("[<", "").replace(">]", "")
                err_addr.append(addr)
                error_found = True
                error_data.append(line)
                continue
            if error_found == True and oops_seen:
                #func_addresses = re.findall("(\[\<.*\>\])", line)
                #if func_addresses:
                if " from " in line:
                    linez = line.split(" from ")
                    for line in linez:
                        error_data.append(line)
                else:
                    error_data.append(line)
        print("Error Data", error_data, "\n", "Known crashing module", crashing_module)
        if not crashing_module:
            try:
                crashing_module = self.static_find_crashing_mod(module_data, err_addr)
            except:
                print("EXCEPTION:",traceback.format_exc())
                return [], []
            print("Found crashing module", crashing_module)
            if crashing_module == "kernel" or crashing_module == "":
                for ln in error_data:
                    func_addresses = re.findall("(\[\<.*\>\])", ln)
                    print("Func Addresses", func_addresses)
                    if func_addresses:
                        address = ["0x" + func_addresses[0].split()[0].strip("[<>]")]
                        crashing_module = self.static_find_crashing_mod(module_data, address)
                        if crashing_module != "kernel" and crashing_module != "":
                            break
        crashing_mods.append(crashing_module + ".ko")
        try:
            if crashing_module + ".ko" not in module_info:
                module_info[crashing_module + ".ko"] = module_info[current_module + ".ko"] + error_data
            else:
                module_info[crashing_module + ".ko"] += error_data
            #print(module_info[crashing_module+".ko"])
        except:
            module_info[crashing_module + ".ko"] = []
        
        return crashing_mods, module_info

    def solution_finder_recursive(self, opt_set,prev_ofsts,cur_ofsts,target_ofsts,in_tree_module,candidate_type,members,c_img,module_subdir,index,negate, member_pos, negated, *args):
            
            ### Check if the newly added option chenged anything in the offsets else remove it
            if prev_ofsts != {}:
                print("Checked subset",self.solution,"with offsets", cur_ofsts," and target offsets", target_ofsts)
                try:
                    check = check_if_not_diff(prev_ofsts,cur_ofsts)
                except:
                    check = True
                if args and args[0] != args[2]:
                    check = False
                if check:
                    print("Cur offsets", cur_ofsts, "are the same as the Prev offsets", prev_ofsts)
                    return False

            is_solution = True
            ### We found the solution
            for member in cur_ofsts:
                if cur_ofsts[member] != target_ofsts[member]:
                    is_solution = False
                    break

            if is_solution:
                ### This is for the sizes in the case of struct module
                if len(args) > 0:
                    if int(args[0]) == int(args[1]):
                        ### This solution might align struct module but actually its
                        ### a bad solution
                        if sorted(self.solution) in self.bad_struct_module_solutions:
                            return False
                        else:
                            temp_sol = cleanup_solution(negated, self.solution)
                            self.solution = temp_sol
                            return True
                    ### The size of struct module is not correct
                    else:
                        is_solution = False
                else:
                    temp_sol = cleanup_solution(negated, self.solution)
                    self.solution = temp_sol
                    return True
            #### Pruning
            if prev_ofsts != {}:
                for i,member in enumerate(cur_ofsts):
                    if args:
                        print("Solution", self.solution,"with cur_ofst",cur_ofsts,"and size",args[0],"did not cut it")
                    else:
                        print("Solution", self.solution,"with cur_ofst",cur_ofsts, "did not cut it")
                    if negate:
                        if cur_ofsts[member] < target_ofsts[member]:
                            if args and args[0] < args[1]:
                                return False
                            else:
                                return False
                    else:
                        if cur_ofsts[member] > target_ofsts[member]:
                            if args and args[0] > args[1]:
                                return False
                            else:
                                return False
            for i in range(index,len(opt_set)):
                start = time.time()
                cwd = os.getcwd()
                os.chdir(c_img.kern_dir)
                ### Create the new kconf object
                kconf = Kconfig("./arch/{}/Kconfig".format(c_img.arch), warn = False, warn_to_stderr = False)
                ### Load the .config file created by FS
                kconf.load_config(filename=c_img.img_kern_dir + ".config")
                os.chdir(cwd)
                self.solution.append(opt_set[i].replace("IS_ENABLED",""))
                print("Currently checking solution set", list(set(negated + self.solution)))
                try:
                    if args:
                        c_img.do_compile(1,module_subdir,c_img.arch, list(set(negated + self.solution)),kconf, args[2])
                    else:
                        c_img.do_compile(1,module_subdir,c_img.arch, list(set(negated + self.solution)),kconf)
                except:
                    self.solution.pop(-1)
                    print(traceback.format_exc())
                    continue
                try:
                    new_offsets, struct_size = c_img.get_offsets(in_tree_module,candidate_type,members, member_pos, negate)
                    if new_offsets == {}:
                        self.solution.pop(-1)
                        continue
                    end = time.time()
                    print ('Execution time',(end-start))
                    ### Normal case
                    if len(args) == 0:
                        found = self.solution_finder_recursive(opt_set,cur_ofsts,new_offsets,target_ofsts, in_tree_module,candidate_type,members,c_img,module_subdir,i+1,negate, member_pos, negated)
                    ### Struct module case
                    else:
                        found = self.solution_finder_recursive(opt_set,cur_ofsts,new_offsets,target_ofsts, in_tree_module,candidate_type,members,c_img,module_subdir,i+1,negate, member_pos, negated, struct_size, args[1], args[0], args[2])
                except:
                    print(traceback.format_exc())
                    found = False

                if found and set(sorted(self.solution)) not in self.bad_solutions:
                    return True
                self.solution.pop(-1)
                ### Call once with current element included
                
            return False

def cleanup_solution(negated, curr_sol):

    what_to_remove = []
    options = list(set(negated + curr_sol))
    for opt in options:
        if "!" in opt:
            temp = negate_options([opt])
            if temp[0] in options:
                what_to_remove.append(opt)
    
    print("WHAT TO REMOVE IN SOLUTION", what_to_remove) 
    for opt in what_to_remove:
        options.remove(opt)

    return options

class Pexpect_QEMU():
    def __init__(self, c_img, gdb):
        self.arch = c_img.arch
        self.endian = c_img.endian
        self.img = c_img.img
        self.c_img = c_img
        self.kernel = c_img.kernel
        self.vmlinux = "{}/{}/{}/vmlinux".format(cu.result_dir_path, self.img, self.kernel)
        self.vmlinux_arm = "{}/{}/{}/zImage".format(cu.result_dir_path, self.img, self.kernel)
        self.gdb = gdb
        self.vermagic = c_img.vermagic
    
    ############################## Private #################################
    def __get_qemu_cmd(self):
        
        #TODO: With ARM you also need to chage the kernel parameters in
        #####  the command
        if self.arch == "mips":
            if self.endian == "little endian":
                qemu = "qemu-system-mipsel"
                rootfs = "{}{}/rootfs_mipsel.qcow2".format(cu.fs_dir,self.img)
            else:
                qemu = "qemu-system-mips"
                rootfs = "{}{}/rootfs_mips.qcow2".format(cu.fs_dir,self.img)
        elif self.arch == "arm":
            qemu = "qemu-system-arm"
            rootfs = "{}{}/rootfs_arm.qcow2".format(cu.fs_dir,self.img)
        else:
            qemu= ""
            rootfs = ""

        if self.gdb == True:
            gdb_server = "-s -S"
        else:
            gdb_server= ""

        machine = self.c_img.qemu_opts["machine"]
        if self.c_img.qemu_opts["cpu"] != "":
            cpu = self.c_img.qemu_opts["cpu"].split()[1]
        else:
            cpu = ""

        iface = self.c_img.qemu_opts["iface"]
        if iface == "":
            iface = "if=ide"

        blk_dev = self.c_img.qemu_opts["blk_dev"]
        tty = self.c_img.qemu_opts["tty"]
        
        if self.arch == "mips":
            cmd = f"{qemu} -kernel {self.vmlinux} -drive file={rootfs},index=0,media=disk,{iface} -append \"root={blk_dev} rootwait rw console={tty} firmadyne.reboot=0 firmadyne.devfs=0 firmadyne.execute=0 firmadyne.procfs=0 firmadyne.syscall=0\" -cpu {cpu} -nographic -M {machine} -m 256M {gdb_server}"
        elif self.arch == "arm":
            cmd = f"{qemu} -kernel {self.vmlinux_arm} -drive file={rootfs},index=0,file.locking=off,media=disk,{iface} -append \"root={blk_dev} rootwait rw console={tty} firmadyne.reboot=0 firmadyne.devfs=0 firmadyne.execute=0 firmadyne.procfs=0 firmadyne.syscall=0 mem=256M\" -nographic -M {machine} -m 256M {gdb_server}"

        print("CMD=",cmd)
        self.cmd = cmd
    #######################################################################

    def stop_child(self):
        if self.child.isalive():
            self.child.delayafterclose = 1.0
            self.child.delayafterterminate = 1.0
            self.child.sendline('init 0')

        if self.child.isalive():
            print('Child did not exit gracefully.', 'Killing forcefully the child with pid',str(self.child.pid))

        res = ""
        pid = None
        try:
            pid_to_kill = 'ps aux | grep \"/{0}/\"'.format(self.img)
            res = subprocess.check_output(pid_to_kill,shell=True)
        except Exception as e:
            print(e)

        results = res.decode('utf-8').split("\n")
        for rs in results:
            if "grep" not in rs:
                try:
                    pid = int(rs.split()[1])
                    print("Killing pid",pid)
                except:
                    pass
                break        
        try:
            if pid:
                os.kill(pid,signal.SIGINT)
        except Exception as e:
            pass

        time.sleep(2)
        print("After kill")
    ### Initiate Pexpect
    def run_pe(self,q):
        ### Get the QEMU command ###
        self.__get_qemu_cmd()

        try:
            ### Init Pexpect & GDB ###
            q.put("start")
            self.child = pe.spawn(self.cmd)
            self.child.expect('(?i)login:',timeout=60)
            
            ### Pass Login ###
            self.child.sendline("root")
            self.child.expect('# ',timeout=30)

        except:
            print(traceback.format_exc())
            return False
        return True
    
    ### Run a command
    def run_cmd(self,cmd, mod):
        
        ### Clear the pexpect buffer first
        try:
            child.read_nonblocking(16834,timeout=10)
        except:
            pass
        ### Now run the actual command
        out = None
        try:
            print("RUNNING A COMMAND IN PEXPECT:", cmd)
            self.child.sendline(cmd)
            self.child.expect('# ',timeout=60)
            out = self.child.before.decode("utf-8")
        except:
            print(traceback.format_exc())
            out = self.child.before.decode("utf-8")
            with open(cu.log_path + "dslc_results.out","a") as f:
                msg = "Image {}:{}:Pexpect timeout\n".format(self.img, mod.split("/")[-1])
                f.write(msg)
        
        return out




########################################################################################

###################### Scenario to execute during the analysis ##########################
def exec_scenario(pexp,ups_deps,q):
    ### Spawn the pexpect instance
    success = pexp.run_pe(q)
    if not success:
        q.put("Done")
        q.put([])
        return
    for mod in ups_deps:
        resp = pexp.run_cmd("insmod {}".format(mod), mod)
        if resp != None:
            print(resp)
            if pexp.gdb == False:
                q.put(resp)
        else:
            print("There was some error with when loading the module",mod)
            resp = "Nothing"
            break
    
    print("Stopping child")
    pexp.stop_child()
    print("Stopped child")
    
    q.put("Done")
    #q.put(resp)
    print("Exiting thread")


##################### Find Data Structure Unalignment ############################
# Find the unalignment of the target data structure, by using the traces of the 
# upstream and the custom execution 
##################################################################################
def filter_kernel_funcs(ups_trace, cust_trace):
    filt_ups_trace = []
    filt_cust_trace = []
    for instr in ups_trace:
        if re.findall("(\<\w+\+\w+\>)",instr):
            continue
        filt_ups_trace.append(instr)
    
    for instr in cust_trace:
        if re.findall("(\<\w+\+\w+\>)",instr):
            continue
        filt_cust_trace.append(instr)
    
    return filt_ups_trace,filt_cust_trace

def find_unalignment(ups_trace,cust_trace,arch):
    ### First filter all the functions in the kernel since they should access the struct correctly
    ### We are only interested in different accesses of the struct from instructions from within 
    ### the modules
    #ups_trace, cust_trace = filter_kernel_funcs(upstream_trace,custom_trace)
    ups_ofst = None
    for i,instr in enumerate(ups_trace):
        if i >= len(cust_trace):
            break
        ups_instruction = instr.split(":")[1].split(" ")[1]
        cust_instruction = cust_trace[i].split(":")[1].split(" ")[1]
        if arch == "mips":
            ups_ofst = instr.split(",")[1].split("(")[0]
            cust_ofst = cust_trace[i].split(",")[1].split("(")[0]
        elif arch == "arm":
            if "#" in instr.split(":")[1]:
                ups_ofst = instr.split("#")[1].strip("]")
            else:
                ups_ofst = "0"
            if "#" in cust_trace[i].split(":")[1]:
                cust_ofst = cust_trace[i].split("#")[1].strip("]")
            else:
                cust_ofst = "0"

        if ups_instruction != cust_instruction:
            print("Upstream and Custom execution differ at index {} with instructions {} and {} respectively".format(instr,custom_trace[i]))
        else:
            #TODO: Also find the member of the struct that we are looking for
            if (ups_ofst != cust_ofst and ("unix_create" not in instr and "unix_create" not in cust_trace[i])):
                print("The offset of member ... should be at {} instead of {}".format(cust_ofst,ups_ofst))
                print(instr," ", custom_trace[i],"index",i)
                return cust_ofst,ups_ofst
    return None, ups_ofst

def check_if_not_diff(l1, l2):
    same = False
    for mem in l1:
        if l2[mem] == l1[mem]:
            continue
        else:
            return same
    same = True
    return same


### We need this to get information about the functions of the 
### dependency modules and the error trace
def first_dry_run(c_img, cust_mod_deps):
    pexp = Pexpect_QEMU(c_img, False)
    
    ### The queue will hold the output of pexpect
    queue = mp.Queue()
    proc = mp.Process(target = exec_scenario, args = \
                            (pexp, cust_mod_deps, queue,))
    proc.start()
    proc.join()
    
    section_info = []
    call_trace = []
    
    if not queue.empty():
        queue.get()

    segm_fault = False
    ### Get the messages from the Pexpect queue and parse them
    ### To get the section info and the error information
    for dep in cust_mod_deps:
        if not queue.empty():
            output = queue.get()
            if output != "Done":
                sections = []
                flag = False
                pc_flag = False
                func_name = ""
                if type(output) == list:
                    return None, None, None
                for line in output.split("\n"):
                    ln = line.strip("\r\r")
                    if "Segmentation fault" == ln or "Kernel panic":
                        segm_fault = True
                    if "PC is at" in line:
                        tokens = line.split(" ")
                        if len(tokens) == 5:
                            func_name = line.split(" ")[3]
                            pc_flag = True
                    ### Save the address where the error happened and the return
                    ### address for MIPS here
                    if "epc   :" in line or "pc :" in line or "ra    :" in line:    
                        call_trace.append(ln.split()[2])
                        if "pc :" in line and pc_flag == True:
                            call_trace.append(ln.split()[2] + " " + func_name + " dummy")
                            pc_flag = False
                    ### Also save the address were the execution was 
                    ### supposed to return to (This is for ARM)
                    if "lr :" in line:
                        call_trace.append(ln.split()[6])
                    if ".text" in ln:
                        sections.append(ln)
                    if ".init" in ln:
                        sections.append(ln)
                    if "psr:" in ln:
                        continue

                    ### Now catch the error if it is our module
                    if "Call Trace:" in ln or "Backtrace" in ln or \
                        "Stack:" in ln:

                        flag = True
                        func_addresses = re.findall("(\[\<.*\>\])", ln)
                        if func_addresses:
                            fnc_addr = func_addresses[0].split(">]")
                            for f_addr in fnc_addr:
                                if f_addr != '':
                                    call_trace.append(f_addr)
                        continue

                    if flag == True and ("stack_done" not in ln and \
                                        "Code" not in ln and ln != ''):

                        func_addresses = re.findall("(\[\<.*\>\])", ln)

                        if not func_addresses:
                            continue
                        call_trace.append(line)

                    ### We are done with this error output, go to the
                    ### next section info
                    if flag == True and ("stack_done" in ln or \
                                        "Code" in ln or ln == ''):
                        flag = False
                        break

                ### Save the section info for all the dependency modules 
                ### and our module. We will use it to detect the function that
                ### caused the error
                section_info.append([dep,sections])

    return section_info, call_trace, segm_fault

##################################################################################
def negate_options(opts):
    negated_opts = []
    for opt in opts:
        neg_opt = "!({})".format(opt)
        # Change the dependency conditional to CNF
        expression = to_cnf( "(" + neg_opt.replace("!","~").replace("&&","&").replace("||","|") + ")") 
        deps_cond = str(expression).replace("~","!").replace("&","&&").replace("|","||")
        negated_opts.append(deps_cond)

    return negated_opts


##################################################################################
def get_struct_conditionals(c_img, module, candidate_type):
    option_list = {}

    ### We also need to parse the .config file of the image for options 
    ### that should not be enabled but they actually are
    config_file = c_img.img_kern_dir + ".config"
    config_opts_enabled = cu.read_file(config_file)

    ### Gather all the options for the Candidate data struture
    root = AST("root", [])
    start_block = AST(candidate_type,[],-1)
    start_block.parent = root

    option_list[candidate_type] = \
                sorted(c_img.struct_dict_conds[candidate_type]["conds"],
                       key = lambda x:x[1])
    option_list = c_img.find_struct_options(candidate_type, module,
                                            option_list, root,
                                            start_block)
    print("Struct conditionals", option_list)

    ### Create the powerset for all the options for the candidate DS
    struct_option_tuples = []
    for elem in option_list:
        struct_option_tuples += option_list[elem]
    
    try:
        struct_options, starts, ends = map(list,zip(*struct_option_tuples))
    except:
        return None, None
    struct_options = list(set(struct_options))

    ### Filter out the options that are not related to the configuration
    ### options within the kernel .config file
    filtered_struct_options = []
    for opt in struct_options:
        if "CONFIG_" not in opt:
            continue
        filtered_struct_options.append(opt)
    
    print("Filtered Struct Options", filtered_struct_options)

    ### Now add the options within logical expressions that compose the guard
    ### options in the guard-options set to the set of configuration options
    ### found from the symbol information. We need to isolate the options in
    ### the "filtered_struct_options" set that are not present in the option
    ### set found in stage 1 since only these options might change the
    ### candidate struct layout
    the_guards = []
    for opt in c_img.guards:
        temp = opt.replace("&&","").replace("||","").replace("!","").split(" ")
        the_guards += temp
    c_img.options = list(set(c_img.options))
    the_guards = list(set(the_guards))

    if '' in c_img.options:
        c_img.options.remove('')
    if '' in the_guards:
        the_guards.remove('')
    print("Options", c_img.options, "\n", the_guards)

    ### Now isolate which of the above filtered options are new and can be
    ### enabled in the kernel to change the layout of the candidate struct
    ### and which options are already enabled, which can also change the
    ### layout of the struct if they are disabled
    not_enabled_opts = []
    enabled_opts = []
    for elem in filtered_struct_options:
        tmp = elem.replace("&&","").replace("||","").replace("!","").split(" ")
        flag1 = False
        for opt in c_img.options + the_guards:
            if opt in tmp:
                flag1 = True
                break
        if not flag1:
            not_enabled_opts.append(elem)
        else:
            enabled_opts.append(elem)
    
    if '' in not_enabled_opts:
        not_enabled_opts.remove('')

    ### Now that we have the already enabled options we need to find which
    ### of these options not belong in the options found in stage 1.
    ### These extra options were enabled in the .config but not by kcre
    ### Probably by an option's select, thus we might have to disable them
    extra_opts = []
    for conf_opt in config_opts_enabled:
        ### Don't include comments or junk information from the .config
        if not conf_opt or "#" in conf_opt:
            continue
        tokens = conf_opt.split("=")
        for elem in filtered_struct_options:
            tmp = elem.replace("&&","").replace("||","").replace("!","").split()
            if tokens == ['']:
                continue
            if tokens[0] in tmp and (tokens[1] == "y" or tokens[1] == "m") \
                                and tokens[0] not in c_img.options:
                if elem not in enabled_opts:
                    extra_opts.append(elem)
                if elem in not_enabled_opts:
                    not_enabled_opts.remove(elem)
                break

    print("Enabled Options")
    print(enabled_opts)
    print("Extra Enabled Options")
    print(extra_opts)
    print("Not Enabled Options")
    print(not_enabled_opts)
    return not_enabled_opts, extra_opts


def analyze_modules(c_img, crashing_module, ups_mods_order, crash_mods_order,
                    functions, subs_mappings, exists_ups_mod):
    function = None
    in_which_mod = None
    error_addr = None
    temp_dict = cu.create_dict(ups_mods_order)
    init_module_cnt = 0
    init_module_seen = 0

    for func_info in functions:
        function = func_info[0]
        if function == "init_module":
            init_module_cnt += 1
    print("Init module cnt", init_module_cnt)
    for func_info in functions:
        function = func_info[0]
        in_which_mod = func_info[1]
        error_addr = func_info[2]
        ### kmem_cache_alloc is a special heuristic
        if function == "kmem_cache_alloc":
            return None, None, None, None, None, True, None, in_which_mod
        ### If this is a kernel function we cannot analyze it so go to the
        ### next one till we hit a module function
        if in_which_mod == "kernel" or function == "":
            continue
        ### init_module is usually the first function in the call-trace
        ### (bottom-up) so no point going on
        if function == "init_module":
            if init_module_seen == init_module_cnt:
                return None, None, None, None, None, False, None, "kernel"
            else:
                init_module_seen += 1
            continue
        if function == "sys_init_module" or function == "stack_done":
            return None, None, None, None, None, False, None, in_which_mod
        break
    ### The crashing module does not have an upstream counterpart, go on
    if not exists_ups_mod:
        return None, None, None, None, None, False, None, in_which_mod
    ### We could not find in which module (either the crashing module or a 
    ### dependency) the error occured so go on
    if not in_which_mod or in_which_mod == "kernel":
        return None, None, None, None, None, False, None, in_which_mod

    ### If we have subbed a dependency of the crashing module with an
    ### upstream module run the ghidra on the replaced module
    print("Subs mappings\n", subs_mappings)
    for sub in subs_mappings:
        if in_which_mod == sub[0]:
            in_which_mod = sub[1]
    
    crashing_mod_path = "{}{}".format(c_img.extracted_fs_dir, in_which_mod)
    upstream_mod_path = temp_dict[in_which_mod.split("/")[-1]]
    
    ups_param_dict, crash_param_dict, ups_var_dict, crash_var_dict, ups_param_types = \
                None, None, None, None, None
    print("FUNCTION TO ANALYZE FOR CRASHING MODULE", crashing_module, "IS", function)
    ### First get the info from the upstream module
    ghidra_cmd = f"{cu.ghidra_dir}support/analyzeHeadless {cu.script_dir}ghidra Project{c_img.img}" \
        f" -import \"{upstream_mod_path}\" -postScript ghidra_dslc.py \"{function}\" -readOnly" \
        f" -scriptlog \"{cu.script_dir}ghidra/\""

    ### Analyze the crashing module (Maybe it might have been replaced with
    ### one of its dependencies) with ghidra
    ghidra_dir = "{}ghidra/".format(cu.script_dir)
    try:
        ups_output = subprocess.check_output(ghidra_cmd, cwd = ghidra_dir,stderr = subprocess.PIPE,
                    shell = True).decode("utf-8").split("\n")
    except:
        print(traceback.format_exc())
        print("Could not analyze the upstream kernel module", upstream_mod_path)
    
    print("Upstream module:")
    for i, line in enumerate(ups_output):
        if line == "Param references":
            print("Param references\n", ups_output[i+1])
            ups_param_dict = dict(json.loads(ups_output[i+1]))
        if line == "Variable references":
            print("Variable references\n",ups_output[i+1])
            ups_var_dict = dict(json.loads(ups_output[i+1]))
        if line == "Param types":
            print("Variable types\n", ups_output[i+1])
            ups_param_types = dict(json.loads(ups_output[i+1]))
    
    ### Now get the information from the custom module
    ghidra_cmd = f"{cu.ghidra_dir}support/analyzeHeadless {cu.script_dir}ghidra Project{c_img.img}" \
        f" -import \"{crashing_mod_path}\" -postScript ghidra_dslc.py \"{function}\" -readOnly" \
        f" -scriptlog \"{cu.script_dir}ghidra/\""

    try:
        cust_output = subprocess.check_output(ghidra_cmd, cwd = ghidra_dir,
                    stderr = subprocess.PIPE,
                    shell = True).decode("utf-8").split("\n")
    except:
        print(traceback.format_exc())
        print("Could not analyze the custom kernel module",crashing_mod_path)
    
    print("Distributed module:")
    for i, line in enumerate(cust_output):
        if line == "Param references":
            crash_param_dict = json.loads(cust_output[i+1],
                            object_pairs_hook = OrderedDict)
            print("Param references\n", crash_param_dict)
        if line == "Variable references":
            crash_var_dict = json.loads(cust_output[i+1],
                            object_pairs_hook = OrderedDict)
            print("Variable references\n", crash_var_dict)

    if c_img.img not in all_the_instructions:
        all_the_instructions[c_img.img] = [[crashing_module, ups_param_dict, ups_var_dict, crash_param_dict, crash_var_dict]]
    else:
        all_the_instructions[c_img.img].append([crashing_module, ups_param_dict, ups_var_dict, crash_param_dict, crash_var_dict])

    return ups_param_dict, crash_param_dict, ups_var_dict, crash_var_dict, \
           ups_param_types, False, upstream_mod_path, in_which_mod

def fix_kmem_cache_alloc(c_img, crashing_module, crash_mod_deps):

    candidate_structs = []

    ### First use kconfiglib to get a tree representation of the .config
    ### file that was used to compile the KFs kernel. We will need this
    ### in order to recompile the kernel and check if our kmem_cache_alloc
    ### heuristic actually solved the struct alignment issue
    kconf = c_img.create_kconfig()

    which_slab = None
    if "CONFIG_SLAB" in c_img.options and not "CONFIG_SLUB" in c_img.options:
        
        solution = ["ZONE_DMA"]
        which_slab = "slab"

    elif "CONFIG_SLUB" in c_img.options and "CONFIG_SLUB_DEBUG" not in c_img.options \
            and "CONFIG_SLUB_DEBUG" not in c_img.guards:

        solution = ["EMBEDDED","!CONFIG_SLUB_DEBUG"]
        which_slub = "slub"
    else:
        return None

    ### Check if the heuristic is actually valid. The only way to check is to
    ### recompile the kernel and reload the previously crashing module and
    ### check if it crashes again
    if solution:
        c_img.do_compile(0, "/", c_img.arch, solution, \
                         kconf)
    
    ### Recreate the filesystem with the updated upstream modules
    c_img.create_fs()

    section_info, instr_trace, segm_fault = first_dry_run(c_img, crash_mod_deps)
    #functions = c_img.find_crashing_ds(module, candidate_structs, \
                                       #section_info, instr_trace)
    functions = c_img.find_funcs(crashing_module, section_info,  instr_trace)

    ### The error is fixed
    if not functions:
        return solution
    else:
        return None

def get_stats(member_offsets_dict, instr_stats_dict, var_dict):

    for indx, param in enumerate(var_dict):
        crash_instr_data = var_dict[param]
        for data in crash_instr_data:
            instr_op = data[1]
            operand = data[2]
            offset = data[3]
            if param not in member_offsets_dict.keys():
                member_offsets_dict[param] = [offset]
                instr_op_seen = {}
                instr_op_seen[instr_op] = 1
                instr_stats_dict[param] = instr_op_seen
            else:
                member_offsets_dict[param].append(offset)
                if instr_op not in instr_stats_dict[param].keys():
                    instr_stats_dict[param][instr_op] = 1
                else:
                    instr_stats_dict[param][instr_op] += 1

    return member_offsets_dict, instr_stats_dict

### With this function we will compare the counts of different instructions
### that access the structs found by ghidra. We compare the same instructions
### for two structs (subtract the instruction counts) and keep an overall score
### of similarity between two structs. The lowest score wins
def get_struct(member_offsets_ups, member_offsets_crash, instr_stats_ups,
               instr_stats_crash, ups_var_types, c_img, matched_structs):

    for struct_ups in sorted(member_offsets_ups, key = len, reverse = True):
        if struct_ups in matched_structs:
            continue
        matched_struct = ""
        overall_score = 1000000
        ### Get the unique instruction counts
        instr_ops_ups = instr_stats_ups[struct_ups]
        for struct_crash in member_offsets_crash:
            instr_ops_crash = instr_stats_crash[struct_crash]
            instr_score = 0
            for instr in instr_ops_ups:
                if instr in instr_ops_crash:
                    instr_score += abs(instr_ops_ups[instr] - \
                                       instr_ops_crash[instr])
                else:
                    instr_score += instr_ops_ups[instr]
            for instr in instr_ops_crash:
                if instr not in instr_ops_ups:
                    instr_score += instr_ops_crash[instr]
            if instr_score < overall_score:
                overall_score = instr_score
                matched_struct = struct_crash

        matched_structs[struct_ups] = matched_struct
    
    ord_matched_structs = {}
    for struct_ups in member_offsets_ups:
        ord_matched_structs[struct_ups] = matched_structs[struct_ups]
    print("Matched structs", ord_matched_structs)
    for struct in ord_matched_structs:
        ups_var_type = "struct {}".format(ups_var_types[struct].replace("typedef ","").split()[0])
        if ups_var_type not in c_img.struct_dict_conds.keys():
            continue
        ups_struct_offsets, crash_struct_offsets = [], []
        try:
            ups_struct_offsets = sorted(list(set(member_offsets_ups[struct])))
            crash_struct_offsets = sorted(list(set(member_offsets_crash[ord_matched_structs[struct]])))
        except:
            print("Unmatched struct", struct)
        not_common = list(set(ups_struct_offsets) ^ set(crash_struct_offsets))
        ### One is a subset of the other... No point in testing, so go to the next
        ups_struct_ofsts_set= set(ups_struct_offsets)
        crash_struct_ofsts_set = set(crash_struct_offsets)
        print(ups_struct_ofsts_set, crash_struct_ofsts_set)
        if ups_struct_ofsts_set.issubset(crash_struct_ofsts_set) or crash_struct_ofsts_set.issubset(ups_struct_ofsts_set):
            continue
        if ups_struct_offsets != [] and crash_struct_offsets != [] and not_common != []:
            return struct, ups_struct_offsets, crash_struct_offsets

    return None, None, None

def get_seen_instr(instr_stats_ups, instr_stats_crash):
    seen_instructions = set()
    for elem in instr_stats_ups:
        for instr in instr_stats_ups[elem]:
            seen_instructions.add(instr)
    for elem in instr_stats_crash:
        for instr in instr_stats_crash[elem]:
            seen_instructions.add(instr)
    
    return seen_instructions

def get_crash_struct(ups_param_dict, crash_param_dict, ups_vars_dict,
                     crash_vars_dict, var_types, c_img):
    
    member_offsets_ups = {}
    instr_stats_ups = {}
    member_offsets_crash = {}
    instr_stats_crash = {}
    matched_structs = {}

    member_offsets_ups, instr_stats_ups = get_stats(member_offsets_ups,
                                                    instr_stats_ups,
                                                    ups_param_dict)
    member_offsets_crash, instr_stats_crash = get_stats(member_offsets_crash,
                                                    instr_stats_crash,
                                                    crash_param_dict)
    ### first match the parameters
    for struct_ups in sorted(member_offsets_ups, key = len, reverse = True):
        if struct_ups in matched_structs:
            continue
        matched_struct = ""
        overall_score = 1000000
        ### Get the unique instruction counts
        instr_ops_ups = instr_stats_ups[struct_ups]
        for struct_crash in member_offsets_crash:
            instr_ops_crash = instr_stats_crash[struct_crash]
            instr_score = 0
            for instr in instr_ops_ups:
                if instr in instr_ops_crash:
                    instr_score += abs(instr_ops_ups[instr] - \
                                       instr_ops_crash[instr])
                else:
                    instr_score += instr_ops_ups[instr]
            for instr in instr_ops_crash:
                if instr not in instr_ops_ups:
                    instr_score += instr_ops_crash[instr]
            if instr_score < overall_score:
                overall_score = instr_score
                matched_struct = struct_crash

        matched_structs[struct_ups] = matched_struct
    
    member_offsets_ups, instr_stats_ups = get_stats(member_offsets_ups,
                                                    instr_stats_ups,
                                                    ups_vars_dict)
    member_offsets_crash, instr_stats_crash = get_stats(member_offsets_crash,
                                                    instr_stats_crash,
                                                    crash_vars_dict)
    print("Interesting data")
    print(member_offsets_ups,"\n")
    print(instr_stats_ups, "\n")
    print(member_offsets_crash, "\n")
    print(instr_stats_crash, "\n")
    #seen_instructions = get_seen_instr(instr_stats_ups, instr_stats_crash)
    #ups_
    #print("Seen instructions", seen_instructions)
    #for indx, member in enumerate(ups_param_dict):
            #param = "param_" + str(indx + 1)
            #if param in crash_param_dict.keys():
                #matched_structs[member] = param

    which_struct, struct_offsets_ups, struct_offsets_crash = \
            get_struct(member_offsets_ups, member_offsets_crash, 
                       instr_stats_ups, instr_stats_crash, var_types, c_img, matched_structs)

    return which_struct, struct_offsets_ups, struct_offsets_crash

def get_static_crash_data(cust_deps, module_info):
    section_info = []
    call_trace = []

    for dep in cust_deps:
        sections = []
        flag = False
        pc_flag = False
        func_name = ""
        dep_name = dep.split("/")[-1]
        try:
            output = module_info[dep_name]
        except:
            dep_name = dep_name.replace("-","_")
            output = module_info[dep_name]

        for line in output:
            ln = line.strip("\r\r")
            if "Segmentation fault" == ln:
                segm_fault = True
            ### Save the address where the error happened and the return
            ### address for MIPS here
            if "PC is at" in line:
                tokens = line.split(" ")
                if len(tokens) == 5:
                    func_name = line.split(" ")[3]
                    pc_flag = True
            if "epc   :" in line or "pc :" in line or "ra    :" in line:
                print("PC",ln)
                try:
                    error_info_ln = line.split(":")[1]
                    error_info_ln_tokens = error_info_ln.split(" ")
                    what_to_save = f"[<{error_info_ln_tokens[1]}>] " + " ".join(error_info_ln_tokens[2:])
                    call_trace.append(what_to_save)
                except:
                    call_trace.append(ln.split()[2])
                    
                if "pc :" in line and pc_flag == True:
                    call_trace.append(ln.split()[2] + " " + func_name + " dummy")
                    pc_flag = False
            ### Also save the address were the execution was 
            ### supposed to return to (This is for ARM)
            if "lr :" in line:
                call_trace.append(ln.split()[6])
            if ".text" in ln:
                sections.append(ln)
            if ".init" in ln:
                sections.append(ln)
            if "psr:" in ln:
                continue

            ### Now catch the error if it is our module
            if "Call Trace:" in ln or "Backtrace" in ln or \
                "Stack:" in ln:
                flag = True
                func_addresses = re.findall("(\[\<.*\>\])", ln)
                if func_addresses:
                    fnc_addr = func_addresses[0].split(">]")
                    for f_addr in fnc_addr:
                        if f_addr != '':
                            call_trace.append(f_addr)
                continue

            if flag and ("stack_done" not in ln and \
                                "Code" not in ln and ln != ''):
                func_addresses = re.findall("(\[\<.*\>\])", ln)

                if not func_addresses:
                    continue
                call_trace.append(line)

            ### We are done with this error output, go to the
            ### next section info
            if flag == True and ("stack_done" in ln or \
                                "Code" in ln):
                flag = False
                break

        ### Save the section info for all the dependency modules 
        ### and our module. We will use it to detect the function that
        ### caused the error
        section_info.append([dep,sections])

    return section_info, call_trace

def save_solution(c_img, solution):
    image_info_fl = "{}/{}.pkl".format(cu.img_info_path, c_img.img)
    info = cu.read_pickle(image_info_fl)

    if "dslc" not in info.keys():
        info["dslc"] = solution
    else:
        temp = set(info["dslc"] + solution)
        info["dslc"] = list(temp)
    print("DSLC info", info["dslc"])

    cu.write_pickle(image_info_fl, info)
    os.system("cp " + c_img.kern_dir + ".config " + c_img.img_kern_dir)
    os.system("cp " + c_img.kern_dir + "Module.symvers " + c_img.img_kern_dir)
    os.system("cp " + c_img.kern_dir + "System.map " + c_img.img_kern_dir)
    os.system("cp " + c_img.kern_dir + "cscope.files " + c_img.img_kern_dir)

def analyze_image_modules(c_img):

    ### Get the first crashing module for the image, if it exists
    #crashing_module, upstream_exists = c_img.get_crashing_module()
    crashing_module = ""
    if c_img.serial_out != []:
        crashing_modules, module_info = c_img.get_static_crash_mod_info(c_img.serial_out,
                                                                    in_firmadyne = True)
        c_img.bad_cust_mods = crashing_modules

    while crashing_module != None:
        crashing_module, upstream_exists = c_img.get_crashing_module()
        if crashing_module == None:
            c_img.struct_mod_ok = True
            return None

        cu.clean_kernel_source(c_img.kernel, "ubuntu", c_img.arch)
        ### First check if the "struct module" layout is ok
        ### Then proceed with fixing any other struct that
        ### has an issue
        ### Kernel configuration file for the kernel compilation
        solution = []
        solution_set = None

        print("Checking crashing module", crashing_module)
        try:
            crash_mod_deps, ups_mod_deps, full_path_ups_mod_deps, subs_mappings = \
                c_img.get_dependencies(crashing_module, upstream_exists)
        except:
            if c_img.serial_out == []:
                c_img.struct_mod_ok = True
            print(traceback.format_exc())
            with open(cu.log_path + "dslc_results.out","a") as f:
                msg = "Image {}:{}:Failed_to_get_deps\n".format(c_img.img, crashing_module)
                f.write(msg)

        if not c_img.struct_mod_ok:
            print("Need to align struct module")
            c_img.struct_mod_ok = True
            try:
                struct_mod_sol = c_img.fix_struct_module(crash_mod_deps)
            except:
                print(traceback.format_exc())
                return None
            return struct_mod_sol

        ### Create the cscope database for symbol searching
        c_img.create_cscope_db(ups_mod_deps)

        ### Unfortunately we need to run an emulation instance to get the error
        ### info cause we also need information about the dependencies of the
        ### module
        if c_img.serial_out == []:
            #section_info, call_trace, segm_fault = first_dry_run(c_img, crash_mod_deps)
            module_crash_serial_out = cu.read_file(f"{c_img.mod_errors_path}dmesg_{crashing_module}_distributed")
            #_, module_info = c_img.get_static_crash_mod_info(module_crash_serial_out, crashing_module.replace(".ko",""))
            try:
                _, module_info = c_img.get_static_crash_mod_info(module_crash_serial_out,
                                                                 crashing_module = crashing_module.replace(".ko",""))
                print("Module info type", type(module_info))
                section_info, call_trace = get_static_crash_data(crash_mod_deps, module_info)
            except:
                print(traceback.format_exc())
                with open(cu.log_path + "dslc_results.out","a") as f:
                    msg = "Image {}:{}:Error in getting crashing data\n".format(c_img.img, crashing_module)
                    f.write(msg)
                continue
            segm_fault = True
        else:
            section_info, call_trace = get_static_crash_data(crash_mod_deps, module_info)
            print(call_trace)
            segm_fault = True
        
        if section_info == None and call_trace == None and segm_fault == None:
            with open(cu.log_path + "dslc_results.out","a") as f:
                msg = "Image {}:{}:Emulation error\n".format(c_img.img, crashing_module)
                f.write(msg)
            continue

        ### Now find the functions present in the call trace
        functions = c_img.find_funcs(crashing_module, section_info, call_trace)
        ### We could not get a valid call trace for this module
        if not functions:
            if not upstream_exists:
                with open(cu.log_path + "dslc_results.out","a") as f:
                    msg = "Image {}:{}:No_ups_modules\n".format(c_img.img, crashing_module)
                    f.write(msg)
                continue
            with open(cu.log_path + "dslc_results.out","a") as f:
                msg = "Image {}:{}:No_functions\n".format(c_img.img, crashing_module)
                f.write(msg)
            continue

        ups_param_dict, crash_param_dict, ups_vars_dict, crash_vars_dict, \
                        var_types, is_kmem_cache, actual_crashing_mod, only_kernel = \
                        analyze_modules(c_img, crashing_module,
                                        full_path_ups_mod_deps, crash_mod_deps,
                                        functions, subs_mappings,
                                        upstream_exists)
        
        print("FUNCTION ORIGIN", only_kernel)
        ### First check if our our kmem_cache_alloc heuristic does the trick
        if is_kmem_cache:
            kmem_solution = fix_kmem_cache_alloc(c_img, crashing_module,
                                                 crash_mod_deps)
            with open(cu.log_path + "dslc_results.out","a") as f:
                msg = "Image {}:{}:kmem_cache_alloc:{}\n".format(c_img.img, crashing_module, kmem_solution)
                f.write(msg)
            if kmem_solution != None:
                return kmem_solution
            else:
                continue
        
        if not is_kmem_cache and not upstream_exists:
            with open(cu.log_path + "dslc_results.out","a") as f:
                msg = "Image {}:{}:No_ups_modules\n".format(c_img.img, crashing_module)
                f.write(msg)
                continue
        if only_kernel == "kernel":
            with open(cu.log_path + "dslc_results.out","a") as f:
                msg = "Image {}:{}:Only_kernel_functions\n".format(c_img.img, crashing_module)
                f.write(msg)
                continue

        ### Ghidra did not find anything so just continue to the next module
        if ups_param_dict == None or crash_param_dict == None:
            with open(cu.log_path + "dslc_results.out","a") as f:
                msg = "Image {}:{}:Ghidra_error_none_param_dicts\n".format(c_img.img, crashing_module)
                f.write(msg)
            continue

        ### Now we have all the load/store instructions for all the modules that
        ### make use of the variables in the crashing function, thus we have to
        ### find the struct that caused the crash along with the incorrectly
        ### accessed member
        crsh_struct, ups_struct_ofsts, crash_struct_ofsts = \
                        get_crash_struct(ups_param_dict, crash_param_dict,
                                         ups_vars_dict, crash_vars_dict,
                                         var_types, c_img)
        if crsh_struct == None:
            with open(cu.log_path + "dslc_results.out","a") as f:
                msg = "Image {}:{}:All_structs aligned\n".format(c_img.img, crashing_module)
                f.write(msg)
            continue

        candidate_struct = "struct {}".format(var_types[crsh_struct].replace("typedef ","").split()[0])
        print("Candidate struct is {} with offsets {} {}".format(candidate_struct, ups_struct_ofsts, crash_struct_ofsts))

        if ups_struct_ofsts == None or crash_struct_ofsts == None:
            with open(cu.log_path + "dslc_results.out","a") as f:
                msg = "Image {}:{}:{}:None_struct_ofsts\n".format(c_img.img, crashing_module, candidate_struct)
                f.write(msg)
            continue
        if ups_struct_ofsts == [] or crash_struct_ofsts == []:
            with open(cu.log_path + "dslc_results.out","a") as f:
                msg = "Image {}:{}:{}:Empty_struct_ofsts\n".format(c_img.img, crashing_module, candidate_struct)
                f.write(msg)
            continue

        negate = False

        if len(ups_struct_ofsts) >= len(crash_struct_ofsts):
            for indx, ofst in enumerate(ups_struct_ofsts):
                if indx >= len(crash_struct_ofsts):
                    break
                if ofst > crash_struct_ofsts[indx]:
                    print("OFST", ofst, "CUST OFST", crash_struct_ofsts[indx])
                    negate = True
                    break
        else:
            for indx, ofst in enumerate(crash_struct_ofsts):
                if indx >= len(ups_struct_ofsts):
                    break
                if ofst < ups_struct_ofsts[indx]:
                    negate = True
                    break


        ### Get all the options that when enabled can modify the layout of the
        ### candidate struct. Also get options not present in stage one that
        ### might need to get disabled
        not_enabled_opts, extra_opts = \
                          get_struct_conditionals(c_img, crashing_module,
                                                  candidate_struct)
        
        if not_enabled_opts == None or extra_opts == None:
            with open(cu.log_path + "dslc_results.out","a") as f:
                msg = "Image {}:{}:{}:Bad_struct_no_conditionals\n".format(c_img.img, crashing_module, candidate_struct)
                f.write(msg)
            continue

        ### Get the members of the candidate struct that were accessed in both
        ### the upstream and crashing module
        members_accessed, member_pos = c_img.find_accessed_members(candidate_struct,
                                                       ups_struct_ofsts,
                                                       actual_crashing_mod)
        print("Accessed members", members_accessed, member_pos)

        #if negate:
        negated = negate_options(extra_opts)
        #not_enabled_opts = negated
        not_enabled_opts = extra_opts + not_enabled_opts
        negate = False
        #else:
            #negated = []
        
        try:
            initial_ofsts = cu.create_dict_key_vals(members_accessed,
                                                ups_struct_ofsts)
            target_ofsts = cu.create_dict_key_vals(members_accessed,
                                               crash_struct_ofsts)
        except:
            with open(cu.log_path + "dslc_results.out","a") as f:
                msg = "Image {}:{}:{}:Bad_struct_Offsets {},{} \n".format(c_img.img, crashing_module, candidate_struct, ups_struct_ofsts, crash_struct_ofsts)
                f.write(msg)
            continue

        
        crashing_module_name = actual_crashing_mod.split("/")[-1]
        module_subdir = actual_crashing_mod.split("/kernel/")[1].replace(crashing_module_name,
                                                                        "")
        in_tree_module = cu.kern_dir + "{}{}/{}{}".format(cu.kernel_prefix,
                                                          c_img.kernel.replace("linux-",""),
                                                          module_subdir, crashing_module_name)
        
        print("Module", module_subdir)
        print("In tree module", in_tree_module)
        
        print("NEGATE", negate, not_enabled_opts)
        try:
            found = c_img.solution_finder_recursive(not_enabled_opts, {}, initial_ofsts, target_ofsts, in_tree_module, candidate_struct, members_accessed, c_img, module_subdir, 0 , negate, member_pos, negated)
        except:
            print(traceback.format_exc())
            with open(cu.log_path + "dslc_results.out","a") as f:
                msg = "Image {}:{}:{}:Solution_error\n".format(c_img.img, crashing_module, candidate_struct)
                f.write(msg)
            continue

        if found and c_img.solution != []:
            with open(cu.log_path + "dslc_results.out","a") as f:
                msg = "Image {}:{}:{}:{}\n".format(c_img.img, crashing_module, candidate_struct, c_img.solution)
                f.write(msg)
            print("Solution is", c_img.solution)
            return c_img.solution
        else:
            with open(cu.log_path + "dslc_results.out","a") as f:
                msg = "Image {}:{}:{}:No_solution\n".format(c_img.img, crashing_module, candidate_struct)
                f.write(msg)

        #crashing_module, upstream_exists = c_img.get_crashing_module()

def test_solution(c_img, solution, save_config = False):
    ### Now run the emulation again and check the modules
    ### If the set of bad modules has not changed then there
    ### is no solution available so go to the next image
    kconf = c_img.create_kconfig()
    c_img.do_compile( 0, "/", c_img.arch, solution, \
                     kconf, save_config)
    load_mods("", "", 1, c_img.img, "./", "ups_subs")

def layout_correct(image, infile, serial_out, fi_opts):
    ### One or multiple images?
    if image != 0:
        images = [str(image)]
        if serial_out != '':
            serial_output = cu.read_file(serial_out)
        else:
            serial_output = []
    elif infile != '':
        images = cu.read_file(infile)
        serial_output = []
    else:
        print ('Please provide at least one image ID or file with image IDs')
        return

    for image in images:
        ### Get necessary info about the image
        which_info = ["kernel","arch","endian","modules",
                "options","final_files","guards","vermagic", "module_options"]
        info = cu.get_image_info(image, which_info)

        kernel, arch, endian, cust_modules, options, final_files, \
                guards, vermagic, module_options = [info[i] for i in range(0, 9)]
        ### Get a crashing module and the module order
        prev_bad_modules = set()
        solution = None
        solution_buffer = []
        flag = False
        tested_struct_module = False
        stored_module_solution = False
        bad_struct_module_solutions = []
        bad_solutions = []
        crashed_modules_firmadyne = []
        while True:
            try:
                c_img = Image(image, kernel, arch, endian, vermagic,
                            cust_modules, final_files, options, guards,
                            module_options, serial_output, tested_struct_module, fi_opts)
                c_img.get_struct_info()
                if serial_output != []:
                    c_img.bad_cust_mods = []
            except:
                #print(traceback.format_exc())
                if not flag:
                    kconf = c_img.create_kconfig()
                    c_img.do_compile(0, "/", c_img.arch, [], \
                                     kconf)
                    load_mods("", "", 1, c_img.img, "./", "ups_subs")
                    flag = True
                    continue
                else:
                    break

            if not c_img.bad_cust_mods and serial_output == []:
                print("No crashing modules for image", c_img.img)
                if solution != None:
                    save_solution(c_img, solution)
                    solution_buffer += solution
                break
            elif not c_img.bad_cust_mods and serial_output != []:
                c_img.bad_cust_mods = crashed_modules_firmadyne

            if not solution and prev_bad_modules == set(c_img.bad_cust_mods) and tested_struct_module:
                print("No additional solution can be found for image's", c_img.img, "modules")
                break
            ### We fixed some modules but not all, thus save the intermediate
            ### solution and go on with the rest of the modules
            if solution != None and ((prev_bad_modules != set(c_img.bad_cust_mods) and len(prev_bad_modules) > len(c_img.bad_cust_mods)) or
                                     tested_struct_module and not stored_module_solution):
                if tested_struct_module and not stored_module_solution:
                    stored_module_solution = True

                save_solution(c_img, solution)
                solution_buffer += solution
                bad_solutions = []

            elif solution != None and (prev_bad_modules == set(c_img.bad_cust_mods) or len(prev_bad_modules) <= len(c_img.bad_cust_mods)) and stored_module_solution:
                print("This solution", solution," is not good for image", c_img.img, "Trying other solution")
                bad_solutions.append(set(sorted(solution)))
                c_img.bad_solutions = bad_solutions


            key_set = [kernel] + c_img.bad_cust_mods
            key = frozenset(key_set)
            #if key in images_fixed.keys():
                #continue
            solution = None
            print(c_img.bad_cust_mods)
            try:
                solution = analyze_image_modules(c_img)
            except:
                print(traceback.format_exc())
                with open(cu.log_path + "/fucked_up.out", "a") as f:
                    f.write(image +"\n")
            
            ### Now we have have tried to recover the layout of struct module
            ### Proceed with the rest of crashing modules if any
            if tested_struct_module:
                prev_bad_modules = set(c_img.bad_cust_mods)
            
            ### This was the struct module layout recovery run
            ### We do not need to do this again
            if c_img.struct_mod_ok:
                tested_struct_module = True
                if not solution:
                    stored_module_solution = True
                if serial_output != []:
                    crashed_modules_firmadyne = list(set(c_img.bad_cust_mods))
                    c_img.bad_cust_mods = []

            if solution:
                if serial_output != []:
                    print("Found a potential Firmadyne solution for", c_img.img, "Please compile manually the kernel for the solution\n", solution)
                    break
                if c_img.struct_mod_ok and not stored_module_solution:
                    test_solution(c_img, solution_buffer + solution, True)
                else:
                    test_solution(c_img, solution_buffer + solution)
            elif not solution and serial_output != [] and tested_struct_module and crashed_modules_firmadyne != [] and c_img.bad_cust_mods != []:
                print("There is no Firmadyne solution for", c_img.img, "Aborting")
                break

            time.sleep(1)

def main():
    global all_the_instructions
    parser = argparse.ArgumentParser( \
            description = 'Find DT structure error cause for firmware images')
    parser.add_argument( \
            '--image_id', help = 'The image ID with the crashing module',
            default = 0)
    parser.add_argument( \
            '--infile', type = str, help = 'A file containing the image IDs with'
            ' crashing modules', default = '')
    parser.add_argument(
            '--serial_out', type = str, help = 'Serial output of an emulation'
            ' run that contains the Call Trace for a crashing module. To be used'
            ' with the image_id argument', default = '')
    parser.add_argument( \
            '--fi_opts', type = str, help = 'Compile with firmadyne dslc fixes',
            default = '')
    
    ### Parse the arguments
    res= parser.parse_args()
    image = res.image_id
    infile = res.infile
    serial_out = res.serial_out
    fi_opts = res.fi_opts
    
    
    layout_correct(image, infile, serial_out, fi_opts)

if __name__ == "__main__":
    main()
