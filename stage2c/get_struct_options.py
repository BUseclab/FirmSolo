#!/usr/bin/env python3




import os
import sys
currentdir = os.path.dirname(os.path.realpath(__file__))
parentdir = os.path.dirname(currentdir)
sys.path.append(parentdir)
from stage2a.kcre import Image as Img                           ### We also have an image class here
from stage2a.kconfiglib import Kconfig
from stage2b.get_order import get_dictionary
from pygdbmi.gdbcontroller import GdbController
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
from stage2c import get_ds_conds
import csv

found_solution = False
solution_set = None
subsets_dict = {}
powset = {}

task_struct_dict = {}

remove_options = ["CONFIG_LOCK_STAT","CONFIG_LOCKDEP","CONFIG_GENERIC_LOCKBREAK","CONFIG_DEBUG_SPINLOCK"]

ds_types = ["struct","union","enum","root"]


type_sizes = {
        "int": 4,
        "char": 1,
        "u8": 1,
        "u16": 2,
        "u32": 4,
        "__u8": 1,
        "__u16": 2,
        "__u32": 4,
        "short": 2,
        "long": 4
        }

#TODO: 
# Most important! Based on the error logs of the crashing module:
#       1) Get all the functions in the Call Trace
#       2) Going from top to bottom find their prototypes
#       3) Find all the functions they call? (Usually the error happens in an inline function)
#       4) Find all the external data structures that are used by the module ("There lies the problem")
#       5) Search if any of the params used by the aforementioned functions are global


class QueueNode():
    def __init__(self,cond,seen):
        self.cond = cond
        self.seen = seen

    def set_seen(self):
        self.seen = True

    def unset_seen(self):
        self.seen = False


class AST(NodeMixin):
    def __init__(self,cond,members=None,end_block=-1,next_node=None,parent=None,children=[]):
        self.cond = cond
        self.members = members
        self.end_block = end_block
        self.next_node = next_node
        self.parent = parent
        self.children = children
    def set_root(self,root):
        self.root = root

def print_tree(tree):
    for pre,_,node in RenderTree(root):
        treestr = u"%s%s" %(pre,node.cond)
        print(treestr.ljust(8),node.members)


root = AST("root",[])


class Approximation():
    def __init__(self,tree,powerset,t_member_type,t_member,t_ofst):
        self.tree = tree
        self.powerset = powerset
        self.t_member_type = t_member_type
        self.t_member = t_member
        self.t_ofst = t_ofst
        self.approximations = []
    
    def find_member_size(self,m_type):
        if "*" in m_type:
            size = 4
            return size

        ### Primitive types
        for elem in type_sizes.keys():
            if elem in m_type:
                size = type_sizes[elem]
                return size
        ### Nothing of the above so we return the
        ### default type which is int
        size = 4
        
        return size


    def find_union_enum_size(self,data_type,current,subset,cur_ofst):
       # print("Finding the size of",data_type,current.cond)
        if data_type == "enum":
            flag = False
            for member in current.members:
                if self.t_member_type == member[0] and self._t_member == member[1]:
                    flag = True
            cur_ofst += self.find_member_size(current.members[0][0])
            return cur_ofst,flag
        ### Data type is a Union
        else:
            max_size = 0
        #    print("Getting the size of members of union",current.cond)
            for member in current.members:
                if self.t_member_type == member[0] and self._t_member == member[1]:
                    flag = True
                size = self.find_member_size(member[0])
                if size > max_size:
                    max_size = size
            ### Now to find the size of a nested data type in the union
            ### We just initiate recursion with cur_ofst = 0 and we let
            ### it find the size itself
         #   print("Going into union's",current.cond,"children")
            for child in current.children:
                size,found = self.recursion(child,subset,0)
                if found:
                    return cur_ofst + size, found
                else:
                    if size > max_size:
                        max_size = size

            return cur_ofst + max_size, False


    def recursion(self,current,subset,cur_ofst):
        #print("Checking",current.cond)
        
        data_type = current.cond.split(" ")[0]
        if data_type not in ds_types and current.cond not in subset:
            return cur_ofst,False
        
        if data_type == "union" or data_type == "enum":
            cur_ofst, found = self.find_union_enum_size(data_type,current,subset,cur_ofst)
        ### Members
        for mem in current.members:
            if mem[0] == self.t_member_type and mem[1] == self.t_member:
                return cur_ofst,True
            cur_ofst += self.find_member_size(mem[0])
        ### Children
        for child in current.children:
            cur_ofst,found = self.recursion(child,subset,cur_ofst)
            if found:
                return cur_ofst,True

        return cur_ofst,False
    
    def traverse_tree(self,subset):
        cur_ofst = 0
        found = False
        ### Members 
        for mem in self.tree.members:
            if mem[0] == self.t_member_type and mem[1] == self.t_member:
                return cur_ofst,True
            cur_ofst += self.find_member_size(mem[0])
        ## Children
        for child in self.tree.children:
            cur_ofst,found = self.recursion(child,subset,cur_ofst)
            if found:
                break
        if not found:
            return -1
        return cur_ofst            
    
    ### For multithreaded run
    def find_offset(self,subset):
        print("Checking Subset",subset)   
        appr_ofst = self.traverse_tree(subset)
        return [subset,abs(appr_ofst - self.t_ofst)]
        
    ### Find the approximations for the powerset in parallel
    def find_approximation(self):
        p = mp.Pool(cu.num_of_threads)
        
        self.approximations = p.map(self.find_offset,self.powerset)
        
        self.approximations = sorted(self.approximations, key=lambda x:x[1])


class Image():
    def __init__(self, img, kernel,cust_modules,final_files):
        self.img = img
        self.bad_mod_file = "{}{}/bad_modules_ups.pkl".format(cu.loaded_mods_path, img)
        self.mod_errors_file = "{}{}/{}_ups_faults.pkl".format(cu.loaded_mods_path,img,img)
        self.mod_load_info_file = "{}{}/{}_ups.pkl".format(cu.loaded_mods_path,img,img)
        self.kernel = cu.kernel_prefix + kernel
        self.indx = 0
        self.cust_modules = cust_modules
        self.img_kern_dir = "{}{}/{}/".format(cu.result_dir_path,self.img,self.kernel)
        self.kern_dir = cu.kern_sources + self.kernel + "/"
        self.__get_kernel_syms()
        self.final_files = final_files

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
        try:
            mod_load_info = cu.multi_read_pickle(self.mod_load_info_file,6)
            cust_mod_subs = mod_load_info[3] + mod_load_info[4]
        except:
            print("Image {} does not have any load information yet...Run stage 3 first".format(self.img))
        
        self.cust_mod_subs = cust_mod_subs

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

    ############################################################################
    def get_module_info(self):
        # Get important information about the craching custom modules
        # and the existing upstream modules for the image
        self.__get_cust_mod_info()
        self.__get_ups_mod_info()
    
    ### We need to create the cscope DB since we have to search for the functions
    ### during the errors. We do not need to run cscope to all the files in the 
    ### kernel tree but only the files that FS found
    def create_cscope_db(self,ups_deps):
        cscope_fl = self.kern_dir + "cscope.files"
        with open(cscope_fl,"w") as f:
            ### First files related to the main kernel
            for fl in self.final_files:
                f.write("./" + fl + "\n")
            ### Second files related to the kernel modules
            module_related_files = []
            for mod in ups_deps:
                module = mod.split("/")[-1]
                module_subdir = mod.split("/kernel/")[1].replace(module,"")
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
            res = subprocess.run("cscope -q -b",cwd=self.kern_dir,shell=True)
        except:
            print("Creating the cscope database failed")
    
    ### Check for a specific symbol with cscope
    ### We are interested in the file that contains the implementation of the symbol
    def run_cscope_cmd(self,func):
        res = ""
        try:
            res = subprocess.check_output('cscope -q -d -L1"{0}"'.format(func),cwd=self.kern_dir,shell=True,timeout=30).decode("utf-8")
        except:
            print(traceback.format_exc())
            print("Cscope searching for func",func,"failed")
        return res


        #self.struct_dict = cu.read_pickle(struct_file)

    def get_crashing_module(self):
        # Get the next craching module with an upstream counterpart
        module = None
        while self.indx < len(self.bad_cust_mods):
            mod = self.bad_cust_mods[self.indx]
            if self.__check_if_upstream_exists(mod):
                module = mod
                self.indx += 1
                return module,True
            self.indx += 1
        return None,False
        

    def get_dependencies(self, module):
        module_path = self.cust_mod_dict[module]
        
        # Custom module order (Only for the bad module)
        cust_order, paramz = [], {}
        #cust_order, paramz = get_mod_order(module_path,self.cust_modules,cust_order,"shipped",paramz)
        
        # Upstream module order (The corresponding upstream module)
        ups_order, ups_paramz = [], {}
        #ups_order, ups_paramz = get_mod_order(module,self.ups_mod_dict,self.ups_mod_order,ups_order,"vanilla",ups_paramz)
        # Save the path to the upstream module in the filesystem 
        # so that we can use it afterwards
        print("UPS_order",ups_order)
        print("MODULE",module)
        for mod_path in ups_order:
            if module in mod_path:
                self.ups_mod_path = mod_path
        #ups_mod_index = self.ups_mod_dict[module]
        #print("INDEX",ups_mod_index)
        #self.ups_mod_path = ups_order[3]
        full_path_ups_order = []
        for path in ups_order:
            full_path_ups_order.append(path)

        ups_order = list(map(lambda x: "./native/" + x.split("/lib/modules/")[1],ups_order))
        
        #### Now if the dependencies for the custom module were substituted we need to use their
        #### upstream counterpart
        if len(cust_order) > 1:
            for indx,mod_path in enumerate(cust_order[:-1]):
                for sub in self.cust_mod_subs:
                    if mod_path.split("/")[-1] == sub[2]:
                        cust_order[indx] = sub[1].replace("/my_mod_dir/","./native/")


        return cust_order, ups_order,full_path_ups_order
    
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
    
    ### Get the parameters of the erroneous function
    def get_func_global_structs(self,function,global_structs):
        ### Pattern to get all the struct, unions and enums 
        ### definitions/arguments within the scope of the function
        ### Of course this wont get all the Data structures that
        ### might be used (Source code parsing needed)

        ### First find the file that contains the implementation of
        ### the function
        cscope_res = self.run_cscope_cmd(function)
        if cscope_res != "":
            c_file = self.kern_dir + cscope_res.split()[0]
        else:
            return []
        
        print("CFILE",c_file)
        ### Now we need to find the start and end line of the function
        ### within the file because we need to parse it
        cmd1 = 'ctags --fields=+ne --output-format=json -o - --sort=no {0} | grep "{1}"'.format(c_file,function)
        res = ""
        try:
            res = subprocess.check_output(cmd1,shell=True).decode("utf-8")
        except:
            print("Could find the beginning and end of function",function)
            return []
        
        start = None
        end = None
        for line in res.split("\n"):
            json_obj = json.loads(line)
            if json_obj["name"] == function:
                start = json_obj["line"]
                end = json_obj["end"]
                break
        print("start",start,"end",end)
        
        if start == None:
            return []
        ### Now we have the start and end of the function in the file
        ### parse the function to find usage of global structs
        g_structs = self.__parse_and_get_structs(c_file,start,end,global_structs)

        return g_structs
    
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
                f_addr = int(tokens[0],0)
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
        

        print(func_name)
        return func_name,error_loc


    ### This is a function that will find us the function where the error
    ### actually happened
    def find_crashing_ds(self,module,global_structs,section_info,call_trace):
        print("Error file",self.mod_errors_file)
        #errors = cu.read_pickle(self.mod_errors_file)
        #print("ERRORS",errors)
        stack_trace = []
        function = ""
        functions = []
        ds_candidates = []
        for line in call_trace:
            print(line)
            if "psr:" in line:
                continue
            tokens = line.split(" ")
            error_addr = tokens[0].replace("[<","").replace(">]","")
            addr_name = None
            if len(tokens) > 2:
                ### Case we have the address name
                if "+" in tokens[1]:
                    addr_name = tokens[1].split("+")[0].strip("(")
                    is_kernel_func = self.check_if_kernel_func(addr_name)

            stack_trace.append([error_addr,addr_name])
                #if len(error[2][0].split()) > 2:
                    #function = error[2][0].split()[-2].split("+")[0]
                #else:
                    #function = error[2][0].split()[-1].split("+")[0]
        
        for trace in stack_trace:
            print("FUNCTION ADDRESS","0x" + trace[0])
            address = trace[0]
            function = trace[1]
            if "0x" not in address:
                address = "0x" + address
            ### This means that KALLSYMS is disabled so we only have an address
            ### Search for the function
            if function == None:
                function,error_loc = self.get_function_with_error(address,section_info)
            ### We know the name, however we also need the module that has that function
            else:
                temp,error_loc = self.get_function_with_error(address,section_info)
            try:
                print("FUNCTION",function)
                if function == "kmem_cache_alloc":
                    ds_candidates = [['struct', 'cache_sizes', '&', 'malloc_sizes[0]']]
                if function == "nf_conntrack_helper_register":
                    ds_candidates = [['struct', 'net', '&', 'init_net']]
                ds_candidates = [['struct', 'net', '&', 'init_net']]
                
                if function == ".init":
                    function = "init_module"
                if [function,error_loc] not in functions:
                    functions.append([function,error_loc])
                #break
                #ds_candidates = self.get_func_global_structs(function,global_structs)
                #if ds_candidates != []:
                #    break
            except:
                print(traceback.format_exc())
                ds_candidates = []
        
        #if functions != []:
            #with open(cu.log_path + "last_funcs_of_mod_errors.csv", "a") as f:
                #sw = csv.writer(f,delimiter=',')
                #sw.writerow([self.img,module] + functions)
                #f.write("Image: " + self.img + " Module: " + module + " Call_Trace_Func: " +function+"\n")
        
        print("DS Candidates",ds_candidates)
        return ds_candidates,functions
    



    def find_module_members(self,struct,module_path):
        ds_tokens = struct.split()

        cmd = "pahole -C {} -E {}".format(ds_tokens[1],module_path)
        res = ""
        try:
            res = subprocess.check_output(cmd,shell=True).decode("utf-8")
        except:
            print(traceback.format_exc())
        
        declared_in_fl = ""
        try:
            declared_in_fl = res.split("\n")[1].split()[2].split(":")[0]
        except:
            print(res.split("\n")[1])
            raise
        
        print("Declared in ",declared_in_fl)
        members = res.split("\n")[1:-2]

        return members
    
    def update_config_file(self,arch,options,kconf):
        #config_tree_file = img_kern_dir + "config.pkl"
        #config_tree = cu.read_pickle(config_tree_file)
        

        cwd = os.getcwd()
        os.chdir(self.kern_dir)
        img_obj = Img(kconf,self.img)
        
        ### Enable the options in the config file ###
        for opt in options:
            img_obj.filename = None
            img_obj.kconf._tokens = img_obj.kconf._tokenize("if " + opt.replace("CONFIG_",""))
            img_obj.kconf._line = opt.replace("CONFIG_","")
            img_obj.kconf._tokens_i = 1
            expression = img_obj.kconf._expect_expr_and_eol()
            img_obj._split_expr_info(expression,expression)

        try:
            ### Write to .config in the kernel source tree
            img_obj.kconf.write_config(filename=None)
        except:
            print("Config write failed")
        os.chdir(cwd)


    def do_compile(self,container,distro,ds_recovery,s_mod_dir,arch,options,kconf):
        ### Compile the FS kernel also adding the argument options
        if "ubnt" in container:
            python = "python3.7"
        else:
            python = "python3.5"
        
        ### If we want to compile a standalone module
        ### Get the .config file from the result directory of the image
        ### and just enable the additional options
        if ds_recovery:
            self.update_config_file(arch,options,kconf)

        lxc_cmd = "lxc exec {} -- {} {}compile_scripts/firm_kern_comp.py {} {} -d {} -m {} -s \"no\" -l".format(container,python,"/Experiments2/scripts/",self.img,distro,ds_recovery,s_mod_dir)

        for option in options:
            lxc_cmd += " " + "\"{}\"".format(option)

        print("Compilation Command",lxc_cmd)
        try:
            res = subprocess.call(lxc_cmd,shell=True)
        except:
            print(traceback.format_exc())
    
    def create_fs(self):
        ### Create the Filesystem for that new image
        cmd = "{}fs_and_snap_scripts/create_fs.py '' {} 1 qcow2 3000".format(cu.script_dir,self.img)
        try:
            res = subprocess.call(cmd,shell=True)
        except:
            print(traceback.format_exc())
    

    ### Find the member that was accessed incorrectly
    def find_accessed_members(self,struct, offsets,module_path):
        members = self.find_module_members(struct,module_path)
        
        ### A bit of black magic
        members_accessed = []
        for line in members:

            #pattern = re.search('\*(.?)*\*',line)
            #if pattern == None:
             #   continue
            #tokens = list(filter(None, pattern.group().split(" ")))
            tokens = list(filter(None, line.split(" ")))
            if tokens == [] or "{" in line or "}" in line:
                continue
            #print("TOKENZ",tokens)
            if "cacheline" in tokens or "cachelines:" in tokens:
                continue
            if int(tokens[-3]) in offsets :
                members_accessed.append(list(filter(None,line.split(" ")))[-5].strip(";"))

        return members_accessed

    

    def get_offsets(self,module_path,struct,members_accessed):
        members = self.find_module_members(struct,module_path)
        
        new_offsets = {}
        ### A bit of black magic
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
            for i,member in enumerate(members_accessed):
                if (member + ";") in tokens:
                    print("Here",member,tokens[-3])
                    new_offsets[member] = int(tokens[-3])
        
        return new_offsets


class GDB_module():
    def __init__(self, img_kern):
        self.img_kern = img_kern
        self.gdb_args =  ['gdb-multiarch','--nx','--quiet','--interpreter=mi3']
        self.gdb_script = "{}auto_gdb.gdb".format(cu.dt_project_dir)
        self.gdbmi = None
        self.trace = []

    #### Initialize and run GDB for the specific image
    def run_gdb(self):
        
        print("Initiating GDB...")
        self.gdbmi = GdbController(self.gdb_args)
        print(self.gdbmi.spawn_new_gdb_subprocess())
        
        response = self.gdbmi.write('-file-exec-and-symbols {}'.format(self.img_kern))
        #pprint(response)
    
        response = self.gdbmi.write('source {}'.format(self.gdb_script))
        #pprint(response)
    #    response = self.run_cmd("-exec-continue")

        return response
    
    ### Run a GDB command through the Machine Interface
    def run_cmd(self,cmd):
        
        try:
            response = self.gdbmi.write(cmd,timeout_sec=120)
        except:
            return None
        
        for i,elem in enumerate(response):
            if elem['message'] == "stopped":
                if elem['payload']['reason'] == 'read-watchpoint-trigger':
                    instruction = response[i+1]['payload'].replace("\\t","  ").replace("   ","",1).strip("\\n")
                    self.trace.append(instruction)
                    return instruction        
        return None
        
    def stop_gdb(self):
        print("Killing GDB")
        res = ""
        pid = None
        try:
            pid_to_kill = 'ps aux | grep \"/{0}/\"'.format("gdb-multiarch --nx --quiet --interpreter=mi3")
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
            print(e)

        time.sleep(1)
        print('GDB killed.')


class Pexpect_QEMU():
    def __init__(self,arch, endian, img, kernel, gdb):
        self.arch = arch
        self.endian = endian
        self.img = img
        self.kernel = kernel
        self.vmlinux = "{}/{}/{}{}/vmlinux".format(cu.result_dir_path,self.img,cu.kernel_prefix,self.kernel)
        self.vmlinux_arm = "{}/{}/{}{}/zImage".format(cu.result_dir_path,self.img,cu.kernel_prefix,self.kernel)
        self.gdb = gdb
    
    ############################## Private #################################
    def __get_qemu_cmd(self):
        
        #TODO: With ARM you also need to chage the kernel parameters in
        #####  the command
        if self.arch == "mips":
            if self.endian == "little endian":
                qemu = "qemu-system-mipsel"
                rootfs = "{}{}/rootfs.qcow2".format(cu.fs_dir,self.img)
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
        
        if self.arch == "mips":
            cmd = "{} -kernel {} -drive file={},index=0,media=disk -append \"root=/dev/hda rw console=ttyS0 firmadyne.reboot=0 firmadyne.devfs=0 firmadyne.execute=0 firmadyne.procfs=0 firmadyne.syscall=0\" -cpu 34Kf -nographic -M malta -m 256 {}".format(qemu,self.vmlinux,rootfs,gdb_server)
        elif self.arch == "arm":
            cmd = "{} -kernel {} -drive file={},index=0,file.locking=off,media=disk -append \"root=/dev/sda rw console=ttyAMA0 firmadyne.reboot=0 firmadyne.devfs=0 firmadyne.execute=0 firmadyne.procfs=0 firmadyne.syscall=0\" -nographic -M versatilepb -m 256 {}".format(qemu,self.vmlinux_arm,rootfs,gdb_server)


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
            print(e)

        time.sleep(2)
        print('Child exited gracefully.')
        
        #print("Killing GDB")
        #res = ""
        #try:
            #pid_to_kill = 'ps aux | grep \"/{0}/\"'.format("gdb-multiarch")
            #res = subprocess.check_output(pid_to_kill,shell=True)
        #except Exception as e:
            #print(e)

        #results = res.decode('utf-8').split("\n")
        #for rs in results:
            #if "grep" not in rs:
                #pid = int(rs.split()[1])
                #print("Killing pid",pid)
                #break        
        #try:
            #os.kill(pid,signal.SIGINT)
        #except Exception as e:
            #print(e)

        #time.sleep(1)
        #print('GDB killed.')
    
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
    
    ### Run a command
    def run_cmd(self,cmd):
        
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
        
        return out


###################### Scenario to execute during the analysis ##########################
def exec_scenario(pexp,ups_deps,q):
    ### Spawn the pexpect instance
    pexp.run_pe(q)
    for mod in ups_deps:
        resp = pexp.run_cmd("insmod {}".format(mod))
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
    
    q.put("Done")
    q.put(resp)


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



def run_analysis(pexp,cust_deps,ups_deps,arch):
    #TODO: Make the analysis for the modules in
    #####  one function for code reuse 

    ### Start the Pexpect process as a separate thread
    ### Continue manipulating GDB until we receive done from the queue
    queue = mp.Queue()
    proc = mp.Process(target=exec_scenario, args=(pexp,ups_deps,queue,) )
    proc.start()
    ### Create a GDB instance

    gdb = GDB_module(pexp.vmlinux)
    while queue.empty():
        pass
    if queue.get() == "start":
        response = gdb.run_gdb()
    while queue.empty():
        response = gdb.run_cmd("-exec-continue")
        if response != None:
            pprint(response)
    
    ## Empty the queue
    while not queue.empty():
        print(queue.get())
    
    
    print("GDB is exiting BRAHHHHHHHHHHH!!!!")
    response = gdb.gdbmi.exit()
    gdb.stop_gdb()
    time.sleep(3)
    assert response is None
    assert gdb.gdbmi.gdb_process is None
    

    proc.join()
    print("TRACE UPSTREAM",gdb.trace)
    upstream_trace = gdb.trace
    ### Custom modules trace
    proc = mp.Process(target=exec_scenario, args=(pexp,cust_deps,queue,) )
    proc.start()
    ### Create a GDB instance
    gdb2 = GDB_module(pexp.vmlinux)
    while queue.empty():
        pass
    
    if queue.get() == "start":
        response = gdb2.run_gdb()
    
    while queue.empty():
        response = gdb2.run_cmd("-exec-continue")
        if response != None:
            pprint(response)
    
    while not queue.empty():
        stdout = queue.get() ### Actual output of pexpect
    
    response = gdb2.gdbmi.exit()
    gdb2.stop_gdb()
    time.sleep(3)
    assert response is None
    assert gdb2.gdbmi.gdb_process is None
    
    proc.join()
    print("TRACE CUSTOM",gdb2.trace)
    custom_trace = gdb2.trace
    
    if "Segmentation fault" not in stdout:
        no_error = True
    else:
        no_error = False
    
    target_ofst, upstream_offset = find_unalignment(upstream_trace,custom_trace,arch)

    if target_ofst == None:
        print("We could not find an alignment issue between the 2 modules")
    
    return no_error,target_ofst,upstream_offset


### Create the script required by GDB to watch the struct
def create_gdb_script(d_type,d_name,pointer,struct,dep_num):
    index = None
    try:
        index = re.search("\[\w+\]",struct).group()
    except:
        pass
    struct_type = "{} {}".format(d_type,d_name)
    if index:
        index = index.replace("[","").replace("]","")
        template = gdb_script_template2 % dict(STRUCT=re.sub("\[\w+\]","",struct),STYPE=struct_type,INDEX=index)
    else:
        template = gdb_script_template % dict(STRUCT=struct,STYPE=struct_type,POINTER=pointer)
    ### Ignore all the dependencies we load before the module
    ignore = "ignore 1 {}".format(dep_num)
    print("TEMPLATE\n",template)
    with open(currentdir + "/auto_gdb.gdb", "w") as f:
        f.write(template)
        f.write(ignore)


def solution_finder_recursive(opt_set,cur_ofsts,target_ofsts,kconf,solution,in_tree_module,candidate_type,members,arch,c_img,module_subdir,index):
        global solution_set
        
        is_solution = True
        ### We found the solution
        for member in cur_ofsts:
            if cur_ofsts[member] != target_ofsts[member]:
                is_solution = False
                break
        if is_solution:
            solution_set = [*solution]
            return True
            #### Pruning
        for i,member in enumerate(cur_ofsts):
            print("Solution",solution,"with cur_ofst",cur_ofsts,"did not cut it")
            if cur_ofsts[member] > target_ofsts[member]:
                return False
        #elif int(cur_ofst) > int(target_ofst):
            #print("Solution",solution,"with cur_ofst",cur_ofst,"did not cut it")
            #return False
        #else:
        for i in range(index,len(opt_set)):
            start = time.time()
            cwd = os.getcwd()
            os.chdir(c_img.kern_dir)
            ### Create the new kconf object
            kconf = Kconfig("./arch/{}/Kconfig".format(arch))
            ### Load the .config file created by FS
            kconf.load_config(filename=c_img.img_kern_dir + ".config")
            os.chdir(cwd)
            solution.append(opt_set[i])
            c_img.do_compile(c_img.container,"ubuntu",1,module_subdir,arch,solution,kconf) 
            new_offsets = c_img.get_offsets(in_tree_module,candidate_type,members)
            print("Checked subset",solution,"with offsets",new_offsets,"and target offset",target_ofsts)
            end = time.time()
            print ('Execution time',(end-start))
            found = solution_finder_recursive(opt_set,new_offsets,target_ofsts,kconf,solution,in_tree_module,candidate_type,members,arch,c_img,module_subdir,i+1)
            if found:
                return True
            solution.pop(-1)
            ### Call once with current element included
            
        return False

class Kernel():
    def __init__(self,kernel,arch):
        self.kernel = kernel
        self.arch = arch


    def fix_offsets(self,members,opts,struct,mem0_offset):
        
        for indx,mem in enumerate(members):
            members[indx][1] = mem[1] - mem0_offset
        
        all_members = members
        #print("STRUCT", struct, "MEMBERS", all_members)

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
        print("MEMBERS\n",members)

        if members:
            member0_ofst = int(members[0][1])
            members,option_list,all_members = self.fix_offsets(members,option_list,struct,member0_ofst)
            #print("MEMBERS with conditionals\n",all_members)
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
            if struct in s_dict:
                struct_file = s_dict[struct][1].replace(self.kernel +"/","")
                #print("Struct",struct,"file",struct_file, s_dict[struct])
                #if struct_file == declared_in_fl:
                members += s_dict[struct][0]
        
        #members = [item for sublist in members for item in sublist]
        #members[0] = list(map(list,members[0]))
        #print("MEMBERZ", members, len(members))
        ### Find if a member is actually an alias
        for indx,elem in enumerate(members):
            if not elem or type(elem) != list():
                continue
            for dt_name in self.struct_dict_conds.keys():
                if self.struct_dict_conds[dt_name]["alias"] == []:
                    continue
                try:
                    aliases,line_nums = map(list,zip(*self.struct_dict_conds[dt_name]["alias"]))
                except:
        #            print (self.struct_dict_conds[dt_name]["alias"])
                    raise
                print(elem)
                if elem[0] in aliases:
                    #print("ALIAS",elem,"OF",dt_name)
                    members[indx][0] = dt_name
                    break
        return members
    
    def get_struct_info(self):
        struct_file = "{}struct_info/{}_{}_struct_options.pkl".format(cu.container_data_path,self.kernel,self.arch)
        if os.path.exists(struct_file):
            with open(struct_file,"rb") as f:
                self.struct_dict_conds = pickle.load(f)
                self.struct_dict_members = pickle.load(f)
        else:
            self.struct_dict_conds, self.struct_dict_members = get_ds_conds.main(self.kernel,self.arch)

def get_struct_conditionals(c_kern,candidate_type):
    module = ""
    option_list = {}
    c_kern.get_struct_info()
    
    ### Gather all the options for the Candidate data struture
    start_block = AST(candidate_type,[],-1)
    start_block.parent = root

    option_list[candidate_type] = sorted(c_kern.struct_dict_conds[candidate_type]["conds"],key = lambda x:x[1])
    option_list = c_kern.find_struct_options(candidate_type,module,option_list,root,start_block)
    print("Struct conditionals",option_list)
    
    ### Create the powerset for all the options for the candidate DS
    the_option_tuples = []
    for elem in option_list:
        the_option_tuples += option_list[elem]

    try:
        the_options,starts,ends = map(list,zip(*the_option_tuples))
        the_options = list(set(the_options))
    except:
        the_options = []

    final_options = []
    for opt in the_options:
        if "CONFIG_" not in opt:
            continue
        final_options.append(opt)
    
    print("Final Options",final_options)
    #for mem in c_kern.struct_dict_members:
        #if "struct module" in mem:
            #print(mem["struct module"])
    ### This is buggy
    #for elem in remove_options:
        #if elem in must_have:

    return the_options


def check_kernel(kernel,arch,candidate_type):
    c_kern = Kernel(kernel,arch)

    module = ""
    #candidate_type = "{} {}".format("struct","kmem_cache")
    final_options = get_struct_conditionals(c_kern,candidate_type)
    task_struct_dict[kernel] = final_options
    return final_options

def main():
    parser = argparse.ArgumentParser(description='Find DT structure error cause for firmware images')
    parser.add_argument('--kernel',type=str,help='The image ID with the crashing module',default='')
    parser.add_argument('--infile',type=str,help='A file containing the image IDs with crashing modules',default='')
    parser.add_argument('--ds',type=str,help='Data structure to get',default='')
    parser.add_argument('--arch',type=str,help='Architecture to check',default='')
    
    res= parser.parse_args()
    kernel = res.kernel
    infile = res.infile
    ds = res.ds
    arch = res.arch
    outfile = cu.log_path + "task_struct_opts.out"
    outfile_pkl = cu.log_path + "task_struct_opts.pkl"
    if ds == '':
        print("Print please provide a data structure")

    if kernel != '':
        kernels = [str(kernel)]
    elif infile != '':
        kernels = cu.read_file(infile)
    else:
        print ('Please provide at least one image ID or file with image IDs')
        sys.exit(0)
    for kernel in kernels:
        ### Get necessary info about the image
        try:
            final_options = check_kernel(kernel,arch,ds)
            #print(final_options)
            #print(task_struct_dict)
            #cu.write_file(outfile,[kernel +"\n" + ", ".join(final_options)+ "\n\n"],"a")
        except:
            print(traceback.format_exc())
        time.sleep(1)
    
    #cu.write_pickle(outfile_pkl,task_struct_dict)

if __name__ == "__main__":
    main()
