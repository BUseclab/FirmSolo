#!/usr/bin/env python3
import pika
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
from get_symbol_info import *
from parse_kernel_source import *
import re


done = []

###### Extract vermagic and symbols from the modules #######

def get_ver_magic_and_symbols(filename):
    
    modulez = []
    ver_magicz = []
    undef_symbolz = []
    def_symbolz = []
    
    refd_kernels = []
    extra_vers = []
    with open(filename,"r") as f:
            
            if os.stat(filename).st_size == 0:
                return modulez,ver_magicz,symbolz,""
            
            line = f.readline()
   
            while line:
                mod_data = line.split(":")
                module = mod_data[0]
                modulez.append(module)
                vermagic = mod_data[1].split()
                
                if vermagic not in ver_magicz:
                    ver_magicz.append(vermagic)
   
                symbol_num = int(mod_data[2])
            
                kernel = vermagic[0] 
                
                arch = ""
                if vermagic[0] != "Undefined":
                    for tk in vermagic:
                        if "MIPS" in tk:
                            arch = "mips"
                        elif "ARM" in tk:
                            arch = "arm"
                    kern,extravers = get_kernel_info(kernel)
                    refd_kernels.append(kern)
                    extra_vers.append(extravers)

                for i in range(0,symbol_num):

                    line = f.readline()

                    if line.startswith("U"):

                         symbol = line.split()[-1]

                         if symbol not in undef_symbolz:
                             undef_symbolz.append(symbol)
                    
                    else:
                         tkn = line.split()[0]
                         if tkn.isupper():
                         #line.startswith("T") or line.startswith("t"):
                             symbol = line.split()[-1]

                             if symbol not in def_symbolz:
                                 def_symbolz.append(symbol)
   
                line=f.readline()
                if "/" not in line:
                     line=f.readline()
    
    return modulez,ver_magicz,undef_symbolz,arch,refd_kernels,extra_vers,def_symbolz


######################################################################################

def get_kernel_info(kernel):
    
    kern = kernel
    extravers = ""
    if kernel != "Undefined":
        if kernel == "2.6.2219":
            kern = "2.6.22.19"
        else:
            kern = re.search("(\d+\.*){3}(\d+){0,}",kernel).group()
            extravers = kernel.replace(kern,"")
        
    return kern,extravers

def get_endian_compiler(modulez,arch):

    cwd = os.getcwd()
    os.chdir(cu.custom_mod_dir)

    module = modulez[1]

    elf_header = os.popen("readelf -h "+ module+ " | grep Data").read()
    
    if "little endian" in elf_header:
      if arch == "mips":
        cross = "CROSS_COMPILE=mipsel-linux-gnu-" 
      elif arch == "arm":
        cross = "CROSS_COMPILE=arm-linux-gnueabi-"
      endianess = "little endian"
    else:
      if arch == "mips":
        cross = "CROSS_COMPILE=mips-linux-gnu-" 
      elif arch == "arm":
        cross = "CROSS_COMPILE=arm-linux-gnueabi-"
      endianess = "big endian"
    
 #   print (cross)
    
    os.chdir(cwd)              

    return endianess,cross

def filter_syms(undef_syms, def_syms):
    symbolz = []
    other = []

    for sym in undef_syms:
        if sym not in def_syms:
            symbolz.append(sym)
        else:
            other.append(sym)

    return symbolz,other

def create_dictionary(fl):
    #infile = "{0}linux-{1}/{2}".format(kern_dir,linux,fl)
    obj = Parse(fl)
    obj.parse_input()
    obj.parse_conditionals()
    obj.create_dict(obj.tree,obj.tree.cond)

def open_kallsyms():
    fl = "{0}/Data/firma_images_confs.pkl".format(cu.abs_path)
    with open(fl,"rb") as f:
        images = pickle.load(f)
        sym_files = pickle.load(f)
        confs = pickle.load(f)
 #       syms = pickle.load(f)
        syms = []
    
    return images, syms,sym_files
def create_pkl(data):
        ### Check if we already have the info for the image
        
        f = data[0]
        ksyms = data[1]
        ksyms_files = data[2]
        print("\nCREATING PICKLE FOR IMAGE",f,"\n")

        infoz = os.listdir(cu.img_info_path)
        
        have_info = False
        if (f + ".pkl") in infoz:
              have_info = True
        
        

        info_pkl = cu.img_info_path + f + ".pkl"
        
        filename = cu.custom_mod_nm_info + f
        
        syms_fl_dict = {}
        syms_fl_groups = []
        syms_fl_dict2 = {}
        syms_fl_groups2 = []
        
        #### We need to create the information ###
        if have_info == False:
            try:
                modulez,ver_magicz,undef_symbolz,arch,refd_kernels,extra_vers,def_symbolz = get_ver_magic_and_symbols(filename)
            except Exception as e:
                print(e)
                return
            
            symbolz,other = filter_syms(undef_symbolz, def_symbolz)
              #print(other)
            print("Last undefined symbols are",len(symbolz))
            print(arch)

            if arch != "":
                endian, cross = get_endian_compiler(modulez,arch)
            else: 
                return
        else:
            unpickled = cu.read_pickle(info_pkl)
            sym_files = unpickled[8]
            linux = unpickled[0] 
            kernel_dir = "{0}linux-{1}".format(cu.kern_sources,linux)
            symbolz= set(unpickled[4] + ksyms)

            for files in ksyms_files:
                if "slab.c" not in files and "slub.c" not in files and "slob.c" not in files:
                    sym_files.append(files)

            for files in sym_files:
                syms_fl_dict, syms_fl_groups = find_file_freqs(files,syms_fl_dict,syms_fl_groups)
            
 #           print(syms_fl_groups,"\n")
 #           print(syms_fl_dict,"\n")
   #         for files in ksyms_files:
    #            syms_fl_dict2, syms_fl_groups2 = find_file_freqs(files,syms_fl_dict2,syms_fl_groups2)
            
  #          print(syms_fl_groups2)
  #          print(syms_fl_dict2,"\n")
            
            ### Find the dominant files ###
            print("Breaking arbitration")
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
            
            print(final_files)
            #### Now two things 1) Find the conf_opts guarding the compilation of these files
            #### and 2) find any additional config options guarding the export symbols within a file
            print("Finding the config options and additional guards")
            seen_opt = []
            dictionaries = []
            add_guards = []
            cwd = os.getcwd()
            os.chdir(kernel_dir)
            # Find the exporting file first
            for fl in final_files:
                def_file = fl.split("/")[-1]
                print("Parsing def_file",fl)
                dictionaries.append ( create_dictionary(fl))
                conf_opt,Makefile = find_conf_opt(fl,def_file)
                if conf_opt not in seen_opt:
                    seen_opt.append(conf_opt)
            

            for sym in symbolz:
                for dictn in dictionaries:
                    try:
                        guard = dictn[sym]
                        add_guards.append(guard)
                    except:
                        pass
            # Find additional guarding options
            
            print("CONFIG OPTIONS",seen_opt)
            print("ADDITIONAL GUARDS",add_guards)
            new_pickle = []
            for i in range(0,9):
                new_pickle.append(unpickled[i])
            new_pickle.append(final_files)
            new_pickle.append(seen_opt)
            new_pickle.append(add_guards)
            cu.write_pickle(info_pkl,new_pickle)
            os.chdir(cwd)
            return

        if ver_magicz[0][0] != "Undefined":
            kernel_dir = "{0}linux-{1}".format(cu.kern_sources,refd_kernels[0])
            if not os.path.exists(kernel_dir):
                return
            print(filename,refd_kernels[0],image_num)
            if not have_info:
                sym_files = find_sym_files(refd_kernels[0],symbolz,arch)
            
            symbolz = set(symbolz + ksyms)
            ### This will break the arbitration between the files
            
            for files in ksyms_files:
                if "slab.c" not in files and "slub.c" not in files and "slob.c" not in files:
                    sym_files.append(files)
            
            for files in sym_files:
                syms_fl_dict, syms_fl_groups = find_file_freqs(files,syms_fl_dict,syms_fl_groups)
            
            ### Find the dominant files ###
            print("Breaking arbitration")
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
            
            print(final_files)
            #### Now two things 1) Find the conf_opts guarding the compilation of these files
            #### and 2) find any additional config options guarding the export symbols within a file
            
            print("Finding the config options and additional guards")
            seen_opt = []
            dictionaries = []
            add_guards = []
            cwd = os.getcwd()
            os.chdir(kernel_dir)
            # Find the exporting file first
            for fl in final_files:
                def_file = fl.split("/")[-1]
                dictionaries.append ( create_dictionary(fl))
                #dictionaries[fl] = create_dictionary(fl)
                conf_opt,Makefile = find_conf_opt(fl,def_file)
                if conf_opt not in seen_opt:
                    seen_opt.append(conf_opt)
            

            for sym in symbolz:
                for dictn in dictionaries:
                    try:
                        guard = dictn[sym]
                        add_guards.append(guard)
                    except:
                        pass
            # Find additional guarding options
            
            print("CONFIG OPTIONS",seen_opt)
            print("ADDITIONAL GUARDS",add_guards)
            os.chdir(cwd)
            ## Store the info to a pickled object
            pickled_info = [refd_kernels[0],extra_vers[0],modulez,ver_magicz,symbolz,arch,endian,cross,sym_files,final_files,seen_opt,add_guards]
            cu.write_pickle(info_pkl,pickled_info)

if __name__ == '__main__':
    image_num = 0
    infile = sys.argv[1]
    
    files = cu.read_file(infile)
    #arm_images = cu.read_pickle(infile)
    #files = list(map(lambda x: x.split("/")[-1],arm_images))
    
    cnt = int(sys.argv[2])
    #files = ["13906"]
    ksyms_images, ksyms,ksyms_files = open_kallsyms()
    
    data = []
    for image in files[0:cnt]:
        kindx = -1
        try:
            kindx = ksyms_images.index(image)
        except:
            pass
        if kindx != -1:
            #data.append([image,ksyms[kindx],ksyms_files[kindx]])
            data.append([image,[],ksyms_files[kindx]])
        else:
            data.append([image,[],[]])

    p = Pool(cu.num_of_threads)
    
    res = p.map(create_pkl,data)
    

    #for image in files[0:cnt]:
        #print("\nCREATING PICKLE FOR IMAGE",image,"\n")
        #create_pkl(image)


#logfile.close()


