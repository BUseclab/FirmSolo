#!/usr/bin/env python3
import pika
import sys
import os
import string
import pickle
import time
import subprocess
from custom_utils import *
from multiprocessing import Pool
import tarfile



done = []


def find_definition(sym,kernel_dir="{0}/archive/".format(abs_path)):

    #run cscope -> take the first file with definition -> return the whole path + file
    #fls = subprocess.run(["cscope","-d","-L1",sym], stdout=subprocess.PIPE)
    
    print(kernel_dir)
    cmd = 'cscope -d -L4"EXPORT_SYMBOL({0})"'.format(sym)
    fls = subprocess.run(cmd, stdout=subprocess.PIPE,cwd=kernel_dir,shell=True)
    filez = fls.stdout.decode("utf-8")
    #print(filez)

    if filez == "":
        cmd = 'cscope -d -L4"EXPORT_SYMBOL_GPL({0})"'.format(sym)
        fls = subprocess.run(cmd, stdout=subprocess.PIPE,cwd=kernel_dir,shell=True)
        filez = fls.stdout.decode("utf-8")
        #print(filez)
    
    if filez == "": 
        cmd = 'cscope -d -L1"{0}"'.format(sym)
        fls = subprocess.run(cmd, stdout=subprocess.PIPE,cwd=kernel_dir,shell=True)
        filez = fls.stdout.decode("utf-8")
 #   print(filez)
    #path = ""
    #fl = ""

    if filez != "":
        return [None,filez]

    return [sym,None]


def find_and_cscope(image_dir):

    # Find the files for cscope 
    find_cmd = "find . -path \"./arch/*\" ! -path \"./arch/mips*\" -prune -o -path \"./Documentation*\" -prune -o -name \"*.[cxsS]\" -print >./cscope.files"
    
    os.chdir(image_dir)
    os.system(find_cmd)
    os.chdir(abs_path)

    try:
        cscope = subprocess.run(['cscope','-b','-q'], cwd=image_dir)
    except:
        print("Cscope failed")


def untar_kernel(kern):
    #untar the kernel directory


    tarf = tar_dir + kern
    kernel = kern.replace(".tar.gz","")
    kernel_dirz = kern_dir + kernel

    try:
        print("Opening tar file",tarf)
        untar = tarfile.open(tarf)
    except Exception as e:
        print("Kernel " + tarf + " does not exist")
        print(e)
        return

    try:
        print("Untaring file to directory",kern_dir)
        untar.extractall(kern_dir)
        untar.close()

    except:
        print ('Kernel '+ tarf + " failed to extract")   
        return
    
    print("Creating cscope for",kernel_dirz)
    find_and_cscope(kernel_dirz)


def find_sym_files(kernel,symbolz):
    cwd = os.getcwd()
    def_files = []
    kernel_dir = kern_src + "linux-"+ kernel
    #print(kernel_dir)
    #find_and_cscope(kernel_dir)
    #check_kernel(kernel_dir,kernel)
    for sym in symbolz:
        filez = find_definition(sym,kernel_dir)
        if filez != "":
            if filez not in def_files:
                def_files.append(filez)

    return def_files


if __name__ == '__main__':
    image_num = 0
    ubuntu = 0
    lenny = 0
    
    p = Pool(6)
    
    with open(abs_path + "all_undefined_symbols.out","r") as f:
        lines = f.readlines()

    #syms = list(map(lambda x:x.split(" ")[2].strip("\n"),lines))
    syms = list(map(lambda x:x.strip("\n"),lines))

    #print(syms)
    out = p.map(find_definition,syms)
    
    undef_syms,res =  map(list, zip(*out))

    filt = list(filter(None, res)) 
    final = list(set(filt))
    
    filt2 = list(filter(None, undef_syms)) 
    final2 = list(set(filt2))

    print (final,"\n",len(final))
    
    with open("def_syms.out","w") as f:
        for sym in final2:
            f.write(sym + "\n")

 #   with open("14406_files.pkl","wb") as f:
  #          pickle.dump(final,f)
        
    #debian_done = read_file(log_path+"debian_done")
    #filez = ubuntu_done + debian_done
    
    #files = list(filter(None,list(map(lambda x: x if x not in done_images else None,filez[100:]))))
    
    #print("Filez",len(files))
    #print(files)
    #print(len(files))
    
 #   done_images = get_done_images()

    #res = p.map(create_pickle,files)

    # Check if input is only one image 
    # if yes then just send this else
    # Read all the images we want to send
    #res = check_if_numeric(infile)
    #if res == True:
    #    files = [infile]
    #else:
    #    files = read_file(infile)
    
