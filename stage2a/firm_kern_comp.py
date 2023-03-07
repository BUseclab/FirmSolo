#! /usr/bin/env python3


import os
from shutil import which
import sys
currentdir = os.path.dirname(os.path.realpath(__file__))
parentdir = os.path.dirname(currentdir)
sys.path.append(parentdir)
sys.path.append(currentdir)
import custom_utils as cu
import subprocess
from multiprocessing import Pool, Process
from kcre import update_config
from fix_kconf import fix_configs
import tarfile
from hot_fixes import hot_fixes
import pickle
import argparse as argp
import traceback
from firmadyne_fix import apply_fdyne_hooks
import time as tm

def exported_syms(kern_dir):
    symvers = []
    sysmap = []
    
    with open(kern_dir+"System.map", "r") as f2:

        line = f2.readline()

        while line:
            symbol = line.split()[2]
            sysmap.append(symbol)
            line = f2.readline()

    return symvers, sysmap

def clean_source(kernel,kern_dir):
    # Clean kernel source directory-> clean compilation
    try:
            image_dir = kern_dir + kernel
            mrproper = subprocess.run(['make','mrproper'],\
                cwd=image_dir, stderr=subprocess.PIPE,stdout=subprocess.PIPE)
            print("Cleaning kernel source")
            print (mrproper.stdout.decode("utf-8"))
    except:
            print("Something went wrong with cleaning the kernel")

def remove_kernel_dir(ds_recovery, kern_dir):
    
    if not ds_recovery:
        # Remove kernel source directory if it exists -> clean compilation
        try:
                os.system("rm -rf " + kern_dir + "/")
        except:
                print("The kernel is not yet extracted...Cant remove it")


def create_directories(kernel,resultdir,new_kern_dir,kern_dir,tar_dir,tarf,ds_recovery,s_config):

    # Result directory
    try:
         os.mkdir(resultdir)
    except:
         print("Directory {0} already exists".format(resultdir))
    
    if not ds_recovery and s_config == "yes":
        # Kernel directory inside result directory
        try:
             os.system("rm -rf " + new_kern_dir)
             os.mkdir(new_kern_dir)
        except:
             print("Directory {0} already exists".format(new_kern_dir))

    print (kernel)
    
    remove_kernel_dir(ds_recovery, kern_dir + kernel)
  #  else:
   #     clean_source(kernel,kern_dir)
    
 # Creating the module directory
    #try:
         #os.system("rm -rf " + module_dir)
         #os.mkdir(module_dir)
    #except:
         #print("Directory {0} already exists".format(module_dir))
    
    if not ds_recovery:

        # untar the kernel directory
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



def make_defconfig(cross,arch,image_dir,kernel,defconf,logfile,errfile):
    cwd = os.getcwd()
    os.chdir(image_dir)
    print ("Changed Directory to ",image_dir)
    print("Cross Compiler",cross, "Kernel",kernel)
    #os.system("cp /Kernels/compile_scripts/.config " + image_dir)
    
    try:
        subprocess.call('cp {0} {1}/.config'.format(defconf,image_dir),shell=True)
        cmd = 'yes "" | make ARCH={} CROSS_COMPILE={} oldconfig'.format(arch,cross)
    except:
        print("Could not copy the defconfig to dir",image_dir)
    #os.system("cp {0} {1}/.config".format(defconf,image_dir))
    #cflags = "CFLAGS='-mlong-calls'"
   # cmd = 'yes "" | make ARCH=mips {0} oldconfig'.format(cross)
    #cmd = 'make ARCH=mips {0} malta_defconfig'.format(cross)
    try:
        defconfig = subprocess.run(cmd,\
                shell=True,cwd=image_dir, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
        
        print ("Done with defconfig",defconf)
    
    except:
        print("There is an error with the defconfig of " + kernel)
    
    with open(logfile, "w") as f:
            
            try:
                f.write("Defconfig logs: \n")
                f.write(defconfig.stdout.decode("utf-8"))
                f.write("\n")
            
            except:
                print("Errors with defconfig logs")

    with open(errfile, "w") as f:
            try:

                f.write("Defconfig errors: \n")
                f.write(defconfig.stderr.decode("utf-8"))
                f.write("\n")
                
            except:
                print("Errors with error files")
    os.chdir(cwd)
    print ("Changed Directory back to ",cwd)

def do_compile(cross,arch,image_dir,extraversion,logfile,errfile,kernel,time,ds_recovery,single_module_dir, new_kern_dir):
    cwd = os.getcwd()
    os.chdir(image_dir)
    print ("Changed Directory to ",image_dir)
    
    vers = kernel.split(".")
    if len(vers) > 3:
        EXTRAVER = "EXTRAVERSION=." + vers[-1] + extraversion
    else:
        EXTRAVER = "EXTRAVERSION=" + extraversion
    print("Extraversion is",EXTRAVER)
    
    ### Normal Compilation
    if not ds_recovery:
        try:
            comp = subprocess.run(['make','ARCH={}'.format(arch), "CROSS_COMPILE={}".format(cross),EXTRAVER, '-j8'], cwd=image_dir, stderr=subprocess.PIPE,stdout=subprocess.PIPE)
            print ("Done with the kernel compilation")
        except Exception as e:
            print("There is an error with the compilation of {0}".format(kernel))
            print (e)
        
        # if arch == "mips":
        #     try:
        #         subprocess.check_output('make ARCH={} CROSS_COMPILE={} {} prepare'.format(arch,cross,EXTRAVER),shell=True)
        #     except:
        #         print("Make prepare failed in",image_dir)
        # else:
        #     try:
        #         subprocess.check_output('make ARCH={} CROSS_COMPILE={} {} prepare scripts'.format(arch,cross,EXTRAVER),shell=True)
        #     except:
        #         print("Make prepare failed in",image_dir)
        
        if kernel < "linux-2.6.23":
            try:
                subprocess.check_output('make ARCH={} CROSS_COMPILE={} {} scripts'.format(arch,cross,EXTRAVER),shell=True)
            except:
                print("Make prepare failed in",image_dir)
        else:
            try:
                subprocess.check_output('make ARCH={} CROSS_COMPILE={} {} prepare scripts'.format(arch,cross,EXTRAVER),shell=True)
            except:
                print("Make prepare failed in",image_dir)

        try:
            if kernel < "linux-3.0.0":
                subprocess.check_output('make ARCH={} CROSS_COMPILE={} {} SUBDIRS=scripts/mod'.format(arch,cross,EXTRAVER),shell=True)
            else:
                subprocess.check_output('make ARCH={} CROSS_COMPILE={} {} M=scripts/mod'.format(arch,cross,EXTRAVER),shell=True)
        except:
            print("Make scripts/mod failed in",image_dir)
        
        mod_install = "INSTALL_MOD_PATH=" + new_kern_dir

        try:
            modz = subprocess.run(['make','ARCH={}'.format(arch), "CROSS_COMPILE={}".format(cross),EXTRAVER,mod_install,'modules_install', '-j8'], cwd=image_dir, stderr=subprocess.PIPE,stdout=subprocess.PIPE)
            print ("Done with module install".format(time))
        except Exception as e:
            print("There is an error with the {0}st compilation of {1}".format(time,kernel))
            print (e)
        
        with open(logfile, "a") as f:
                try:
                    
                    f.write("Compilation{0} logs: \n".format(time))
                    f.write(comp.stdout.decode("utf-8"))
                    f.write("\n")
                    
                    f.write("Compilation{0} module install logs: \n".format(time))
                    f.write(modz.stdout.decode("utf-8"))
                    f.write("\n")
                    
                except:
                    print("Errors with compilation logs")

        with open(errfile, "a") as f:
                try:
                    
                    f.write("Compilation{0} errors: \n".format(time))
                    f.write(comp.stderr.decode("utf-8"))
                    f.write("\n")
                    
                    f.write("Compilation{0} module install errors: \n".format(time))
                    f.write(modz.stderr.decode("utf-8"))
                    f.write("\n")
                except:
                    print("Errors with compilaton error files")
    ### Ds recovery single module Compilation
    else:
        print("In DS recovery mode...Building directory",single_module_dir)
        cmd = 'yes "" | make ARCH={} CROSS_COMPILE={} oldconfig'.format(arch,cross)
        try:
            out = subprocess.check_output(cmd,shell=True).decode("utf-8")
            print(out)
        except:
            print("Make oldconfig failed in",image_dir)
        
        if kernel < "linux-2.6.23":
            try:
                subprocess.check_output('make ARCH={} CROSS_COMPILE={} {} scripts'.format(arch,cross,EXTRAVER),shell=True)
            except:
                print("Make prepare failed in",image_dir)
        else:
            try:
                subprocess.check_output('make ARCH={} CROSS_COMPILE={} {} prepare scripts'.format(arch,cross,EXTRAVER),shell=True)
            except:
                print("Make prepare failed in",image_dir)

        try:
            if kernel < "linux-3.0.0":
                subprocess.check_output('make ARCH={} CROSS_COMPILE={} {} SUBDIRS=scripts/mod'.format(arch,cross,EXTRAVER),shell=True)
            else:
                subprocess.check_output('make ARCH={} CROSS_COMPILE={} {} M=scripts/mod'.format(arch,cross,EXTRAVER),shell=True)
        except:
            print("Make scripts/mod failed in",image_dir)
        
        start_time = tm.time()
        try:
            if kernel < "linux-3.0.0":
                subprocess.check_output('make ARCH={} CROSS_COMPILE={} {} -C {} SUBDIRS={} modules'.format(arch,cross,EXTRAVER,image_dir,single_module_dir), shell=True)
            else:
                subprocess.check_output('make ARCH={} CROSS_COMPILE={} {} -C {} M={} modules'.format(arch,cross,EXTRAVER,image_dir,single_module_dir), shell=True)

        except:
            print("Make for the target module failed in",image_dir)
        end_time = tm.time()

        print("Python time for compilation of one module",(end_time-start_time))
 #       try:
  #          subprocess.call('make ARCH={} CROSS_COMPILE={} {} SUBDIRS={} {} modules_install'.format(arch,cross,EXTRAVER,single_module_dir,mod_install),shell=True)
   #     except:
    #        print("Make modules_install failed in",image_dir)


    os.chdir(cwd)
    print ("Changed Directory back to ",cwd)


def find_and_cscope(image_dir,arch):

    # Find the files for cscope 
    #find_cmd = "find . -path \"./arch/*\" ! -path \"./arch/mips*\" -prune -o -path \"./Documentation*\" -prune -o -name \"*.[chxsS]\" -print >./cscope.files"
    find_cmd = "find . -path \"./arch/*\" ! -path \"./arch/{}*\" -prune -o -path \"./Documentation*\" -prune -o -name \"Makefile\" -print >./cscope.files".format(arch)
    
    os.chdir(image_dir)
    os.system(find_cmd)
    os.system("rm ./Kconfig")
    os.system("cp arch/{}/Kconfig .".format(arch))
    os.chdir("../../..")

    try:
        cscope = subprocess.run(['cscope','-b','-q'], cwd=image_dir)
    except:
        print("Cscope failed")


def copy_files(image_dir,new_kern_dir, s_config):
    print("Copy files from directory {0} to directory {1}".format(image_dir,new_kern_dir))
    os.system("cp " + image_dir + "vmlinux " + new_kern_dir )
    if s_config == "yes":
        os.system("cp " + image_dir + ".config " + new_kern_dir)
        os.system("cp " + image_dir + "Module.symvers " + new_kern_dir)
        os.system("cp " + image_dir + "System.map " + new_kern_dir)
        os.system("cp " + image_dir + "cscope.files " + new_kern_dir)
    #os.system("cp " + image_dir + "modules.builtin " + new_kern_dir)
    os.system("cp " + image_dir + "arch/arm/boot/zImage " + new_kern_dir)

def save_sym_data(image,image_dir,outfile,symbolz,time,kernel,kern_dir,new_kern_dir,ds_recovery):

    unknown = []
    try:
         if time == "2":
            symvers, sysmap = exported_syms(image_dir)

         for sym in symbolz:
            if time == "2":
                if (sym not in symvers) and (sym not in sysmap):
                     unknown.append(sym)
            else:
                unknown.append(sym)
         
         if time == "1":
             mode = "w"
             line = " Undefined Symbols: \n"
         else:
             mode = "a"
             line = " Final Undefined Symbols: \n"
         
         if not ds_recovery:
             with open(outfile, mode) as f:
                     f.write(str(len(unknown)) + line)
                     for ln in unknown:
                             f.write(ln)
                             f.write("\n")
                     f.write("\n")
    except:
         print("The kernel did not compile and symvers is not there")
         sys.exit(1)
    
    ################ Cleanup after the first time ###############
    #if time == "1":
        #os.system("cp " + image_dir + ".config " + new_kern_dir)
        #clean_source(kernel,kern_dir)
        #os.system("cp " + new_kern_dir + ".config " + image_dir)
    #############################################################
    
    return unknown

def apply_patch(image_dir, patch):
    print("Applying patch", patch, "to kernel", image_dir)
    cwd = os.getcwd()
    os.chdir(image_dir)
    cmd = "cat {} | patch -p1 -E -d .".format(patch)
    try:
        subprocess.run(cmd, shell = True, stderr=subprocess.PIPE,stdout=subprocess.PIPE)
    except:
        print(traceback.format_exc())
    os.chdir(cwd)

def patch_kernel(image_dir, kernel):
    if kernel < "linux-2.6.31":
        return
    patches = os.listdir(cu.openwrt_patch_dir)
    kern_tokens = kernel.split('.')
    kern = ".".join(kern_tokens[:2])
    kern_plus = ".".join(kern_tokens[:3])
    which_patch = None
    for patch in sorted(patches):
        if kernel in patch:
            which_patch = cu.openwrt_patch_dir + patch
            break
    if not which_patch:
        for patch in sorted(patches):
            if kern_plus in patch:
                which_patch = cu.openwrt_patch_dir + patch
                break
        if not which_patch:
            for patch in sorted(patches):
                if kern in patch:
                    which_patch = cu.openwrt_patch_dir + patch
                    break
    if which_patch:
        apply_patch(image_dir, which_patch)

def compile_kernel(image, ds_options, ds_recovery,single_module_dir,s_config, openwrt, kernel, extraversion,modulez,ver_magicz,symbolz,arch,endianess, cross, conf_opts, guard_expr, module_options):
    
    kernel = cu.kernel_prefix + kernel 
    resultdir = cu.result_dir_path + image + "/"
    new_kern_dir = resultdir + kernel + "/"
    tarf = cu.tar_dir + kernel + ".tar.gz"
    image_dir = cu.kern_dir + kernel + "/"
    ### Get the correct toolchain
    cross = cu.get_toolchain(kernel, arch, endianess)
    
    create_directories(kernel,resultdir,new_kern_dir,cu.kern_dir,cu.tar_dir,tarf,ds_recovery,s_config)
    if openwrt:
        patch_kernel(image_dir, kernel)

    print  ("Image_dir = " + image_dir)
    
    outfile = resultdir + "results.out"
    print (outfile)
    
    logfile = resultdir + "logs.out"
    print (logfile)

    errfile = resultdir + "errors.out"
    print (errfile)
    #if arch == "arm":
        #cross = "arm-unknown-linux-uclibcgnueabi-"

    if not ds_recovery:
        print("Running Firmsolo in normal mode")
        ################## Firmadyne Patches #################
        apply_fdyne_hooks(image_dir,kernel)

        ########### Some Hot Fixes ############################
        hot_fixes(image_dir,kernel)
        
        ######### Patch Configuration files #########
        #print ("Fixing Kconfig files for kernel", image_dir)
        fix_configs(image_dir,kernel)
    
    #print_ioctls(image_dir)
    ####### Create the default cofing file #################
        if arch == "mips":
            defconfig = cu.get_vendor(image,arch,ds_recovery,new_kern_dir)
        else:
            if "ARMv6" in ver_magicz:
                defconfig = cu.get_vendor(image,arch,ds_recovery,new_kern_dir,"armv6")
            elif "ARMv7" in ver_magicz:
                defconfig = cu.get_vendor(image,arch,ds_recovery,new_kern_dir,"armv7")
            else:
                defconfig = cu.get_vendor(image,arch,ds_recovery,new_kern_dir,"armv5")

        #defconfig = cu.get_vendor(image)
        make_defconfig(cross,arch,image_dir,kernel,defconfig,logfile,errfile)
        
        ################### Compile once ###########################
        #do_compile(cross,image_dir,extraversion,logfile,errfile,kernel,module_dir,"1")
        
        
        ################## Save Undefned Symbol Data ##############
        unknown = save_sym_data(image,image_dir,outfile,symbolz,"1",kernel,cu.kern_dir,new_kern_dir,ds_recovery)

        ################## Find cmd & Cscope ######################
        find_and_cscope(image_dir,arch)

        ########## Update Configuration file with the new options ########
        #config_file = None
        try:
           update_config(image,kernel,image_dir,resultdir,unknown,ver_magicz,endianess,arch,modulez,conf_opts,guard_expr,module_options,ds_options)
           #encoded = jsonpickle.encode(config_file)      
           #cu.write_pickle(new_kern_dir + "config.pkl",encoded)

        except:
            print(traceback.format_exc())

    ######## Compile twice to include the new modules #########
    print("Compiling kernel for image", image)
    do_compile(cross,arch,image_dir,extraversion,logfile,errfile,kernel,"2",ds_recovery,single_module_dir, new_kern_dir)
    
    if not ds_recovery:
        copy_files(image_dir,new_kern_dir, s_config)
        ################# Save Undefned Symbol Data ##############
        unknown = save_sym_data(image,image_dir,outfile,symbolz,"2",kernel,cu.kern_dir,new_kern_dir,ds_recovery)
    
    #remove_kernel_dir(ds_recovery, image_dir)
    return 0       

### This is mostly for the DSLC step 1 where it fixes
### the struct module
def modify_the_vermagic(vermagic, ds_options):
    for option in ds_options:
        if option == "CONFIG_SMP":
            if "SMP" not in vermagic:
                vermagic.append("SMP")
            ds_options.remove(option)
        if option == "CONFIG_MODULE_UNLOAD":
            if "mod_unload" not in vermagic:
                vermagic.append("mod_unload")
            ds_options.remove(option)
        if option == "!CONFIG_SMP":
            if "SMP" in vermagic:
                vermagic.remove("SMP")
            ds_options.remove(option)
        if option == "!CONFIG_MODULE_UNLOAD":
            if "mod_unload" in vermagic:
                vermagic.remove("mod_unload")
            ds_options.remove(option)
    return vermagic, ds_options


def run_the_compilation(image, ds_opt_fl, ds_opt_list, ds_recovery, s_mod_dir, s_config, override_vermagic, openwrt, firmadyne):

    ### This for DSLC... Are we in DSLC mode or running 
    if ds_recovery < 0:
        ds_recovery = 0
    if ds_recovery > 1:
        ds_recovery =1

    # Data Structure alignment options
    ds_options = []
    if ds_opt_fl != None:
        ds_options = cu.read_file(ds_opt_fl)
    else:
        if ds_opt_list != []:
            ds_options = ds_opt_list

    which_info = ["kernel","extraversion","modules","vermagic","symbols","arch","endian","cross","options","guards", "module_options"]
    info = cu.get_image_info(image,which_info)
    
    dslc = []
    try:
        which_info = ["dslc"]
        temp = cu.get_image_info(image, which_info)
        dslc = temp[0]
    except:
        ### The image does not have any extra options from dslc
        pass
    
    if dslc != None:
       ds_options += dslc

    if firmadyne:
        firma_dslc = []
        try:
            which_info = ["fdyne_dslc"]
            temp = cu.get_image_info(image, which_info)
            fdyne_dslc = temp[0]
        except:
            print("The image does not have any DSLC solutions for Firmadyne experiments")
            ### The image does not have any extra options from dslc
            pass
        ds_options += fdyne_dslc

    # Kernel, Extraversion, Version Magic
    print("Vermagic", info[3])
    if override_vermagic:
        info[3], ds_options = modify_the_vermagic(info[3], ds_options)

    print(info[0],info[1],info[5],info[3],info[7])
    compile_kernel(image,ds_options,ds_recovery,s_mod_dir,s_config, openwrt,*info)

if __name__ == "__main__":
    parser = argp.ArgumentParser(description='Compile the FS kernel for an image')
    parser.add_argument('image',help='The firmware image to compile the FS kernel for')
    parser.add_argument('-f','--ds_opt_fl',help='Options for fixing DS alignment', default=None)
    parser.add_argument('-l','--ds_opt_list',nargs='*',help='Option list for fixing DS alignment. Precedence is given to option --ds_opt_fl', default=[])
    parser.add_argument('-d','--ds_recovery',type=int,help='This is used for DS recovery...The FS kernel must be compiled previously (Should have values 0/1)', default=0)
    parser.add_argument('-m','--s_mod_dir',help='The kernel directory containing the Makefile for the target module...It must be used with ds_recovery', default="")
    parser.add_argument('-s','--s_config',help='Save the .config file...Used mostly in DS recovery', default="yes")
    parser.add_argument('-o','--override_vermagic',help='Specify this option to modify the vermagic during KCRE. Used by DSLC', action = 'store_true')
    parser.add_argument('-w','--openwrt',help='Specify this option to enable the MIPS OpenWRT patch', action = 'store_true')
    parser.add_argument('-e','--firmadyne',help='Include the DSLC fixes for the Firmadyne experiments', action = 'store_true')
    
    res = parser.parse_args()
    image = res.image
    ds_opt_fl = res.ds_opt_fl
    ds_opt_list = res.ds_opt_list
    ds_recovery = res.ds_recovery
    s_mod_dir = res.s_mod_dir
    s_config = res.s_config
    override_vermagic = res.override_vermagic
    openwrt = res.openwrt
    firmadyne = res.firmadyne
    
    run_the_compilation(image, ds_opt_fl, ds_opt_list, ds_recovery, s_mod_dir, s_config, override_vermagic, openwrt, firmadyne)
