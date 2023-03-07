#!/usr/bin/env python3

import os
import custom_utils as cu
import argparse
from stage1.get_image_info import get_image_info
from stage2a import firm_kern_comp
from stage2b import load_mods
from stage2c import dslc
from gather_data_scripts.get_mods_info import get_image_data
import subprocess as sb
import tarfile

subdirs = ["results", "Loaded_Modules", "Filesystems", "Data", "Image_Info", "kernel_ksyms_confs", "kernel_sources", "kernel_tars", "logs", "kernel_dirs","Fuzz_Results_Cur", "kernel_dicts", "firmadyne_results"]

class FirmSolo():
    def __init__(self, image):
        self.image = image
        self.extracted_fs_dir = f"{cu.result_dir_path}/{self.image}/extracted_fs/"
        self.image_tar = f"{cu.abs_path}/images/{self.image}.tar.gz" 
        
        ### Create the result directories
        self._create_result_dirs()

        self._check_if_extracted()
        ### Create the results directory
        if not self.fs_extracted:
            self._create_result_dir()

            ### Untar the filesystem for image in the results directory
            self._extract_filesystem()
    
    def _create_result_dirs(self):
        for subdir in subdirs:
            cmd = f"mkdir -p {cu.abs_path}{subdir}"
            try:
                sb.run(cmd, shell = True)
            except:
                pass   
        
        cmd = f"mkdir -p {cu.abs_path}/Data/" + "fuzzer_data"
        try:
            sb.run(cmd, shell = True)
        except:
            pass
        
        cmd = f"mkdir -p {cu.abs_path}/Data/" + "struct_info"
        try:
            sb.run(cmd, shell = True)
        except:
            pass

    def _check_if_extracted(self):
        try:
            files = os.listdir(self.extracted_fs_dir)
        except:
            self.fs_extracted = False
            return

        if len(files) == 0:
            self.fs_extracted = False
        else:
            self.fs_extracted = True

    def _create_result_dir(self):
        cmd = ["mkdir", "-p", self.extracted_fs_dir]
        try:
            sb.run(cmd)
        except:
            print(f"Print could not create output directory for image {self.image}")
            raise

    def _extract_filesystem(self):
        print(f"Untaring the filesystem for iamge {self.image}")
        try:
            untar = tarfile.open(self.image_tar)
        except:
            print("Could not open the filesystem tar for image {self.image}")
            raise

        try:
            untar.extractall(self.extracted_fs_dir)
            untar.close()
        except:
            print("Could not untar the filesystem for image {self.image}")
            raise

    def get_image_data(self):
        get_image_data(self.image)

    def run_stage1(self):
        success = get_image_info(self.image)
    
    def run_stage2a(self, ds_opt_fl, ds_opt_list, openwrt, firmadyne):
        ### These are for DSLC
        ds_recovery = 0
        single_module_dir = ""
        save_config = "yes"
        override_vermagic = False

        ### Actually compile the kernel
        firm_kern_comp.run_the_compilation(self.image, ds_opt_fl, ds_opt_list, ds_recovery, \
                single_module_dir, save_config, override_vermagic, openwrt, firmadyne)

    
    def run_stage2b(self):
        infile = ""
        outfile = ""
        workdir = "./"
        mode = "ups_subs"
        cnt = 1
        
        ### Run the emulation
        load_mods.load_mods(infile, outfile, 1, self.image, workdir, mode)

    def run_stage2c(self, serial_out, firmadyne):
        infile = ""
        if firmadyne:
            fi_opt = "-e"
        else:
            fi_opt = ""
        dslc.layout_correct(self.image, infile, serial_out, fi_opt)
    
    def save_firmadyne_dslc(self, opts):
        try:
            info = cu.get_image_info(self.image, "all")
        except:
            print("This image has not been analyzed yet. Run stage 1 first")
        
        if 'fdyne_dslc' in info.keys():
            info['fdyne_dslc'] = list(set(info['fdyne_dslc'] + opts))
        else:
            info['fdyne_dslc'] = opts

def main():
    parser = argparse.ArgumentParser(description='Extract metadata information from firmware images')
    parser.add_argument('-i','--image',help ='A single image to get the information from',default = None)
    parser.add_argument('-a', '--all', help = 'Select to run all stages of FS', action = 'store_true')
    parser.add_argument('-s', '--stage', type = str, help ='Select a specific stage of FS to run [1, 2a, 2b, 2c]', default = "1")
    parser.add_argument('-f','--ds_opt_fl',help='Options for fixing DS alignment', default=None)
    parser.add_argument('-l','--ds_opt_list',nargs='*',help='Option list for fixing DS alignment. Precedence is given to option --ds_opt_fl', default=[])
    parser.add_argument('-m','--s_mod_dir',help='The kernel directory containing the Makefile for the target module...It must be used with ds_recovery', default="")
    parser.add_argument('-w','--openwrt',help='Specify this option to enable the MIPS OpenWRT patch', action = 'store_true')
    parser.add_argument('-e','--firmadyne',help='Include the DSLC fixes for the Firmadyne experiments', action = 'store_true')
    parser.add_argument( '--serial_out', type = str, help ='Serial output of an emulation run that contains the Call TRace for a crashing module. Used by DSLC for crashes within firmadyne', default = '')
    parser.add_argument('-d', '--image_data', help ='Get data about the image (e.g., kernel modules, loaded modules, module substitutions, etc)', action = 'store_true')
    parser.add_argument('-c', '--firmadyne_dslc', help ='Save the configuration options found by running DSLC for firmadyne. It should be used with -l or -f', action = 'store_true')


    args = parser.parse_args()
    image = args.image
    all_stages = args.all
    stage = args.stage
    ds_opt_fl = args.ds_opt_fl
    ds_opt_list = args.ds_opt_list
    openwrt = args.openwrt
    firmadyne = args.firmadyne
    serial_out = args.serial_out
    image_data = args.image_data
    firmadyne_dslc = args.firmadyne_dslc

    if not image:
        print("You must provide an image ID")
        return

    firmsolo = FirmSolo(image)

    if image_data:
        firmsolo.get_image_data()
        return

    if firmadyne_dslc and (ds_opt_list or ds_opt_fl):
        if ds_opt_fl:
            opts = cu.read_file(ds_opt_fl)
        else:
            opts = ds_opt_list
        firmsolo.save_firmadyne_dslc(opts)

    if all_stages:
        firmsolo.run_stage1()
        firmsolo.run_stage2a(ds_opt_fl, ds_opt_list, openwrt, firmadyne)
        firmsolo.run_stage2b()
        firmsolo.run_stage2c(serial_out, firmadyne)

    else:
        if stage == '1':
            firmsolo.run_stage1()
        elif stage == '2a':
            firmsolo.run_stage2a(ds_opt_fl, ds_opt_list, openwrt, firmadyne)
        elif stage == '2b':
            firmsolo.run_stage2b()
        elif stage == '2c':
            firmsolo.run_stage2c(serial_out, firmadyne)
        else:
            print("Please provide a correct stage to run [1, 2a, 2b, 2c]")

if __name__ == "__main__":
    main()
