# FirmSolo

FirmSolo is a framework that exposes Linux-based IoT kernel modules to downstream analysis (e.g., TriforceAFL, Firmadyne).
FirmSolo provides two stages: 1) In the first stage FirmSolo extracts metadata information from the kernel modules within a firmware image (e.g., kernel symbols, arch, endianness). 2) In the second stage FirmSolo uses the extracted metadata information to build a Linux kernel (supported by QEMU) that can load the firmware binary kernel modules and expose them to dynamic analysis systems, such as TriforceAFL and/or Firmadyne. 
Currently FirmSolo only supports only MIPS and ARM 32bit Linux-based firmware images.

This repository contains the prototype implementation of FirmSolo based on the Usenix 2023 [paper](https://www.usenix.org/conference/usenixsecurity23/presentation/angelakopoulos).

# Docker
Below there is a link to a docker image that contains FirmSolo, Firmadyne, and TriforceAFL. We highly recommend you use that since all the artifacts are already setup within the docker image.

https://drive.google.com/file/d/1ZjOBpLKOffz4PigNH1xkZsy3zvhGMt7p/view?usp=share_link

You can also find the docker image here:
https://doi.org/10.5281/zenodo.7789886

Execute:

```
docker load < firmsolo.tar.gz
```

**Running the docker**

```
docker run -v $(pwd):/output --rm -it --privileged firmsolo /bin/bash
```

It is assumed that your work directory (`<work_dir>`) is the current directory (`$(pwd)`)

Inside the docker run:
```
mkdir -p /output/images/
echo core >/proc/sys/kernel/core_pattern
cd /sys/devices/system/cpu
echo performance | tee cpu*/cpufreq/scaling_governor
```


**Note:** The container needs to be privileged since some operations require root permissions, such as creating/mounting file-systems.

Since all the FirmSolo artifacts are installed in the docker, you can skip to the Examples sections.

# Manual Installation
If you want to install FirmSolo manually you first need to install some dependencies:

```
sudo apt-get install build-essential zlib1g-dev pkg-config libglib2.0-dev binutils-dev libboost-all-dev autoconf libtool libssl-dev libpixman-1-dev libpython3-dev python3-pip python3-capstone virtualenv gcc make g++ python3 python2 flex bison dwarves kmod universal-ctags kpartx fdisk fakeroot git dmsetup kpartx netcat-openbsd nmap python3-psycopg2 snmp uml-utilities util-linux vlan busybox-static wget cscope qemu qemu-system-arm qemu-system-mips qemu-system-mipsel qemu-utils

pip3 install ply anytree sympy requests pexpect scipy
```

**Note:** We are using qemu-2.12 since it is compatible with Firmadyne. If you want to use this version of QEMU then you need to install it manually. Follow the instructions here: https://www.qemu.org/download/

Install the git submodules (after cloning and going into the FirmSolo directory):
```
git submodule init

git submodule update
```

**Install Ghidra:**

Follow instuctions in https://ghidra-sre.org/InstallationGuide.html

**Install our custom implementation for TriforceAFL/TriforceLinuxSyscallFuzzer:**

Download TriforceAFL from:

https://drive.google.com/file/d/1qMwsVd0kQWg-WH3VmvKkOcyOqsSfClsl/view?usp=share_link

Download TriforceLinuxSyscallFuzzer from:

https://drive.google.com/file/d/1ogwxAU3ikHJin3L-DuVORVx6efHiCRag/view?usp=share_link

Execute:
```
tar xvf triforceafl.tar.gz

tar xvf triforcelsf.tar.gz

cd TriforceAFL && make
```

**Install our custom implementation for Firmadyne:**

Download Firmadyne from:

https://drive.google.com/file/d/1hkLdjLv9aLrtIebYm39etTS1NlQaRxZy/view?usp=share_link

Execute:

```
tar xvf firmadyne.tar.gz
```

**Download the buildroot filesystems**

Use this link:
https://drive.google.com/file/d/11GiU8N1U4Nkhv-kurkoGgwmp38CM_Umg/view?usp=share_link

and download the buildroot_fs.tar.gz file within FirmSolo's installation directory

Then execute:
```
tar xvf buildroot_fs.tar.gz
```

**Toolchain**

Finally specify the toolchain(s) to be used by FirmSolo. Go into the installation directory of FirmSolo
and edit the `custom_utils.py` script. Within the `get_toolchain` function edit
the `cross` variable with the path(s) to your toolchain(s).

# Instructions
The main interface to FirmSolo is the `firmsolo.py` script in the root directory:

```
usage: firmsolo.py [-h] [-i IMAGE] [-a] [-s STAGE] [-f DS_OPT_FL] [-l [DS_OPT_LIST ...]] [-m S_MOD_DIR] [-w] [-e] [--serial_out SERIAL_OUT] [-d] [-c]

Extract metadata information from firmware images

options:
  -h, --help            show this help message and exit
  -i IMAGE, --image IMAGE
                        A single image to get the information from
  -a, --all             Select to run all stages of FS
  -s STAGE, --stage STAGE
                        Select a specific stage of FS to run [1, 2a, 2b, 2c]
  -f DS_OPT_FL, --ds_opt_fl DS_OPT_FL
                        Options for fixing DS alignment
  -l [DS_OPT_LIST ...], --ds_opt_list [DS_OPT_LIST ...]
                        Option list for fixing DS alignment. Precedence is given to option --ds_opt_fl
  -m S_MOD_DIR, --s_mod_dir S_MOD_DIR
                        The kernel directory containing the Makefile for the target module...It must be used with ds_recovery
  -w, --openwrt         Specify this option to enable the MIPS OpenWRT patch
  -e, --firmadyne       Include the DSLC fixes for the Firmadyne experiments
  --serial_out SERIAL_OUT
                        Serial output of an emulation run that contains the Call Trace for a crashing module. Used by DSLC for crashes within firmadyne
  -d, --image_data      Get data about the image (e.g., kernel modules, loaded modules, module substitutions, etc)
  -c, --firmadyne_dslc  Save the configuration options found by running DSLC for firmadyne. It should be used with -l or -f
```
**Note:** FirmSolo takes as input the extracted file-system of a firmware image. To extract the filesystem of a firmware image use the `extractor.py` script of Firmadyne and then store the file-system and the orginal kernel (if extracted) under the _images_ directory in your workdir. For more instructions refer to https://github.com/firmadyne/firmadyne

**Configuration (No need to run if the docker is used)**

First edit the `custom_utils.py` script and specify these paths:
```
abs_path
script_dir
ghidra_dir
tafl_lsf_dir
tafl_dir
```
There is a description for each of these paths in the script.
Importantly, the `abs_path` is the absolute path to your work directory (`<work_dir>`) and `script_dir` is the absolute path to where FirmSolo is installed. 

Run:
```
mkdir -p <abs_path>/images/
```

The `images` directory stores the extracted file-systems and kernels of the target firmware images.

**All stages**

To run all the stages of FirmSolo execute:

```
python3 firmsolo.py -i <image_id> -a
```

**Run stages individually**

To run a stage individually execute:

```
python3 firmsolo.py -i <image_id> -s <1, 2a, 2b, 2c>
```

**Get data about a firmware image**

To get data about a firmware image (e.g., total kernel modules, loaded kernel modules, etc) execute:

```
python3 firmsolo.py -i <image_id> -d
```

# TriforceAFL

Setup TriforceAFL:
```
echo core >/proc/sys/kernel/core_pattern
cd /sys/devices/system/cpu
echo performance | tee cpu*/cpufreq/scaling_governor
```

To fuzz the kernel modules of a firmware image execute:

```
python3 ./triforceafl/triforce_run.py -i <image_id> -t <time>[s,m,h]
```

This script will search for kernel modules that expose an IOCTL interface and will start fuzzing them for the time specified.
The results will be saved in `<work_dir>/Fuzz_Results_Cur/`

To easily test the crash inputs found by TriforceAFL execute:

```
python3 ./triforceafl/get_fuzzing_cmd.py <image_id>
```

This will provide you with a bug testing command for each crash found by TriforceAFL. Copy and run any of these commands to test for a bug.

# Firmadyne
To re-host and analyze a firmware image with Firmadyne execute:

```
cd /firmadyne
```

Change the above to wherever you installed firmadyne

Edit the `firmadyne.config` file and change the `FS_OUT_DIR` and `FS_SCRIPT_DIR` to your work_dir and FirmSolo installation directories respectively (within the docker it should be already set to `/output/` and `/FirmSolo/` respectively).

Run a full analysis by executing:

```
./experiment.sh <image_id>
```

The firmadyne results will be saved under the `<work_dir>/firmadyne_results/<image_id>.`

To check if a bug was successfull you need to manually check the serial logs for a crash. The serial logs for the ExploitDB `remote` and `local` exploits are under `<working_dir>/firmadyne_results/<image_id>/[remote,local]` directories. The serial logs for the TriforceAFL bugs are under the `<working_dir>/firmadyne_results/<image_id>/afl` directory

**Note:** The kernel module bug analysis with firmadyne is generally shaky. You may need to re-run the analysis.

# Examples
Download the two example images from this link:

https://drive.google.com/file/d/1xzdTAz3PexQD8YWWAg7KYyQ8dQiVTGiR/view?usp=share_link

Execute:

```
tar xvf examples.tar.gz
cp -r ./examples/* <work_dir>/images/
```
You should run the above outside the docker container, if you are using it.
You should change the `<work_dir>` to your work directory on the host machine.

**To analyze example 1 execute:**
```
cd <fs_install_dir>/

python3 firmsolo.py -i 1 -a

python3 firmsolo.py -i 1 -d
```

Change `<fs_install_dir>` to the installation directory of FirmSolo (`/FirmSolo` if you are working within the docker).

Please excuse the ugly prints during the analysis. If everything worked correctly you should be getting:

```
Image: 1 Total Modules: 16 Loaded Modules: 5 Crashing Modules: 0 Substitutions: 0 

All Modules:
 ['emf', 'ctf', 'igs', 'wl', 'et', 'sierra_net', 'GobiNet', 'cdc_ncm', 'GobiSerial', 'acos_nat', 'opendns', 'ipv6_spi', 'libcrc32c', 'AccessCntl', 'ubd', 'l7_filter'] 

Loaded Modules:
 ['sierra_net', 'GobiNet', 'acos_nat', 'ipv6_spi', 'libcrc32c'] 

Crashing Modules:
 [] 

Substitutions:
 [] 
```

**To run TriforceAFL for 30 minutes:**

```
python3 ./triforceafl/triforce_run.py -i 1 -t 30m
```

This will fuzz any kernel module that exposes an IOCTL interface for 30 minutes.
After fuzzing is done, you can get/test any crashes with this command:

```
python3 ./triforceafl/get_fuzzing_cmd.py 1
```

Copy/paste and run any commands printed out under the `CRASHES:` section corresponding to each IOCTL interface fuzzed,
to quickly test the crashes found by TriforceAFL.

**To run Firmadyne:**

```
cd <firmadyne_workdir>
./experiment.sh 1
```

You should change `<firmadyne_workdir>` to where firmadyne is installed (`/firmadyne/` within the docker)

It might be the case, while running the exploits from ExploitDB and the bugs found by TriforceAFL that the
kernel just hangs instead of printing an `Oops` message in the serial logs. You may need to rerun the analysis in this case.

**Note:** To run example 2 just replace the image id in the above commands with 2.

# Bibtex citation

```
@inproceedings {firmsolo,
author = {Ioannis Angelakopoulos, Gianluca Stringhini and Manuel Egele},
title = {FirmSolo: Enabling dynamic analysis of binary Linux-based IoT kernel modules},
booktitle = {{USENIX} Security Symposium},
year = {2023},
publisher = {{USENIX} Association},
month = aug,
}
```
# Contact us
For any further information contact `jaggel@bu.edu`.
