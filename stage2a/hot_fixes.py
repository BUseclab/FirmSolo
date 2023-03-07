#!/usr/bin/env python

import os
import sys
currentdir = os.path.dirname(os.path.realpath(__file__))
parentdir = os.path.dirname(currentdir)
sys.path.append(parentdir)
import custom_utils as cu
import traceback as tb

def hot_fixes(image_dir,kernel):

  
    # PATH_MAX FIX
    try:
        localfix = image_dir + "scripts/mod/sumversion.c"
        with open(localfix,"r") as f:
            data = f.readlines()
        
        data.insert(8, "#include <linux/limits.h>\n")

        with open(localfix,"w") as f:
            f.writelines(data)

    except:
        print("Error with fixing {0}".format(localfix))
    
    # LAYOUT_AND_ALOCATE HOOK (special hook for finding the address of a module before its loaded)
    try:
        localfix = image_dir + "kernel/module.c"
        with open(localfix,"r") as f:
            data = f.readlines()
        where_to_add = 0
        flag = False
        cnt = 0
        for indx,line in enumerate(data):
            if "mod->module_core = ptr;" in line:
                 where_to_add = indx + 1
                 flag = True
            ### This is for changing only the next to DEBUGP macros to  printk
            ### to get information about the module addresses
            if ("DEBUGP" in line or "pr_debug" in line) and flag ==True:
                if "DEBUGP" in line:
                    data[indx] = data[indx].replace("DEBUGP","printk")
                elif "pr_debug" in line:
                    data[indx] = data[indx].replace("pr_debug","printk")
                cnt+=1
                if cnt == 2:
                    break

        if where_to_add != 0:
            data.insert(where_to_add, "\tprintk(KERN_INFO \"Module_name: %s Module_address: 0x%x Module_size: %lu\\n\",mod->name,mod->module_core,mod->core_size);\n")

        with open(localfix,"w") as f:
            f.writelines(data)

    except:
        print("Error with fixing {0}".format(localfix))
    
    # DELAY FIX
    if kernel < "linux-2.6.31":
        try:
            localfix = image_dir + "arch/mips/lib/delay.c"
            with open(localfix,"r") as f:
                data = f.readlines()

            data[45] = "        __delay((us * 0x000010c7ull * HZ * lpj) >> 32);\n"
            data[53] = "        __delay((ns * 0x00000005ull * HZ * lpj) >> 32);\n"

            with open(localfix,"w") as f:
                f.writelines(data)

        except:
            print("Error with fixing {0}".format(localfix))

    #FIRMADYNE FIX
    #Copy the firmadyne kernel module before compiling
    
    Firmadyne_header = image_dir + "include/linux/"
    print("Firmadyne header dir",Firmadyne_header)
    
    try:
        os.system("cp {}/fdyne.h {}".format(cu.fdyne_data,Firmadyne_header))
    except:
        print("Copying Firmadyne header to the kernel sources failed")

    Firmadyne = image_dir + "drivers/"
    print("Firmadyne dir ",Firmadyne)
    
    if kernel < "linux-2.6.24":
        firmadyne_dir = "firmadyne_old_kerns/"
    else:
        firmadyne_dir = "firmadyne"

    try:
        os.system("cp -r {}{} {}/firmadyne/".format(cu.fdyne_data,firmadyne_dir,Firmadyne))
    except:
        print("Copying Firmadyne module to kernel sources failed")

    # SIGNAL FIX
    if kernel >= "3.0.0":
        try:
            localfix = image_dir + "kernel/signal.c"
            with open(localfix,"r") as f:
                data = f.readlines()
            
            for indx,line in enumerate(data):
                if "SA_RESTORER" in line and not "__ARCH_HAS_SA_RESTORER" in line:
                    data[indx] = line.replace("SA_RESTORER","__ARCH_HAS_SA_RESTORER")


            with open(localfix,"w") as f:
                f.writelines(data)

        except:
            print("Error with fixing {0}".format(localfix))
    #Fix the Makefiles and Kconfig files so that it is visible

    #Makefile
    try:
        Makefile = image_dir + "drivers/Makefile"
        with open(Makefile,"r") as f:
            data= f.read()

        with open(Makefile,"a") as f:
            f.write("obj-y            += firmadyne/\n")

    except:
        print("Error with", Makefile)

 #   Kconfig

    try:
        Kconfig = image_dir + "drivers/Kconfig"
        with open(Kconfig,"r") as f:
            data = f.readlines()
        
        data.insert(3, "source \"drivers/firmadyne/Kconfig\"\n")

        with open(Kconfig,"w") as f:
            f.writelines(data)

    except:
        print("Error with with writing {0} for Firmadyne".format(Kconfig))

    
    ## fix the inode.c file -> ibase is a macro
    try:
        file_to_fix = image_dir + "net/bridge/br_fdb.c"
        with open(file_to_fix, "r") as f:
            data = f.readlines()
        
        for indx,line in enumerate(data):
            if "void __exit br_fdb_fini(void)" in line:
                data[indx] = "void br_fdb_fini(void)\n"
                break

        with open(file_to_fix, "w") as f:
            f.writelines(data)

    except:
        print("Error with fixing {0}".format(file_to_fix))

    ## vmalloc fix
    #try:
        #localfix = image_dir + "drivers/staging/rtl8192su/r8192U_core.c"
        #with open(localfix,"r") as f:
            #data = f.readlines()

        #data.insert(67, "#include <linux/vmalloc.h>\n")

        #with open(localfix,"w") as f:
            #f.writelines(data)

    #except:
        #print("Error with fixing {0}".format(localfix))
    
    ## vmalloc fix
    #try:
        #localfix = image_dir + "arch/mips/include/asm/ptrace.h"
        #with open(localfix,"r") as f:
            #data = f.readlines()

        #data.insert(140, "#define regs_return_value(_regs) ((_regs)->regs[2])\n")

        #with open(localfix,"w") as f:
            #f.writelines(data)

    #except:
        #print("Error with fixing {0}".format(localfix))
    
    try:
        fix = """#include <linux/kobject.h>
#include <linux/kdev_t.h>
#include <linux/list.h>

    struct file_operations;
    struct inode;
    struct module;\n
"""
        if kernel < "linux-2.6.20":
            localfix = image_dir + "include/linux/cdev.h"
            with open(localfix,"r") as f:
                data = f.readlines()

            data.insert(4, fix)

            with open(localfix,"w") as f:
                f.writelines(data)

    except:
        print("Error with fixing {0}".format(localfix))
    
    ## Instrument the kernel to print info about the devices registered by modules
    try:
        kernel = image_dir.split("/")[-2].split("-")[1]
        localfix = image_dir + "drivers/base/core.c"
        with open(localfix,"r") as f:
            data = f.readlines()
        
        indx = 0
        flag = False
        for indx,line in enumerate(data):
            if "int device_add(" in line:
                flag = True
        #print ("Kernel",kernel)
            if "pr_debug" in line and flag == True:
                if kernel < "2.6.29" and kernel >= "2.6.15":
                    data[indx] = "\tprintk(KERN_INFO \"Registering device %s:%d:%d\\n\",dev->bus_id, MAJOR(dev->devt),MINOR(dev->devt));\n\t\n"
                    break
                elif kernel >= "2.6.29": 
                    data[indx] = "\tprintk(KERN_INFO \"Registering device %s:%d:%d\\n\",dev_name(dev), MAJOR(dev->devt),MINOR(dev->devt));\n\t\n"
                    break

        with open(localfix,"w") as f:
            f.writelines(data)

    except Exception as e:
        print("Error with fixing {0}".format(localfix))
        print(e)
    
    try:
        kernel = image_dir.split("/")[-2].split("-")[1]
        localfix = image_dir + "fs/char_dev.c"
        with open(localfix,"r") as f:
            data = f.readlines()
        
        flag = False
        insert_cdev_release = 0
        for indx,line in enumerate(data):
            if "static struct kobj_map *cdev_map;" in line:
                insert_cdev_release = indx - 1
            if "__register_chrdev_region(unsigned int" in line:
                flag = True
            if "return cd;" in line and flag == True:
        #print ("Kernel",kernel)
                data.insert(indx,"\tprintk(KERN_INFO \"Registering device %s:%d:%d\\n\",name, major,baseminor);\n\t\n")
                break
        

        data.insert(7, "#include <linux/fdyne.h>\n")

        template1 = """
        if (IS_ERR(cd)){
                if (strcmp(name, "acos_nat_cli") == 0) {
                    cdev_del(&acos_nat_cli_cdev);
                    unregister_chrdev_region(MKDEV(major, 0), 1);
                } 
                else if (strcmp(name, "brcmboard") == 0) {
                    cdev_del(&brcmboard_cdev);
                    unregister_chrdev_region(MKDEV(major, 0), 1);
                }
                else if (strcmp(name, "dsl_cpe_api") == 0) {
                    cdev_del(&dsl_cpe_api_cdev);
                    unregister_chrdev_region(MKDEV(major, 0), 1);
                }
                else if (strcmp(name, "gpio") == 0) {
                    cdev_del(&gpio_cdev);
                    unregister_chrdev_region(MKDEV(major, 0), 1);
                }
                else if (strcmp(name, "nvram") == 0) {
                    cdev_del(&nvram_cdev);
                    unregister_chrdev_region(MKDEV(major, 0), 1);
                }
                else if (strcmp(name, "pib") == 0) {
                    cdev_del(&pib_cdev);
                    unregister_chrdev_region(MKDEV(major, 0), 1);
                }
                else if (strcmp(name, "sc_led") == 0) {
                    cdev_del(&sc_led_cdev);
                    unregister_chrdev_region(MKDEV(major, 0), 1);
                }
                else if (strcmp(name, "tca0") == 0) {
                    cdev_del(&tca0_cdev);
                    unregister_chrdev_region(MKDEV(major, 0), 1);
                }
                else if (strcmp(name, "ticfg") == 0) {
                    cdev_del(&ticfg_cdev);
                    unregister_chrdev_region(MKDEV(major, 0), 1);
                }
                else if (strcmp(name, "watchdog") == 0) {
                    cdev_del(&watchdog_cdev);
                    unregister_chrdev_region(MKDEV(major, 0), 1);
                }
                else if (strcmp(name, "wdt") == 0) {
                    cdev_del(&wdt_cdev);
                    unregister_chrdev_region(MKDEV(major, 0), 1);
                }
                else if (strcmp(name, "zybtnio") == 0) {
                    cdev_del(&zybtnio_cdev);
                    unregister_chrdev_region(MKDEV(major, 0), 1);
                }
                cd = __register_chrdev_region(major, 0, 256, name);
        """
        
        template2 = """
        if (IS_ERR(cd)){
                if (strcmp(name, "acos_nat_cli") == 0) {
                    cdev_del(&acos_nat_cli_cdev);
                    unregister_chrdev_region(MKDEV(major, 0), 1);
                } 
                else if (strcmp(name, "brcmboard") == 0) {
                    cdev_del(&brcmboard_cdev);
                    unregister_chrdev_region(MKDEV(major, 0), 1);
                }
                else if (strcmp(name, "dsl_cpe_api") == 0) {
                    cdev_del(&dsl_cpe_api_cdev);
                    unregister_chrdev_region(MKDEV(major, 0), 1);
                }
                else if (strcmp(name, "gpio") == 0) {
                    cdev_del(&gpio_cdev);
                    unregister_chrdev_region(MKDEV(major, 0), 1);
                }
                else if (strcmp(name, "nvram") == 0) {
                    cdev_del(&nvram_cdev);
                    unregister_chrdev_region(MKDEV(major, 0), 1);
                }
                else if (strcmp(name, "pib") == 0) {
                    cdev_del(&pib_cdev);
                    unregister_chrdev_region(MKDEV(major, 0), 1);
                }
                else if (strcmp(name, "sc_led") == 0) {
                    cdev_del(&sc_led_cdev);
                    unregister_chrdev_region(MKDEV(major, 0), 1);
                }
                else if (strcmp(name, "tca0") == 0) {
                    cdev_del(&tca0_cdev);
                    unregister_chrdev_region(MKDEV(major, 0), 1);
                }
                else if (strcmp(name, "ticfg") == 0) {
                    cdev_del(&ticfg_cdev);
                    unregister_chrdev_region(MKDEV(major, 0), 1);
                }
                else if (strcmp(name, "watchdog") == 0) {
                    cdev_del(&watchdog_cdev);
                    unregister_chrdev_region(MKDEV(major, 0), 1);
                }
                else if (strcmp(name, "wdt") == 0) {
                    cdev_del(&wdt_cdev);
                    unregister_chrdev_region(MKDEV(major, 0), 1);
                }
                else if (strcmp(name, "zybtnio") == 0) {
                    cdev_del(&zybtnio_cdev);
                    unregister_chrdev_region(MKDEV(major, 0), 1);
                }
                cd = __register_chrdev_region(major, baseminor,1, name);
        """
        for indx,line in enumerate(data):
            ### For old kernels < 2.6.23
            if "cd = __register_chrdev_region(major, 0, 256, name)" in line:
                data.insert(indx+3,"\n\t}\n")
                data.insert(indx+1, template1)
                break
            ### For newer kernels
            elif "cd = __register_chrdev_region(major, baseminor, count, name)" in line:
                data.insert(indx + 3,"\n\t}\n")
                data.insert(indx + 1, template2)
                break

        with open(localfix,"w") as f:
            f.writelines(data)

    except Exception as e:
        print("Error with fixing {0}".format(localfix))
        print(e)
    
    try:
        kernel = image_dir.split("/")[-2].split("-")[1]
        localfix = image_dir + "kernel/module.c"
        with open(localfix,"r") as f:
            data = f.readlines()
        
        flag = False
        for indx,line in enumerate(data):
            if "check_version(Elf_Shdr" in line:
                data.insert(indx+7,"\treturn 1;\n")
                break

        with open(localfix,"w") as f:
            f.writelines(data)

    except Exception as e:
        print("Error with fixing {0}".format(localfix))
        print(e)
    
    try:
        localfix = image_dir + "scripts/dtc/dtc-lexer.l"
        with open(localfix,"r") as f:
            data = f.readlines()
        
        for indx,line in enumerate(data):
            if "YYLTYPE yylloc;" in line:
                data[indx] = "extern YYLTYPE yylloc;\n"
                break

        with open(localfix,"w") as f:
            f.writelines(data)

    except Exception as e:
        print("Error with fixing {0}".format(localfix))
        print(e)

    try:
        localfix = image_dir + "scripts/dtc/dtc-lexer.lex.c_shipped"
        with open(localfix,"r") as f:
            data = f.readlines()
        
        for indx,line in enumerate(data):
            if "YYLTYPE yylloc;" in line:
                data[indx] = "extern YYLTYPE yylloc;\n"
                break

        with open(localfix,"w") as f:
            f.writelines(data)

    except Exception as e:
        print("Error with fixing {0}".format(localfix))
        print(e)

    try:
        localfix = image_dir + "kernel/timeconst.pl"
        with open(localfix,"r") as f:
            data = f.readlines()
        
        for indx,line in enumerate(data):
            if "defined(@val)" in line:
                data[indx] = "       if (!@val) {\n"
                break

        with open(localfix,"w") as f:
            f.writelines(data)

    except Exception as e:
        print("Error with fixing {0}".format(localfix))
        print(e)
