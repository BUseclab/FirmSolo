#!/usr/bin/env python

import os
import sys
import re
currentdir = os.path.dirname(os.path.realpath(__file__))                                                
parentdir = os.path.dirname(currentdir)                                                                 
sys.path.append(parentdir) 
import custom_utils as cu

def fix_configs(kern_dir,kernel):
  cwd = os.getcwd()
  os.chdir(kern_dir)
  try:
    with open("drivers/telephony/Kconfig","r") as f1:
      data = f1.read()
  except:
    print("File drivers/telephony/Kconfig not found")
  try:
    new_data = data.replace('depends ISA || PCI', 'depends on ISA || PCI')
    
    with open("drivers/telephony/Kconfig","w") as f1:
      f1.write(new_data)
  except:
    print("Valid1")

  try:
    with open("drivers/input/misc/Kconfig","r") as f1:
      data = f1.read()
  except:
    print("File drivers/input/misc/Kconfig not found")
  
  try:
    new_data = data.replace('depends EXPERIMENTAL', 'depends on EXPERIMENTAL')
    
    with open("drivers/input/misc/Kconfig","w") as f1:
      f1.write(new_data)
  except:
    print("Valid2")
  try:
    with open("drivers/leds/Kconfig","r") as f1:
      data = f1.readlines()
  except:
    print("File drivers/leds/Kconfig not found")

  try:  
    for indx,line in enumerate(data):
        if "depends" in line and "depends on" not in line:
            data[indx] = data[indx].replace("depends","depends on")

 #   new_data = data.replace('depends LEDS_CLASS && ARCH_H1940', 'depends on LEDS_CLASS && ARCH_H1940')
  #  new_data = new_data.replace('depends LEDS_CLASS && PXA_SHARP_C7xx', 'depends on LEDS_CLASS && PXA_SHARP_C7xx')
   # new_data = new_data.replace('depends NEW_LEDS', 'depends on NEW_LEDS')
    
    with open("drivers/leds/Kconfig","w") as f1:
      f1.writelines(data)
  except:
    print("Valid3")
  try:
    with open("drivers/hwmon/Kconfig","r") as f1:
      print("Opened")
      data = f1.read()
  except:
    print("File drivers/leds/Kconfig not found")

  try:  
    print("tristate \"Fintek F75375S/SP and F75373\";")
    new_data = data.replace("tristate \"Fintek F75375S/SP and F75373\";", "tristate \"Fintek F75375S/SP and F75373\"")
    
    with open("drivers/hwmon/Kconfig","w") as f1:
      f1.write(new_data)
  except:
    print("Valid4")


  try:
      os.system("rm sound/soc/ux500/Kconfig")
      os.system("cp  {}scripts/compile_scripts/Kconfig sound/soc/ux500/".format(cu.abs_path))

  except:
    print("Valid5")



  try:
    with open("drivers/media/usb/stk1160/Kconfig","r") as f1:
      print("Opened")
      data = f1.read()
  except:
    print("File drivers/media/usb/stk1160/Kconfig not found")

  try:  
    new_data = data.replace(".", "")
    
    with open("drivers/media/usb/stk1160/Kconfig","w") as f1:
      f1.write(new_data)
  except:
    print("Valid6")
                
  try:
    with open("drivers/ide/Kconfig","r") as f1:
      data = f1.read()
  except:
    print("File drivers/ide/Kconfig not found")

  try:  
    new_data = data.replace("depends BLK_DEV_IDE_AU1XXX", "depends on  BLK_DEV_IDE_AU1XXX")
    
    with open("drivers/ide/Kconfig","w") as f1:
      f1.write(new_data)
  except:
    print("Valid7")
  try:
    with open("drivers/serial/Kconfig","r") as f1:
      data = f1.read()
  except:
    print("File drivers/serial/Kconfig not found")

  try:  
    new_data = data.replace("depends V850E_UART && V850E_ME2", "depends on V850E_UART && V850E_ME2")
    new_data2 = new_data.replace("depends HAS_TXX9_SERIAL && BROKEN", "depends on HAS_TXX9_SERIAL && BROKEN")
    
    with open("drivers/serial/Kconfig","w") as f1:
      f1.write(new_data2)
  except:
                print("Valid8")   
  try:
    with open("drivers/char/Kconfig","r") as f1:
      data = f1.read()
  except:
    print("File drivers/char/Kconfig not found")

  try:  
    new_data = data.replace("depends TANBAC_TB022X", "depends on TANBAC_TB022X")
    
    with open("drivers/char/Kconfig","w") as f1:
      f1.write(new_data)
  except:
                print("Valid9")   
  try:
    with open("fs/Kconfig","r") as f1:
      data = f1.read()
  except:
    print("File fs/Kconfig not found")

  try:  
    new_data = data.replace("depends X86 || IA64 || PPC64 || SPARC64 || SUPERH || BROKEN", "depends on X86 || IA64 || PPC64 || SPARC64 || SUPERH || BROKEN")
    
    with open("fs/Kconfig","w") as f1:
      f1.write(new_data)
  except:
                print("Valid10")   
  try:
    with open("drivers/rtc/Kconfig","r") as f1:
      data = f1.read()
  except:
    print("File drivers/rtc/Kconfig not found")

  try:  
    new_data = data.replace("\#", "")
    
    with open("drivers/rtc/Kconfig","w") as f1:
      f1.write(new_data)
  except:
                print("Valid11")   
  try:
    with open("drivers/usb/net/Kconfig","r") as f1:
      data = f1.read()
  except:
    print("File drivers/usb/net/Kconfig not found")

  try:  
    new_data = data.replace("\xa0", "")
    
    with open("drivers/usb/net/Kconfig","w") as f1:
      f1.write(new_data)
  except:
                print("Valid12")   
         
  try:
    with open("drivers/net/Kconfig","r") as f1:
      data = f1.read()
  except:
    print("File drivers/net/Kconfig not found")

  try:  
    new_data = data.replace("require m", "")
    
    with open("drivers/net/Kconfig","w") as f1:
      f1.write(new_data)
  except:
                print("Valid13")   

  try:
    with open("net/l2tp/Kconfig","r") as f1:
      data = f1.readlines()
  except:
    print("File drivers/net/Kconfig not found")
    
  try:
    indx = 0
    for line in data:
        if "tristate \"Layer Two Tunneling Protocol (L2TP)\"" in line:
            break
        indx += 1

    data.insert(indx + 1,"\tdepends on (IPV6 || IPV6=n)\n")
    
    with open("net/l2tp/Kconfig","w") as f1:
      f1.writelines(data)
  except:
    print("Valid14")

  try:
    with open("arch/mips/Kconfig","r") as f1:
      data = f1.readlines()
  except:
    print("File arch/mips/Kconfig not found")

  if kernel >= "linux-2.6.22":
      try:
        zone_dma = False
        for i,line in enumerate(data):
            if "config ZONE_DMA\n" in line:
                data[i+1] = "\tbool \"Enable ZONE_DMA\"\n\tdefault n\n"
            if "config MIPS_MALTA\n" in line:
                zone_dma = True
            if "select GENERIC_ISA_DMA" in line and zone_dma == True:
                data[i] = "\tselect GENERIC_ISA_DMA_SUPPORT_BROKEN\n"
                if kernel >= "linux-2.6.23":
                    break
            if "config GENERIC_ISA_DMA_SUPPORT_BROKEN\n" in line:
                del data[i+2]
                break


        with open("arch/mips/Kconfig","w") as f1:
          f1.writelines(data)
      except:
        print("Valid15")
  
  try:
    with open("drivers/serial/Kconfig","r") as f1:
      data = f1.read()
  except:
    print("File drivers/serial/Kconfig not found")
  try:
    new_data = data.replace('depends HAS_TXX9_SERIAL', 'depends on  HAS_TXX9_SERIAL')
    
    with open("drivers/serial/Kconfig","w") as f1:
      f1.write(new_data)
  except:
    print("Valid16")
  
  try:
    with open("sound/aoa/fabrics/Kconfig","r") as f1:
      data = f1.read()
  except:
    print("File sound/aoa/fabrics/Kconfig not found")
  
  try:
    new_data = data.replace('depends SND_AOA', 'depends on SND_AOA')
    
    with open("sound/aoa/fabrics/Kconfig","w") as f1:
      f1.write(new_data)
  except:
    print("Valid17")
  
  try:
    with open("arch/arm/Kconfig","r") as f1:
      data = f1.readlines()
  except:
    print("File arch/arm/Kconfig not found")
    
  try:
    zone_dma = False
    for i,line in enumerate(data):
        if "config ZONE_DMA\n" in line:
            data[i+1] = "\tbool \"Enable ZONE_DMA\"\n"
            break
 #           data.insert(i+1,"\tdefault n\n")
            
 #       if "config ARCH_VERSATILE\n" in line:
  #          zone_dma = True
   #         data.insert(i+2,"\tselect ZONE_DMA\n")
    #        break

    with open("arch/arm/Kconfig","w") as f1:
      f1.writelines(data)
  except:
    print("Valid18")

  try:
    with open("drivers/staging/iio/light/Kconfig","r") as f1:
      data = f1.read()
  except:
    print("File drivers/staging/iio/light/Kconfig not found")

  try:
    new_data = data.replace('\\#', '#')
    
    with open("drivers/staging/iio/light/Kconfig","w") as f1:
      f1.write(new_data)
  except:
    print("Valid19")

  try:
    with open("net/ipv6/Kconfig","r") as f1:
      data = f1.readlines()
  except:
    print("File net/ipv6/Kconfig not found")
  
  try:
    for indx,line in enumerate(data):
        if "default IPV6" in line:
            data[indx] = line.replace("default IPV6","default n")

    with open("net/ipv6/Kconfig","w") as f1:
      f1.writelines(data)
  except:
    print("Valid20")

  try:
    with open("net/netfilter/Kconfig","r") as f1:
      data = f1.readlines()
  except:
    print("File net/netfilter/Kconfig not found")

  try:
    indx = 0
    flag = False
    for line in data:
        if "config NETFILTER_XT_TARGET_TPROXY" in line:
            flag = True
            break
        indx += 1

    if flag:
        data.insert(indx + 2,"\tdepends on (IPV6 || IPV6=n)\n")

    indx = 0
    flag = False
    for line in data:
        if "config NETFILTER_XT_MATCH_SOCKET" in line:
            flag = True
            break
        indx += 1

    if flag:
        data.insert(indx + 2,"\tdepends on (IPV6 || IPV6=n)\n")
    
    indx = 0
    flag = False
    for line in data:
        if "config NETFILTER_TPROXY" in line:
            flag = True
            break
        indx += 1

    if flag:
        data.insert(indx + 2,"\tdepends on (IPV6 || IPV6=n)\n")

    with open("net/netfilter/Kconfig","w") as f1:
      f1.writelines(data)
  except:
    print("Valid21")
  
  try:
    with open("init/Kconfig","r") as f1:
      data = f1.readlines()
  except:
    print("File init/Kconfig not found")
    
  try:
    zone_dma = False
    for i,line in enumerate(data):
        if "config CONSTRUCTORS\n" in line:
            data[i+1] = "\tbool \"Enable CONSTRUCTORS\"\n"
            break

    with open("init/Kconfig","w") as f1:
      f1.writelines(data)
  except:
    print("Valid22")

  os.chdir(cwd)
if __name__ == "__main__":
  fix_configs("./")
