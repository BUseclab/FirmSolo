#!/usr/bin/env python3
import sys
import os
currentdir = os.path.dirname(os.path.realpath(__file__))
parentdir = os.path.dirname(currentdir)
sys.path.append(parentdir)
import string
import pickle
import subprocess
import custom_utils as cu
import traceback
from pathlib import Path
import re

done = []

def decode(input_string):

    # Initial state
    # String is stored as a list because
    # python forbids the modification of
    # a string
    displayed_string = [] 
    cursor_position = 0

    # Loop on our input (transitions sequence)
    for character in input_string:

        # Alphanumeric transition
        if str.isalnum(character) or str.isspace(character):
            # Add the character to the string
            displayed_string[cursor_position:cursor_position+1] = character 
            # Move the cursor forward
            cursor_position += 1

        # Backward transition
        elif character == "\x08":
            # Move the cursor backward
            cursor_position -= 1
        else:
            displayed_string[cursor_position:cursor_position+1] = character 
            #print("{} is not handled by this function".format(repr(character)))

    # We transform our "list" string back to a real string
    return "".join(displayed_string)


def __read_makefile(makefile):
    with open(makefile,"r",errors='ignore') as f:
        mk = f.read()
    
    return mk

### Get the configuration option that is guarding the file
### by using regular expressions

def find_option(path,fl):
    filename = fl.replace('.c','')
    directory = path.replace(fl,'')
    Makefile = directory + "Makefile"
    
    print("Searching conf opt for file in make file",path,Makefile)
    #Check if Makefile exists
    make = Path(Makefile)
    
    if not (make.exists()):
        return None
    
    ### First read the Makefile as a large string
    mk = __read_makefile(Makefile)

    ### Now search for the substring that contains the file
    result1 = None
    try:
        pattern = "(.+?)(\\=)((.*?)(\\n))*(.*?)(\\b" + "{}\\.o\\b)".format(filename)
        result1 = re.search(pattern,mk)
    except:
        print("The search for option that enables the file {} failed".format(path))
        print(traceback.format_exc())
        return None

    ### Now we have the match in result1
    ### We have to check if it contains a CONFIG or it contains another
    ### file that will lead us to the CONFIG option
    ### First isolate the part that possibly contains the CONFIG OPTION
    guard_part_obj = re.search("(.+?-.+?)(?=[:+=\\s])",result1.group())
    
    ### Save the match
    guard_part = guard_part_obj.group()

    ### Special case for substitutions in the guard
    if guard_part and "subst" in guard_part:
        match = re.search(r'\(([^()]*)\)',guard_part)
        conf_opt = match[0].strip("()")
        print("Found Conf Opt",conf_opt)
        return conf_opt
    
    ### Check if CONFIG_OPTION is ready in that part
    if guard_part and  "CONFIG_" in guard_part:
        conf_opt = re.search(r"(?<=\()(.+?)(?=\))",guard_part).group()
        print("Found Conf Opt",conf_opt)
        return conf_opt
    elif "-y" in guard_part or "-m" in guard_part:
        print("No conf opt")
        return None
    ### This a case we have an intermediate file which will lead us to the option
    elif "-" in guard_part:
        parts = guard_part.split("-")
        ending = parts[-1]
        new_file = "-".join(parts).replace("-"+ending,"")
        ### Now try again with the new file/module
        print("Retrying to find the conf option with file",new_file)
        conf_opt = find_option(directory,new_file)
        print("Found Conf Opt",conf_opt)
        return conf_opt

    return None


def find_conf_opt(path,fl):
    # We must look at the Makefile in the same directory as the file with the definition in order to take the config option -> use fgrep

    # Modify the name of the file appropriately
    fl.strip(" ")
    temp = fl.replace(".c",'')
    file_lookup = temp +'.o'
    candidate = ""
    directory = path.replace(fl,'')
    Makefile = directory+"Makefile"
    MAkefile = directory+"MAkefile"

    #Check if Makefile exists
    make = Path(Makefile)
    # Patch #4
    if not (make.exists()):
        return "",""

    #Remove tabs from Makefile 
    try:
        os.system("tr -d \"\t\" < " + Makefile + " > " + MAkefile)
    except:
        print("Changing "+ Makefile + " failed")

    try:
        result = subprocess.run(["fgrep","-rn","--include=MAkefile", file_lookup,directory], stdout=subprocess.PIPE)
        fgrep_output = result.stdout.decode("utf-8")

        if fgrep_output == "":
            return "", Makefile
    except:
        print("\nFgrep for " + fl + "failed")
        return "",""

    print("\nFGREP output:",fgrep_output, "\nMakefile directory:" ,directory,"\nFile to lookup:",file_lookup)

    # Patch #1
    #Case that we cant immidiately find a definition with "-". Probably due to the use of \ -> must use perl
    if "-" not in fgrep_output.split()[0].split(":")[-1] or ".o" in fgrep_output.split()[0].split(":")[-1]:
         test = False
    else:
         test = True

    # when lines continue to a new line with backslash
    if "\\" in fgrep_output or test == False:
        try:
              perl_result = os.popen('perl -pe \'s/\\\\\\n/ /\' '+ Makefile +'  | grep ' + file_lookup).read()

              #print ("Perl original Result: \n", perl_result)

              # Patch #5
              #We must find the correct operand used for the definition
              lines = perl_result.split("\n")

              if ":=" in lines[0]:
                     oper = ":="
              elif "+=" in lines[0]:
                     oper = "+="
              else:
                     oper = "="

              perl_def = lines[0].split(oper)
              #print("Perl__Operant",perl_def)

              # Patch #6
              if perl_def[0] == "targets ":
                     return "", Makefile

              result_tokens = perl_def[0].split("-")

              #print("Perl__Tokens",result_tokens)

              obj1 = perl_def[0].split("-")[0]

              #print("Perl__OBJ1",obj1)

              #Only 1 definition so we get the Config Option
              if len(perl_def[0].split("-")) > 1:
                     conf_opt = perl_def[0].split("-")[1]
                     #print("Perl__CONF_OPT",conf_opt)
              # Multiple definitions so we must recurse them until we find the Config Option
              else:
                     conf_opt = ""
                     #print("Perl__CONF_OPT",conf_opt)

              # Patch #7
              # recusrion into the multiple definitions
              j=1
              while obj1 == temp or temp in obj1:
                 print("here1")
                 if "+=" in lines[j]:
                          obj1 =  lines[j].split("+=")[0].split("-")[0]
                          conf_opt = lines[j].split("+=")[0].split("-")[1]
                          result_tokens = lines[j].split("+=")[0].split("-")
                 elif ":=" in lines[j]:
                          obj1 =  lines[j].split(":=")[0].split("-")[0]
                          conf_opt = lines[j].split(":=")[0].split("-")[1]
                          result_tokens = lines[j].split(":=")[0].split("-")
                 else:
                          obj1 =  lines[j].split("=")[0].split("-")[0]
                          conf_opt = lines[j].split("=")[0].split("-")[1]
                          result_tokens = lines[j].split("=")[0].split("-")

                 j+=1

              # Patch #8
              if obj1 == "lib":
                   if "CONFIG_" not in conf_opt:
                          return "", Makefile

              print("Perl Final Obj1",obj1,"Perl Final Conf opt",conf_opt)

              if "CONFIG_" in conf_opt:
                  print("Config option",conf_opt)
                  conf_opt = conf_opt.replace('$(','').replace(')','')
                  return conf_opt.strip(" \t"), Makefile

        except Exception as e:
              print("Perl search failed for file " + file_lookup)
              print("Perl Error: \n",str(e))

    else: #We do not have the correct file with the correct Config Option to enable
        ## Special case
        if "subst" in fgrep_output:
            match = re.search(r'\(([^()]*)\)',fgrep_output)
            opt = match[0].strip("()")
            return opt,Makefile

        result_tokens = fgrep_output.split()[0].split(":")[-1].split("-")
        # Patch #3

        #Multiple "-" in the definition -> we must take the last one
        if len(result_tokens) > 2:
              # print("Nested obj")
               obj1 ="obj"
               conf_opt = result_tokens[2]
        else:
               operand = "+="
               #if "+=" in result_tokens[0]:
                   #operand = "+="
               #elif ":=" in result_tokens[0]:
                   #operand = ":="
               #else:
                   #operand = "="

               obj1 = result_tokens[0].split(operand)[0]
               if obj1 == "lib":
                   if "CONFIG_" not in result_tokens[1]:
                       return "", Makefile

           #    print("Else Obj1",obj1)
               conf_opt = result_tokens[1].split(operand)[0]
               if "CONFIG_" in conf_opt:
                   print("Config option",conf_opt)
                   conf_opt = conf_opt.replace('$(','').replace(')','')
                   return conf_opt.strip(" \t"), Makefile

            #   print("Else Conf Opt",conf_opt)

    if obj1 != "obj" or "CONFIG_" not in conf_opt:

       # print("Trying to find the correct file with the Config Option",obj1,conf_opt)

        parts = result_tokens
        ending = parts[-1]
        option = "-".join(parts)
        real_module = ' ' + option.replace("-"+ending,"") + ".o"
        #if obj1 == "obj" and "y" in conf_opt:
            #paths = directory.split("/")
            #if len(paths[:-1]) > 1:
                #directory = "/".join(paths[:-2]) +"/"
                #real_module = paths[-2] + "/"
                #print(directory,real_module)

        #The file that holds the definition is linked against the real module
        #We must find the option for the real module
        
        try:
            result = subprocess.run(["fgrep","-rn", real_module,directory + "Makefile"],stdout=subprocess.PIPE)
            fgrep2_result = result.stdout.decode("utf-8")
            if fgrep2_result == "":
                  return "", Makefile
        except:
            print("Fgrep failed for the real module" + real_module)
            return "",""
        # Patch #10

       # print("FGREP2 Result: ",fgrep2_result.split(),"Real module:", real_module)
        if "#" not in fgrep2_result.split()[0]:
            if "CONFIG_" in fgrep2_result.split()[0]:
                match = re.search(r'\(([^()]*)\)',fgrep2_result.split()[0])
                conf_opt = match[0].strip("()")
            #else:
                #conf_opt = fgrep2_result.split()[0].split(":")[-1].split("-")[1]
                #conf_opt = conf_opt.replace('$(','').replace(')','')
        elif "#" in fgrep2_result.split()[0]:
                if len(fgrep2_result.split()) > 1:
                       for token in fgrep2_result.split():
                             if real_module in token and "obj" in token:
                                    conf_opt = token.split(":")[-1].split("-")[1]
                                    conf_opt = conf_opt.replace('$(','').replace(')','')
                             elif "CONFIG_" in token:
                                    match = re.search(r'\(([^()]*)\)',token)
                                    conf_opt = match[0].strip("()")
                else:
                       print("NOT IN MAKEFILE GIVEN")

        print("Config option",conf_opt)
        return conf_opt.replace('$(','').replace(')','').strip(" \t"), Makefile
    else:
        print("Config option",conf_opt)
        conf_opt = conf_opt.replace('$(','').replace(')','')
        return conf_opt.strip(" \t"), Makefile

def find_definition(data):
    sym = data[0]
    sym_dict = data[1]
    k_dir = data[2]
    
    filez = None
    #run cscope -> take the first file with definition -> return the whole path + file
    #fls = subprocess.run(["cscope","-d","-L1",sym], stdout=subprocess.PIPE)
    ### If the file is ready just return it
    if sym in sym_dict.keys():
        filez = sym_dict[sym]
        return filez


    cmd = 'cscope -d -L4"EXPORT_SYMBOL({0})"'.format(sym)
    try:
        filez = subprocess.check_output(cmd,cwd=k_dir,shell=True,timeout=100).decode("utf-8")
    except:
        print(traceback.format_exc())

    if filez == "":
        cmd = 'cscope -d -L4"EXPORT_SYMBOL_GPL({0})"'.format(sym)
        try:
            filez = subprocess.check_output(cmd,cwd=k_dir,shell=True,timeout=100).decode("utf-8")
        except:
            print(traceback.format_exc())
    if filez == "":
        cmd = 'cscope -d -L1"{0}"'.format(sym)
        try:
            filez = subprocess.check_output(cmd,cwd=k_dir,shell=True,timeout=60).decode("utf-8")
        except:
            print(traceback.format_exc())

    #print(filez)
    #path = ""
    #fl = ""
    
    return filez

def find_and_cscope(image_dir,arch="arm"):

    # Find the files for cscope 
    find_cmd = "find . -path \"./arch/*\" ! -path \"./arch/{}*\" -prune -o -path \"./Documentation*\" -prune -o -name \"*.[chxsS]\" -print >./cscope.files".format(arch)

    os.chdir(image_dir)
    os.system(find_cmd)
    os.chdir(cu.abs_path)

    try:
        cscope = subprocess.run('cscope -b -q', cwd=image_dir,shell=True)
    except:
        print("Cscope failed")

##### This will find all the frequencies for the files that export symbols ####

def find_file_freqs(filez,syms_fl_dict,syms_fl_groups):

    path = ""
    fl = ""
    if filez != "" and filez != None:
        export_files = []
        tokens = filez.split("\n")
        del tokens[-1]
        for token in tokens:
            # For each of the results returned by cscope for an exported
            # symbol get the file path that exports it and then update 
            # the file seen frequency dictionary
            path = token.split()[0]
            if path in export_files:
                continue
            export_files.append(path)
            try:
                syms_fl_dict[path] += 1
            except:
                syms_fl_dict[path] = 1
        flag = False
        indx = -1
        print(filez)
        print(export_files,"\n")
        for fl in export_files:
            for index,group in enumerate(syms_fl_groups):
                if fl in group:
                    flag = True
                    indx = index
                    break
            if flag == True:
                break
        if flag == True:
            for fl in export_files:
                if fl not in syms_fl_groups[indx]:
                    syms_fl_groups[indx].append(fl)
        else:
            syms_fl_groups.append(export_files)

    return syms_fl_dict, syms_fl_groups

##################################################################################

def find_sym_files(kernel,symbolz,arch):
    cwd = os.getcwd()
    def_files = []
    kernel_dir = cu.kern_sources + "linux-"+ kernel
    #print(kernel_dir)
    #find_and_cscope(kernel_dir,arch)
    for sym in symbolz:
        filez = find_definition(sym,kernel_dir)
        def_files.append(filez)
        #if filez != "":
            #if filez not in def_files:
                #def_files.append(filez)

    return def_files
