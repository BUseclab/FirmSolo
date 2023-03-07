#! /usr/bin/env python


import os
import sys
import subprocess
from kconfiglib import Kconfig, Symbol, Choice, MENU, COMMENT, TRI_TO_STR,STRING, BOOL, TRISTATE, HEX,AND,OR,NOT,EQUAL,UNEQUAL, standard_kconfig, expr_str, expr_items, expr_value
from pathlib import Path
import pickle
import re
#from sympy.logic import simplify_logic
#from sympy.logic.boolalg import to_cnf


#command to get the files necessary for cscope
# find . -path "./arch/*" ! -path "./arch/mips*" -prune -o -path "Documentation*" -prune -o -name "*.[chxsS]" -print >./cscope.files


########## Manually Set Config Options #################
ver_tokens = ["mod_unload","MIPS32_R1","32BIT","MIPS32_R2","preempt","modversions","64KB","ARMv5","ARMv6","ARMv7","p2v8"]
conf_match = ["CONFIG_MODULE_UNLOAD","CONFIG_CPU_MIPS32_R1","CONFIG_32BIT","CONFIG_CPU_MIPS32_R2","CONFIG_PREEMPT","CONFIG_MODVERSIONS","CONFIG_PAGE_SIZE_64KB","CONFIG_ARCH_VERSATILE CONFIG_CPU_ARM926T","CONFIG_ARCH_REALVIEW CONFIG_REALVIEW_EB_ARM11MP CONFIG_MACH_REALVIEW_PB11MP CONFIG_REALVIEW_EB_ARM11MP_REVB CONFIG_CPU_V6","CONFIG ARCH_REALVIEW CONFIG_MACH_REALVIEW_EB CONFIG_REALVIEW_EB_A9MP CONFIG_MACH_REALVIEW_PBA8 CONFIG_MACH_REALVIEW_PBX CONFIG_CPU_V7","CONFIG_ARM_PATCH_PHYS_VIRT"]
vermagic_opts = {
                "mod_unload" : "CONFIG_MODULE_UNLOAD",
                "MIPS32_R1"  : "CONFIG_CPU_MIPS32_R1",
                "MIPS32_R2"  : "CONFIG_CPU_MIPS32_R2",
                "preempt"    : "CONFIG_PREEMPT",
                "modversions": "CONFIG_MODVERSIONS",
                "64KB"       : "CONFIG_PAGE_SIZE_64KB",
                "ARMv5"      : "CONFIG_ARCH_VERSATILE CONFIG_CPU_ARM926T",
                "ARMv6"      : "CONFIG_ARCH_REALVIEW \
                                CONFIG_REALVIEW_EB_ARM11MP \
                                CONFIG_MACH_REALVIEW_PB11MP \
                                CONFIG_REALVIEW_EB_ARM11MP_REVB CONFIG_CPU_V6",
                "ARMv7"      : "CONFIG ARCH_REALVIEW CONFIG_MACH_REALVIEW_EB \
                                CONFIG_REALVIEW_EB_A9MP \
                                CONFIG_MACH_REALVIEW_PBA8 \
                                CONFIG_MACH_REALVIEW_PBX CONFIG_CPU_V7",
                "p2v8"       : "CONFIG_ARM_PATCH_PHYS_VIRT",
                "SMP"        : "CONFIG_SMP"
        }

#conf_match = ["CONFIG_MODULE_UNLOAD","CONFIG_CPU_MIPS32_R1","CONFIG_32BIT","CONFIG_CPU_MIPS32_R2","CONFIG_PREEMPT","CONFIG_MODVERSIONS","CONFIG_PAGE_SIZE_64KB","CONFIG_ARCH_VERSATILE CONFIG_CPU_ARM926T","CONFIG ARCH_REALVIEW CONFIG_REALVIEW_EB_ARM11MP CONFIG_REALVIEW_EB_ARM11MP_REVB CONFIG_MACH_REALVIEW_PB11MP CONFIG_MACH_REALVIEW_PB1176 CONFIG_CPU_V6","CONFIG_ARCH_VEXPRESS CONFIG_ARCH_VEXPRESS_CA9X4 CONFIG_CPU_V7","CONFIG_ARM_PATCH_PHYS_VIRT"]

preempt = ["CONFIG_PREEMPT_NONE","CONFIG_PREEMPT_VOLUNTARY","CONFIG_PREEMPT"]

arch_spec= ["SMP","MT_SMTC"]
arch_spec_match= ["MT_SMP","MT_SMTC"]

########################################################

#################### CORE NTEFILTER MODULES & OPTIONS #########################
# These will be enabled in case to custom counterpart module exists to aid the
# emulation
###############################################################################
#core_nf_modules = ["x_tables.ko","nf_conntrack.ko","ip_tables.ko","iptable_filter.ko","iptable_nat.ko","iptable_mangle.ko","iptable_raw.ko","ebtables.ko","ebtable_broute.ko","ebtable_filter.ko","ebtable_nat.ko"]
#core_nf_options = ["CONFIG_NETFILTER_XTABLES","CONFIG_NF_CONNTRACK","CONFIG_IP_NF_IPTABLES","CONFIG_IP_NF_FILTER","CONFIG_NF_NAT","CONFIG_IP_NF_MANGLE","CONFIG_IP_NF_RAW","CONFIG_BRIDGE_NF_EBTABLES","CONFIG_BRIDGE_EBT_BROUTE","CONFIG_BRIDGE_EBT_T_FILTER","CONFIG_BRIDGE_EBT_T_NAT"]

core_nf_modules = ["x_tables.ko","nf_conntrack.ko","ip_tables.ko","iptable_filter.ko","iptable_nat.ko"]
core_nf_options = ["CONFIG_NETFILTER_XTABLES","CONFIG_NF_CONNTRACK","CONFIG_IP_NF_IPTABLES","CONFIG_IP_NF_FILTER","CONFIG_NF_NAT"]

class Image:
    def __init__(self,kconf,image, module_configs, arch):
        self.kconf = kconf
        self.image= image
        self.module_configs = module_configs
        self.arch = arch

################# Expression Parsing Functions #########################
    def split_expr(self,expr, op):
        res = []

        def rec(subexpr):
            if subexpr.__class__ is tuple and subexpr[0] is op:
                if subexpr[0] is NOT:
                    if subexpr[1].__class__ is tuple:
                         rec(subexpr[1])
                    else:
                         res.append(subexpr[1])
                else:
                    rec(subexpr[1])
                if subexpr[0] is not NOT and subexpr[0] is not EQUAL and subexpr[0] is not UNEQUAL:
                    rec(subexpr[2])
            #Case of aa simple symbol
            else:
                if op is not NOT:
                    res.append(subexpr)


        rec(expr)
        return res



    def tuple_case(self,target,term):
        print("\t The dependency {0} is a tuple".format(expr_str(term)))
        
        if term[0] == NOT:
            return
      # We manually parse for EQUAL and UNEQUAL operations in the expression because the recursion breaks
        if term[0] != EQUAL and term[0] != UNEQUAL: 
            self._split_expr_info(target,term)
            return
         
        if "!=" in expr_str(term):
            print ("\tOperator UNEQUAL in expression", expr_str(term))

            if "\"n\"" in expr_str(term):
                self.set_option_value(term[1].name, 2)
                #term[1].set_value(2)
            elif "\"y\"" in expr_str(term):
                self.set_option_value(term[1].name, 0)
                #term[1].set_value(0)
            else:
                print("\t\tTerm {0} UNEQUAL Term {1}".format(term[1],term[2]))

                if term[2].str_value == "y":
                     self.set_option_value(term[1].name, 0)
                     #term[1].set_value(0)
                else:
                     self.set_option_value(term[1].name, 2)
                     #term[1].set_value(2)
            return
        if "=" in expr_str(term):
            print ("\tCase of EQUAL for expr", expr_str(term))

            if "\"n\"" in expr_str(term):
                self.set_option_value(term[1].name, 0)
                #term[1].set_value(0)
            elif "\"y\"" in expr_str(term):
                self.set_option_value(term[1].name, 2)
                #term[1].set_value(2)
            else:
                print("\t\tEQUAL",term[1],term[2])

                if term[2].str_value == "y":
                     self.set_option_value(term[1].name, 2)
                     #term[1].set_value(2)
                else:
                     self.set_option_value(term[1].name, 0)
                     #term[1].set_value(0)
            return


    def get_operators(self,expr):

        if len(self.split_expr(expr, AND)) > 1:
            split_op = AND
            op_str = "&&"
        else:
            if len(self.split_expr(expr,NOT)) != 0:
                 split_op = NOT
                 op_str = "!"
            else:
                 split_op = OR
                 op_str = "||"

        return split_op, op_str

    # Set a value when we have the NOT operator
    def val_setting(self,term, op_str):

        if op_str == "!":
          print("Operant == NOT...Setting to n",\
                  term.name, "Visibility", term.visibility, "Assignable", term.assignable,"Dependencies",term.direct_dep)

          if term.tri_value == 0:
            #print("Value equals to 0...setting to 2")
            #term.set_value(2)
            pass
          else:
            print("Value equals to 2...setting to 0")
            self.set_option_value(term.name, 0)
            print("The new value is ", term.tri_value)
            #term.set_value(0)
            if term.tri_value != 0:
                print("Trying to force the value to 0")
                self.set_undefined_option(term,0)
    
    # Recursive function for breaking down dependency expressions
    def _split_expr_info(self,target,expr):
        
        # We did something and made the target symbol visible
        # No point in continuing setting deps
        

        # Get the dominant operator for the expression
        split_op, op_str = self.get_operators(expr)

        for i, term in enumerate(self.split_expr(expr, split_op)):
            
            if isinstance(target,tuple):
                if expr_value(target) > 0:
                    print("We made target expression {0} true...returning!".format(expr_str(target)))
                    return
            else:
                if target.visibility > 0:
                    print("We made target {0} visible".format(target.name))
                    ### Used for a single symbol
                    if not isinstance(term,tuple) and term.tri_value == 0:
                        print("However target {0} is not enabled...Setting the target".format(target.name))
                        self.set_option(term.name,2)
                    return

            # Our expression is a tuple so we must break it further down
            if isinstance(term, tuple):
                # This subdep is already satisfied continue
                if expr_value(term) > 0 and term[0]!= NOT:
                    print("The subdep {0} is already satisfied continuing...".format(expr_str(term)))
                    continue
                # Case of complicated NOT expression...Aborting!!
                #if term[0] == NOT and len(term[1]) > 2:
                if term[0] == NOT and len(term) == 2:
                    if isinstance(term[1], tuple):
                        print("Found complex NOT expr {0} Aborting...".format(expr_str(term)))
                        continue
                    else:
                        print("Found simple NOT expr {0} Not Aborting...".format(expr_str(term[1])))
                        #self._split_expr_info(term[1],term[1].direct_dep)
                        self.val_setting(term[1],"!")
                        continue
                
                # We are dealing with a tuple... We need to break further down
                self.tuple_case(target,term)
            
            # The dependency is just a symbol we must find its type
            else:
                # The term is a string
                if isinstance(term,str):
                    print("Simple Symbol/String dep {0} not breaking further down".format(term))
                    self.set_option(term,2)
                else:
                    # The dep is empty, dont know how we got here
                    if term.name == None:
                        return
                    print("Simple Symbol/String dep {0} with value {1} not breaking further down".format(term.name,term.tri_value))
                    # Case of a simple NOT operation...just call val_setting
                    if op_str == "!":
                        self.val_setting(term,op_str)
                    # Just set the symbol
                    else:
                        if term != self.kconf.y and term.tri_value == 0:
                            self.set_option(term.name,2)
        
        return

#################################################################################################################################


##################### Version Magic/Symbols Specific functions #########################
    def set_ver_magic(self,ver_magic):
        print("VERMAGIC",ver_magic)
        ARCH=""
        release = ""
        for token in ver_magic:
            if token in vermagic_opts:
                if "MIPS" in token:
                    release = token
                    ARCH="MIPS"
                elif "ARM" in token:
                    ARCH="ARM"
                    release = token
        
        print ("RELEASE",release)
        try:
            option = vermagic_opts[release]
        except:
            option = ""
        #release_indx = ver_tokens.index(release)
        #option = conf_match[release_indx]
        
        options = option.split()
        for opt in options:
            self.set_option(opt,2)
        
        if ARCH== "ARM" and release >= "ARMv5":
                #self.set_option("CPU_V6K",2)
            if release > "ARMv5":
                self.set_option("CONFIG_CPU_ARM926T",0)
                self.set_option("CONFIG_CPU_32v5",0)
            if release == "ARMv6":
                self.set_option("REALVIEW_EB_A9MP",0)
                self.set_option("MACH_REALVIEW_PBA8",0)
                self.set_option("CONFIG_CPU_V7",0)
                if "p2v8" not in ver_magic:
                    self.set_option("CONFIG_REALVIEW_HIGH_PHYS_OFFSET",0)
                    self.set_option("CONFIG_ARM_PATCH_PHYS_VIRT",0)

            if release == "ARMv7":
                self.set_option("CONFIG_MACH_REALVIEW_PB1176",0)
                self.set_option("CONFIG_MACH_REALVIEW_PB11MP",0)
                self.set_option("CONFIG_REALVIEW_EB_ARM11MP",0)
                self.set_option("CONFIG_CPU_V6",0)
                self.set_option("CONFIG_CPU_V6K",0)
                if "p2v8" not in ver_magic:
                    self.set_option("CONFIG_REALVIEW_HIGH_PHYS_OFFSET",0)

                #armv6_disable = conf_match[8].split()
                #for opt in armv6_disable:
                    #if opt != "CONFIG_ARCH_REALVIEW":
                        #self.set_option(opt,0)


        for token in ver_magic:
            if token in vermagic_opts:
                #indx = ver_tokens.index(token)
                #option = conf_match[indx]
                options = vermagic_opts[token]
                for opt in options.split():
                    print("VER_TOKEN",option)
                    self.set_option(opt,2)
            if token in arch_spec:
                self.set_option(token,2)
                indx = arch_spec.index(token)
                option = ARCH + "_" + arch_spec_match[indx]
                self.set_option(option,2)
                print("ARCH_SPEC",option)
        if ARCH == 'MIPS':
            self.set_option("MIPS_MALTA",2)
        


        for token in ver_tokens:
            if token not in ver_magic:
                if token == "preempt":
                    self.set_option("CONFIG_PREEMPT_NONE",2)
                    continue
                if token == "modversions":
                    self.set_option("CONFIG_MODVERSIONS",0)
                    continue
                if token == "mod_unload":
                    self.set_option("CONFIG_MODULE_UNLOAD",0)
                    continue
                #indx = ver_tokens.index(token)
                #option = conf_match[indx]
                #set_option(option,0)
        flag = False
        for token in arch_spec:
            if token in ver_magic:
                flag = True
                break
        if flag == False:
            if ARCH == "MIPS":
                self.set_option("CONFIG_MIPS_MT_DISABLED",2)
                self.set_option("CONFIG_SYS_SUPPORTS_MULTITHREADING",0)
            self.set_option("CONFIG_SMP",0)
        
        if ARCH== "ARM" and release >= "ARMv5":
                #self.set_option("CPU_V6K",2)
            if release > "ARMv5":
                self.set_option("CONFIG_CPU_ARM926T",0)
                self.set_option("CONFIG_CPU_32v5",0)
            if release == "ARMv6":
                self.set_option("REALVIEW_EB_A9MP",0)
                self.set_option("MACH_REALVIEW_PBA8",0)
                self.set_option("CONFIG_CPU_V7",0)
                if "p2v8" not in ver_magic:
                    self.set_option("CONFIG_REALVIEW_HIGH_PHYS_OFFSET",0)
                    self.set_option("CONFIG_ARM_PATCH_PHYS_VIRT",0)

            if release == "ARMv7":
                self.set_option("CONFIG_MACH_REALVIEW_PB1176",0)
                self.set_option("CONFIG_MACH_REALVIEW_PB11MP",0)
                self.set_option("CONFIG_REALVIEW_EB_ARM11MP",0)
                self.set_option("CONFIG_CPU_V6",0)
                self.set_option("CONFIG_CPU_V6K",0)
                if "p2v8" not in ver_magic:
                    self.set_option("CONFIG_REALVIEW_HIGH_PHYS_OFFSET",0)

    def get_min_value(self, select_list):
        min_value = 2
        for select in select_list:
            if isinstance(select, tuple):
                value = expr_value(select[0])
            else:
                value = select.tri_value
            if value < min_value:
                min_value = value

        return min_value
    
########################### Core Value Setting Function ###############################
# This function is responsible for setting the value of an option in the kconf tree and
# subsequently to .config. First check if the option is related to the upstream modules
# we have to compile and if yes set the option to 1 if value > 1
########################################################################################

    def set_option_value(self, option, value, overwrite=False):
        if option not in self.kconf.syms.keys():
            print("Option", option, "does not exist")
            return
        if self.arch == "arm" and option == "GPIOLIB":
            return
        if isinstance(value, str):
            self.kconf.syms[option].set_value(value)
            return
        if not overwrite:
            if "CONFIG_" + option in self.module_configs and self.kconf.syms[option].tri_value == 1 and value > 1:
                print("Trying to set a module_config option")
                return 
        #    self.kconf.syms[option].set_value(1)
        print("In set_option_value...setting sym option",option," to value", value)
        self.kconf.syms[option].set_value(value)
        print("New value of option", option," is", self.kconf.syms[option].tri_value)

        #else:
        #    select_deps_value = self.get_min_value(self.kconf.syms[option].selects)
        #    print("Option", option, "has a min value for selects", select_deps_value)
        #    if select_deps_value > 0:
        #        self.kconf.syms[option].set_value(min(select_deps_value, int(value)))
        #    else:
        #        self.kconf.syms[option].set_value(int(value))


########################### Core Option Setting Function ###############################
# This function is responsible for calling the KCRE algorithm to set and option along 
# with its dependencies
########################################################################################
    
    def set_option(self,conf_opt,value, overwrite=False):

            conf_opt = conf_opt.replace("subst m,y,$(","").strip("+=")
            if (conf_opt != "IKCONFIG_PROC"):
                option = conf_opt.replace("CONFIG_","")
            else:
                option = conf_opt
            
            if option == "XFRM" and value > 0:
                option = "INET_XFRM_MODE_TUNNEL"
            
            ### This is for old kernels that have NF_CONNTRACK_ENABLED
            if option == "NF_CONNTRACK" and value > 0 and "NF_CONNTRACK_ENABLED" in self.kconf.syms:
                self.set_option_value("NF_CONNTRACK_ENABLED", 2, overwrite)
                #self.kconf.syms["NF_CONNTRACK_ENABLED"].set_value(2)
            
            print("Setting Option",option,conf_opt,"to value",value)
            
            try:
                sym = self.kconf.syms[option]
            except:
                print("Conf option",option,"does not exist in the tree")
                return

            if isinstance(sym,(Symbol,Choice)):
                print("Symbol:", sym.name, "Is assignable:", sym.assignable,\
                    "Is visible:", sym.visibility,"Dependency:", expr_str(sym.direct_dep))            
                # Some immediate setting of valuess

                if sym.tri_value == value:
                    print("SYMBOL",sym.name,"already has value",value)
                    return

                if value == 0:
                    self.set_option_value(sym.name, 0)
                    #sym.set_value(0)
                    return

                if value not in range(0,4):
                    self.set_option_value(sym.name, value)
                    #sym.set_value(value)
                    return
                
                #Type is bool and we might try to set to m...Just set it to y
                if sym.type == BOOL:
                    if value == 1:
                        print("Type of symbol", sym.name, "is bool thus the value cannot be set to 1")
                        #self.set_option_value(sym.name, 2, args)
                        #sym.set_value(2)
                        return

                if value in sym.assignable:
                    print("The value {0} can be set directly for {1}...Setting the value".format(value, option))
                    self.set_option_value(sym.name, value, overwrite)
                    print ("Config string to write to the .config file for option {0} is {1} and new visibility {2}".format(sym.name, sym.config_string, sym.visibility))
                    #sym.set_value(value)
                    return
                
                # Everything else did not work so its time to fix the deps
                deps = expr_str(sym.direct_dep)
                # Change the dependency conditional to CNF
                #expression = to_cnf( "(" + deps.replace("!","~").replace("&&","&").replace("||","|") + ")") 
                #deps_cond = str(expression).replace("~","!").replace("&","&&").replace("|","||")
                # Now parse the dependency expression again with Kconfiglib and then try to satisfy it
               # self.filename = None
               # self.kconf._tokens = img_inst.kconf._tokenize("if " + deps_cond.replace("CONFIG_",""))
                #img_inst.kconf._line = deps_cond.replace("CONFIG_","")
                #img_inst.kconf._tokens_i = 1
                #deps_expression = img_inst.kconf._expect_expr_and_eol()
                # Now try to satisfy the dependencies
                #img_inst._split_expr_info(sym,deps_expression)
                
                self._split_expr_info(sym,sym.direct_dep)
                print("Dependencies of {} have value {}".format(sym.name,expr_value(sym.direct_dep)))
                
                
                if sym.visibility == 0:
                    print("Still not visible... trying to set symbol",sym.name,"by using its reverse dependencies (selected by)")
                    self.set_undefined_option(sym,value, overwrite)
                    #sym.set_value(value)
                else:
                    self.set_option_value(sym.name, min(value, sym.visibility), overwrite)
                    #sym.set_value(min(value,sym.visibility))

                print ("Config string to write to the .config file for option {0} is {1} and new visibility {2}, assignable {3}".format(sym.name, sym.config_string, sym.visibility, sym.assignable))
            # Case of a choice
                if sym.choice:
                    parent = sym.choice
                    # Disable the rest of the choices... Might not be needed
                    for sym in parent.syms:
                        if sym is not parent.user_selection and sym.visibility:
                            self.set_option_value(sym.name, 0, overwrite)
                            #sym.set_value(0)
                        else:
                            continue

################# Function to force the setting of an option ##########################
# When we cant set an option with KCRE try to force it by enabling the options that
# select it (VERY DANGEROUS!!!)
#######################################################################################

    def set_undefined_option(self,opt,value, overwrite=False):
        if (opt.type != TRISTATE  and value == 1) or opt.name not in self.kconf.syms:
            print("Option ", opt.name, "is bool and cannot be set to 1")
            return
        rev_deps = opt.rev_dep
        print("Reverse dependencies of symbol", opt.name, "are", expr_str(rev_deps))
        # First break the slected by condition in term of ORs
        or_break = self.split_expr(rev_deps,OR)
        # Now for each one of the expressions break in term of AND and see if
        # symbol or the subexpression can be set to one
        # We wont break any further cause things are going to get complicated
        for subexpr in or_break:
            print("Checking REV dep", expr_str(subexpr))
            if expr_value(subexpr) == 0 and value == 0:
                print("REV dep", expr_str(subexpr), "is already 0")
                continue
            #if expr_value(rev_deps) > 0:
                #break
            and_break = self.split_expr(subexpr,AND)
            for term in and_break:
                # If we have a subexpression check if its value is above 0
                # If yes continue to other terms if not just abort
                if isinstance(term,tuple):
                    print("Removing tuple", expr_str(term))
                    if expr_value(term) == 0:
                        break
                    else:
                        continue
                # If the term is just a symbol just check if its deps are above 0
                # then try to set it else abort
                elif isinstance(term,(Symbol,Choice)):
                    print("Looking at the rev dep of",opt.name,":", term.name, "with_value", term.tri_value)
                    if (term.tri_value > 0 and value > 0 and value != term.tri_value and opt.tri_value != value):
                        if not term.name:
                            continue
                        print("Setting the rev dep",term.name,"for symbol",opt.name,"with assignability",term.assignable,"to value",value)
                        self.set_option_value(term.name, value, overwrite)
                        if term.tri_value != value:
                            print("Still not equal to value", value, " ... trying to set symbol",term.name,"by using its reverse dependencies (selected by) to value", value)
                            self.set_undefined_option(term,value, overwrite)
                            #term.set_value(value)
                        if expr_value(subexpr) > 0:
                            break
                    elif (expr_value(term.direct_dep) >= 0 and term.tri_value == 0 and value == 1):
                        if not term.name:
                            continue
                        print("Setting the rev dep",term.name,"for symbol",opt.name,"with assignability",term.assignable,"to value",value)
                        self.set_option_value(term.name, value, overwrite)
                        if term.tri_value != value:
                            print("Still not equal to value", value, " ... trying to set symbol",term.name,"by using its reverse dependencies (selected by) to value", value)
                            self.set_undefined_option(term,value, overwrite)
                        if expr_value(subexpr) > 0:
                            break
                    elif (expr_value(term.direct_dep) > 0 and term.tri_value == 0 and value > 0):
                        print("Setting the rev dep",term.name,"for symbol",term.name,"with assignability",term.assignable, "and current value", term.tri_value)
                        if value in term.assignable:
                            self.set_option_value(term.name, value, overwrite)
                            #term.set_value(value)
                        else:
                            print("Setting to the value of direct dep", expr_str(term.direct_dep))
                            self.set_option_value(term.name, expr_value(term.direct_dep))
                            #term.set_value(expr_value(term.direct_dep))
                    elif (expr_value(term.direct_dep) > 0 and term.tri_value > 0 and value ==0):
                        if term.name and (term.name == "NET" or term.name == "INET"):
                            continue
                        print("Setting the rev dep",term.name,"for symbol",opt.name,"with assignability",term.assignable,"to value",value)
                        if value in term.assignable:
                            #self.set_option_value(term.name, value, args)
                            term.set_value(value)
                            if value in opt.assignable:
                                self.set_option_value(opt.name, value, True)
                                #opt.set_value(value)
                                return
                        if term.tri_value != value:
                            print("Still not equal to value", value, " ... trying to set symbol",term.name,"by using its reverse dependencies (selected by) to value", value)
                            self.set_undefined_option(term,value, True)

                if opt.tri_value == value:
                    print("Value of", opt.name,"is", opt.tri_value, "same as", value, "...Returning")
                    return
        
        if opt.visibility > 0:
            self.set_option_value(opt.name, value, overwrite)
            #opt.set_value(value)

########################### Function to set the existing upstream modules ############################# 
# Set all the upstream modules that have a corresponding custom module to value M
########################################################################################################

    def set_upstream_modules(self,module_configs):
        print("Setting options related to custom modules to M")
        for opt in module_configs:
            option = opt.replace("CONFIG_","")
            try:
                sym = self.kconf.syms[option]
            except:
                print("Conf option",option,"does not exist in the tree")
                continue
            
            if isinstance(sym,(Symbol,Choice)):
                print("Symbol:", sym.name, "Is assignable:", sym.assignable,\
                    "Is visible:", sym.visibility,"Dependency:", expr_str(sym.direct_dep), "and curr value", sym.tri_value)            
                # Some immediate setting of valuess

                if sym.tri_value != 1:
                    self.set_option(sym.name,1)
                    if sym.tri_value != 1: 
                        self.set_option_value(sym.name, 1)
                        #sym.set_value(1)

######################################## End of Image Class #############################################

########################### Function to find the existing upstream modules ############################# 
# For all the custom modules in the set find the Config options that enable their upstream
# counterpart modules in the kernel
########################################################################################################

def find_custom_module_options(modulez):
    
    print("Finding the config options pertaining to the counterpart upstream modules of the custom modules")
    #run cscope -> take the first file with definition -> return the whole path + file
    module_options = []
    for mod in modulez:
        module = mod.split("/")[-1].replace(".ko",".o")
        option = ""
        cscope = 'cscope -d -L6"{0}"'.format(module)
        try:
            option = subprocess.check_output(cscope, shell=True).decode("utf-8")
        except:
            print("The module",module,"does not exist in the upstream kernel source")
            continue
        
        opt = ""
        options = option.split("\n")
        for line in options:
            token = line.split(" ")[-1]
            if token == module:
                opt = line

        if opt != "":
            if "subst" in opt:
                opt_temp =opt.replace("obj-$(subst y,","")
                opt_temp =opt_temp.replace("$(subst m,y,","")
                match = re.findall('\$\(.*?\)',opt_temp)
                print("MATCH",match)
                for m in match:
                    conf_opt = m.strip("$()")
                    if conf_opt not in module_options:
                        module_options.append(conf_opt)

            else:
                conf_opt = opt.split("-")[1].split(")")[0].strip("$(")
            #if module not in vanilla_modules:
                #vanilla_modules.append(module)
                if conf_opt not in module_options:
                    module_options.append(conf_opt)
    
    print("Module options",module_options)
    #mod_opts = list(map(lambda x:x.replace("CONFIG_",""),module_options))

    return module_options

def def_and_set(kconf,image,kernel,ver_magicz,unknown,endianess,arch,modulez,resultdir,seen_opt,module_configs,guard_options,ds_options):
    
    print("Version Magic",ver_magicz)
    
    img_inst = Image(kconf,image, module_configs, arch)
    
    # In case the custom netfilter modules do not exist enable
    # them as part of the FS kernel proper (In general needed by images)
    module_names = list(map(lambda x:x.split("/")[-1],modulez))
    
    # Check for some core netfilter modules
    # This is to please Firmadyne and could be removed for FS
    flag = False
    for indx,mod in enumerate(core_nf_modules):
        if mod in module_names:
            flag = True
            break

    for indx,mod in enumerate(core_nf_modules):
        if flag == False:
            img_inst.set_option(core_nf_options[indx],2)
        else:
            img_inst.set_option(core_nf_options[indx],1)
    
    #TODO: Have a check each time an option is enabled: We only 
    ### enable the option, its deps and whatever they "select"
    ### Any additional option that is enabled by default should be disabled
    #if arch == "mips":
    #    img_inst.set_option("BRIDGE",2)
            ### This option is enabled by default when enabling NETFILTER with BRIDGE
            ### We do not want that because this behavior is not controlled by KCRE
    #    img_inst.set_option("BRIDGE_NETFILTER", 0)
    #elif arch == "arm":
    #    if "CONFIG_BRIDGE" in seen_opt or "CONFIG_BRIDGE" in guard_options:
    #        img_inst.set_option("BRIDGE",2)
                ### This option is enabled by default when enabling NEFILTER with BRIDGE
                ### We do not want that because this behavior is not controlled by KCRE
    #        img_inst.set_option("BRIDGE_NETFILTER",0)

    # Good place to set the upstream modules to M
    img_inst.set_upstream_modules(module_configs)

    for opt in seen_opt:
        if "CONFIG_" not in opt:
            continue
        img_inst.set_option(opt,2)
    
    # Options for Emulation debugging and Firmadyne
    # Need to clean this up and maybe not enable all
    # of these
    img_inst.set_option("CONFIG_FIRMADYNE",2)
    img_inst.set_option("CONFIG_MODULE_SRCVERSION_ALL",0)
    img_inst.set_option("CONFIG_LOCALVERSION_AUTO",0)

    ### Somehow this option prevents the kernel from booting
    ### the QEMU image in these kernels 
    if kernel > "linux-3.10.0":
        img_inst.set_option("CONFIG_GPIOLIB",0)
    img_inst.set_option("CONFIG_DEBUG_INFO",2)
    img_inst.set_option("CONFIG_MTD",2)
    img_inst.set_option("CONFIG_MTD_PARTITIONS",2)
    img_inst.set_option("CONFIG_MTD_NAND",2)
    img_inst.set_option("CONFIG_MTD_NAND_NANDSIM",2)
    img_inst.set_option("CONFIG_SERIAL_8250_EXTENDED",2)
    img_inst.set_option("CONFIG_SERIAL_8250_PCI",2)
    img_inst.set_option("CONFIG_SERIAL_8250_CONSOLE",2)
    img_inst.set_option("CONFIG_SERIAL_8250_MANY_PORTS",2)
    img_inst.set_option("CONFIG_SERIAL_8250_RSA",2)
    img_inst.set_option("CONFIG_BLK_DEV_INITRD",2)
    img_inst.set_option("CONFIG_BLK_DEV_RAM",2)
    
    # Also enabled in malta_defconfig so we enable them
    # as well
    #img_inst.set_option("CONFIG_EMBEDDED",2)
    img_inst.set_option("CONFIG_PROC_FS",2)
    img_inst.set_option("CONFIG_SYSFS",2)
    img_inst.set_option("CONFIG_SHMEM",2)
    img_inst.set_option("CONFIG_TMPFS",2)
    
    img_inst.set_option("CONFIG_ZONE_DMA",0)
    img_inst.set_option("CONFIG_SOUND",0)
    img_inst.set_option("CONFIG_UEVENT_HELPER_PATH","")
    img_inst.set_option("CONFIG_CMDLINE","")
    img_inst.set_option("CONFIG_CMDLINE_OVERRIDE",0)
    img_inst.set_option("CONFIG_EMBEDDED",2)

    ### This is a bug...While KCRE sees that this is value y
    ### it writes in .config value m
    if arch == "arm":
        try:
            if img_inst.kconf.syms["NEW_LEDS"].tri_value == 2:
                img_inst.set_option("CONFIG_LEDS_CLASS",2, True)
        except:
            pass

# Copied the code from eval_string in kconfiglib
    for guard in guard_options:
        img_inst.filename = None
        img_inst.kconf._tokens = img_inst.kconf._tokenize("if " + guard.replace("CONFIG_",""))
        img_inst.kconf._line = guard.replace("CONFIG_","")
        img_inst.kconf._tokens_i = 1
        expression = img_inst.kconf._expect_expr_and_eol()
        img_inst._split_expr_info(expression,expression)
    
# Enable the options for the Data Structure alignment 
    for opt in ds_options:
        img_inst.filename = None
        img_inst.kconf._tokens = img_inst.kconf._tokenize("if " + opt.replace("CONFIG_",""))
        img_inst.kconf._line = opt.replace("CONFIG_","")
        img_inst.kconf._tokens_i = 1
        expression = img_inst.kconf._expect_expr_and_eol()
        img_inst._split_expr_info(expression,expression)
    
    
    img_inst.set_option("CONFIG_VGA_CONSOLE",0)
    img_inst.set_option("CONFIG_VIDEO_IVTV",0)
    
    img_inst.set_option("IDE",2, "override")
    img_inst.set_option("CONFIG_BLK_DEV_IDEDISK",2, True)
    img_inst.set_option("CONFIG_IDE_GENERIC",2, True)
    img_inst.set_option("CONFIG_IDE_GD",2, True)
    img_inst.set_option("BLK_DEV_PIIX",2, True)
    img_inst.set_option("EXT2_FS",2, True)
    img_inst.set_option("CONFIG_MODULE_FORCE_LOAD",2, True)
    img_inst.set_option("CONFIG_EXT2_FS_POSIX_ACL",0, True)
    ### Annoying debugging printouts for PREEMPT...Disable this
    img_inst.set_option("CONFIG_DEBUG_PREEMPT",0, True)
    
    img_inst.set_ver_magic(ver_magicz)
    img_inst.set_option("CONFIG_HZ_250",2)
    
    if arch == "arm":
        if "ARMv5" in ver_magicz:
            img_inst.set_option("CONFIG_SCSI_SYM53C8XX",2, True)
            img_inst.set_option("CONFIG_SCSI_SYM53C8XX_2",2, True)
        if "CONFIG_ARM_UNWIND" not in seen_opt and "CONFIG_ARM_UNWIND" not in guard_options and kernel < "linux-3.10":
            img_inst.set_option("CONFIG_ARM_UNWIND",0)
        img_inst.set_option("CONFIG_SCSI",2, True)
        img_inst.set_option("CONFIG_BLK_DEV_SD",2, True)
        img_inst.set_option("CONFIG_VT",0)
        img_inst.set_option("CONFIG_VIDEO_DEV",0)
        img_inst.set_option("CONFIG_MMC",2, True)
        img_inst.set_option("CONFIG_MMC_BLOCK",2,True)
        img_inst.set_option("CONFIG_MMC_ARMMCI",2,True)
        img_inst.set_option("CONFIG_SMC91X",0,True)
        img_inst.set_option("CONFIG_MMU",2,True)
    
    if img_inst.arch == "mips" and kernel < "linux-4.0":
        img_inst.set_option("CONFIG_CC_STACKPROTECTOR_REGULAR", 0)
        img_inst.set_option("CONFIG_CC_STACKPROTECTOR_NONE", 2)
    
    if arch == "mips":
        if endianess == "little endian":
            img_inst.set_option("CPU_LITTLE_ENDIAN",2)
        else:
            img_inst.set_option("CPU_BIG_ENDIAN",2)
    
    print ("OPTIONS\n",seen_opt)

    print("GUARDS\n",guard_options)
    
    print("DS OPTIONS\n",ds_options)

    print("Module Config", img_inst.module_configs)
    
    try:
        img_inst.kconf.write_config()
    except:
        print("Kconfig write failed")

    print("KERNEL is", kernel)
    ### Return the kconf object so that we can store it
###########################################################################################

################################### Interface to KCRE ####################################
# This function will call the KCRE algorithm to enable the options in the .config file
##########################################################################################

def update_config(image,kernel,kern_dir,resultdir,unknown,ver_magicz,endianess,arch,modulez,seen_opt,guard_options,module_configs, ds_options):
    ### Change Dir to the kernel sources we will use ###
    cwd = os.getcwd()
    os.chdir(kern_dir)
    # Load Kconfig file 
    kconf = Kconfig("Kconfig", warn = False, warn_to_stderr = False)
    kconf.load_config(filename=kern_dir + ".config")
    
   # guard_options = []
    #module_configs = find_custom_module_options(modulez)
    not_mod_options = []
    for opt in ds_options:
        if opt not in module_configs:
            not_mod_options.append(opt)

    upd_kconf = def_and_set(kconf,image,kernel,ver_magicz,unknown,endianess,arch,modulez,resultdir,seen_opt,module_configs,guard_options,not_mod_options)
   
    ### Change to default directory ##
    os.chdir(cwd)
    
    #print(type(upd_kconf))

   
