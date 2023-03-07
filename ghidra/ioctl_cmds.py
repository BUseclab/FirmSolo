#!/usr/bin/env python2
# Examples of basic Ghidra scripting in Python
# @category: Examples.Python


from ghidra.util.task import ConsoleTaskMonitor
from ghidra.app.decompiler import DecompileOptions, DecompInterface
from ghidra.util import Conv
import sys
#### Command number reverse engineering functions
#### Taken from the linux kernel

_IOC_NRSHIFT = 0
_IOC_TYPESHIFT = 8
_IOC_SIZESHIFT = 16
_IOC_DIRSHIFT = 29

_IOC_NRMASK = ((1 << 8) - 1)
_IOC_TYPEMASK = ((1 << 8) -1)
_IOC_SIZEMASK = ((1 << 13) -1)
_IOC_DIRMASK = ((1 << 3) -1)

def IOC_DIR(num):
    return ((num >> _IOC_DIRSHIFT) & _IOC_DIRMASK)

def IOC_TYPE(num):
    return ((num >> _IOC_TYPESHIFT) & _IOC_TYPEMASK)

def IOC_NR(num):
    return ((num >> _IOC_NRSHIFT) & _IOC_NRMASK)

def IOC_SIZE(num):
    return ((num >> _IOC_SIZESHIFT) & _IOC_SIZEMASK)

found_cmds = []

mnemonics = ["INT_EQUAL","INT_NOTEQUAL","INT_LESS","INT_LESSEQUAL"]

# == helper functions =============================================================================
def get_switch_addrs(tables):
    addresses = []
    for table in tables:
        labels = table.getLabelValues()
        addresses += list(map(lambda x:"0x"+Conv.toHexString(x),labels))
    return addresses

def get_high_function(func):
    options = DecompileOptions()
    monitor = ConsoleTaskMonitor()
    ifc = DecompInterface()
    ifc.setOptions(options)
    ifc.openProgram(getCurrentProgram())
    # Setting a simplification style will strip useful `indirect` information.
    # Please don't use this unless you know why you're using it.
    #ifc.setSimplificationStyle("normalize") 
    res = ifc.decompileFunction(func, 60, monitor)
    high = res.getHighFunction()
    return high

def dump_refined_pcode(func, high_func,outfile):
    opiter = high_func.getPcodeOps()
    j_tables = high_func.getJumpTables()
    switch_addresses = get_switch_addrs(j_tables)
    with open(outfile,"a") as f:
        while opiter.hasNext():
            op = opiter.next()
            #if opiter.hasNext() and (op.getMnemonic() in mnemonics )and opiter.next().getMnemonic() == "CBRANCH":
            print("{}".format(op.toString()))
            inputs = op.getInputs()
            if len(inputs) < 2:
                continue
            if inputs[0].isRegister() and inputs[1].isConstant():
                cmd_num = int(inputs[1].getOffset())
                if cmd_num in found_cmds:
                    continue
                if IOC_SIZE(cmd_num) == 0 or IOC_SIZE(cmd_num) == 1 or (IOC_SIZE(cmd_num) % 4) == 0:
                    found_cmds.append(cmd_num) 
                    f.write("{}:{}:{}:{}:{}\n".format(cmd_num,IOC_DIR(cmd_num),IOC_TYPE(cmd_num),IOC_NR(cmd_num), IOC_SIZE(cmd_num)))
        for address in switch_addresses:
            try:
                addr = int(address.replace("ffffffff",""),16)
            except:
                continue
            if addr in found_cmds:
                continue
            if IOC_SIZE(addr) == 0 or IOC_SIZE(addr) == 1 or (IOC_SIZE(addr) % 4) == 0:
                print("SWITCH ADDRESS",addr)
                found_cmds.append(addr) 
                f.write("{}:{}:{}:{}:{}\n".format(addr,IOC_DIR(addr),IOC_TYPE(addr),IOC_NR(addr), IOC_SIZE(addr)))




def main():
    args = getScriptArgs()
    print (args)
    outfile = args[0]
    function = getFirstFunction()
    while function is not None:
            print (function.getName())
            hf = get_high_function(function)            # we need a high function from the decompiler
            dump_refined_pcode(function, hf,outfile)            # dump straight refined pcode as strings
            function = getFunctionAfter(function)


if __name__ == "__main__":
    main()



