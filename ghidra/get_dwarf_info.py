#!/usr/bin/env python2
# Examples of basic Ghidra scripting in Python
# @category: Examples.Python

from __future__ import print_function
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.app.decompiler import DecompileOptions, DecompInterface
from ghidra.util import Conv
from binascii import hexlify
from ghidra.app.merge.listing import *
from ghidra.program.model.listing import *
from ghidra.program.model.pcode import HighFunctionDBUtil,VarnodeTranslator, PcodeOp
from ghidra.program.model.symbol import SourceType
from ghidra.program.database.symbol import *
import sys,os
from ghidra.program.util import SymbolicPropogator
import json

#### Command number reverse engineering functions
#### Taken from the linux kernel


listing = currentProgram.getListing()
monitor = ConsoleTaskMonitor()

param_dict = dict()
param_refs = dict()

# == helper functions =============================================================================

def get_high_function(func):
    options = DecompileOptions()
    ifc = DecompInterface()
    ifc.setOptions(options)
    ifc.openProgram(getCurrentProgram())
    # Setting a simplification style will strip useful `indirect` information.
    # Please don't use this unless you know why you're using it.
    #ifc.setSimplificationStyle("normalize") 
    res = ifc.decompileFunction(func, 60, monitor)
    high = res.getHighFunction()
    return high

def is_load_store(ops):
  flag_ld_st = False
  flag_call = False
  for op in ops:
     operation = op.getMnemonic()
     if operation == "LOAD" or operation == "STORE":
        flag_ld_st = True
     if "CALL" in operation or "BRANCH" in operation:
        flag_call = True
  if flag_ld_st == True and flag_call == False:
     return True
  else:
     return False


def dump_refined_pcode(func, high_func):
    vnodes_to_check = []
    HighFunctionDBUtil.commitParamsToDatabase(high_func, True, SourceType.DEFAULT)
    params = func.getParameters()
    for param in params:
        dt_type = str(param.getDataType())
        param_vnode = param.getLastStorageVarnode()
        param_dict[param.getName()] = [param_vnode]
        param_refs[dt_type + " " + param.getName()] = []
        instructions = listing.getInstructions(func.getBody(),True)
        while instructions.hasNext():
            instr = instructions.next()
            ops = instr.getPcode()
            for op in ops:
                 inputs = op.getInputs()
                 out = op.getOutput()
                 if out in param_dict[param.getName()]:
                    param_dict[param.getName()].remove(out)
                 for vnode in param_dict[param.getName()]:
                    for inpt in inputs:
                       if vnode.equals(inpt):
                          if op.getOpcode() == PcodeOp.INT_ADD and is_load_store(ops):
                              scalar = instr.getOpObjects(1)
                              param_refs[dt_type + " " + param.getName()].append([str(instr),str(scalar[0])])
                          if op.getOpcode() == PcodeOp.COPY and out.isRegister() and len(ops) == 1:
                              if out not in param_dict[param.getName()]:
                                  param_dict[param.getName()].append(out)

def main():
    args = getScriptArgs()
    #print (args)
    function_name = str(args[0])
    #image = str(args[1])
    #module = str(args[2])
    found = False
    try:
        function = getGlobalFunctions(function_name)[0]
        found = True
    except:
        print("The function is with a section header")
    
    ### The function has its own section...We need to find it
    if not found:
        memblocks = getMemoryBlocks()
        for block in memblocks:
            if ".text.{}".format(function_name) in block.getName():
                createFunction(block.getStart(),block.getName().replace(".text.",""))
                function = getFunctionAt(block.getStart())
                break

    hf = get_high_function(function)
    dump_refined_pcode(function,hf)
    print("Param references")
    print(json.dumps(dict(param_refs)))

if __name__ == "__main__":
    main()



