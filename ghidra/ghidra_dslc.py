#!/usr/bin/env python2
# Examples of basic Ghidra scripting in Python
# @category: Examples.Python

from __future__ import print_function
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.app.decompiler import DecompileOptions, DecompInterface, \
                                    PrettyPrinter, ClangToken, ClangTokenGroup
from ghidra.util import Conv
from binascii import hexlify
from ghidra.app.merge.listing import *
from ghidra.program.model.listing import *
from ghidra.program.model.pcode import HighFunctionDBUtil, \
                                    VarnodeTranslator, PcodeOp
from ghidra.program.model.symbol import SourceType
from ghidra.program.database.symbol import *
import sys,os
from ghidra.program.util import SymbolicPropogator, ProgramContextImpl, VarnodeContext
import json
from collections import OrderedDict
from ghidra.app.decompiler.component import DecompilerUtils
from ghidra.program.model.listing.CodeUnitFormatOptions \
                                    import ShowBlockName;
from ghidra.program.model.listing.CodeUnitFormatOptions \
                                    import ShowNamespace;
from ghidra.program.model.block import SimpleBlockModel, \
                                    BasicBlockModel
from ghidra.program.model.lang import OperandType
from ghidra.app.decompiler.component import DecompilerUtils, \
                                            DecompilerPanel, DecompilerController
from java.util import ArrayList
import traceback

#### Command number reverse engineering functions
#### Taken from the linux kernel


listing = currentProgram.getListing()
monitor = ConsoleTaskMonitor()
language = str(currentProgram.getLanguage().getProcessor())
lang = currentProgram.getLanguage()
programContext = ProgramContextImpl(lang)
spaceContext = ProgramContextImpl(lang)
context = VarnodeContext(currentProgram, programContext, spaceContext)

param_dict = dict()
variable_refs = OrderedDict()
param_refs = OrderedDict()
param_names = []
param_types = dict()
seen = []
mem_related = ["INT_ADD", "PTRADD", "PTRSUB", "STORE", "LOAD", "CAST", "INT_SUB"]

########################### helper functions ############################

def findTokensByName(name, group):
    tokens = ArrayList()
    tokens = doFindTokensByName(tokens, group.getCCodeMarkup(), name)
    return tokens

def doFindTokensByName(tokens, group, name):
    for i in range(0, group.numChildren()):
        child = group.Child(i)
        if isinstance(child, ClangTokenGroup):
            tokens = doFindTokensByName(tokens, child, name)
        elif isinstance(child, ClangToken):
            token = child
            if str(name) == str(token.getText()):
                tokens.add(token)
    return tokens

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
    return high,res

def is_load_store(mnemonic):
    if mnemonic not in mem_related:
        return False
    return True
  #flag_ld_st = False
  #flag_call = False
  #for op in ops:
     #operation = op.getMnemonic()
     #if operation == "LOAD" or operation == "STORE":
        #flag_ld_st = True
     #if "CALL" in operation or "BRANCH" in operation:
        #flag_call = True
  #if flag_ld_st == True:
     #return True
  #else:
     #return False


def dump_refined_pcode(func, high_func, decompres):
    setCurrentLocation(func.getEntryPoint())
    HighFunctionDBUtil.commitParamsToDatabase(high_func, True,
                                            SourceType.DEFAULT)
    params = func.getParameters()
    for param in params:
        param_names.append(param.getName())

    ### First get the local symbols (These contain the accurate varnode
    ### for the arguments)
    lsm = high_func.getLocalSymbolMap()
    symbols = lsm.getSymbols()
    for sym in symbols:
        param_types[sym.getName()] = str(sym.getDataType())
        tokens = findTokensByName(sym.getName(), decompres)
        param_dict[sym.getName()] = []
        for token in tokens:
            minAddr = token.getMinAddress()
            if not minAddr:
                continue
            instr = listing.getInstructionAt(minAddr)
            if not instr:
                continue
            
            token_op_mnemonic = token.getPcodeOp().getMnemonic()
            ops = instr.getPcode()
            if not is_load_store(token_op_mnemonic):
                continue

            op_num = instr.getNumOperands()
            if op_num < 2:
                continue
            if OperandType().isAddress(instr.getOperandType(1)):
                continue

            try:
                op_objs = instr.getOpObjects(2)
            except:
                pass
            if not op_objs:
                op_objs = instr.getOpObjects(1)

            if len(op_objs) < 2:
                continue
            token_vnode = token.getVarnode()
            register = currentProgram.getRegister(token_vnode)
            inputs = instr.getInputObjects()
            
            if token_vnode == token.getPcodeOp().getOutput():
                if sym.getName() in param_names:
                    if sym.getName() not in param_refs.keys():
                        param_refs[sym.getName()] = []
                    param_refs[sym.getName()].append([str(instr), str(instr).split()[0], "O", 0])
                else:
                    if sym.getName() not in variable_refs.keys():
                        variable_refs[sym.getName()] = []
                    variable_refs[sym.getName()].append([str(instr), str(instr).split()[0], "O", 0])

            if token_vnode in token.getPcodeOp().getInputs():
                offset = 0
                if str(token_op_mnemonic) == "PTRADD":
                    high_op_inputs = token.getPcodeOp().getInputs()
                    if high_op_inputs[-1].isConstant() and high_op_inputs[-2].isConstant():
                        offset = context.getConstant(high_op_inputs[-1],None) * context.getConstant(high_op_inputs[-2], None)
                    elif high_op_inputs[-1].isConstant():
                        offset = context.getConstant(high_op_inputs[-1],None)
                    elif high_op_inputs[-2].isConstant():
                        offset = context.getConstant(high_op_inputs[-2],None)
                if str(token_op_mnemonic) == "INT_ADD":
                    high_op_inputs = token.getPcodeOp().getInputs()
                    if high_op_inputs[-1].isConstant():
                        offset += context.getConstant(high_op_inputs[-1],None)
                elif str(token_op_mnemonic) == "INT_SUB":
                    high_op_inputs = token.getPcodeOp().getInputs()
                    if high_op_inputs[-1].isConstant():
                        offset += context.getConstant(high_op_inputs[-1],None)
                elif str(token_op_mnemonic) == "PTRSUB":
                    high_op_inputs = token.getPcodeOp().getInputs()
                    if high_op_inputs[-1].isConstant() and high_op_inputs[-2].isConstant():
                        offset = context.getConstant(high_op_inputs[-1],None) * context.getConstant(high_op_inputs[-2], None)
                    elif high_op_inputs[-1].isConstant():
                        offset = context.getConstant(high_op_inputs[-1],None)
                    elif high_op_inputs[-2].isConstant():
                        offset = context.getConstant(high_op_inputs[-2],None)
                    #iter = high_func.getPcodeOps(minAddr)
                    #while iter.hasNext():
                        #high_op = iter.next()
                        #operation = high_op.getMnemonic()
                        #if str(operation) == "PTRSUB" or str(operation) == "INT_SUB":
                            #offset += context.getConstant(high_op.getInputs()[-1],None)
                elif str(token_op_mnemonic) == "CAST":
                    iter = high_func.getPcodeOps(minAddr)
                    while iter.hasNext():
                        high_op = iter.next()
                        operation = high_op.getMnemonic()
                        if str(operation) == "INT_ADD" or str(operation) == "INT_SUB":
                            if high_op.getInputs()[-1].isConstant():
                                offset += context.getConstant(high_op.getInputs()[-1],None)
                elif str(token_op_mnemonic) == "STORE":
                    flag = False
                    iter = high_func.getPcodeOps(minAddr)
                    while iter.hasNext():
                        high_op = iter.next()
                        operation = high_op.getMnemonic()
                        if high_op == token.getPcodeOp():
                            flag = True
                        if flag == True and str(operation) == "INT_ADD" or str(operation) == "INT_SUB":
                            if high_op.getInputs()[-1].isConstant():
                                offset += context.getConstant(high_op.getInputs()[-1],None)
                elif str(token_op_mnemonic) == "LOAD":
                    flag = False
                    iter = high_func.getPcodeOps(minAddr)
                    while iter.hasNext():
                        high_op = iter.next()
                        operation = high_op.getMnemonic()
                        if high_op == token.getPcodeOp():
                            flag = True
                        if flag == True and str(operation) == "INT_ADD" or str(operation) == "INT_SUB":
                            if high_op.getInputs()[-1].isConstant():
                                offset += context.getConstant(high_op.getInputs()[-1],None)
                if sym.getName() in param_names:
                    if sym.getName() not in param_refs.keys():
                        param_refs[sym.getName()] = []
                    param_refs[sym.getName()].append([str(instr), str(instr).split()[0], "I", offset])
                else:
                    if sym.getName() not in variable_refs.keys():
                        variable_refs[sym.getName()] = []
                    variable_refs[sym.getName()].append([str(instr), str(instr).split()[0], "I", offset])

def main():
    args = getScriptArgs()
    #print (args)
    function_name = str(args[0])
    #function_name = str("nf_conntrack_helper_register")
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

    hf,res = get_high_function(function)
    dump_refined_pcode(function,hf,res)
    #for val in param_dict:
        #print("Variable", val)
        #print(param_dict[val])
    print("Param references")
    print(json.dumps(param_refs))
    print("Variable references")
    print(json.dumps(variable_refs))
    print("Param types")
    print(json.dumps(param_types))

if __name__ == "__main__":
    main()



