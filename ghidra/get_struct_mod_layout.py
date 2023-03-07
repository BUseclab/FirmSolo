#!/usr/bin/env python2
# Examples of basic Ghidra scripting in Python
# @category: Examples.Python

from __future__ import print_function
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.app.decompiler import DecompileOptions, DecompInterface, PrettyPrinter
from ghidra.util import Conv
from binascii import hexlify
from ghidra.app.merge.listing import *
from ghidra.program.model.listing import *
from ghidra.program.model.pcode import HighFunctionDBUtil,VarnodeTranslator, PcodeOp
from ghidra.program.model.symbol import SourceType
from ghidra.program.database.symbol import *
import sys,os
from ghidra.program.util import SymbolicPropogator, ProgramLocation
import json
import ghidra.program.model.data.DataTypeDisplayOptions;
from ghidra.program.model.listing.CodeUnitFormatOptions import ShowBlockName;
from ghidra.program.model.listing.CodeUnitFormatOptions import ShowNamespace;
from collections import OrderedDict
from ghidra.app.decompiler.component import DecompilerUtils, DecompilerPanel
from ghidra.app.util import DisplayableEol

listing = currentProgram.getListing()
monitor = ConsoleTaskMonitor()
language = str(currentProgram.getLanguage().getProcessor())
endian = str(currentProgram.getLanguage().getLanguageDescription()).split("/")[1]

def main():
    ### Get the ".gnu.linkonce.this_module" information
    ### because this blocks holds the __this_module
    ### which is essentially the struct module
    memblocks = getMemoryBlocks()
    for block in memblocks:
        if ".gnu.linkonce.this_module" in block.getName():
            start = block.getStart()
            end = block.getEnd()
            size = block.getSize()
            break
    
    current = start
    cu = listing.getCodeUnitAt(current)
    bts = list(cu.getBytes())
    found = []
    if len(bts) == size:
        found = []
        indx = 0
        while indx < size:
            byte = bts[indx]
            if byte != 0x0:
                if endian == "little":
                    temp = []
                    for i in range(2,-1,-1):
                        byte = bts[indx + i]
                        if byte < 0:
                            byte = str(format((byte & ((1 << 8) - 1)),'02x'))
                        else:
                            byte = str(format(byte,'02x'))
                        temp.append(byte.replace("0x",""))
                    found.append([indx,"".join(temp)])
                    found.append([indx,"".join(temp[::-1])])
                else:
                    temp = []
                    for i in range(0,3):
                        byte = bts[indx + i]
                        if byte < 0:
                            byte = str(format(byte & ((1 << 8) - 1),'02x'))
                        else:
                            byte = str(format(byte,'02x'))
                        temp.append(byte.replace("0x",""))
                    found.append([indx-1,"".join(temp)])
                    found.append([indx-1,"".join(temp[::-1])])
                indx = indx+4
                continue
            indx+=1
    else:
        indx = 0
        while indx < size:
            cu = listing.getCodeUnitAt(current)
            bts = list(cu.getBytes())
            if len(bts) > 1:
                current = current.add(len(bts)+1)
                indx += len(bts) + 1
                continue
            byte = hex(bts[0])
            if byte != '0x0':
                if endian == "little":
                    temp = []
                    for i in range(2,-1,-1):
                        new_addr = current.add(i)
                        cu = listing.getCodeUnitAt(new_addr)
                        bts = list(cu.getBytes())
                        byte = bts[0]
                        if byte < 0:
                            byte = str(format(byte & ((1 << 8) - 1),'02x'))
                        else:
                            byte = str(format(byte,'02x'))
                        temp.append(byte.replace("0x",""))
                    found.append([indx,"".join(temp)])
                    found.append([indx,"".join(temp[::-1])])
                else:
                    temp = []
                    for i in range(0,3):
                        new_addr = current.add(i)
                        cu = listing.getCodeUnitAt(new_addr)
                        bts = list(cu.getBytes())
                        byte = bts[0]
                        if byte < 0:
                            byte = str(format(byte & ((1 << 8) - 1),'02x'))
                        else:
                            byte = str(format(byte,'02x'))
                        temp.append(byte.replace("0x",""))
                    found.append([indx-1,"".join(temp)])
                    found.append([indx-1,"".join(temp[::-1])])
                
                current = current.add(4)
                indx = indx+4
                continue
            current = current.add(1)
            indx += 1

    ### Get the init_module, cleanup_module pointers
    ### and the size of struct module
    final_info = {}
    for indx,addr in found:
        address = current.getAddress(addr)
        func = getFunctionAt(address)
        if func:
            if "init" in func.getName():
                final_info["init_module"] = indx
            elif "exit" in func.getName():
                final_info["cleanup_module"] = indx
            else:
                final_info[func.getName()] = indx

    final_info["size"] = size
    print("Module Layout")
    print(json.dumps(final_info))

if __name__ == "__main__":
    main()



