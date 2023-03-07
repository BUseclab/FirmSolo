#!/usr/bin/env python3


import os
import sys
currentdir = os.path.dirname(os.path.realpath(__file__))
parentdir = os.path.dirname(currentdir) 
sys.path.append(parentdir)
from stage1.cpp import *
import ply.lex as lex
from anytree import NodeMixin,RenderTree
import re
from sympy.logic import simplify_logic
from sympy.logic.boolalg import to_cnf


directives = ["ifdef","ifndef","if","elif","else"]
start_cond = ["ifdef","ifndef","if"]
interm_cond = ["elif","else"]


### Tree Node
class AST(NodeMixin):
    def __init__(self,directive,cond,export=None,next_node=None,parent=None,children=None):
        self.directive = directive
        self.cond = cond
        self.next_node = next_node
        self.export= export
        self.parent=parent
        if children:
            self.children = children

### Parser of directives
class Parse:
    def __init__(self,cfile):
        self.lexer = lex.lex()
        self.cfile = cfile
        self.file = open(cfile,errors='ignore')
        self.input = self.file.read()
        self.p = Preprocessor(self.lexer)
        self.tree = AST("root","")
        self.mapping = {}

    def parse_input(self):
        self.p.parse(self.input,self.file)
        while True:
            tok = self.p.token()
            if not tok: break
    
    ### Recreate the line from the lexer tokens
    def get_line(self,indx):
        token_list = self.p.conditionalz[indx]
        line = ""
        for token in token_list:
            if token.value == '0L':
                line += ""
            else:
                if token == token_list[0]:
                    line += token.value + " "
                else:
                ### Leave a space in case there isnt one
                ### Without this the execution is going to break
                    line += token.value
            line_num = token.lineno
        
        if "defined\\s" in line:
            line = line.replace("defined\\s","").strip(";\n")
        elif "defined" in line:
            line = line.replace("defined","").strip(";\n")
        elif "IS_ENABLED" in line:
            line = line.replace("IS_ENABLED(","").replace(")","")
        else:
            line = line.strip(";\n")
        
        return line, line_num
    
    #def cond_update(self, line, cond):
        #try:
            #self.mapping(line) += "&& {0}".format(cond)
        #except:
            #self.mapping(line) = cond
    
    ## Parser for inner blocks which is recursive
    def block_parse(self,indx,level,parent):
        while indx < len(self.p.conditionalz):
            line,line_num = self.get_line(indx)
            tokens = line.split()
            
            ### When we encounter an if directive then we
            ### parse until the end of the whole block
            ### In case of another if directive we enter the
            ### recursive mode
            if tokens[0] in directives:
                if tokens[0] != "else":
                    if tokens[0] == "ifndef":
                        condition = "!(" + " ".join(tokens[1:]) + ")"
                    else:
                        condition = " ".join(tokens[1:])
                ### The else directive is a special case, which 
                ### will be handled when the tree is parsed for the
                ### last time
                else:
                    condition = ""
                        
                block = AST(tokens[0],condition)
             #   print("Creating new block",block.directive,block.cond,"Level",level)
                block.export = []
                level += 1
                # Start parsing until the end of the block
                # We assume that the blocks are ended correctly
                indx += 1 
                line,line_num = self.get_line(indx)
                tokens = line.split()
                #while tokens[0] not in start_cond and tokens[0] not in interm_cond:
                while True:
                    if "EXPORT_SYMBOL" in line:
                        block.export.append(line)
                    elif tokens[0] in start_cond:
                        block,indx,level = self.block_parse(indx,level,block)
                        #block.children.append(child)
                    elif "endif" in line:
                        ## This is the end of the block so put
                        ## it to the parent and continue parsing
              #          print(block.directive,block.cond,block.export,"Level",level,"with parent",parent.directive,parent.cond)
                        level -= 1
                        #print(block)
                        block.parent = parent
                        return parent,indx,level
                    elif tokens[0] in interm_cond:
                        # We found an intermediate directive
                        # so leave the while 
                        block.parent = parent
               #         print(block.directive,block.cond,block.export,"Level",level)
                        level -= 1
                        break
                    # Parse the next line
                    indx += 1
                    if indx >= len(self.p.conditionalz):
                        break
                    line,line_num = self.get_line(indx)
                    tokens = line.split()


    ### Start parsing the top level conditionals
    ## Parser for the outer blocks which is sequencial
    def parse_conditionals(self):
        indx = 0
        level = 0
        while indx < len(self.p.conditionalz):
            line,line_num = self.get_line(indx)
            tokens = line.split()
            
            ### When we encounter an if directive then we
            ### parse until the end of the whole block
            ### In case of another if directive we enter the
            ### recursive mode
            if tokens[0] in directives:
                if tokens[0] != "else":
                    if tokens[0] == "ifndef":
                        condition = "!(" + " ".join(tokens[1:]) + ")"
                    else:
                        condition = " ".join(tokens[1:])
                ### The else directive is a special case, which 
                ### will be handled when the tree is parsed for the
                ### last time
                else:
                    condition = ""
                        
                block = AST(tokens[0],condition)
                #print("Creating new block",block.directive,block.cond,"Level",level)
                block.export = []
                level += 1
                # Start parsing until the end of the block
                # We assume that the blocks are ended correctly
                indx += 1 
                line,line_num = self.get_line(indx)
                tokens = line.split()
                #while tokens[0] not in start_cond and tokens[0] not in interm_cond:
                while True:
                    if "EXPORT_SYMBOL" in line:
                        block.export.append(line)
                    elif tokens[0] in start_cond:
                        block,indx,level = self.block_parse(indx,level,block)
                 #       print("Returned from recursion",block.directive,block.cond)
                        #block.children.append(child)
                    elif "endif" in line:
                        ## This is the end of the block so put
                        ## it to the parent and continue parsing
                  #      print(block.directive,block.cond,block.export,"Level",level)
                        level -= 1
                        block.parent = self.tree
                        indx += 1
                        break
                    elif tokens[0] in interm_cond:
                        # We found an intermediate directive
                        # so leave the while 
                        block.parent = self.tree
                   #     print(block.directive,block.cond,block.export,"Level",level)
                        level -= 1
                        break
                    # Parse the next line
                    indx += 1
                    if indx >=len(self.p.conditionalz):
                        break
                    line,line_num = self.get_line(indx)
                    tokens = line.split()
            
            #### All the EXPORTS outside an if else are not important
            while "EXPORT_SYMBOL" in line and level == 0:
                indx +=1
                if indx >= len(self.p.conditionalz):
                    break
                line,line_num = self.get_line(indx)
        
    def create_dict(self,root,par_cond):
        children = root.children
        cur_cond = ""
        inverted_cond = ""
        for child in children:
            
            if child.directive in start_cond:
                cur_cond = child.cond
                if child.directive == "ifndef":
                    inverted_cond = child.cond.replace("!(","").replace(")","")
                else:
                    inverted_cond = "!(" + child.cond + ")"

                if "CONFIG_" not in child.cond:
                    continue

                for expr in child.export:
                    symbol = expr.replace("EXPORT_SYMBOL","").replace("_GPL","").replace("(","").replace(")","").strip(" ")
                    if par_cond != "":
                        print("PAR COND",par_cond)
                        expression = to_cnf( "(" + par_cond.replace("!","~").replace("&&","&").replace("||","|") + ") & (" + cur_cond.replace("!","~").replace("&&","&").replace("||","|") + ")")
                        #self.mapping[expr] = "(" + par_cond + ") && (" + cur_cond + ")"
                        self.mapping[symbol] = str(expression).replace("~","!").replace("&","&&").replace("|","||")
                    else:
                        expression = to_cnf(cur_cond.replace("!","~").replace("&&","&").replace("||","|"))
                        self.mapping[symbol] = str(expression).replace("~","!").replace("&","&&").replace("|","||")

            
            if child.directive in interm_cond:
                if child.directive == "elif":
                    #cur_cond = "(" + inverted_cond + ") && (" + child.cond + ")"
                    cur_cond = "(" + child.cond + ")"
                    inverted_cond = "(" + inverted_cond + ") && !(" +  child.cond + ")"
                else:
                    cur_cond = inverted_cond
                
                if "CONFIG_" not in child.cond and "CONFIG_" not in inverted_cond:
                    continue
            
                for expr in child.export:
                    symbol = expr.replace("EXPORT_SYMBOL","").replace("_GPL","").replace("(","").replace(")","").strip(" ")
                    if par_cond != "":
                        expression = to_cnf( "(" + par_cond.replace("!","~").replace("&&","&").replace("||","|") + ") & (" + cur_cond.replace("!","~").replace("&&","&").replace("||","|") + ")")
                        #self.mapping[expr] = "(" + par_cond + ") && (" + cur_cond + ")"
                        if symbol in self.mapping.keys():
                            self.mapping[symbol] += " || " + str(expression).replace("~","!").replace("&","&&").replace("|","||")
                        else:
                            self.mapping[symbol] = str(expression).replace("~","!").replace("&","&&").replace("|","||")
                    else:
                        expression = to_cnf(cur_cond.replace("!","~").replace("&&","&").replace("||","|"))
                        if symbol in self.mapping.keys():
                            self.mapping[symbol] += " || " + str(expression).replace("~","!").replace("&","&&").replace("|","||")
                        else:
                            self.mapping[symbol] = str(expression).replace("~","!").replace("&","&&").replace("|","||")

                        
                        #self.mapping[symbol] = str(expression).replace("~","!").replace("&","&&").replace("|","||")
                    #if par_cond != "":
                        #self.mapping[expr] = "(" + par_cond + ") && (" + cur_cond +")"
                    #else:
                        #self.mapping[expr] = cur_cond
            
            if child.children != []:
                self.create_dict(child,cur_cond)
                

if __name__ == "__main__":
    infile = sys.argv[1]

    obj = Parse(infile)
    obj.parse_input()
    obj.parse_conditionals()
    for pre,_,node in RenderTree(obj.tree):
            treestr = u"%s%s" %(pre,node.directive)
            print(treestr.ljust(8),node.cond,node.export)
    #print(RenderTree(obj.tree))
    obj.create_dict(obj.tree,obj.tree.cond)
    print(obj.mapping)
