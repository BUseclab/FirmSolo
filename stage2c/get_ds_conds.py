#!/usr/bin/env python3


import os, sys
currentdir = os.path.dirname(os.path.realpath(__file__))
parentdir = os.path.dirname(currentdir)
sys.path.append(parentdir)
sys.path.append("{}/stage1/".format(parentdir))
from cpp import *
from custom_utils import *
from multiprocessing import Pool
import subprocess as sb
import ply.lex as lex
import re
import traceback
import pickle
import json
from sympy.logic import simplify_logic
from sympy.logic.boolalg import to_cnf
from collections import deque
from anytree import NodeMixin,RenderTree

directives = ["ifdef","ifndef","if","elif","else","endif"]

kinds = ["struct","enum","union","typedef","member"]
operators = ["&&","||","!"]

def parse_input(pp,inpt,fl):
    pp.parse(inpt,fl)
    while True:
        tok = pp.token()
        if not tok: break

def parse_ifdefs(conditionals):
    ifdefs = []
    line_numz = []
    for token_list in conditionals:
        line = ""
        for indx,tokens in enumerate(token_list):
            if tokens.value == '0L':
                line += ""
            else:
                if indx == 1 and tokens.value != " ":
                    line += " " + tokens.value
                else:
                    line += tokens.value
            line_num = tokens.lineno
        
        tokenz = line.split()
        if tokenz[0] in directives:
            ifdefs.append(line)
            line_numz.append(line_num)

    return ifdefs, line_numz


### Run the regex with the specific line on the pattern
def match_pattern(which_pattern,pattern,line,matched,indx):
    
    result = ""
    try:
        result = re.search(pattern,line)
        if result != None:
            print(which_pattern,"RESULT:",result.group(),"\nLINE",line)
    except:
        print(traceback.format_exc())
        print("Could not match pattern 1 in file",fl,":",indx)
        return None,""
    
    return result, matched


### Save start and end line along with the alias for the struct
def save_struct_info(result,ds_name,parent,member_name,line,indx,matched,struct_dict,struct_member_dict,fl):
    
    pattern6 = "(?<=:)((.+?)(:){1}(.+?)(::){0,1}(.+?)(?=\s))"
    tokens = line.split()
    #print(result.group(),"\n\n",line)
    ### Strip the parent from any other macro like volatile
    ### and such
    #if parent:
        #print("Parent",parent)
    if parent:
        parent = parent.strip(" *")
    stripped_parent = None
    try:
        stripped_parent = re.search("(\s)(.+?)(\s)(.+)",parent)
    except:
        pass
    if stripped_parent:
        parent = re.sub(" ","",stripped_parent.group(),1)
    ### Case of a typedef...just update the dict
    if parent and matched == "typedef":
        line_num = result["line"]
        try:
            struct_dict[parent][2].append([ds_name,line_num])
        except:
            pass
            #print("TYPEDEF UPDATE FAILED")
            #print(traceback.format_exc())
            #print(result)
        return struct_dict,struct_member_dict
    
    elif parent and matched != "member":
        try:
            line_num = result["line"]
            if ds_name not in struct_member_dict[parent]:
                struct_member_dict[parent][0].append([ds_name,line_num,""])
        except:
            #print("MEMBER1 UPDATE FAILED")
            #print(traceback.format_exc())
            #print(result)
            pass

    elif parent and matched == "member":
        variable = ds_name
        ds_name = member_name
        try:
            line_num = result["line"]
            if ds_name not in struct_member_dict[parent]:
                struct_member_dict[parent][0].append([ds_name,line_num,variable])
        except:
            #print("MEMBER2 UPDATE FAILED")
            #print(traceback.format_exc())
            #print(result)
            pass
        return struct_dict,struct_member_dict
        
    #print("Struct name",ds_name,list(ds_name))
        #if ds_name not in struct_member_dict.keys():
            #struct_member_dict[ds_name] = []
        #### Now check if this data structure is actually a nested member of some other
        #### data structure
        #matched = "parent"
        #parent,matched =  match_pattern("PATTERN6",pattern6,line,matched,indx)
        #if parent != None:
            #parent_tokens = parent.group().split("\t")[1].split(":")
            #parent_name = parent_tokens[0] + " " + parent_tokens[-1]

    ### This is new DS we must put it in the dictionary
    start_num = result["line"]
    end_num = result["end"]
    if ds_name not in struct_dict.keys():
        struct_dict[ds_name] = [start_num,end_num,[]]
    if ds_name not in struct_member_dict.keys():
        struct_member_dict[ds_name] = [[],fl.replace(kern_dir,"")]
    
    return struct_dict,struct_member_dict


def is_alias(member_name,struct_dict):
    is_alias = False
    actual_name = None
    for elem in struct_dict:
        #if struct_dict[elem][2] != "":
            #print("ALIAS of elem",elem,struct_dict[elem][2])
        if member_name in struct_dict[elem][2]:
            is_alias = True
            actual_name = elem

    return is_alias, actual_name


def find_blocks(ifdefs,line_numz,fl):
    
    stack = deque()
    
    final_blocks = []
    for indx,ifdef in enumerate(ifdefs):
        if ifdef == "elif" or ifdef == "else":
            continue

        if ifdef != "endif":
            stack.append([ifdef,line_numz[indx]])
        else:
            try:
                block = stack.pop()
            except:
                print("FILE",fl)
                raise
            block.append(line_numz[indx])
            final_blocks.append(block)

    return final_blocks

def get_typedefs(fl):
    
    #print("Analyzing file",fl)
    struct_dict = {}
    struct_member_dict = {}
    #### res will contain a huge string with all the struct definitions so it needs further parsing
    cmd1 = 'ctags --fields=+ne --output-format=json -o - --sort=no {0} | grep "struct\|enum\|union"'.format(fl)
    #print("CMD1",cmd1)
    res = ""
    try:
        res = sb.check_output(cmd1,shell=True).decode("utf-8")
     #   print(res)
    except:
        #print(traceback.format_exc())
        #print("Couldnt parse file",fl)
        return [{},{}]
    
    ### Now also call the Preprocessor on the file to get the ifdefs
    ## The results will be in the pp.conditionalz
    lexer = lex.lex()
    pp = Preprocessor(lexer)
    try:
        cfile = open(fl,errors='ignore',encoding='utf-8')
    except:
        #print(traceback.format_exc())
        return [{},{}]
    inpt = cfile.read()
    
    ## Do the pre-processor parsing
    parse_input(pp,inpt,fl)

    ## Now parse the ctags result
    lines = res.split("\n")
    ### Paterns to find the data structures
    pattern1 = "struct(\s*)(.[^)=;,:\s]+?)(\s*)({?)((\s*)(\\\/\*)(.+?)(\*\\\/))*(\$\/;)"   # structs
    pattern2 = "enum(\s*)(.[^)=;,:\s]+?)(\s*)({?)((\s*)(\\\/\*)(.+?)(\*\\\/))*(\$\/;)"     # enums
    pattern3 = "union(\s*)(.[^)=;,:\s]+?)(\s*)({?)((\s*)(\\\/\*)(.+?)(\*\\\/))*(\$\/;)"    # unions
    ## Pattern4 catches the typedefs/aliases of a data struct
    pattern4 = "(?<=\^)(\\t)?(})(.*?)(?=;\$\/)"
    #pattern4 = "(?<=\^})(.*?)(\$\/;)?(?=\s)"
    pattern5 = "(typeref:(.+?):(.+))"
    pattern6 = "(?<=\d\s)([^:]\w+):(\w+::){0,}(\w+(?!:))(?=\s)"
    #pattern6 = "(?<=:)((.+?)(:){1}(.+?)(::){0,1}(.*))"
    
    for indx,line in enumerate(lines):
        if not line:
            continue
        
        ds_name = None ### Data struct name
        json_obj = json.loads(line)
        typeref = None
        scope = None
        scopeKind = None
        typedef = None
        parent = None
        
        if "pattern" not in json_obj.keys():
            continue
        pattern = json_obj["pattern"]
        ### Remove the comments from the pattern
        replacement = "\\\\\/\*(.*)\*\\\\\/"
        
        new_pattern = re.sub(replacement,"",pattern)
        if "{" in new_pattern:
            if "={" in new_pattern or "= {" in new_pattern:
                continue
        #if "=" in new_pattern:
            #continue

        ### kind is always there
        kind = json_obj["kind"]
        if kind == "enumerator":
            kind = "member"
        
        name = json_obj["name"]
        
        ### Now try to get each one
        if "typeref" in json_obj.keys():
            typeref = json_obj["typeref"]
        if "scope" in json_obj.keys():
            scope = json_obj["scope"]
        if "scopeKind" in json_obj.keys():
            scopeKind = json_obj["scopeKind"]
        
        if kind not in kinds or scopeKind == "function":
            continue
        
        ### Now that we have each one we need to distinguish the
        ### data structures
        ### This means that we have an outer struct
        if kind != "member":
            member_name = None
            ### The name will be invalid if kind is typedef but we do not care
            ds_name = kind + " " + name
            ### Check if its a typedef
            if kind == "typedef":
                valid_typedef = None
                try:
                    valid_typedef = re.search(pattern4,pattern)
                except:
                    #print("Pattern",pattern,"does not have a valid typedef")
                    pass
                if not valid_typedef:
                    continue
                
                if "volatile" in typeref:
                    no_volatile = typeref.replace("typename:volatile ","")
                else:
                    no_volatile = typeref.replace("typename:","")
                tokens = no_volatile.split(":")
                try:
                    parent = tokens[0] + " " + tokens[1].split()[0]
                except:
                    parent = tokens[0]
                    #print(traceback.format_exc())
                    #print(tokens)
                ds_name = name 
            ### This means that the DS is nested so we also have to update its parent
            elif typeref:
                member_name = typeref.replace("typename:","").replace(":"," ")
                member_name = re.sub("\[(.*?)\]","",member_name)
                parent = scopeKind + " " + scope.split(":")[-1].replace("__packed","")
            ### In this case we have an anonymous DS that is also nested
            elif scope:
                parent = scopeKind + " " + scope.split(":")[-1].replace("__packed","")
            
            struct_dict,struct_member_dict = save_struct_info(json_obj,ds_name,parent,member_name,line,indx,kind,struct_dict,struct_member_dict,fl)
        else:
            ### This is a special case of typedef where the 
            ### a nested DS is given an alias without a typedef in the beginning
            valid_typedef = None
            ds_name = name
            member_name = None
            try:
                valid_typedef = re.search(pattern4,pattern)
            except:
                #print("Pattern",pattern,"does not have a valid typedef")
                pass
            if valid_typedef:
                kind = "typedef"
                if "volatile" in typeref:
                    no_volatile = typeref.replace("typename:volatile ","")
                else:
                    no_volatile = typeref.replace("typename:","")
                tokens = no_volatile.split(":")
                ### Case that the number of bits is also defined as <:num>
                ### We need to remove it
                if check_if_numeric(tokens[-1]):
                    del tokens[-1]

                parent = tokens[0] + " " + re.sub("\[(.*?)\]","",tokens[-1].split()[0].replace("__packed",""))
            else:
                try:
                    member_name = typeref.replace("typename:","").replace(":"," ")
                    member_name = re.sub("\[(.*?)\]","",member_name)
                except:
                    #print(traceback.format_exc())
                    member_name = name
                    #print(json_obj)
                parent = scopeKind + " " + scope.split(":")[-1].replace("__packed","")
                
                alias, actual_name = is_alias(member_name,struct_dict)

                #if typeref and "typename" in typeref and not alias:
                    #print("NOT AN ALIAS",member_name)
                #    continue
            
            struct_dict,struct_member_dict = save_struct_info(json_obj,ds_name,parent,member_name,line,indx,kind,struct_dict,struct_member_dict,fl)
    
    ifdefs, line_numz = parse_ifdefs(pp.conditionalz)
    #print(pp.conditionalz)

    f_conds = find_blocks(ifdefs,line_numz,fl)
    #print(f_conds)
    #print(ifdefs,line_numz)
    final_dict = {}
    for item in struct_dict:
        start = struct_dict[item][0]
        end = struct_dict[item][1]
        alias = struct_dict[item][2]

        if item not in final_dict.keys():
            final_dict[item] = [[],alias,[]]
        
        for indx,elem in enumerate(f_conds):
            ifdef = elem[0]
            start_line = elem[1]
            end_line = elem[2]
            if int(start_line) >= int(start) and int(start_line) <= int(end):
                #ifdef = ifdefs[indx]
                final_dict[item][0].append(elem)
            if int(start_line) <= int(start) and int(end_line) >= int(end):
                final_dict[item][2].append(elem)


    return [final_dict,struct_member_dict]


def get_strcut_freqs(data):
    
    fl = data[0]
    structs = data[1]
    struct_dict = {}
    #### res will contain a huge string with all the struct definitions so it needs further parsing
    cmd1 = 'ctags --fields=+ne -o - --sort=no {0} | grep "struct\|enum\|union" | grep -v "function"'.format(fl)
    res = ""
    try:
        res = sb.check_output(cmd1,shell=True).decode("utf-8")
        #print(res)
    except:
        print(traceback.format_exc())
        print("Couldnt parse file",fl)
        return {}
    

    ## Now parse the ctags result
    lines = res.split("\n")
    for indx,line in enumerate(lines):
        for struct in structs:
            if struct in line:
                if struct in struct_dict.keys():
                    struct_dict[struct] += 1
                else:
                    struct_dict[struct] = 1


    return struct_dict

def get_kernel_files(kernel,arch):
    kernel_dir = kern_dir + kernel +"/"

    cmd = "find {} -path \"{}arch/*\" ! -path \"{}arch/{}*\" -prune -o -path \"{}Documentation*\" -prune -o -name \"*.[ch]\"".format(kernel_dir,kernel_dir,kernel_dir,arch,kernel_dir)
    res = None
    try:
        res = sb.check_output(cmd,shell=True).decode("utf-8")
    except:
        print("Finding the C source files in kernel dir {} was unsuccessful".format(kernel))
        print(traceback.format_exc())
    
    files = []
    if res:
        files = res.split("\n")

    return [kernel,files]

def main(kernel,arch):
    
    p = Pool(6)
    res = get_kernel_files(kernel,arch)
    files = res[1]
    files.remove("")

    result = p.map(get_typedefs,files)
    res,struct_member_dict = map(list,zip(*result))
    cnt = 0
    outfile = container_data_path + "/struct_info/{}_{}_struct_options.pkl".format(kernel,arch)
    
    #res = read_pickle(outfile)
    unique_structs= []
    struct_dict = {}
    for fdict in res:
        for elem in fdict:
            if "^" in elem:
                if "=" in elem:
                    continue
                new_elem = elem.split("^")[1].split("{")[0].replace("\t"," ")
            else:
                if "=" in elem:
                    continue
                new_elem = elem.split("{")[0].replace("\t"," ")
            #print(new_elem, elem)
            
            tokens = new_elem.split(" ")
            if len(tokens) < 2 or tokens[1] == "":
                continue
            else:
                struct_name = tokens[0] + " " + tokens[1]
                #if struct_name not in unique_structs:
                    #unique_structs.append(struct_name)
            #print("Struct name",struct_name)
                    
            conditionals = []
            for tupl in fdict[elem][0] + fdict[elem][2]:
                cond = tupl[0]
                #cond = cond.replace("defined","").replace("(","").replace(")","").replace("||"," ").replace("&&"," ").replace("!","")
                cond = cond.replace("defined","").replace("(","").replace(")","").replace("IS_ENABLED","")
                #print(cond)
                tokens = cond.split()
                conditional_string = ""
                for token in tokens:
                    #if "CONFIG_" not in token and token not in operators:
                        #continue
                    #else:
                    if token in directives:
                        continue
                    if token != tokens[-1]:
                        conditional_string += token + " "
                    else:
                        conditional_string += token
                        #conditionals.append(token)
                    #if token not in all_ifdefs.keys():
                        #all_ifdefs[token] = 1
                    #else:
                        #all_ifdefs[token] +=1
                if conditional_string != "":
                    ### Change the conditional to CNF and then append it
                    try:
                        expression = to_cnf(conditional_string.replace("!","~").replace("&&","&").replace("||","|"))
                        conditionals.append([str(expression).replace("~","!").replace("&","&&").replace("|","||"),tupl[1],tupl[2]])
                    except:
                        pass
                        #print(traceback.format_exc())
                        #print(conditional_string)

            if struct_name not in struct_dict.keys():
                #if "net_device" in struct_name:
                    #print (elem)
                    #print(fdict[elem][0])
                struct_dict[struct_name] = {"cond_num":len(conditionals), "conds":conditionals, "alias":fdict[elem][1]}
            else:
                #if "net_device" in struct_name:
                    #print (elem)
                    #print(fdict[elem])
                struct_dict[struct_name]["cond_num"] += len(conditionals)
                struct_dict[struct_name]["conds"] += conditionals

    sorted_dict = struct_dict
    #sorted_dict = dict(sorted(struct_dict.items(),key = lambda x:x["conds"]["cond_num"],reverse=True))
    #print(sorted_dict["struct net"],"\n")
    #indx = 0
    #for elem in sorted_dict:
        #if indx == 100:
            #break
        ##print(elem,sorted_dict[elem])
        #indx += 1

    #print(struct_member_dict)
    with open(outfile,"wb") as f:
        pickle.dump(sorted_dict,f)
        pickle.dump(struct_member_dict,f)
    #write_pickle(outfile2,sorted_dict)
    
    return sorted_dict, struct_member_dict

if __name__ == "__main__":
    
    kernel_dirs = os.listdir(kern_dir)

    #linux_files = sys.argv[1]
    kernel = sys.argv[1]
    arch = sys.argv[2]
    main(kernel, arch)
