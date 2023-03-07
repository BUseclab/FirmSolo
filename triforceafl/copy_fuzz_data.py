#!/usr/bin/env python



import os,sys

delimeter = "\xa5\xc9"


if __name__ == "__main__":
    
    fuzz_data = []
    
    start_addr = sys.argv[1]

    end_addr = sys.argv[2]

    fname = sys.argv[3]

    filename = sys.argv[4]

    ioctl_case = sys.argv[5]
    
    print("Inside copy",filename)
    fuzz_data.append(start_addr + "\0")
    fuzz_data.append(end_addr + "\0")
    fuzz_data.append(fname + "\0")
    fuzz_data.append(ioctl_case + "\0")

    data = delimeter.join(fuzz_data)

    with open(filename,"w") as f:
        f.write(data)


