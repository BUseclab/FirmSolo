#!/usr/bin/env python3

import os
import sys
import subprocess
import traceback

########################## FRIMADYNE HOOK REPLACEMENT #####################################

inet_bind = """
        if (fdyne_syscall & LEVEL_NETWORK){
                unsigned int sport = htons(((struct sockaddr_in *)uaddr)->sin_port);
                printk(KERN_INFO "firmadyne: inet_bind[PID: %d (%s)]: proto:%s, port:%d\\n", current->pid, current->comm, sock->type == SOCK_STREAM ? "SOCK_STREAM" : (sock->type == SOCK_DGRAM ? "SOCK_DGRAM" : "SOCK_OTHER"), sport);
        }
"""

inet_accept = """
        if (fdyne_syscall & LEVEL_NETWORK){
                printk(KERN_INFO "firmadyne: inet_accept[PID: %d (%s)]:\\n", current->pid, current->comm);
        }
"""

register_vlan_dev = """
        if (fdyne_syscall & LEVEL_NETWORK){
                printk(KERN_INFO "firmadyne: register_vlan_dev[PID: %d (%s)]: dev:%s vlan_id:%d\\n", current->pid, current->comm, dev->name, vlan_dev_vlan_id(dev));
        }
"""
register_vlan_dev2 = """
        if (fdyne_syscall & LEVEL_NETWORK){
                unsigned short v_id;
                vlan_dev_get_vid(dev,&v_id);
                printk(KERN_INFO "firmadyne: register_vlan_dev[PID: %d (%s)]: dev:%s vlan_id:%d\\n", current->pid, current->comm, dev->name, v_id);
        }
"""
### This is for old kernels < 2.6.23
register_vlan_device = """
        if (fdyne_syscall & LEVEL_NETWORK){
                printk(KERN_INFO "firmadyne: register_vlan_dev[PID: %d (%s)]: dev:%s vlan_id:%d\\n", current->pid, current->comm, eth_IF_name, VLAN_ID);
        }
"""

inet_insert_ifa = """
        if (fdyne_syscall & LEVEL_NETWORK){
                printk(KERN_INFO "firmadyne: __inet_insert_ifa[PID: %d (%s)]: device:%s ifa:0x%08x\\n", current->pid, current->comm, ifa->ifa_dev->dev->name, ifa->ifa_address);

        }

"""

br_add_if = """
        if (fdyne_syscall & LEVEL_NETWORK){
                printk(KERN_INFO "firmadyne: br_add_if[PID: %d (%s)]: br:%s dev:%s\\n", current->pid, current->comm, br->dev->name, dev->name);
        }

"""

#### This is the actual system call so search for SYSCALL_DEFINE3(socket and sys_socket for kernels < 2.6.27.18
sys_socket = """
        if (fdyne_syscall & LEVEL_NETWORK){
                printk(KERN_INFO "firmadyne: sys_socket[PID: %d (%s)]: family:%d, type:%d, protocol:%d\\n", current->pid, current->comm, family, type, protocol);
        }

"""
### Search for SYSCALL_DEFINE5(setsockopt and sys_setsockopt for kernels < 2.6.27.18
sys_setsockopt = """
        if (fdyne_syscall & LEVEL_NETWORK){
                printk(KERN_INFO "firmadyne: sys_setsockopt[PID: %d (%s)]: fd:%d, level:%d, optname:%d\\n", current->pid, current->comm, fd, level, optname);

        }
"""

do_mount = """
        if (fdyne_syscall & LEVEL_SYSTEM){
                printk(KERN_INFO "firmadyne: do_mount[PID: %d (%s)]: mountpoint:%s, device:%s, type:%s\\n", current->pid, current->comm, dir_name, dev_name, type_page);

        }
"""

vfs_mknod = """
        if (fdyne_syscall & LEVEL_FS_W){
                printk(KERN_INFO "firmadyne: vfs_mknod[PID: %d (%s)]: file:%s major:%d minor:%d\\n", current->pid, current->comm, dentry->d_name.name, MAJOR(dev), MINOR(dev));

        }
"""

vfs_unlink = """
        if (fdyne_syscall & LEVEL_FS_W){
                printk(KERN_INFO "firmadyne: vfs_unlink[PID: %d (%s)]: file:%s\\n", current->pid, current->comm, dentry->d_name.name);
        }
"""

### For kernels between 2.6.25 - 2.6.36
do_vfs_ioctl_old = """
        if (fdyne_syscall & LEVEL_SYSTEM){
                unsigned char direction = _IOC_DIR(cmd);
                unsigned int magic = _IOC_TYPE(cmd);
                unsigned int ordinal = _IOC_NR(cmd);
                unsigned int size = _IOC_SIZE(cmd);
                printk(KERN_INFO "firmadyne: vfs_ioctl[PID: %d (%s)]: fd:%d filename:%s cmd:0x%x direction:%lu magic:%lu ord:%lu arg_size:%lu unlocked_ioctl:0x%x ioctl:0x%x compat_ioctl:0x%x\\n", current->pid, current->comm, fd,filp->f_path.dentry->d_name.name, cmd,direction,magic,ordinal,size,filp->f_op->unlocked_ioctl,filp->f_op->ioctl,filp->f_op->compat_ioctl);

        }
"""
### For kernels above 2.6.36
do_vfs_ioctl = """
        if (fdyne_syscall & LEVEL_SYSTEM){
                unsigned char direction = _IOC_DIR(cmd);
                unsigned int magic = _IOC_TYPE(cmd);
                unsigned int ordinal = _IOC_NR(cmd);
                unsigned int size = _IOC_SIZE(cmd);
                printk(KERN_INFO "firmadyne: vfs_ioctl[PID: %d (%s)]: fd:%d filename:%s cmd:0x%x direction:%lu magic:%lu ord:%lu arg_size:%lu unlocked_ioctl:0x%x compat_ioctl:0x%x\\n", current->pid, current->comm, fd,filp->f_path.dentry->d_name.name, cmd,direction,magic,ordinal,size,filp->f_op->unlocked_ioctl,filp->f_op->compat_ioctl);

        }
"""

### Search vfs_ioctl for kernels < 2.6.25
vfs_ioctl = """
        if (fdyne_syscall & LEVEL_SYSTEM){
                unsigned char direction = _IOC_DIR(cmd);
                unsigned int magic = _IOC_TYPE(cmd);
                unsigned int ordinal = _IOC_NR(cmd);
                unsigned int size = _IOC_SIZE(cmd);
                printk(KERN_INFO "firmadyne: vfs_ioctl[PID: %d (%s)]: fd:%d filename:%s cmd:0x%x direction:%lu magic:%lu ord:%lu arg_size:%lu unlocked_ioctl:0x%x ioctl:0x%x compat_ioctl:0x%x\\n", current->pid, current->comm, fd,filp->f_dentry->d_name.name, cmd,direction,magic,ordinal,size,filp->f_op->unlocked_ioctl,filp->f_op->ioctl,filp->f_op->compat_ioctl);

        }
"""

### Search for SYSCALL_DEFINE4(reboot and sys_reboot for kernels > 2.6.29
sys_reboot = """
        static char *envp_init[] = { "HOME=/", "TERM=linux", "LD_PRELOAD=/firmadyne/libnvram.so", NULL };
        static char *argv_init[] = { "/sbin/init", NULL };

        kernel_cap_t pE, pP, pI;
        struct cred *new;

        if (fdyne_reboot || fdyne_syscall & LEVEL_SYSTEM) {
                printk(KERN_INFO "firmadyne: sys_reboot[PID: %d (%s)]: magic1:%x, magic2:%x, cmd:%x\\n", current->pid, current->comm, magic1, magic2, cmd);
        }

        if (fdyne_reboot && cmd != LINUX_REBOOT_CMD_CAD_OFF && cmd != LINUX_REBOOT_CMD_CAD_ON) {
                if (security_capget(current, &pE, &pI, &pP)) {
                        printk(KERN_WARNING "firmadyne: security_capget() failed!\\n");
                        goto out;
                }

                if (!(new = prepare_creds())) {
                        printk(KERN_WARNING "firmadyne: prepare_creds() failed!\\n");
                        goto out;
                }

                cap_lower(pE, CAP_SYS_BOOT);
                cap_lower(pI, CAP_SYS_BOOT);
                cap_lower(pP, CAP_SYS_BOOT);

                if (security_capset(new, current_cred(), &pE, &pI, &pP)) {
                        printk(KERN_WARNING "firmadyne: security_capset() failed!\\n");
                        abort_creds(new);
                        goto out;
                }

                commit_creds(new);
                printk(KERN_INFO "firmadyne: sys_reboot: removed CAP_SYS_BOOT, starting init...\\n");

                call_usermodehelper(argv_init[0], argv_init, envp_init, -1);
        }

        out:
            ;;
"""

### This implementation for old kernels might be totally unsafe and incorrect below < 2.6.2
sys_reboot_old = """
        static char *envp_init[] = { "HOME=/", "TERM=linux", "LD_PRELOAD=/firmadyne/libnvram.so", NULL };
        static char *argv_init[] = { "/sbin/init", NULL };

        kernel_cap_t pE, pP, pI;

        if (fdyne_reboot || fdyne_syscall & LEVEL_SYSTEM) {
                printk(KERN_INFO "firmadyne: sys_reboot[PID: %d (%s)]: magic1:%x, magic2:%x, cmd:%x\\n", current->pid, current->comm, magic1, magic2, cmd);
        }

        if (fdyne_reboot && cmd != LINUX_REBOOT_CMD_CAD_OFF && cmd != LINUX_REBOOT_CMD_CAD_ON) {
              /*  if (security_capget(current, &pE, &pI, &pP)) {
                        printk(KERN_WARNING "firmadyne: security_capget() failed!\\n");
                        goto out;
                }
                */
                cap_lower(pE, CAP_SYS_BOOT);
                cap_lower(pI, CAP_SYS_BOOT);
                cap_lower(pP, CAP_SYS_BOOT);
                
                if (!security_capset_check(current, &pE, &pI, &pP)) {
                        printk(KERN_WARNING "firmadyne: security_capset_check() failed!\\n");
                        goto out;
                }

                security_capset_set(current, &pE, &pI, &pP);

                printk(KERN_INFO "firmadyne: sys_reboot: removed CAP_SYS_BOOT, starting init...\\n");

                call_usermodehelper(argv_init[0], argv_init, envp_init, -1);
        }

        out:
            ;;
"""

do_sys_open = """
        if (fdyne_syscall & LEVEL_FS_R){
                printk(KERN_INFO "firmadyne: open[PID: %d (%s)]: file:%s\\n", current->pid, current->comm, filename);
        }

"""

### Search for SYSCALL_DEFINE1(close and sys_close before kernels < 2.6.27.18
sys_close = """
        if(fdyne_syscall & LEVEL_FS_R){
                printk(KERN_INFO "firmadyne: close[PID: %d (%s)]: fd:%d\\n", current->pid, current->comm, fd);

        }
"""

do_execve = """
        static char *envp_init[] = { "HOME=/", "TERM=linux", "LD_PRELOAD=/firmadyne/libnvram.so", NULL };

        int j,ret;
        static char *argv_init[] = { "/firmadyne/console", NULL };

        if (fdyne_execute == 2) {
                fdyne_execute = 0;

                printk(KERN_INFO "firmadyne: do_execve: %s\\n", argv_init[0]);
                ret = call_usermodehelper(argv_init[0], argv_init, envp_init, -1);

                printk(KERN_WARNING "OFFSETS: offset of pid: 0x%x offset of comm: 0x%x RET:%d\\n", offsetof(struct task_struct, pid), offsetof(struct task_struct, comm),ret);
        }
       // else if (fdyne_execute > 0) {
       //         fdyne_execute += 1;
       // }

        if (fdyne_syscall & LEVEL_SYSTEM && strcmp("khelper", current->comm)) {
                printk(KERN_INFO "firmadyne: do_execve[PID: %d (%s)]: argv:", current->pid, current->comm);
                for (j = 0; j >= 0 && j < count(argv, 0x7FFFFFFF); j++) {
                        printk(" %s", argv[j]);
                }

                printk(", envp:");
                for (j = 0; j >= 0 && j < count(envp, 0x7FFFFFFF); j++) {
                        printk(" %s", envp[j]);
                }
        }

"""

do_execve_common = """
        static char *envp_init[] = { "HOME=/", "TERM=linux", "LD_PRELOAD=/firmadyne/libnvram.so", NULL };

        int j;
        static char *argv_init[] = { "/firmadyne/console", NULL };

        if (fdyne_execute == 2) {
                fdyne_execute = 0;

                printk(KERN_INFO "firmadyne: do_execve: %s\\n", argv_init[0]);
                call_usermodehelper(argv_init[0], argv_init, envp_init, UMH_NO_WAIT);

                printk(KERN_WARNING "OFFSETS: offset of pid: 0x%x offset of comm: 0x%x\\n", offsetof(struct task_struct, pid), offsetof(struct task_struct, comm));
        }
       // else if (fdyne_execute > 0) {
       //         fdyne_execute += 1;
       // }

        if (fdyne_syscall & LEVEL_SYSTEM && strcmp("khelper", current->comm)) {
                printk(KERN_INFO "firmadyne: do_execve[PID: %d (%s)]: argv:", current->pid, current->comm);
                for (j = 0; j >= 0 && j < count(argv, 0x7FFFFFFF); j++) {
                        printk(" %s", get_user_arg_ptr(argv,j));
                }

                printk(", envp:");
                for (j = 0; j >= 0 && j < count(envp, 0x7FFFFFFF); j++) {
                        printk(" %s", get_user_arg_ptr(envp,j));
                }
        }

"""

do_fork = """
        if (fdyne_syscall & LEVEL_EXEC && strcmp("khelper", current->comm)) {
                printk(KERN_INFO "firmadyne: do_fork[PID: %d (%s)]: clone_flags:0x%lx, stack_size:0x%lx\\n", current->pid, current->comm, clone_flags, stack_size);
        }
"""

do_fork_ret = """
        if (fdyne_syscall & LEVEL_EXEC && strcmp("khelper", current->comm)) {
                printk(KERN_INFO "firmadyne: do_fork_ret[PID: %d (%s)] = %ld\\n", current->pid, current->comm, nr);
        }

"""

do_exit = """
       if (fdyne_syscall & LEVEL_EXEC  && strcmp("khelper", current->comm) ){
                printk(KERN_INFO "firmadyne: do_exit[PID: %d (%s)]: code:%lu\\n", current->pid, current->comm, code);

        }
"""

send_signal = """
        if(fdyne_syscall & LEVEL_EXEC){
                printk(KERN_INFO "firmadyne: do_send_sig_info[PID: %d (%s)]: PID:%d, signal:%u\\n", current->pid, current->comm, t->pid, sig);

        }
"""

### Search for do_mmap_pgoff before kernel < 2.6.23
mmap_region = """
        if (fdyne_syscall & LEVEL_EXEC && (vm_flags & VM_EXEC)) {
                if (file && file->f_path.dentry) {
                        printk(KERN_INFO "firmadyne: mmap_region[PID: %d (%s)]: addr:0x%lx -> 0x%lx, file:%s\\n", current->pid, current->comm, addr, addr+len, file->f_path.dentry->d_name.name);
                }
                else {
                        printk(KERN_INFO "firmadyne: mmap_region[PID: %d (%s)]: addr:0x%lx -> 0x%lx\\n", current->pid, current->comm, addr, addr+len);
                }
        }

"""

do_mmap_pgoff = """
        if (fdyne_syscall & LEVEL_EXEC && (flags & VM_EXEC)) {
                if (file && file->f_dentry) {
                        printk(KERN_INFO "firmadyne: mmap_region[PID: %d (%s)]: addr:0x%lx -> 0x%lx, file:%s\\n", current->pid, current->comm, addr, addr+len, file->f_dentry->d_name.name);
                }
                else {
                        printk(KERN_INFO "firmadyne: mmap_region[PID: %d (%s)]: addr:0x%lx -> 0x%lx\\n", current->pid, current->comm, addr, addr+len);
                }
        }

"""

device_add = """
        if (firmsolo) {
            char d_name[1024] = "/dev/";
            struct device *par = NULL;
            struct device *dv;
            dv = get_device(dev);
            par = get_device(dv->parent);
            while (par != NULL){
                if (dev_name(par)){
                    printk(KERN_INFO "Here\\n");
                    strcat(d_name,dev_name(par));
                }
                par = get_device(par->parent);
            }
            printk(KERN_INFO "Here2\\n");
            dev_set_name(dv, "%s", dv->init_name);
            strcat(d_name,dev_name(dv));
            printk(KERN_INFO "Creating device %s:%d:%d\\n",d_name,MAJOR(dv->devt),MINOR(dv->devt));
        }

"""

__setup_irq = """
        int i;
        struct sigaction *old_temp;
        old_temp = desc->action;
        if (old_temp){
            for (i =irq; i<128; i++){
                desc = irq_to_desc(i);
                old_temp = desc->action;
                if (!old_temp){
                    irq = i;
                    break;
                }
            }
        }
        if (desc->chip == &no_irq_chip){
            desc->chip = &dummy_irq_chip;   
        }
"""

__setup_irq_new = """
        int i;
        struct sigaction *old_temp;
        old_temp = desc->action;
        if (old_temp){
            for (i =irq; i<128; i++){
                desc = irq_to_desc(i);
                old_temp = desc->action;
                if (!old_temp){
                    irq = i;
                    break;
                }
            }
        }
        if (desc->irq_data.chip == &no_irq_chip){
            desc->irq_data.chip = &dummy_irq_chip;   
        }
"""

setup_irq = """
        int i;
        struct irq_desc *desc_temp = irq_desc + irq;
        struct irqaction *old_temp;
        old_temp = desc_temp->action;
        if (old_temp){
            for (i =irq; i<128; i++){
                desc_temp = irq_desc + irq;
                old_temp = desc_temp->action;
                if (!old_temp){
                    irq = i;
                    break;
                }
            }
        }
        if (desc_temp->chip == &no_irq_chip){
            desc_temp->chip = &dummy_irq_chip;   
        }
"""

run_init_process = """
	if (fdyne_execute == 1)
		fdyne_execute = 2;
"""
###########################################################################################

################################### FILES TO PATCH ########################################

fl_inet_bind = "net/ipv4/af_inet.c"
fl_inet_accept = "net/ipv4/af_inet.c"
fl_register_vlan_dev = "net/8021q/vlan.c"
fl_register_vlan_device = "net/8021q/vlan.c"
fl_inet_insert_ifa = "net/ipv4/devinet.c"
fl_br_add_if = "net/bridge/br_if.c"
fl_sys_socket = "net/socket.c"
fl_sys_setsockopt = "net/socket.c"
fl_do_mount = "fs/namespace.c"
fl_vfs_mknod = "fs/namei.c"
fl_vfs_unlink = "fs/namei.c"
fl_do_vfs_ioctl = "fs/ioctl.c"
fl_sys_reboot = "kernel/sys.c"
fl_do_sys_open = "fs/open.c"
fl_sys_close = "fs/open.c"
fl_do_execve = "fs/exec.c"
fl_do_fork = "kernel/fork.c"
fl_do_fork_ret = "kernel/fork.c"
fl_do_exit = "kernel/exit.c"
fl_send_signal = "kernel/signal.c"
fl_mmap_region = "mm/mmap.c"
fl_device_add = "drivers/base/core.c"
fl_setup_irq = "kernel/irq/manage.c"
fl_run_init_process = "init/main.c"
###########################################################################################

### The last list are kernel exceptions to the rules so these will search for the extra
### keyword
hooks_dict = {
        "inet_bind": [inet_bind,fl_inet_bind,"all"], 
        "inet_accept":[inet_accept,fl_inet_accept,"all"], 
        "register_vlan_dev":[register_vlan_dev,fl_register_vlan_dev,"above linux-2.6.27"], 
        "register_vlan_dev2":[register_vlan_dev2,fl_register_vlan_dev,"only_between linux-2.6.23 linux-2.6.27","register_vlan_dev",[]], 
        "register_vlan_device":[register_vlan_device,fl_register_vlan_device,"below linux-2.6.23"], 
        "__inet_insert_ifa":[inet_insert_ifa,fl_inet_insert_ifa,"all"], 
        "br_add_if":[br_add_if,fl_br_add_if,"all"],
        "sys_socket":[sys_socket,fl_sys_socket,"only_above linux-2.6.28.1","SYSCALL_DEFINE3(socket",[]], 
        "sys_socket2":[sys_socket,fl_sys_socket,"only_between linux-2.6.27.12 linux-2.6.28","SYSCALL_DEFINE3(socket",[]], 
        "sys_socket3":[sys_socket,fl_sys_socket,"only_below ","sys_socket",["linux-2.6.28"]], 
        "sys_setsockopt":[sys_setsockopt,fl_sys_setsockopt,"only_above linux-2.6.28.1","SYSCALL_DEFINE5(setsockopt",[]], 
        "sys_setsockopt2":[sys_setsockopt,fl_sys_setsockopt,"only_between linux-2.6.27.12 linux-2.6.28","SYSCALL_DEFINE5(setsockopt",[]], 
        "sys_setsockopt3":[sys_setsockopt,fl_sys_setsockopt,"only_below linux-2.6.27.12","sys_setsockopt",["linux-2.6.28"]], 
        "do_mount":[do_mount,fl_do_mount,"all"],"vfs_mknod":[vfs_mknod,fl_vfs_mknod,"all"],
        "vfs_unlink":[vfs_unlink,fl_vfs_unlink,"all"],
        "do_vfs_ioctl_old":[do_vfs_ioctl_old,fl_do_vfs_ioctl,"only_between linux-2.6.25 linux-2.6.36","do_vfs_ioctl",[]],
        "do_vfs_ioctl":[do_vfs_ioctl,fl_do_vfs_ioctl,"only_above linux-2.6.36","do_vfs_ioctl",[]],
        "vfs_ioctl":[vfs_ioctl,fl_do_vfs_ioctl,"only_below linux-2.6.25","vfs_ioctl",[]],
        "sys_reboot":[sys_reboot,fl_sys_reboot,"only_above linux-2.6.29","SYSCALL_DEFINE4(reboot",[]],
        "sys_reboot2":[sys_reboot_old,fl_sys_reboot,"only_between linux-2.6.27.12 linux-2.6.28","SYSCALL_DEFINE4(reboot",[]],
        "sys_reboot3":[sys_reboot_old,fl_sys_reboot,"only_between linux-2.6.28 linux-2.6.28 linux-2.6.29","sys_reboot",[]],
        "sys_reboot4":[sys_reboot_old,fl_sys_reboot,"only_below linux-2.6.27.12","sys_reboot",[]],
        "do_sys_open":[do_sys_open,fl_do_sys_open,"all"],
        "sys_close":[sys_close,fl_sys_close,"only_above linux-2.6.28.1","SYSCALL_DEFINE1(close",[]],
        "sys_close2":[sys_close,fl_sys_close,"only_between linux-2.6.27.12 linux-2.6.28","SYSCALL_DEFINE1(close",[]],
        "sys_close3":[sys_close,fl_sys_close,"only_below linux-2.6.27.12","sys_close",["linux-2.6.28"]],
        "do_execve":[do_execve,fl_do_execve,"below linux-3.0.0"],
        "do_execve_common":[do_execve_common,fl_do_execve,"above linux-3.0.0"],
        "do_fork":[do_fork,fl_do_fork,"all"],
        "do_fork_ret":[do_fork_ret,fl_do_fork_ret,"all"],
        "do_exit":[do_exit,fl_do_exit,"all"],
        "send_signal":[send_signal,fl_send_signal,"all"],
        "mmap_region":[mmap_region,fl_mmap_region,"above linux-2.6.23"],
        "do_mmap_pgoff":[do_mmap_pgoff,fl_mmap_region,"below linux-2.6.23"],
        "__setup_irq":[__setup_irq,fl_setup_irq, "only_between linux-2.6.28 linux-2.6.37","__setup_irq",[]],
        "__setup_irq_new":[__setup_irq_new,fl_setup_irq, "only_above linux-2.6.37","__setup_irq",[]],
        "setup_irq":[setup_irq,fl_setup_irq, "below linux-2.6.28"],
        "run_init_process":[run_init_process,fl_run_init_process, "all"]
#        "device_add":[device_add,fl_device_add,"all"]
        }


main_template = """
unsigned int fdyne_syscall;
static int __init set_fdyne_syscall(char *str)
{
        get_option(&str, &fdyne_syscall);
        // This only takes values between 0 and 255
        fdyne_syscall = fdyne_syscall % 256;
        return 0;
}
__setup("fdyne_syscall=", set_fdyne_syscall);

EXPORT_SYMBOL(fdyne_syscall);

unsigned int fdyne_execute;
static int __init set_fdyne_execute(char *str)
{
       get_option(&str, &fdyne_execute);
       printk(KERN_INFO "FDYNE_EXECUTE = %lu\\n",fdyne_execute);
       return 0;
}
__setup("fdyne_execute=", set_fdyne_execute);

EXPORT_SYMBOL(fdyne_execute);

unsigned int fdyne_reboot;
static int __init set_fdyne_reboot(char *str)
{
        get_option(&str, &fdyne_reboot);
        return 0;
}
__setup("fdyne_reboot=", set_fdyne_reboot);

EXPORT_SYMBOL(fdyne_reboot);

unsigned int firmsolo;
static int __init set_firmsolo(char *str)
{
        get_option(&str, &firmsolo);
        return 0;
}
__setup("firmsolo=", set_firmsolo);

EXPORT_SYMBOL(firmsolo);

"""


def find_cscope_files(kfile):

    #find_cmd = "find . -path \"./arch/*\" ! -path \"./arch/mips*\" -prune -o -path \"./Documentation*\" -prune -o -name \"*.[cxsS]\" -print >./cscope.files"
    find_cmd = "find . -name {} -print >./cscope.files".format(kfile.split("/")[-1])
    #print(find_cmd)
    ### Remove all the prior cscope files
    #try:
        #res = subprocess.call("rm cscope.*",shell=True)
    #except:
        #print(traceback_format.exc())

    try:
        res = subprocess.call(find_cmd,shell=True)
    except:
        print(traceback.format_exc())

def create_cscope_db():
    try:
        res= subprocess.call("cscope -q -b",shell=True)
    except:
        print(traceback.format_exc())

def run_cscope(wts,level):
    res = ""
    cmd = 'cscope -d -{}{}'.format(level,wts)
    try:
        res = subprocess.check_output(cmd,shell=True).decode("utf-8")
    except:
        print(traceback.format_exc())
    
    return res



def modify_file(kfile, wts, tmplt,touched_files):
    print("Applying patch to",wts)
    with open(kfile,"r",errors='ignore') as f:
        lines = f.readlines()
    header_included = False
    if kfile not in touched_files:
        for i,line in enumerate(lines):
            if "#include" in line:
                print("Added include fdyne.h in line",i)
                lines.insert(i,"#include <linux/fdyne.h>\n#include <linux/sched.h>\n")
                header_included = True
                break
    
    if "_ret" in wts:
        end = True
        temp = wts.replace("_ret","")
        wts = temp
    else:
        end = False

    if "SYSCALL" not in wts:
        level = "L1"
    else:
        level = "L6"
        tmp = '"' + wts.replace("(","(.?)") + '"'
        wts = tmp

    ### Find the function definition
    res = run_cscope(wts,level)
    #print(res)
    if res != "":
        results = res.split("\n")
        #print(results)
        for rs in results:
            tokens = rs.split()
            if kfile in tokens[0]:
                break

        start_line = int(tokens[2]) if not header_included else int(tokens[2]) + 1
        #print("Start line",start_line)
    else: 
        print("Could not find",wts)
        return
    
    ### If the function exists the add the template in 
    ### the correct place
    for i, line in enumerate(lines[int(start_line):]):
        if end == False and "{" in line:
            #print("Here",line)
            index = i + int(start_line) + 1
            for ln in tmplt:
                lines.insert(index,ln)
                index += 1
            break
        elif end == True and ("return nr" in line or "return pid" in line):
            ### If the return variable is the pid then change the template
            if "pid" in line:
                temp = tmplt[2].replace("nr)","pid)")
                tmplt[2] = temp
                #print("Fixed",tmplt)

            #print("Here2",line)
            index = i + int(start_line)
            for ln in tmplt:
                lines.insert(index,ln)
                index += 1
            break
    
    with open(kfile,"w") as f:
        f.writelines(lines)


def fix_template(tmplt):
    lines = tmplt.split("\n")

    template = list(map(lambda x:x+"\n",lines))

    return template


def fix_main():
    with open("init/main.c","r",errors='ingore') as f:
        lines = f.readlines()
    
    template = fix_template(main_template)

    for i, line in enumerate(lines):
        if "char * envp_init[MAX_INIT_ENVS+2]" in line or "char *envp_init[MAX_INIT_ENVS+2]" in line:
            lines[i] = "char * envp_init[MAX_INIT_ENVS+3] = { \"HOME=/\", \"TERM=linux\", \"LD_PRELOAD=/firmadyne/libnvram.so\", NULL,  };\n"
            index = i - 2
            for ln in template:
                lines.insert(index,ln)
                index += 1
    with open("init/main.c", "w") as f:
        f.writelines(lines)


def apply_fdyne_hooks(kern_source,kernel):
    cwd = os.getcwd()
    os.chdir(kern_source)
    
    #find_cscope_files()
    #create_cscope_db()
    touched_files = []

    fix_main()

    ### For every function in the dictionary add
    ### the template to the kernel source
    ### Yes Cscope sucks thats why the sort and reverse
    for key in sorted(list(hooks_dict.keys()),reverse=True):
        data = hooks_dict[key]
        
        ### If the length > 3 it means that there
        ### was a change to the function over the
        ### different kernel versions so we need
        ### to apply to apply the template to the
        ### correct function
        what_to_search = key.replace("_old","")
        tmplt = data[0]
        template = fix_template(tmplt)

        fl_to_modify = data[1]
        valid_kernels = data[2]
        tokens = valid_kernels.split(" ")
        
       # if fl_to_modify in touched_files:
        #print("File",fl_to_modify,"is touched...applying cscope")
        find_cscope_files(fl_to_modify)
        create_cscope_db()

        ### The function exists in all the kernels but with different names
        if len(data) > 4:
            if tokens[0] == "only_above":
                if kernel < tokens[1] and kernel not in data[4]:
                    continue
                else:
                   # print("here1")
                    what_to_search = data[3]
            if tokens[0] == "only_below":
                if kernel >= tokens[1] and kernel not in data[4]:
                    continue
                else:
                  #  print("here2")
                    what_to_search = data[3]
            if tokens[0] == "only_between":
                if kernel < tokens[1] or kernel >= tokens[2] and kernel not in data[4]:
                    continue
                else:
                 #   print("here3")
                    what_to_search = data[3]
            if tokens[0] == "below":
                if kernel < tokens[1] or kernel in data[4]:
                    what_to_search = data[3]
            elif tokens[0] == "above":
                if kernel >= tokens[1] or kernel in data[4]:
                    what_to_search = data[3]
            elif tokens[0] == "between":
                #print("here2")
                min_k = tokens[1]
                max_k = tokens[2]
                if kernel >= min_k and kernel < max_k or kernel in data[4]:
                    what_to_search = data[3]
                else:
                    continue
            
            modify_file(fl_to_modify, what_to_search, template,touched_files)
            touched_files.append(fl_to_modify)

            continue
        ### Special case for register_vlan_dev which does not exist in all the
        ### kernels
        if valid_kernels != "all":
            if tokens[0] == "above":
                if kernel < tokens[1]:
                    continue
            elif tokens[0] == "below":
                if kernel >= tokens[1]:
                    continue
        
        modify_file(fl_to_modify, what_to_search, template,touched_files)
        touched_files.append(fl_to_modify)
    
    os.chdir(cwd)
    return



        

