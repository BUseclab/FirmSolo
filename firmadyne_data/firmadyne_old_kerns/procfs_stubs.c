#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/proc_fs.h>
#include <linux/uaccess.h>

#include "procfs_stubs.h"
#include "firmadyne.h"

#define STUB_ENTRIES \
	FILE(blankstatus, NULL) \
	FILE(btnCnt, NULL) \
	FILE(br_igmpProxy, NULL) \
	FILE(BtnMode, NULL) \
	FILE(gpio, NULL) \
	FILE(led, NULL) \
	/* Used by "Firmware_TEW-435BRM_0121e.zip" (12973) */ \
	FILE(push_button, NULL) \
	FILE(rtk_promiscuous, NULL) \
	FILE(rtk_vlan_support, NULL) \
	FILE(RstBtnCnt, NULL) \
	FILE(sw_nat, NULL) \
	DIR(simple_config, NULL) \
	FILE(reset_button_s, simple_config_dir) \
	DIR(quantum, NULL) \
	FILE(drv_ctl, quantum_dir) \
	DIR(rt3052, NULL) \
	DIR(mii, rt3052_dir) \
	FILE(ctrl, mii_dir) \
	FILE(data, mii_dir)

static ssize_t read(struct file *file, char __user *buf, size_t size, loff_t *offset) {
	const char data[] = "0";
	loff_t count = min((loff_t) size, ARRAY_SIZE(data) - *offset);

	if (!devfs) {
		return -EINVAL;
	}

	if (*offset >= ARRAY_SIZE(data)) {
		return 0;
	}

	if (copy_to_user(buf, data + *offset, count)) {
		return -EFAULT;
	}

	*offset += count;
	return count;
}

static ssize_t write(struct file *file, const char __user *buf, size_t size, loff_t *offset) {
	if (!procfs) {
		return -EINVAL;
	}

	return size;
}

#define DIR(a, b) \
	static struct proc_dir_entry *a##_dir;

#define FILE(a, d) \
	;;

	STUB_ENTRIES
#undef FILE
#undef DIR


int register_procfs_stubs(void) {
	int ret = 0;

	if (!procfs) {
		return -EINVAL;
	}

#define DIR(a, b) \
	if (!(a##_dir = proc_mkdir(#a, b))) { \
		printk(KERN_WARNING MODULE_NAME": Cannot register procfs directory: %s!\n", #a); \
		ret = -1; \
	}

#define FILE(a, b) \
	if (!create_proc_entry(#a, 0666, b)) { \
		printk(KERN_WARNING MODULE_NAME": Cannot register procfs file: %s!\n", #a); \
		ret = -1; \
	}


	STUB_ENTRIES
#undef FILE
#undef DIR

	return ret;
}

void unregister_procfs_stubs(void) {
	if (!procfs) {
		return;
	}

#define DIR(a, b) \
	remove_proc_entry(#a, b);

#define FILE(a, b) \
	remove_proc_entry(#a, b);

	STUB_ENTRIES
#undef FILE
#undef DIR
}
