#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/major.h>
#include <linux/miscdevice.h>
#include <linux/kernel.h>
#include <linux/uaccess.h>
#include <linux/version.h>

#include "devfs_stubs.h"
#include "firmadyne.h"

#define STUB_ENTRIES \
	DEVICE(acos_nat_cli, 100, 0, open, read, write, close, acos_ioctl) \
	DEVICE(brcmboard, 206, 0, open, read, write, close, ioctl) \
	DEVICE(dsl_cpe_api, 107, 0, open, read, write, close, ioctl) \
	DEVICE(gpio, 224, 0, open, read, write, close, ioctl) \
	DEVICE(nvram, 111, 0, open, read, write, close, ioctl) \
	DEVICE(pib, 31, 3, open, read, write, close, ioctl) \
	DEVICE(sc_led, 225, 0, open, read, write, close, ioctl) \
	DEVICE(tca0, 183, 0, open, read, write, close, ioctl) \
	DEVICE(ticfg, 0, 0, open, read, write, close, ioctl) \
	DEVICE(watchdog, MISC_MAJOR, WATCHDOG_MINOR, open, read, write, close, ioctl) \
	DEVICE(wdt, 253, 0, open, read, write, close, ioctl) \
	DEVICE(zybtnio, 220, 0, open, read, write, close, ioctl)

static long acos_ioctl(struct file *file, unsigned int cmd, unsigned long arg_ptr) {
	int retval = 0;

	if (!devfs) {
		return -EINVAL;
	}

	printk(KERN_INFO MODULE_NAME": ACOS ioctl: 0x%x\n", cmd);

	switch (cmd) {
		case 0x40046431:
			printk(KERN_WARNING MODULE_NAME": ACOS: agApi_GetFirstTriggerConf\n");
			retval = 1;
			break;
		default:
			retval = 0;
			break;
	}

	return retval;
}

static long ioctl(struct file *file, unsigned int cmd, unsigned long arg_ptr) {
	int retval = 0;

	if (!devfs) {
		return -EINVAL;
	}

	printk(KERN_INFO MODULE_NAME": ioctl: 0x%x\n", cmd);

	switch (cmd) {
		default:
			retval = 0;
			break;
	}

	return retval;
}

static int open(struct inode *inode, struct file *file) {
/*
	if (inode->i_cdev != &c_dev) {
		return -ENODEV;
	}
*/
	if (!devfs) {
		return -EINVAL;
	}

	return 0;
}

static int close(struct inode *inode, struct file *file) {
	if (!devfs) {
		return -EINVAL;
	}

	return 0;
}

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
	if (!devfs) {
		return -EINVAL;
	}

	return size;
}

/*int add_uevent_var(char **envp, int num_envp, int *cur_index,*/
				   /*char *buffer, int buffer_size, int *cur_len,*/
						      /*const char *format, ...)*/


/*static int acl(struct device *dev, struct kobj_uevent_env *env) {*/
	/*add_uevent_var(env, "DEVMODE=%#o", 0666);*/
	/*return 0;*/
/*}*/

static int acl(struct device *dev, char **envp, int num_envp, char *buffer, int buffer_size) {
	int i = 0;
	int length = 0;
	add_uevent_var(envp,num_envp,&i,buffer,buffer_size,&length, "DEVMODE=%#o");
	return 0;
}

#define DEVICE(a, b, c, d, e, f, g, h) \
	static dev_t a##_devno = MKDEV(b, c); \
	struct cdev a##_cdev; \
	static struct class *a##_class; \
	static struct device *a##_dev; \
	static struct file_operations a##_fops = { \
		.owner		= THIS_MODULE, \
		.open		= d, \
		.read		= e, \
		.write		= f, \
		.release	= g, \
		.unlocked_ioctl	= h, \
	};\
	EXPORT_SYMBOL(a##_cdev);

	STUB_ENTRIES
#undef DEVICE

int register_devfs_stubs(void) {
	int ret = 0;

	if (!devfs) {
		return ret;
	}

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,19))
#define DEVICE(a, b, c, d, e, f, g, h) \
	if ((ret = register_chrdev_region(a##_devno, 1, #a)) < 0) { \
		printk(KERN_WARNING MODULE_NAME": Cannot register character device: %s, 0x%x, 0x%x!\n", #a, MAJOR(a##_devno), MINOR(a##_devno)); \
		goto a##_out; \
	} \
\
	if (IS_ERR(a##_class = class_create(THIS_MODULE, #a))) { \
		printk(KERN_WARNING MODULE_NAME": Cannot create device class: %s!\n", #a); \
		unregister_chrdev_region(a##_devno, 1); \
		ret = PTR_ERR(a##_class); \
		goto a##_out; \
	} \
	a##_class->dev_uevent = acl; \
\
	cdev_init(&a##_cdev, &a##_fops); \
\
	if ((ret = cdev_add(&a##_cdev, a##_devno, 1)) < 0) { \
		printk(KERN_WARNING MODULE_NAME": Cannot add class device: %s!\n", #a); \
		class_destroy(a##_class); \
		unregister_chrdev_region(a##_devno, 1); \
		goto a##_out; \
	} \
\
	if (IS_ERR(a##_dev = device_create(a##_class, NULL, a##_devno, #a))) { \
		printk(KERN_WARNING MODULE_NAME": Cannot create device: %s!\n", #a); \
		cdev_del(&a##_cdev); \
		class_destroy(a##_class); \
		unregister_chrdev_region(a##_devno, 1); \
		ret = PTR_ERR(a##_dev); \
	} \
a##_out:

	STUB_ENTRIES
#undef DEVICE
#else
#define DEVICE(a, b, c, d, e, f, g, h) \
	if ((ret = register_chrdev_region(a##_devno, 1, #a)) < 0) { \
		printk(KERN_WARNING MODULE_NAME": Cannot register character device: %s, 0x%x, 0x%x!\n", #a, MAJOR(a##_devno), MINOR(a##_devno)); \
		goto a##_out; \
	} \
\
	if (IS_ERR(a##_class = class_create(THIS_MODULE, #a))) { \
		printk(KERN_WARNING MODULE_NAME": Cannot create device class: %s!\n", #a); \
		unregister_chrdev_region(a##_devno, 1); \
		ret = PTR_ERR(a##_class); \
		goto a##_out; \
	} \
	cdev_init(&a##_cdev, &a##_fops); \
\
	if ((ret = cdev_add(&a##_cdev, a##_devno, 1)) < 0) { \
		printk(KERN_WARNING MODULE_NAME": Cannot add class device: %s!\n", #a); \
		class_destroy(a##_class); \
		unregister_chrdev_region(a##_devno, 1); \
		goto a##_out; \
	} \
\
	if (IS_ERR(a##_dev = device_create(a##_class, NULL, a##_devno, #a))) { \
		printk(KERN_WARNING MODULE_NAME": Cannot create device: %s!\n", #a); \
		cdev_del(&a##_cdev); \
		class_destroy(a##_class); \
		unregister_chrdev_region(a##_devno, 1); \
		ret = PTR_ERR(a##_dev); \
	} \
a##_out:

	STUB_ENTRIES
#undef DEVICE
#endif

	return ret;
}

void unregister_devfs_stubs(void) {
	if (!devfs) {
		return;
	}

#define DEVICE(a, b, c, d, e, f, g, h) \
	device_destroy(a##_class, a##_devno); \
	cdev_del(&a##_cdev); \
	class_destroy(a##_class); \
	unregister_chrdev_region(a##_devno, 1);

	STUB_ENTRIES
#undef DEVICE
}
