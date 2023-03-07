#ifndef _FIRMADYNE_MACROS_H
#define _FIRMADYNE_MACROS_H


extern unsigned int fdyne_syscall;
extern unsigned int fdyne_execute;
extern unsigned int fdyne_reboot;
extern unsigned int firmsolo;

extern struct cdev acos_nat_cli_cdev;
extern struct cdev brcmboard_cdev;
extern struct cdev dsl_cpe_api_cdev;
extern struct cdev gpio_cdev;
extern struct cdev nvram_cdev;
extern struct cdev pib_cdev;
extern struct cdev sc_led_cdev;
extern struct cdev tca0_cdev;
extern struct cdev ticfg_cdev;
extern struct cdev watchdog_cdev;
extern struct cdev wdt_cdev;
extern struct cdev zybtnio_cdev;


/* Network related operations; e.g. bind, accept, etc */
#define LEVEL_NETWORK (1 << 0)
/* System operations; e.g. reboot, mount, ioctl, execve, etc */
#define LEVEL_SYSTEM  (1 << 1)
/* Filesystem write operations; e.g. unlink, mknod, etc */
#define LEVEL_FS_W    (1 << 2)
/* Filesystem read operations; e.g. open, close, etc */
#define LEVEL_FS_R    (1 << 3)
/* Process execution operations; e.g. mmap, fork, etc */
#define LEVEL_EXEC    (1 << 4)

#endif

