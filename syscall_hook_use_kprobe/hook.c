#include <asm/unistd.h>
#include <linux/kallsyms.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/module.h>
#include <linux/version.h>
#include <linux/vmalloc.h>

#include "comm.h"
#include "memory.h"
#include "process.h"

#define MODULE_NAME "syscall_hook"
#define LOG_PREFIX MODULE_NAME ": "


#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 7, 0)
typedef unsigned long (*kallsyms_lookup_name_t)(const char* name);
static kallsyms_lookup_name_t custom_kallsyms_lookup_name;
#else
#define custom_kallsyms_lookup_name kallsyms_lookup_name
#endif

static int fixup_kallsyms_lookup_name(void) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 7, 0)
    struct kprobe kp = {.symbol_name = "kallsyms_lookup_name"};
    int result = register_kprobe(&kp);
    if (result < 0) {
//        printk(KERN_ERR LOG_PREFIX "Failed to register kprobe, returned code: %d\n", result);
        return result;
    }
    custom_kallsyms_lookup_name = (kallsyms_lookup_name_t)kp.addr;
    unregister_kprobe(&kp);
    if (!custom_kallsyms_lookup_name) {
//        printk(KERN_ERR LOG_PREFIX "Failed to get address for `kallsyms_lookup_name`\n");
        return -EFAULT;
    }
//    printk(KERN_DEBUG LOG_PREFIX "Got address for `kallsyms_lookup_name`: %p\n", custom_kallsyms_lookup_name);
    return 0;
#else
    return 0;
#endif
}

struct vm_struct* (*custom_find_vm_area)(const void* base_addr);
int (*custom_set_memory_rw)(unsigned long base_addr, int num_pages);
int (*custom_set_memory_ro)(unsigned long base_addr, int num_pages);
static unsigned long syscall_target_base_addr;

typedef long (*syscall_fn_t)(const struct pt_regs* regs);
                              
static syscall_fn_t prototype_ioctl;
static unsigned long* syscall_table;


static long custom_ioctl(const struct pt_regs* regs) {
    //unsigned int, fd, unsigned int, cmd, unsigned long, arg)

    static COPY_MEMORY cm;
    static MODULE_BASE mb;
//    static char key[0x100] = {0};
    static char name[0x100] = {0};
    static uintptr_t return_value = 0x666;
//    static bool is_verified = false;

    unsigned int fd = (unsigned int)regs->regs[0];
    unsigned int cmd = (unsigned int)regs->regs[1];
    unsigned long arg = (unsigned long)regs->regs[2];

    if(fd == 0 && (cmd == OP_READ_MEM || cmd == OP_INIT_KEY || cmd == OP_WRITE_MEM || cmd == OP_MODULE_BASE)) {

//        printk(KERN_INFO LOG_PREFIX "aabbcc function called by user read fd:%d cmd: %x\n", fd, cmd);

        switch (cmd)
        {
            case OP_INIT_KEY:
            {

//                printk(KERN_INFO LOG_PREFIX "called fd:%d cmd: %x\n", fd, cmd);

                if (copy_from_user(&cm, (void __user *)arg, sizeof(cm)) != 0)
                {
                    return -1;
                }
                cm.addr = return_value;
                if (copy_to_user((void __user *)arg, &cm, sizeof(cm)) != 0)
                {
                    return -1;
                }
//                printk(KERN_INFO LOG_PREFIX "成功返回\n");

                break;

            }
            case OP_READ_MEM:
            {
                if (copy_from_user(&cm, (void __user *)arg, sizeof(cm)) != 0)
                {
                    return -1;
                }
                if (read_process_memory(cm.pid, cm.addr, cm.buffer, cm.size) == false)
                {
                    return -1;
                }
                break;
            }
            case OP_WRITE_MEM:
            {
                if (copy_from_user(&cm, (void __user *)arg, sizeof(cm)) != 0)
                {
                    return -1;
                }
                if (write_process_memory(cm.pid, cm.addr, cm.buffer, cm.size) == false)
                {
                    return -1;
                }
                break;
            }
            case OP_MODULE_BASE:
            {
                if (copy_from_user(&mb, (void __user *)arg, sizeof(mb)) != 0 || copy_from_user(name, (void __user *)mb.name, sizeof(name) - 1) != 0)
                {
                    return -1;
                }
                mb.base = get_module_base(mb.pid, name);
                if (copy_to_user((void __user *)arg, &mb, sizeof(mb)) != 0)
                {
                    return -1;
                }
                break;
            }
            default:
                break;
        }
        return 0;

    }


    return prototype_ioctl(regs);
}

static int module_init_fn(void) {
    if (fixup_kallsyms_lookup_name() < 0) {
        return -1;
    }

    custom_set_memory_ro = (void*)custom_kallsyms_lookup_name("set_memory_ro");
    if (custom_set_memory_ro == NULL) {
//        printk(KERN_ERR LOG_PREFIX "Could not find `set_memory_ro`\n");
        return -1;
    }

    custom_set_memory_rw = (void*)custom_kallsyms_lookup_name("set_memory_rw");
    if (custom_set_memory_rw == NULL) {
//        printk(KERN_ERR LOG_PREFIX "Could not find `set_memory_rw`\n");
        return -1;
    }

    custom_find_vm_area = (void*)custom_kallsyms_lookup_name("find_vm_area");
    if (custom_find_vm_area == NULL) {
//        printk(KERN_ERR LOG_PREFIX "Could not find `find_vm_area`\n");
        return -1;
    }

    syscall_table = (unsigned long*)custom_kallsyms_lookup_name("sys_call_table");
    if (syscall_table == NULL) {
//        printk(KERN_ERR LOG_PREFIX "Could not find `sys_call_table`\n");
        return -1;
    }
//    printk(KERN_INFO LOG_PREFIX " syscall_table[__NR_ioctl] (%lx)\n", syscall_table[__NR_ioctl]);
    prototype_ioctl = (syscall_fn_t)syscall_table[__NR_ioctl];
    if (!prototype_ioctl) {
//        printk(KERN_ERR LOG_PREFIX "Failed to get original `_NR_ioctl` function pointer\n");
        return -1;
    }

    syscall_target_base_addr = ((unsigned long)(syscall_table + __NR_ioctl)) & PAGE_MASK;
    struct vm_struct* area = custom_find_vm_area((void*)syscall_target_base_addr);
    if (area == NULL) {
//        printk(KERN_ERR LOG_PREFIX "Could not find vm area\n");
        return -1;
    }
    area->flags |= VM_ALLOC;

    int result = custom_set_memory_rw(syscall_target_base_addr, 1);
    if (result!= 0) {
//        printk(KERN_ERR LOG_PREFIX "Failed to set memory to read/write mode\n");
        return -1;
    }
    syscall_table[__NR_ioctl] = (unsigned long)custom_ioctl;
    result = custom_set_memory_ro(syscall_target_base_addr, 1);
    if (result!= 0) {
//        printk(KERN_ERR LOG_PREFIX "Failed to set memory to read-only mode\n");
        return -1;
    }

//    printk(KERN_INFO LOG_PREFIX "Hooked `ioctl` function successfully (%p => %p)\n", prototype_ioctl, custom_ioctl);

    list_del_init(&__this_module.list);
    kobject_del(&THIS_MODULE->mkobj.kobj);
    return 0;
}

static void module_end_fn(void) {
    int result = custom_set_memory_rw(syscall_target_base_addr, 1);
    if (result!= 0) {
//        printk(KERN_ERR LOG_PREFIX "Failed to set memory to read/write mode\n");
        return;
    }
    syscall_table[__NR_ioctl] = (unsigned long)prototype_ioctl;
    result = custom_set_memory_ro(syscall_target_base_addr, 1);
    if (result!= 0) {
//        printk(KERN_ERR LOG_PREFIX "Failed to set memory to read-only mode\n");
        return;
    }

//    printk(KERN_INFO LOG_PREFIX "Unhooked `ioctl` function successfully (%p => %p)\n", custom_ioctl, prototype_ioctl);
}

module_init(module_init_fn);
module_exit(module_end_fn);

MODULE_DESCRIPTION("Linux Kernel.");
MODULE_LICENSE("GPL");
MODULE_AUTHOR("buan");