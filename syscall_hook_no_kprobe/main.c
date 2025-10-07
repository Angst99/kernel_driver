#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/mm.h>
#include <linux/syscalls.h>
#include <asm/tlbflush.h>
#include <asm/unistd.h>
#include <linux/linkage.h>
// #include <asm/syscall.h>
#include <linux/version.h>
#include <linux/kconfig.h>

#include <linux/fs.h> // 添加文件操作需要的头文件
#include <linux/seq_file.h> // 添加seq_file相关头

#define bits(n, high, low) (((n) << (63u - (high))) >> (63u - (high) + (low)))

typedef asmlinkage long (*syscall_ioctl_t)(unsigned int fd, unsigned int cmd, unsigned long arg);
typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);
typedef long (*new_syscall_ioctl_t)(const struct pt_regs *);

static kallsyms_lookup_name_t kallsyms_lookup_name_func = NULL; // 使用一个函数指针变量来保存地址

// unsigned long (my_kallsyms_lookup_name)(const char *name);

typedef asmlinkage long (*sys_call_ptr_t)(const struct pt_regs *);
static sys_call_ptr_t *sys_call_table = NULL;


unsigned long start_address;
unsigned long finish_address;
syscall_ioctl_t original_ioctl;

#if LINUX_VERSION_CODE > KERNEL_VERSION(4, 14, 186)
new_syscall_ioctl_t new_original_ioctl;
#endif

static uint64_t page_size_t = 0;
static uint64_t page_level_c = 0;
static uint64_t page_shift_t = 0;
static uint64_t pgd_k_pa = 0;
static uint64_t pgd_k = 0;

static int setts(int value) {
    struct file *file;
    loff_t pos = 0;
    char buf[2];

    file = filp_open("/proc/sys/kernel/kptr_restrict", O_WRONLY, 0);
    if (IS_ERR(file)) {
        printk(KERN_ERR "Failed to open /proc/sys/kernel/kptr_restrict\n");
        return PTR_ERR(file);
    }

    snprintf(buf, sizeof(buf), "%d", value);

    kernel_write(file, buf, strlen(buf), &pos);

    filp_close(file, NULL);

    return 0;
}

static uintptr_t read_kallsyms(const char *symbol) {
    struct file *file;
    loff_t pos = 0;
    char *buf;
    char sym_name[256];
    char *addr_str, *type_str, *name_str;
    uintptr_t addr = 0;
    mm_segment_t old_fs;
    ssize_t ret;

    file = filp_open("/proc/kallsyms", O_RDONLY, 0);
    if (IS_ERR(file)) {
        printk(KERN_ERR "无法打开kallsyms\n");
        return 0;
    }

    old_fs = get_fs();
    set_fs(KERNEL_DS);

    buf = kmalloc(4096, GFP_KERNEL);
    if (!buf) {
        filp_close(file, NULL);
        set_fs(old_fs);
        return 0;
    }

    while ((ret = kernel_read(file, buf, 4096, &pos)) > 0) {
        char *line = buf;
        
        while (*line) {
            char *end = strchr(line, '\n');
            if (end) *end = '\0';
            
            addr_str = line;
            type_str = strchr(line, ' ');
            if (!type_str) break;
            *type_str++ = '\0';
            
            name_str = strchr(type_str, ' ');
            if (!name_str) break;
            *name_str++ = '\0';

            addr = simple_strtoull(addr_str, NULL, 16);
            strncpy(sym_name, name_str, sizeof(sym_name) - 1);
            sym_name[sizeof(sym_name) - 1] = '\0';

            if (strcmp(sym_name, symbol) == 0) {
                kfree(buf);
                filp_close(file, NULL);
                set_fs(old_fs);
                return addr;
            }

            if (end) line = end + 1;
            else break;
        }
    }
    
    kfree(buf);
    filp_close(file, NULL);
    set_fs(old_fs);
    return 0;
}

static unsigned long get_kernel_start_address(void)
{
    struct file *file;
    loff_t pos = 0;
    char buf[128];
    mm_segment_t old_fs;
    int ret;
    unsigned long start_addr = 0;
    char *space_pos;

    file = filp_open("/proc/kallsyms", O_RDONLY, 0);
    if (IS_ERR(file)) {
        printk(KERN_ERR "[hook] Failed to open /proc/kallsyms\n");
        return 0;
    }

    old_fs = get_fs();
    set_fs(KERNEL_DS);

    ret = kernel_read(file, buf, sizeof(buf) - 1, &pos);
    if (ret <= 0) {
        printk(KERN_ERR "[hook] Failed to read /proc/kallsyms\n");
        filp_close(file, NULL);
        set_fs(old_fs);
        return 0;
    }
    
    buf[ret] = '\n'; 

    space_pos = strchr(buf, ' ');
    if (space_pos) {
        *space_pos = '\0';
    }

    start_addr = simple_strtoull(buf, NULL, 16);
    
    filp_close(file, NULL);
    set_fs(old_fs);
    
    printk(KERN_INFO "[hook] Kernel start address: 0x%lx\n", start_addr);
    return start_addr;
}

// 初始化页表工具
__attribute__((no_sanitize("cfi"))) void init_page_util(void)
{
    uint64_t tcr_el1;
    uint64_t ttbr1_el1;
    uint64_t va_bits;
    uint64_t t1sz;
    uint64_t tg1;
    uint64_t baddr;
    uint64_t page_size_mask;
    
    asm volatile("mrs %0, tcr_el1" : "=r"(tcr_el1));
    t1sz = bits(tcr_el1, 21, 16);
    tg1 = bits(tcr_el1, 31, 30);
    va_bits = 64 - t1sz;

    page_shift_t = 12;
    if (tg1 == 1) {
        page_shift_t = 14;
    } else if (tg1 == 3) {
        page_shift_t = 16;
    }
    page_size_t = 1 << page_shift_t;
    page_level_c = (va_bits - 4) / (page_shift_t - 3);
    
    asm volatile("mrs %0, ttbr1_el1" : "=r"(ttbr1_el1));
    baddr = ttbr1_el1 & 0xFFFFFFFFFFFE;
    page_size_mask = ~(page_size_t - 1);
    pgd_k_pa = baddr & page_size_mask;
    pgd_k = (uint64_t)phys_to_virt(pgd_k_pa);
    
    printk(KERN_INFO "[hook] page_size_t: %lx\n", page_size_t);
    printk(KERN_INFO "[hook] page_level_c: %lx\n", page_level_c);
    printk(KERN_INFO "[hook] page_shift_t: %lx\n", page_shift_t);
    printk(KERN_INFO "[hook] pgd_k_pa: %lx\n", pgd_k_pa);
    printk(KERN_INFO "[hook] pgd_k: %lx\n", pgd_k);
}

// 获取页表项
uint64_t *pgtable_entry(uint64_t pgd, uint64_t va)
{
    uint64_t pxd_bits = page_shift_t - 3;
    uint64_t pxd_ptrs = 1u << pxd_bits;
    uint64_t pxd_va = pgd;
    uint64_t pxd_pa = virt_to_phys((void*)pxd_va);
    uint64_t pxd_entry_va = 0;
    uint64_t block_lv = 0;
    int64_t lv = 0;
    uint64_t pxd_desc = 0;

    if(page_shift_t == 0 || page_level_c == 0)
        return NULL;

    for (lv = 4 - page_level_c; lv < 4; lv++) {
        uint64_t pxd_shift = (page_shift_t - 3) * (4 - lv) + 3;
        uint64_t pxd_index = (va >> pxd_shift) & (pxd_ptrs - 1);
        pxd_entry_va = pxd_va + pxd_index * 8;
        
        if (!pxd_entry_va) return NULL;
        
        pxd_desc = *((uint64_t *)pxd_entry_va);
        if ((pxd_desc & 0b11) == 0b11) { // table
            pxd_pa = pxd_desc & (((1ul << (48 - page_shift_t)) - 1) << page_shift_t);
        } else if ((pxd_desc & 0b11) == 0b01) { // block
            uint64_t block_bits = (3 - lv) * pxd_bits + page_shift_t;
            pxd_pa = pxd_desc & (((1ul << (48 - block_bits)) - 1) << block_bits);
            block_lv = lv;
        } else { // invalid
            return NULL;
        }
        
        pxd_va = (uint64_t)phys_to_virt((phys_addr_t)pxd_pa);
        if (block_lv) {
            break;
        }
    }
    
    return (uint64_t *)pxd_entry_va;
}

// 获取内核页表项
inline uint64_t *pgtable_entry_kernel(uint64_t va)
{
    return pgtable_entry(pgd_k, va);
}


sys_call_ptr_t *find_sys_call_table_by_scanning(void)
{
    unsigned long sys_read_addr, sys_write_addr;
    unsigned long start, end;
    // unsigned long i;
    sys_call_ptr_t *candidate;
    
    unsigned long addr;
    setts(0);
    // 获取kallsyms_lookup_name地址
    addr = (unsigned long)read_kallsyms("kallsyms_lookup_name");
    printk(KERN_ERR "[hook]kallsyms_lookup_name address : %lx\n", addr);
    kallsyms_lookup_name_func = (kallsyms_lookup_name_t)addr;
    if (!kallsyms_lookup_name_func) {
        printk(KERN_ERR "[hook] Failed to get kallsyms_lookup_name address\n");
        return NULL;
    }
    
    // 获取已知系统调用的地址
    sys_read_addr = kallsyms_lookup_name_func("sys_read");
    sys_write_addr = kallsyms_lookup_name_func("sys_write");
    
    if (!sys_read_addr || !sys_write_addr) {
        printk(KERN_ERR "[hook] Failed to find known syscalls for scanning\n");
        return NULL;
    }
    
    // 确定搜索范围
    
    
	start = get_kernel_start_address();//kallsyms_lookup_name_func("_stext");
	end = start + 0x2000000;
	printk(KERN_INFO "[hook] Found sys start address by _stext _etext \n");

    
    //ffffff844b100000
    //ffffff844a080800
    printk(KERN_INFO "[hook] Scanning memory from %lx to %lx for sys_call_table\n", start, end);
    
    // 扫描内存，寻找包含已知系统调用地址的模式
    for (candidate = (sys_call_ptr_t *)start; (unsigned long)candidate < end; candidate++) {
    // for (i = start; i < end; i += sizeof(void *)) {
    	// candidate = (sys_call_ptr_t *)i;
        if (candidate[__NR_read] == (sys_call_ptr_t)sys_read_addr &&
            candidate[__NR_write] == (sys_call_ptr_t)sys_write_addr) {
            
            printk(KERN_INFO "[hook] Found sys_call_table candidate at %p\n", candidate);
            
            return candidate;
        }
    }
    
    printk(KERN_ERR "[hook] Failed to find sys_call_table by scanning\n");
    return NULL;
}



// Hook函数实现
#if LINUX_VERSION_CODE <= KERNEL_VERSION(4, 14, 186)
asmlinkage long hook_ioctl(unsigned int fd, unsigned int cmd, unsigned long arg)
{
    long ret = 0;
    printk(KERN_INFO "[hook] gt_hook_ioctl\n");
    ret = original_ioctl(fd, cmd, arg);
    return ret;
}
#else
long new_hook_ioctl(const struct pt_regs *regs)
{
    long ret = 0;
    printk(KERN_INFO "[hook] gt_hook_successful_ioctl\n");
    ret = new_original_ioctl(regs);
    return ret;
}
#endif

// Hook系统调用函数
static int hook_func(unsigned long* hook_function, int nr, sys_call_ptr_t *sys_table)
{
    uint64_t orginal_pte;
    uint64_t *pte;
    
    if(nr < 0 || !sys_table)
        return -EINVAL;

    pte = pgtable_entry_kernel((uint64_t)&sys_table[nr]);
    if(!pte)
        return -EFAULT;
    
    orginal_pte = *pte;
    *pte = (orginal_pte | PTE_DBM) & ~PTE_RDONLY;
    flush_tlb_all();
    
    sys_table[nr] = (sys_call_ptr_t)hook_function;
    
    *pte = orginal_pte;
    flush_tlb_all();
    
    return 0;
}


// 模块初始化
static int __init my_module_init(void) {
    int ret;
    // unsigned long sys_close_addr;

#if !IS_BUILTIN(CONFIG_KPROBES) || !IS_BUILTIN(CONFIG_KRETPROBES)
    
    printk(KERN_INFO "[hook] no kprobe config\n");
#endif
    
    printk(KERN_INFO "[hook] Initializing module\n");
    
    
    sys_call_table = find_sys_call_table_by_scanning();
    if (!sys_call_table) {
        printk(KERN_ERR "Failed to find sys_call_table\n");
        return -ENODEV;
    }
    
    printk(KERN_INFO "Found sys_call_table at %p\n", sys_call_table);
    
  
    
    printk(KERN_INFO "[hook] sys_call_table found at: %px\n", sys_call_table[__NR_ioctl]);
    
    // 保存原始系统调用
    #if LINUX_VERSION_CODE <= KERNEL_VERSION(4, 14, 186)
        original_ioctl = (syscall_ioctl_t)sys_call_table[__NR_ioctl];
    #else
        new_original_ioctl = (new_syscall_ioctl_t)sys_call_table[__NR_ioctl];
    #endif
    
    // 初始化页表工具
    init_page_util();
    
    // // 安装Hook
    #if LINUX_VERSION_CODE <= KERNEL_VERSION(4, 14, 186)
        ret = hook_func((unsigned long*)hook_ioctl, __NR_ioctl, sys_call_table);
    #else
        ret = hook_func((unsigned long*)new_hook_ioctl, __NR_ioctl, sys_call_table);
    #endif
    
    if (ret) {
        printk(KERN_ERR "Failed to hook ioctl: %d\n", ret);
        return ret;
    }
    
    printk(KERN_INFO "[hook] Module initialized successfully\n");
    return 0;
}

// 模块退出
static void __exit my_module_exit(void) {
    int ret;
    
    printk(KERN_INFO "[hook] Exiting module\n");
    
    //移除Hook ioctl移除会崩溃
    #if LINUX_VERSION_CODE <= KERNEL_VERSION(4, 14, 186)
        ret = hook_func((unsigned long*)original_ioctl, __NR_ioctl, sys_call_table);
    #else
        ret = hook_func((unsigned long*)new_original_ioctl, __NR_ioctl, sys_call_table);
    #endif
    
    if (ret) {
        printk(KERN_ERR "[hook] Failed to restore original ioctl: %d\n", ret);
    }
    
    printk(KERN_INFO "[hook] Module exited\n");
}

module_init(my_module_init);
module_exit(my_module_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Custom syscall module using kprobes");
MODULE_AUTHOR("wangchuan");

