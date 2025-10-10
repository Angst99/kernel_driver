#include "memory.h"
#include "mapper.h"
#include <linux/tty.h>
#include <linux/io.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/version.h>

#include <asm/cpu.h>
#include <asm/io.h>
#include <asm/page.h>
#include <asm/pgtable.h>

extern struct mm_struct *get_task_mm(struct task_struct *task);

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5, 4, 61))
extern void mmput(struct mm_struct *);

phys_addr_t translate_linear_address(struct mm_struct *mm, uintptr_t va)
{

	pgd_t *pgd;
	p4d_t *p4d;
	pmd_t *pmd;
	pte_t *pte;
	pud_t *pud;

	phys_addr_t page_addr;
	uintptr_t page_offset;

	pgd = pgd_offset(mm, va);
	if (pgd_none(*pgd) || pgd_bad(*pgd))
	{
		return 0;
	}
	p4d = p4d_offset(pgd, va);
	if (p4d_none(*p4d) || p4d_bad(*p4d))
	{
		return 0;
	}
	pud = pud_offset(p4d, va);
	if (pud_none(*pud) || pud_bad(*pud))
	{
		return 0;
	}
	pmd = pmd_offset(pud, va);
	if (pmd_none(*pmd))
	{
		return 0;
	}
	pte = pte_offset_kernel(pmd, va);
	if (pte_none(*pte))
	{
		return 0;
	}
	if (!pte_present(*pte))
	{
		return 0;
	}
	// 页物理地址
	page_addr = (phys_addr_t)(pte_pfn(*pte) << PAGE_SHIFT);
	// 页内偏移
	page_offset = va & (PAGE_SIZE - 1);

	return page_addr + page_offset;
}
#else
phys_addr_t translate_linear_address(struct mm_struct *mm, uintptr_t va)
{

	pgd_t *pgd;
	pmd_t *pmd;
	pte_t *pte;
	pud_t *pud;

	phys_addr_t page_addr;
	uintptr_t page_offset;

	pgd = pgd_offset(mm, va);
	if (pgd_none(*pgd) || pgd_bad(*pgd))
	{
		return 0;
	}
	pud = pud_offset(pgd, va);
	if (pud_none(*pud) || pud_bad(*pud))
	{
		return 0;
	}
	pmd = pmd_offset(pud, va);
	if (pmd_none(*pmd))
	{
		return 0;
	}
	pte = pte_offset_kernel(pmd, va);
	if (pte_none(*pte))
	{
		return 0;
	}
	if (!pte_present(*pte))
	{
		return 0;
	}
	// 页物理地址
	page_addr = (phys_addr_t)(pte_pfn(*pte) << PAGE_SHIFT);
	// 页内偏移
	page_offset = va & (PAGE_SIZE - 1);

	return page_addr + page_offset;
}
#endif

//#ifndef ARCH_HAS_VALID_PHYS_ADDR_RANGE
//static inline int valid_phys_addr_range(phys_addr_t addr, size_t count)
//{
//	return addr + count <= __pa(high_memory);
//}
//#endif

#ifdef ARCH_HAS_VALID_PHYS_ADDR_RANGE
static size_t get_high_memory(void)
{
	struct sysinfo meminfo;
	si_meminfo(&meminfo);
	return (meminfo.totalram * (meminfo.mem_unit / 1024)) << PAGE_SHIFT;
}
#define valid_phys_addr_range(addr, count) (addr + count <= get_high_memory())
#else
#define valid_phys_addr_range(addr, count) true
#endif

bool read_physical_address(phys_addr_t pa, void *buffer, size_t size)
{
	void *mapped;

	if (!pfn_valid(__phys_to_pfn(pa)))
	{
		return false;
	}
	if (!valid_phys_addr_range(pa, size))
	{
		return false;
	}
	mapped = ioremap_cache(pa, size);
	if (!mapped)
	{
		return false;
	}
	if (copy_to_user(buffer, mapped, size))
	{
		iounmap(mapped);
		return false;
	}
	iounmap(mapped);
	return true;
}


bool write_physical_address(phys_addr_t pa, void *buffer, size_t size)
{
	void *mapped;

	if (!pfn_valid(__phys_to_pfn(pa)))
	{
		return false;
	}
	if (!valid_phys_addr_range(pa, size))
	{
		return false;
	}
	mapped = ioremap_cache(pa, size);
	if (!mapped)
	{
		return false;
	}
	if (copy_from_user(mapped, buffer, size))
	{
		iounmap(mapped);
		return false;
	}
	iounmap(mapped);
	return true;
}

bool read_process_memory(
	pid_t pid,
	uintptr_t addr,
	void *buffer,
	size_t size)
{

	struct task_struct *task;
	struct mm_struct *mm;
	struct pid *pid_struct;
	phys_addr_t pa;

	pid_struct = find_get_pid(pid);
	if (!pid_struct)
	{
		return false;
	}
	task = get_pid_task(pid_struct, PIDTYPE_PID);
	if (!task)
	{
		return false;
	}
	mm = get_task_mm(task);
	if (!mm)
	{
		return false;
	}
	mmput(mm);
	pa = translate_linear_address(mm, addr);
	if (!pa)
	{
		return false;
	}
	return read_physical_address(pa, buffer, size);
}

#include <linux/mutex.h>

static DEFINE_MUTEX(mapper_lock);

bool read_process_memory_by_py_read(
	pid_t pid,
	uintptr_t addr,
	void *dest,
	size_t size)
{

	struct task_struct *task;
	struct mm_struct *mm;
	struct pid *pid_struct;
	phys_addr_t phy_addr;
	unsigned long last_addr;
	size_t mapped_size;


	pid_struct = find_get_pid(pid);
	if (!pid_struct)
	{
		return false;
	}
	task = get_pid_task(pid_struct, PIDTYPE_PID);
	if (!task)
	{
		return false;
	}
	mm = get_task_mm(task);
	if (!mm)
	{
		return false;
	}
	mmput(mm);
	phy_addr = translate_linear_address(mm, addr);
	if (!phy_addr)
	{
		return false;
	}
	
	if (!pfn_valid(__phys_to_pfn(phy_addr)))
	{
		return false;
	}
	if (!valid_phys_addr_range(phy_addr, size))
	{
		return false;
	}
	mapped_size = PAGE_ALIGN(size + (phy_addr & ~PAGE_MASK));

	last_addr = (phy_addr & PAGE_MASK) + mapped_size - 1;
	if (!mapped_size || last_addr < (phy_addr & PAGE_MASK) || (last_addr & ~PHYS_MASK)) {
		pr_err("[ovo] Invalid address range last_addr: size=%zu\n", mapped_size);
        return false;
	}
	
	// 计算页面偏移
    page_offset = phy_addr & (PAGE_SIZE - 1);
    
    // 检查是否跨越页面边界
    if (page_offset + size > PAGE_SIZE) {
        pr_err("[ovo] Access crosses page boundary: offset %zu, size %zu\n",
               page_offset, size);
        return false;
    }
	
	mutex_lock(&mapper_lock);
	if (init_mapper() != 0) {
		pr_err("[ovo] init_mapper failed\n");
		mutex_unlock(&mapper_lock);
		return false;
	}
	// 映射对齐到页面边界的物理地址
	map_phys_page(phy_addr & PAGE_MASK);
	
	if (copy_to_user(dest, mapper_page + page_offset, size)) {
		destroy_mapper();
		mutex_unlock(&mapper_lock);
		return false;
	}
	destroy_mapper();
	mutex_unlock(&mapper_lock);
	
	return true;
}


bool write_process_memory(
	pid_t pid,
	uintptr_t addr,
	void *buffer,
	size_t size)
{

	struct task_struct *task;
	struct mm_struct *mm;
	struct pid *pid_struct;
	phys_addr_t pa;

	pid_struct = find_get_pid(pid);
	if (!pid_struct)
	{
		return false;
	}
	task = get_pid_task(pid_struct, PIDTYPE_PID);
	if (!task)
	{
		return false;
	}
	mm = get_task_mm(task);
	if (!mm)
	{
		return false;
	}
	mmput(mm);
	pa = translate_linear_address(mm, addr);
	if (!pa)
	{
		return false;
	}
	return write_physical_address(pa, buffer, size);
}
