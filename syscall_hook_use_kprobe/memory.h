#include <linux/kernel.h>
#include <linux/sched.h>

phys_addr_t translate_linear_address(struct mm_struct *mm, uintptr_t va);

bool read_physical_address(phys_addr_t pa, void *buffer, size_t size);

bool write_physical_address(phys_addr_t pa, void *buffer, size_t size);

bool read_process_memory(pid_t pid, uintptr_t addr, void *buffer, size_t size);

bool read_process_memory_by_py_read(pid_t pid, uintptr_t addr, void *dest, size_t size);

bool write_process_memory(pid_t pid, uintptr_t addr, void *buffer, size_t size);
