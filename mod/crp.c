#include<linux/module.h>
#include<linux/kernel.h>
#include<linux/mm.h>
#include<linux/mm_types.h>
#include<linux/file.h>
#include<linux/fs.h>
#include<linux/path.h>
#include<linux/slab.h>
#include<linux/dcache.h>
#include<linux/sched.h>
#include<linux/uaccess.h>
#include<linux/fs_struct.h>
#include <asm/tlbflush.h>
#include<linux/uaccess.h>
#include<linux/device.h>
#include<linux/delay.h>
#include<linux/kallsyms.h>
#include<linux/sched/task_stack.h>
#include<linux/ptrace.h>

#include "crp.h"

#define DEVNAME "crp"
#define MAX_FNAME 60
// #define PAGE_SIZE 1 << 12

static int major;
atomic_t  device_opened;
static struct class *demo_class;
struct device *demo_device;

// unsigned long (*kln)(const char *) = 0xffffffffa5344fc0;

static unsigned long gptr;

// checkpointing functions

static pte_t* get_pte(unsigned long address, struct mm_struct* mm){
	pgd_t *pgd;
	p4d_t *p4d;
	pud_t *pud;
	pmd_t *pmd;
	pte_t *ptep;

	pgd = pgd_offset(mm, address);
	if (pgd_none(*pgd) || unlikely(pgd_bad(*pgd)))
		goto nul_ret;
	// printk(KERN_INFO "pgd(va) [%lx] pgd (pa) [%lx] *pgd [%lx]\n", (unsigned long)pgd, __pa(pgd), pgd->pgd); 
	p4d = p4d_offset(pgd, address);
	if (p4d_none(*p4d))
		goto nul_ret;
	if (unlikely(p4d_bad(*p4d)))
		goto nul_ret;
	pud = pud_offset(p4d, address);
	if (pud_none(*pud))
		goto nul_ret;
	if (unlikely(pud_bad(*pud)))
		goto nul_ret;
	// printk(KERN_INFO "pud(va) [%lx] pud (pa) [%lx] *pud [%lx]\n", (unsigned long)pud, __pa(pud), pud->pud); 

	pmd = pmd_offset(pud, address);
	if (pmd_none(*pmd))
		goto nul_ret;
	if (unlikely(pmd_trans_huge(*pmd))){
		// printk(KERN_INFO "I am huge\n");
		// Huge page, get huge page from pmd
		goto nul_ret;
	}
	// printk(KERN_INFO "pmd(va) [%lx] pmd (pa) [%lx] *pmd [%lx]\n", (unsigned long)pmd, __pa(pmd), pmd->pmd); 
	ptep = pte_offset_map(pmd, address);
	if(!ptep){
		printk(KERN_INFO "pte_p is null\n\n");
		goto nul_ret;
	}
	// printk(KERN_INFO "pte(va) [%lx] pte (pa) [%lx] *pte [%lx]\n", (unsigned long)ptep, __pa(ptep), ptep->pte); 
	return ptep;

	nul_ret:
		// printk(KERN_INFO "Address could not be translated\n");
		return NULL;

}

int dump_struct(void* buff, int length, char* fname){
    loff_t pos;
	unsigned long err;
	printk(KERN_INFO "Before file open\n");
	struct file* fp = filp_open(fname, O_RDWR | O_CREAT, S_IRWXU);
	pos = 0;
    if(!fp) return -1;
	printk(KERN_INFO "Before kernel_write\n");
    err = kernel_write(fp, buff, length, &pos);
	printk(KERN_INFO "After kernel_write\n");
    filp_close(fp, NULL);
    if(err != length) return -1;
    return err;
}

int read_struct(void* buff, int length, char* fname){
    loff_t pos;
    unsigned long err;
	struct file* fp = filp_open(fname, O_RDONLY, 0);
	pos = 0;
    if(!fp) return -1;
	err = kernel_read(fp, (char*)buff, length, &pos);
    filp_close(fp, NULL);
    if(err != length) return -1;
    return err;
}

static void do_ckp_vma(struct pid* pid){
	struct vma_copy* block;
	int id = 0;
	struct task_struct* proc = get_pid_task(pid, PIDTYPE_PID);
	if (!proc){
		printk(KERN_INFO "Got NULL proc\n");
		goto nul_ret;
	}
	// Iterate over and copy to /checkpoint/vma/randomid
	struct mm_struct *mm = proc->mm;
	if (!mm){
		printk(KERN_INFO "Got NULL mm\n");
		goto nul_ret;
	}

	struct vm_area_struct *vma = mm->mmap;
	if(!vma){
		printk(KERN_INFO "No vma yet\n");
		goto nul_ret;
	}
	// ID should be some random hash
	block = kzalloc(sizeof(struct vma_copy), GFP_KERNEL);
	if (!block){
		printk(KERN_INFO "Can't allocate memory\n");
		goto nul_ret;
	}
	printk(KERN_INFO "before while\n");
	while(vma){
		block->vm_flags = vma->vm_flags;
		block->vm_start = vma->vm_start;
		block->vm_end = vma->vm_end;
		block->vm_next = (uint64_t)vma->vm_next;
		char fname[MAX_FNAME];
		snprintf(fname, MAX_FNAME, "vma_%d.ckpt", id++);
		printk("Checkpointing at %s\n", fname);
		if(dump_struct(block, sizeof(struct vma_copy), fname) != sizeof(struct vma_copy)){
			printk(KERN_INFO "do_ckp_vma: dump struct failed\n");
			return;
		}
		// do_ckp_mem(pid, )
		vma = vma->vm_next;
	}
	kfree(block);
	put_task_struct(proc);
	return;

nul_ret:
	printk(KERN_INFO "Can not walk vma\n");
	return;
}

static void do_ckp_mem(struct pid* pid, struct mm_struct* mm, struct vm_area_struct* vma){
	// Iterate over and copy to /checkpoint/mem/randomid
	unsigned long address;
	int id = 0;
	for (address = vma->vm_start; address < vma->vm_end; address+=PAGE_SIZE){
		pte_t* ptep = get_pte(address, mm);
		struct page* curr = pte_page(*ptep);
		char fname[MAX_FNAME];
		// This would result in segfault -- folders need to be created. 
		snprintf(fname, MAX_FNAME, "/home/paras/Desktop/checkpoint/page/%lx.ckpt",address);
		dump_struct((char*)curr, sizeof(struct page), fname);

		snprintf(fname, MAX_FNAME, "/home/paras/Desktop/checkpoint/mem/%lx.ckpt", address);
		dump_struct((char*)curr, PAGE_SIZE, fname);            // TODO: get page from struct page
	}
	// put_task_struct(proc);
	return;
}

// static void do_ckp_proc(struct pid* pid){
//         struct task_struct* proc = get_pid_task(pid);
        
//         // Iterate over and copy to /checkpoint/proc/randomid

//         put_task_struct(proc);
//         return;
// }

// Restore functions 

// TODO: get id for the address. 
static int get_id(int address){
	static int id_count = 0;
	return id_count++;
}

static void do_rst_vma(struct pid* pid){
	// checkpoint path : /home/paras/Desktop/checkpoint/
	// The process has already been "created". 
	// Just restore the vma's
	// We might need to return the vma(head) kernel address. 
	int next_vma = 0;
	struct vma_copy *vcopy = kzalloc(sizeof(struct vma_copy), GFP_KERNEL);
	struct vm_area_struct *prev = NULL;
	while(next_vma > 0){
		// allocate buffer and read vma. 
		struct vm_area_struct *vma = kzalloc(sizeof(struct vm_area_struct), GFP_KERNEL);
		char fname[MAX_FNAME];
		snprintf(fname, MAX_FNAME, "vma%d.ckpt", next_vma);		// directory structure 
		read_struct(vcopy, sizeof(struct vma_copy), fname);
		vma->vm_start = vcopy->vm_start;
		vma->vm_end = vcopy->vm_end;
		if (prev){
			prev->vm_next = vma;
		}
		prev = vma;
		vma->vm_next = NULL;			// This will be generated in the next iteration, recursive approach?
		// Update next_vma by lookup using vcopy->vm_next
		next_vma = get_id(vcopy->vm_next);		// get_id is not implemented yet
		// restore pages for this vma
	}
	kfree(vcopy);
}

static void do_rst_mem(struct pid* pid, struct vm_area_struct* vma){
	// iterate over address space
	unsigned long address;
	for(address = vma->vm_start; address < vma->vm_end; address+=PAGE_SIZE){
		// allocate a buffer of size page and read a page to it. 
		// Directly allocate a page and copy to it if possible, don't think linux allows that. 
		char* curr = kzalloc(PAGE_SIZE, GFP_KERNEL);			
		char fname[MAX_FNAME];
		snprintf(fname, MAX_FNAME, "/home/paras/Desktop/checkpoint/vma/%ld.ckpt", address);
		read_struct(curr, PAGE_SIZE, fname);
		// Allocate page in user space how tf do I do this. 
		// copy_to_user(page_addr, curr); ??? 
		// Put this page into page table. 
	}	
}

// static void do_rst_proc(struct pid* pid){

// }


static int demo_open(struct inode *inode, struct file *file)
{
	atomic_inc(&device_opened);
	try_module_get(THIS_MODULE);
	printk(KERN_INFO "Device opened successfully\n");
	return 0;
}

static int demo_release(struct inode *inode, struct file *file)
{
	atomic_dec(&device_opened);
	module_put(THIS_MODULE);
	printk(KERN_INFO "Device closed successfully\n");

	return 0;
}

static void quiesce_pid(void* args)
{
    // int pid = (int)args;
    // struct task_struct *task;
    printk("quiesce_pid: cpu id %d\n", smp_processor_id());
    printk("quiesce_pid: pid %d\n", current->pid);
}

static void ckpt_cpu_state(pid_t pidno){
    struct pid* _pid = find_get_pid(pidno);
    struct task_struct *task = get_pid_task(_pid, PIDTYPE_PID);
    if(task == NULL){
        printk(KERN_INFO "task is null\n");
        return;
    }
    // struct pt_regs* regs = task->thread.regs;
    struct pt_regs* regs = task_pt_regs(task);
    printk(KERN_INFO "ckpt_cpu_state: rax reg %d\n", regs->ax);
    printk(KERN_INFO "ckpt_cpu_state: cs-ip reg %d-%d\n", regs->cs, regs->ip);
	char fname[MAX_FNAME];
	snprintf(fname, MAX_FNAME, "cpu_state%d.ckpt", pidno);
    if(dump_struct(regs, sizeof(struct pt_regs), fname) != sizeof(struct pt_regs)){
        printk(KERN_INFO "ckpt_cpu_state: dump struct failed\n");
        return;
    }
    printk(KERN_INFO "ckpt_cpu_state: rax reg %d\n", regs->ax);
    printk(KERN_INFO "ckpt_cpu_state: cs-ip reg %d-%d\n", regs->cs, regs->ip);
}

static ssize_t demo_read(struct file *filp,
                           char __user*buffer,
                           size_t length,
                           loff_t * offset)
{           
    printk(KERN_INFO "In read\n");
    unsigned long* args = kzalloc(length, GFP_KERNEL);
    if(copy_from_user(args, buffer, length) == 0){
        int command = args[0];
        int pid = args[1];
        printk(KERN_INFO "command = %d, pid = %d\n", command, pid);
        on_each_cpu(quiesce_pid, (void*)pid, 1);
        struct task_struct *task;
        struct pid* _pid = find_get_pid(pid);
        kill_pid(_pid, SIGSTOP, 1);
        task = get_pid_task(_pid, PIDTYPE_PID);
        if(task == NULL){
            printk(KERN_INFO "task is null\n");
            return -1;
        }
        printk(KERN_INFO "task %d status %ld\n", task->pid, task->state);
        // start checkpointing
        // ckpt_cpu_state(pid);
        do_ckp_vma(_pid);
        // finished
        kill_pid(_pid, SIGCONT, 1);
        put_pid(_pid);
        
        return length;
    }
    return -1;
}

static void rest_cpu_state(pid_t pidno){
    // struct pt_regs* regs = task->thread.regs;
    struct pt_regs* regs = current_pt_regs();
    printk(KERN_INFO "rest_cpu_state: rax reg %d\n", regs->ax);
    printk(KERN_INFO "rest_cpu_state: cs-ip reg %d-%d\n", regs->cs, regs->ip);
    if(read_struct(regs, sizeof(struct pt_regs), "cpu_state.ckpt") != sizeof(struct pt_regs)){
        printk(KERN_INFO "rest_cpu_state: dump struct failed\n");
        return;
    }
    printk(KERN_INFO "rest_cpu_state: rax reg %d\n", regs->ax);
    printk(KERN_INFO "rest_cpu_state: cs-ip reg %d-%d\n", regs->cs, regs->ip);
}

static ssize_t
demo_write(struct file *filp, const char *buffer, size_t length, loff_t * offset)
{
           
    printk(KERN_INFO "In write\n");
    unsigned long* args = kzalloc(length, GFP_KERNEL);
    if(copy_from_user(args, buffer, length) == 0){
        int command = args[0];
        int pid = args[1];
        printk(KERN_INFO "command = %d, pid = %d\n", command, pid);
        
        // start restoring
	/*
        rest_cpu_state(pid);
    */  
		// finished
        
        return length;
    }
    return -1;
}

static struct file_operations fops = {
        .read = demo_read,
        .write = demo_write,
        .open = demo_open,
        .release = demo_release,
};

static char *demo_devnode(struct device *dev, umode_t *mode)
{
        if (mode && dev->devt == MKDEV(major, 0))
                *mode = 0666;
        return NULL;
}

int init_module(void)
{
        int err;
	printk(KERN_INFO "Hello kernel\n");
            
        major = register_chrdev(0, DEVNAME, &fops);
        err = major;
        if (err < 0) {      
             printk(KERN_ALERT "Registering char device failed with %d\n", major);   
             goto error_regdev;
        }                 
        
        demo_class = class_create(THIS_MODULE, DEVNAME);
        err = PTR_ERR(demo_class);
        if (IS_ERR(demo_class))
                goto error_class;

        demo_class->devnode = demo_devnode;

        demo_device = device_create(demo_class, NULL,
                                        MKDEV(major, 0),
                                        NULL, DEVNAME);
        err = PTR_ERR(demo_device);
        if (IS_ERR(demo_device))
                goto error_device;
 
        printk(KERN_INFO "I was assigned major number %d. To talk to\n", major);                                                              
        atomic_set(&device_opened, 0);
       
// 	printk(KERN_INFO "dup_mm: %x kln: %x dup_mm: %p\n", kln("dup_mm"), kln, kln("dup_mm"));
	return 0;

error_device:
         class_destroy(demo_class);
error_class:
        unregister_chrdev(major, DEVNAME);
error_regdev:
        return  err;
}

void cleanup_module(void)
{
        device_destroy(demo_class, MKDEV(major, 0));
        class_destroy(demo_class);
        unregister_chrdev(major, DEVNAME);
	printk(KERN_INFO "Goodbye kernel\n");
}

MODULE_AUTHOR("devgiri@iitk.ac.in");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Checkpoint/Restore Process");
