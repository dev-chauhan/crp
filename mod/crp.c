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
#include<linux/highmem.h>
#include<linux/vmacache.h>
#include<linux/fdtable.h>
#include<asm/fsgsbase.h>
#include <asm/segment.h>
#include <linux/sched/mm.h>

#include "crp.h"

#define DEVNAME "crp"
#define MAX_FNAME 60
// #define PAGE_SIZE 1 << 12
#define CURR_DIR "."

#define KLN_OFFSET 0xffffffff8c344fc0

static int major;
atomic_t  device_opened;
static struct class *demo_class;
struct device *demo_device;

unsigned long (*kln)(const char *) = KLN_OFFSET;
struct mm_struct * (*crp_dup_mm)(struct task_struct* tsk, struct mm_struct * oldmm);

static unsigned long gptr;
static unsigned long tmpvar;
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
	// printk(KERN_INFO "Before file open\n");
	struct file* fp = filp_open(fname, O_RDWR | O_CREAT, S_IRWXU);
	pos = 0;
    if(IS_ERR(fp)) return -1;
	// printk(KERN_INFO "Before kernel_write\n");
    err = kernel_write(fp, buff, length, &pos);
	// printk(KERN_INFO "After kernel_write\n");
    filp_close(fp, NULL);
    if(err != length) return -1;
    return err;
}

int read_struct(void* buff, int length, char* fname){
    loff_t pos;
    unsigned long err;
	struct file* fp = filp_open(fname, O_RDONLY, 0);
	pos = 0;
	// printk(KERN_INFO "%p filp_open return\n", fp);
    if(IS_ERR(fp)) return -1;
	err = kernel_read(fp, (char*)buff, length, &pos);
    filp_close(fp, NULL);
    if(err != length) return -1;
    return err;
}

static void get_vma(struct mm_struct* mm)
{
        struct vm_area_struct *vma = mm->mmap;
        char flags[4] = {'-'};
        if(!vma){
                 printk(KERN_INFO "No vma yet\n");
                 goto nul_ret;
        }
        while(vma){
            flags[0] = flags[1] = flags[2] = '-';
            if(vma->vm_flags&(VM_READ)){
                flags[0] = 'R';
            }
            if(vma->vm_flags&(VM_WRITE)){
                flags[1] = 'W';
            }
            if(vma->vm_flags&(VM_EXEC)){
                flags[2] = 'X';
            }
            flags[3] = '\0';
            if(vma->vm_flags&(VM_STACK)){
                printk(KERN_INFO "start:%lx end:%lx flags:%s %s\n",vma->vm_start, vma->vm_end,flags,"STACK");
            }
            printk(KERN_INFO "start:%lx end:%lx flags:%s\n",vma->vm_start, vma->vm_end,flags);
            vma = vma->vm_next;
        
        }
        return;
        
nul_ret:
       printk(KERN_INFO "Can not walk vma\n");
      return;


}

static void do_ckp_vma(struct pid* pid){
	struct vm_area_struct* block;
	int id = 1;
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
    if(dump_struct(mm, sizeof(struct mm_struct), "./checkpoint/vma/mm.ckpt")!= sizeof(struct mm_struct)){
        printk(KERN_INFO "Dump struct failed\n");
        goto nul_ret;
    }
	struct vm_area_struct *vma = mm->mmap;
	if(!vma){
		printk(KERN_INFO "No vma yet\n");
		goto nul_ret;
	}
	// ID should be some random hash
	block = kzalloc(sizeof(struct vm_area_struct), GFP_KERNEL);
	if (!block){
		printk(KERN_INFO "Can't allocate memory\n");
		goto nul_ret;
	}
	// printk(KERN_INFO "before while\n");
	while(vma){
		*block = *vma;
		char fname[MAX_FNAME];
		snprintf(fname, MAX_FNAME, "./checkpoint/vma/%d.ckpt", id++);
		// printk("Checkpointing at %s\n", fname);
		if(block->vm_next != NULL) block->vm_next = id;
		if(block->vm_prev != NULL) block->vm_prev = id-2;
		if(dump_struct(block, sizeof(struct vm_area_struct), fname) != sizeof(struct vm_area_struct)){
			printk(KERN_INFO "do_ckp_vma: dump struct failed\n");
			return;
		}
		// do_ckp_mem(pid, )
		vma = vma->vm_next;
	}
	if(dump_struct(&id, sizeof(int), "./checkpoint/vma/len.ckpt") != sizeof(int)){
		printk(KERN_INFO "do_ckp_vma: dump struct failed\n");
		return;
	}
	kfree(block);
	get_vma(mm);
	put_task_struct(proc);
	return;

nul_ret:
	printk(KERN_INFO "Can not walk vma\n");
	return;
}

static void do_ckp_mem_vma(struct pid* pid, struct mm_struct* mm, struct vm_area_struct* vma){
	// Iterate over and copy to /checkpoint/mem/randomid
	unsigned long address;
	int id = 0;
	for (address = vma->vm_start; address < vma->vm_end; address+=PAGE_SIZE){
		pte_t* ptep = get_pte(address, mm);
		if(!ptep) continue;
		struct page* curr = pte_page(*ptep);
		char fname[MAX_FNAME];
		// This would result in segfault -- folders need to be created. 
		snprintf(fname, MAX_FNAME, "%s/checkpoint/page/%lx.ckpt", CURR_DIR, address);
		dump_struct((char*)curr, sizeof(struct page), fname);

		snprintf(fname, MAX_FNAME, "%s/checkpoint/mem/%lx.ckpt", CURR_DIR, address);
		unsigned long mapped_page = kmap(curr);
		dump_struct((char*)mapped_page, PAGE_SIZE, fname);
		kunmap(mapped_page);
	}
	// put_task_struct(proc);
	return;
}

static void do_ckp_mem(struct pid* pid){
	struct task_struct* proc = get_pid_task(pid, PIDTYPE_PID);
	if (!proc){
		printk(KERN_INFO "Got NULL proc\n");
		goto nul_ret;
	}
	struct mm_struct* mm = proc->mm;
	if (!mm){
		printk(KERN_INFO "Got NULL mm\n");
		goto nul_ret;
	}
	struct vm_area_struct* vma = mm->mmap;
	if(!vma){
		printk(KERN_INFO "No vma yet\n");
		goto nul_ret;
	}
	while(vma){
		do_ckp_mem_vma(pid, mm, vma);
		vma = vma->vm_next;
	}
	put_task_struct(proc);
nul_ret:
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
	struct task_struct * task = get_pid_task(pid, PIDTYPE_PID);
	int next_vma = 0;
	struct vm_area_struct *vcopy = kzalloc(sizeof(struct vm_area_struct), GFP_KERNEL);
	struct vm_area_struct *prev = NULL;
    struct mm_struct *old_mm = kzalloc(sizeof(struct mm_struct), GFP_KERNEL);
    if(read_struct(old_mm, sizeof(struct mm_struct), "./checkpoint/vma/mm.ckpt") != sizeof(struct mm_struct)){
        printk(KERN_INFO "do_rst_vma: read struct failed\n");
        return;
    
    }
    // old_mm = current->mm;
	int len;
	if(read_struct(&len, sizeof(int), "./checkpoint/vma/len.ckpt") != sizeof(int)){
		printk(KERN_INFO "do_rst_vma: read struct failed\n");
		return;
	}
	struct vm_area_struct *vmas[len]; // TODO: use hashmap in future, works for now
	int i;
	for(i=0; i < len; i++) vmas[i] = kzalloc(sizeof(struct vm_area_struct), GFP_KERNEL);
	next_vma = 1;
	while(next_vma > 0){
		// allocate buffer and read vma. 
		// struct vm_area_struct *vma = kzalloc(sizeof(struct vm_area_struct), GFP_KERNEL);
		struct vm_area_struct * vma = vmas[next_vma-1];
		char fname[MAX_FNAME];
		snprintf(fname, MAX_FNAME, "./checkpoint/vma/%d.ckpt", next_vma);		// directory structure 
		read_struct(vcopy, sizeof(struct vm_area_struct), fname);
		*vma = *vcopy;

		// get the kernel space addr from vmas[ ] array
		if(vma->vm_next != NULL) vma->vm_next = vmas[(int)(vma->vm_next) - 1];
		if(vma->vm_prev != NULL) vma->vm_prev = vmas[(int)(vma->vm_prev) - 1];
		// Update next_vma by lookup using vcopy->vm_next
		// next_vma = get_id(vcopy->vm_next);		// get_id is not implemented yet
		next_vma = vcopy->vm_next; // TODO: use hashmap in future, works for now
		// restore pages for this vma
		// set vm_mm
		vma->vm_mm = old_mm;
	}
	old_mm->mmap = vmas[0];
	
	// dup_mm on current task
	vmacache_flush(current);
	// old_mm = task->mm;
	// printk(KERN_INFO "%lx %lx %lx ---\n", current->mm, old_mm, current->active_mm);
	// struct mm_struct * new_mm = crp_dup_mm(current, old_mm);
	// mmput(current->mm);
	struct mm_struct * new_mm = crp_dup_mm(current, task->mm);
	// struct mm_struct* new_mm = old_mm;
	// printk(KERN_INFO "%lx %lx %lx ---\n", new_mm, old_mm, vmas[0]);
	
/*	
	current->mm = task->mm;
	current->active_mm = task->active_mm;
*/	
	/*
	current->mm = old_mm;
	current->active_mm = old_mm;
	*/
	current->mm = new_mm;
	current->active_mm = new_mm;
	// crp_free_mm(curr_mm);
	kfree(vcopy);
}
int written_pages = 0;
static void do_rst_mem_vma(struct pid* pid, struct mm_struct* mm, struct vm_area_struct* vma){
	// iterate over address space
	unsigned long address;
	printk(KERN_INFO "%p %p\n", mm, vma);
	printk(KERN_INFO "vma area: %lx %lx\n", vma->vm_start, vma->vm_end);
	unsigned long tmpflag = vma->vm_flags;
	vma->vm_flags |= VM_WRITE;
	for(address = vma->vm_start; address < vma->vm_end; address+=PAGE_SIZE){
		// allocate a buffer of size page and read a page to it. 
		// Directly allocate a page and copy to it if possible, don't think linux allows that. 
		char* curr = kzalloc(PAGE_SIZE, GFP_KERNEL);			
		char fname[MAX_FNAME];
		snprintf(fname, MAX_FNAME, "%s/checkpoint/mem/%lx.ckpt", CURR_DIR, address);
		// printk(KERN_INFO "%p %s\n", address, fname);
		
		if(read_struct(curr, PAGE_SIZE, fname) < 0){ // file does not exist
			kfree(curr);
			continue;
		}
		// Allocate page in user space how tf do I do this.
		int err;
	       printk(KERN_INFO "writing vm: %lx", address);	
		/*if((err = copy_from_user(curr, address, PAGE_SIZE)) != 0){
            printk(KERN_INFO "cannot read from %lx, err %d\n", address, err);
		
		}*/
		
		if((err = copy_to_user(address, curr, PAGE_SIZE)) != 0){
            printk(KERN_INFO "cannot write to %lx, err %d\n", address, err);
	    vma->vm_flags = tmpflag;
	    kfree(curr);
            return;
        }

		written_pages++;
		kfree(curr);
		// Put this page into page table. 
	}
	vma->vm_flags = tmpflag;
	printk(KERN_INFO "restore vmas: written pages %d", written_pages);
}

static void do_rst_mem(struct pid* pid){
	written_pages = 0;
	struct task_struct* proc = current;
	if (!proc){
		printk(KERN_INFO "Got NULL proc\n");
		goto nul_ret;
	}
	struct mm_struct* mm = proc->mm;
	if (!mm){
		printk(KERN_INFO "Got NULL mm\n");
		goto nul_ret;
	}
	struct vm_area_struct* vma = mm->mmap;
	if(!vma){
		printk(KERN_INFO "No vma yet\n");
		goto nul_ret;
	}
	while(vma){
		do_rst_mem_vma(pid, mm, vma);
		vma = vma->vm_next;
	}
	flush_cache_mm(mm);
	printk(KERN_INFO "memory pages restored: %d\n", written_pages);
nul_ret:
	// put_task_struct(proc);
	return;
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
    struct pt_regs tmpregs = *regs;
    struct thread_struct tmpts = task->thread;
    printk(KERN_INFO "ckpt_cpu_state: rax reg %ld %ld %ld\n", regs->ax, regs->ax, tmpregs.ax);
    printk(KERN_INFO "ckpt_cpu_state: rax reg %ld %ld\n", regs->ax, regs->r15);
    unsigned long rax = regs->ax;
    printk(KERN_INFO "ckpt_cpu_state: cs-ip reg %lx-%lx\n", regs->cs, regs->ip);
	char fname[MAX_FNAME];
	snprintf(fname, MAX_FNAME, "cpu_state.ckpt", pidno);
    if(dump_struct(&tmpregs, sizeof(struct pt_regs), fname) != sizeof(struct pt_regs)){
        printk(KERN_INFO "ckpt_cpu_state: dump struct failed\n");
        return;
    }
    if(dump_struct(&tmpts, sizeof(struct thread_struct), "thread_struct.ckpt") != sizeof(struct thread_struct)){
	    printk(KERN_INFO "ckpt: dump thread struct failed\n");
	    return ;
    }
    printk(KERN_INFO "ckpt_cpu_state: rax reg %ld %ld\n", regs->ax, tmpregs.ax);
    printk(KERN_INFO "ckpt_cpu_state: cs-ip reg %lx-%lx %lx %lx\n", regs->cs, regs->ip, tmpts.fsbase, task->thread.fsbase);
    // printk(KERN_INFO "ckpt_cpu_state: instruction at ip %lx\n", regs->ip);
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
        ckpt_cpu_state(pid);
        do_ckp_vma(_pid);
	do_ckp_mem(_pid);
        // finished
	struct fdtable *files_table;
	//files_table = files_fdtable(task->files);
	// printk(KERN_INFO "f_pos: %d\n", files_table->fd[0]->f_pos);
	//files_table->fd[0]->f_pos = 1;
        kill_pid(_pid, SIGCONT, 1);
        put_pid(_pid);
        
        return length;
    }
    return -1;
}

static void rest_cpu_state(pid_t pidno){
    // struct pt_regs* regs = task->thread.regs;
    struct pt_regs* regs = current_pt_regs();
    
    printk(KERN_INFO "rest_cpu_state: rax reg %ld %ld\n", regs->ax, regs->ax);
    printk(KERN_INFO "ckpt_cpu_state: rax reg %ld %lx\n", regs->ax, current->thread.fsbase);
    printk(KERN_INFO "rest_cpu_state: cs-ip reg %lx-%lx\n", regs->cs, regs->ip);
    if(read_struct(regs, sizeof(struct pt_regs), "cpu_state.ckpt") != sizeof(struct pt_regs)){
        printk(KERN_INFO "rest_cpu_state: dump struct failed\n");
        return;
    }
    struct thread_struct ts;
    if(read_struct(&ts, sizeof(struct thread_struct), "thread_struct.ckpt") != sizeof(struct thread_struct)){
	    printk(KERN_INFO "rest_cpu_state: thread struct failed\n");
   }
    loadsegment(fs, ts.fsbase);
    x86_fsbase_write_cpu(ts.fsbase);
    current->thread = ts;

    printk(KERN_INFO "rest_cpu_state: rax reg %ld %lx\n", regs->ax, current->thread.fsbase);
    printk(KERN_INFO "ckpt_cpu_state: rax reg %ld %ld\n", regs->ax, regs->r15);
    printk(KERN_INFO "rest_cpu_state: cs-ip reg %lx-%lx\n", regs->cs, regs->ip);
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
        
	struct pid* _pid = find_get_pid(pid);
        kill_pid(_pid, SIGSTOP, 1);
        struct task_struct* task = get_pid_task(_pid, PIDTYPE_PID);
        if(task == NULL){
            printk(KERN_INFO "task is null\n");
            return -1;
        }
        // start restoring
        printk(KERN_INFO "starting vma restore\n");
	printk(KERN_DEBUG "current->mm value %lx active %lx\n", current->mm, current->active_mm);
		get_vma(current->mm);
	printk(KERN_DEBUG "current->mm value %lx active %lx\n", current->mm, current->active_mm);
		do_rst_vma(_pid);
	printk(KERN_DEBUG "current->mm value %lx active %lx\n", current->mm, current->active_mm);
        memset(&(current->mm->rss_stat), 0, sizeof(current->mm->rss_stat));
		printk(KERN_INFO "After\n");
		get_vma(current->mm);
		printk(KERN_INFO "starting mem restore\n");
		do_rst_mem(_pid);
		// finished
        rest_cpu_state(pid);
		flush_icache_range(0, 0xffffffff);
        kill_pid(_pid, SIGCONT, 1);
	// flush_cache_all();
        put_pid(_pid);
        
        
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
	printk(KERN_INFO "here\n");
	crp_dup_mm = kln("dup_mm");
	// printk(KERN_INFO "dup_mm: %lx kln: %lx dup_mm: %p\n", crp_dup_mm, kln, kln("dup_mm"));
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
