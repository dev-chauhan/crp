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

#include "crp.h"

#define DEVNAME "crp"
#define MAX_FNAME 35
#define PAGE_SIZE 1 << 12

static int major;
atomic_t  device_opened;
static struct class *demo_class;
struct device *demo_device;

// unsigned long (*kln)(const char *) = 0xffffffffa5344fc0;

static unsigned long gptr;

// checkpointing functions

static pte_t* get_page(unsigned long address, struct mm_struct* mm){
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
        return pte_page(ptep);

        nul_ret:
        //        printk(KERN_INFO "Address could not be translated\n");
               return NULL;

}

static void do_ckp_vma(struct pid* pid){
        struct task_struct* proc = get_pid_task(pid);
        // Iterate over and copy to /checkpoint/vma/randomid
        struct mm_struct *mm = proc->mm;
        struct vm_area_struct *vma = mm->mmap;
        
        if(!vma){
                 printk(KERN_INFO "No vma yet\n");
                 goto nul_ret;
        }
        int id = 0;             // This should be some random hash
        struct vma_copy* block = kzalloc(sizeof(struct vma_copy), GFP_KERNEL);
        while(vma){
                block->vm_flags = vma->vm_flags;
                block->vm_start = vma->vm_start;
                block->vm_end = vma->vm_end;
                block->vm_next = vma->vm_next;
                char fname[MAX_FNAME];
                snprintf(fname, MAX_FNAME, "/checkpoint/vma/%d", id++);
                dump_struct(block, sizeof(struct vma_copy), fname);
                do_ckp_mem(pid, )
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
                struct page* curr = get_page(address, mm);
                char fname[MAX_FNAME];
                snprintf(fname, MAX_FNAME, "/checkpoint/page/%d", id);
                dump_struct(curr, sizeof(struct page), fname);

                snprintf(fname, MAX_FNAME, "/checkpoint/mem/%d", id++);
                dump_struct(curr, PAGE_SIZE, fname);            // TODO: get page from struct page
        }
        put_task_struct(proc);
        return;
}

static void do_ckp_proc(struct pid* pid){
        struct task_struct* proc = get_pid_task(pid);
        
        // Iterate over and copy to /checkpoint/proc/randomid

        put_task_struct(proc);
        return;
}

// Restore functions 

static void do_rst_vma(struct pid* pid){

}

static void do_rst_mem(struct pid* pid){

}

static void do_rst_proc(struct pid* pid){

}


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

int dump_struct(void* buff, int length, char* fname){
    struct file* fp = filp_open(fname, O_RDWR | O_CREAT, S_IRWXU);
    if(!fp) return -1;
    loff_t pos = 0;
    unsigned long err;
    err = kernel_write(fp, buff, length, &pos);
    filp_close(fp, NULL);
    if(err != length) return -1;
    return err;
}

int read_struct(void* buff, int length, char* fname){
    struct file* fp = filp_open(fname, O_RDONLY, 0);
    if(!fp) return -1;
    loff_t pos = 0;
    unsigned long err;
    err = kernel_read(fp, buff, length, &pos);
    filp_close(fp, NULL);
    if(err != length) return -1;
    return err;
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
    if(dump_struct(regs, sizeof(struct pt_regs), "cpu_state.ckpt") < 0){
        printk(KERN_INFO "ckpt_cpu_state: dump struct failed\n");
        return;
    }
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
        printk(KERN_INFO "task %d status %d\n", task->pid, task->state);
        // start checkpointing
        ckpt_cpu_state(pid);
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
    if(read_struct(regs, sizeof(struct pt_regs), "cpu_state.ckpt") < 0){
        printk(KERN_INFO "ckpt_cpu_state: dump struct failed\n");
        return;
    }
    printk(KERN_INFO "rest_cpu_state: rax reg %d\n", regs->ax);
}

static ssize_t
demo_write(struct file *filp, const char *buff, size_t len, loff_t * off)
{
           
    printk(KERN_INFO "In write\n");
    unsigned long* args = kzalloc(length, GFP_KERNEL);
    if(copy_from_user(args, buffer, length) == 0){
        int command = args[0];
        int pid = args[1];
        printk(KERN_INFO "command = %d, pid = %d\n", command, pid);
        
        // start restoring
        rest_cpu_state(pid);
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
