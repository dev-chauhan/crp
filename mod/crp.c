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

#define DEVNAME "crp"

static int major;
atomic_t  device_opened;
static struct class *demo_class;
struct device *demo_device;

// unsigned long (*kln)(const char *) = 0xffffffffa5344fc0;

static unsigned long gptr;


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
    printk(KERN_INFO "ckpt_cpu_state: cs-ip reg %d-%d\n", regs->cs, regs->ip);
    if(dump_struct(regs, sizeof(struct pt_regs), "cpu_state.ckpt") != sizeof(struct pt_regs)){
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
