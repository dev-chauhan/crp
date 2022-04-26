# Checkpoint and Restore Process (CRP)

## Building and preparing
- Run 'make' in the base directory to build user CLI binary.
- Follow the following steps to build the kernel module:

1. Run the following command with sudo permissions and copy the output

bash
    ```$ sudo cat /proc/kallsyms | grep -w kallsyms_lookup_name | cut -d " " -f1```


2. Copy the output to line number 39 (set value of KLN\_OFFSET to this) 

3. Build and insert kernel module (inside mod directory)
bash
    ```
    $ make
    $ sudo insmod crp.ko
    ```


## Using CLI
- Checkpointing - Run the target process and get its pid. Use 
bash
    `$ bin/crp checkpoint <pid> <target name>`


This will create a checkpoint for this process. 

- Restore - Pass the old pid to bin/crp with argument restore
bash
    `$ bin/crp restore <pid> <target name>`

The process will resume from where it was checkpointed.
