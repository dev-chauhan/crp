#pragma once

struct vma_copy{
    unsigned long vm_start;
    unsigned long vm_end;
    unsigned long vm_flags;
    uint64_t vm_next;       // randomid
    uint64_t vm_prev;
};
