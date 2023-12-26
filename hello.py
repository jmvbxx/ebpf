#!/bin/python3
from bcc import BPF

program = r"""
int hello(void *ctx) {
    // Equivalent to printf()
    bpf_trace_printk("Hello World!");
    return 0;
}
"""

# Assign BPF program to variable b
b = BPF(text=program)
# Assign the returned syscall function name of the syscall 'execve'
syscall = b.get_syscall_fnname("execve")
# Attach a kprobe to the BPF program with the following arguments
b.attach_kprobe(event=syscall, fn_name="hello")

while True:
    try:
        # Prints output as-is
        b.trace_print()
    except KeyboardInterrupt:
        exit()
