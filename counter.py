#!/bin/python3
from bcc import BPF
import time

program = r"""
// Create a hash map
BPF_HASH(counter_table);

int counter(void *ctx) {
    u64 uid;
    u64 counter = 0;
    u64 *p;

    // Return user id and group id and assign to variable uid.
    // It bitwise-ANDs it with 0xFFFFFFFF to ensure it fits into a 64-bit
    // `u64` variable.
    uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    // Look up the value associated with the `uid` in the `counter_table`
    // and assign to p.
    p = counter_table.lookup(&uid);
    // Check if p is a valid pointer
    if (p != 0) {
        counter = *p;
    }

    counter++;
    // The updated `counter` is stored back in the `counter_table` and
    // associated with the `uid`.
    counter_table.update(&uid, &counter);
    return 0;
}
"""

# Assign BPF program to variable b
b = BPF(text=program)
# Assign the returned syscall function name of the syscall 'execve'
syscall = b.get_syscall_fnname("execve")
# Attach a kprobe to the BPF program with the following arguments
b.attach_kprobe(event=syscall, fn_name="counter")

while True:
    time.sleep(2)
    s = ""
    for k,v in b["counter_table"].items():
        s += f"ID {k.value}: {v.value}\t"
    print(s)
