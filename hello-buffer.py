#!/bin/python3
from bcc import BPF

program = r"""
// Create a BPF table for pushing out custom event data
BPF_PERF_OUTPUT(output);

// Create a struct with the following
struct data_t {
    int pid;
    int uid;
    char command[16];
    char message[12];
};

int hello(void *ctx) {
    // Initialize a `data_t` struct named `data`
    struct data_t data = {};
    // Create a character array `message`
    char message[12] = "Hello World!";

    // Retrieve current process id (shifted to the right 32 bits) 
    // and assign to `data.pid`
    data.pid = bpf_get_current_pid_tgid() >> 32;
    // Get the user ID that is running the process that triggered
    // the kprobe event. The user ID is held in the lowest 32 bits
    // of the 64-bit value that gets returned
    data.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;

    // Populate the first argument address with the current process name
    bpf_get_current_comm(&data.command, sizeof(data.command));
    // The message "Hellow World!" gets copied into the correct place
    // within the message
    bpf_probe_read_kernel(&data.message, sizeof(data.message), message);

    // Place the data within the map
    output.perf_submit(ctx, &data, sizeof(data));

    return 0;
}
"""

b = BPF(text=program)
syscall = b.get_syscall_fnname("execve")
b.attach_kprobe(event=syscall, fn_name="hello")

def print_event(cpu, data, size):
    data = b["output"].event(data)
    print(f"{data.pid} {data.uid} {data.command.decode()} " + \
          f"{data.message.decode()}")

b["output"].open_perf_buffer(print_event)
while True:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()