/* Every successful execve on the host, from the scheduler's tracepoint.
 *
 * Nothing polls: the kernel writes one record per exec into a ring
 * buffer the isolate drains. The analyst holds this program only for
 * the seconds a trace_execs() call lasts; it is detached the rest of
 * the time.
 */
#include "vmlinux.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

#define COMM_LEN 16
#define FILE_LEN 64

struct exec_event {
  __u32 pid;
  __u32 ppid;
  __u32 uid;
  __u8 comm[COMM_LEN];
  __u8 filename[FILE_LEN];
};

/* Forces the payload struct into BTF; see the yeetkit README. */
struct exec_event *_unused_exec_event __attribute__((unused));

struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 256 * 1024);
} execs SEC(".maps");

SEC("tracepoint/sched/sched_process_exec")
int on_exec(struct trace_event_raw_sched_process_exec *ctx) {
  struct exec_event *event = bpf_ringbuf_reserve(&execs, sizeof(*event), 0);
  if (!event) {
    return 0;
  }

  struct task_struct *task = (struct task_struct *)bpf_get_current_task();
  event->pid = bpf_get_current_pid_tgid() >> 32;
  event->ppid = BPF_CORE_READ(task, real_parent, tgid);
  event->uid = bpf_get_current_uid_gid() & 0xffffffff;
  bpf_get_current_comm(&event->comm, sizeof(event->comm));

  /* The path is a variable-length string appended to the tracepoint
   * record; its offset is in the low 16 bits of the __data_loc word. */
  unsigned int off = ctx->__data_loc_filename & 0xffff;
  bpf_probe_read_kernel_str(&event->filename, sizeof(event->filename), (void *)ctx + off);

  bpf_ringbuf_submit(event, 0);
  return 0;
}
