/* Every outbound TCP connection attempt, from the socket state tracepoint.
 *
 * inet_sock_set_state fires on each TCP state transition. The move into
 * SYN_SENT is a connect() leaving the box; the move from SYN_RECV into
 * ESTABLISHED is an accepted inbound connection. Both are recorded with
 * the pid on the CPU at the time — accurate for connect(), which runs
 * in the caller's context, and best-effort for accepts, which may land
 * in softirq with pid 0.
 */
#include "vmlinux.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

#define COMM_LEN 16
#define AF_INET 2
#define AF_INET6 10

struct connect_event {
  __u32 pid;
  __u32 uid;
  __u16 family;
  __u16 dport;
  __u16 sport;
  __u8 direction; /* 0 = outbound connect, 1 = inbound accept */
  __u8 daddr[16]; /* v4 in the first 4 bytes */
  __u8 comm[COMM_LEN];
};

struct connect_event *_unused_connect_event __attribute__((unused));

struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 256 * 1024);
} connects SEC(".maps");

SEC("tracepoint/sock/inet_sock_set_state")
int on_sock_state(struct trace_event_raw_inet_sock_set_state *ctx) {
  if (ctx->protocol != IPPROTO_TCP) {
    return 0;
  }

  __u8 direction;
  if (ctx->newstate == TCP_SYN_SENT) {
    direction = 0;
  } else if (ctx->oldstate == TCP_SYN_RECV && ctx->newstate == TCP_ESTABLISHED) {
    direction = 1;
  } else {
    return 0;
  }

  struct connect_event *event = bpf_ringbuf_reserve(&connects, sizeof(*event), 0);
  if (!event) {
    return 0;
  }

  event->pid = bpf_get_current_pid_tgid() >> 32;
  event->uid = bpf_get_current_uid_gid() & 0xffffffff;
  event->family = ctx->family;
  event->direction = direction;
  __builtin_memset(event->daddr, 0, sizeof(event->daddr));

  /* Each branch reads the context at a fixed offset. Selecting a
   * pointer with a ternary and reading through it gives the verifier a
   * variable-offset context access, which it rejects. */
  if (direction == 0) {
    /* outbound: the peer is the destination */
    event->dport = ctx->dport;
    event->sport = ctx->sport;
    if (ctx->family == AF_INET6) {
      bpf_probe_read_kernel(event->daddr, 16, ctx->daddr_v6);
    } else {
      bpf_probe_read_kernel(event->daddr, 4, ctx->daddr);
    }
  } else {
    /* inbound: the peer is the source */
    event->dport = ctx->sport;
    event->sport = ctx->dport;
    if (ctx->family == AF_INET6) {
      bpf_probe_read_kernel(event->daddr, 16, ctx->saddr_v6);
    } else {
      bpf_probe_read_kernel(event->daddr, 4, ctx->saddr);
    }
  }
  bpf_get_current_comm(&event->comm, sizeof(event->comm));

  bpf_ringbuf_submit(event, 0);
  return 0;
}
