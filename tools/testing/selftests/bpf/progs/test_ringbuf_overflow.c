// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2023 Data Ex Machina

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

char _license[] SEC("license") = "GPL";

struct ringbuf_map {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, (1<<30));
} ringbuf SEC(".maps");

SEC("uprobe//proc/0/exe:trigger_ringbuf_overflow")
int trigger_ringbuf_overflow(struct pt_regs *ctx)
{
	void *reservation = bpf_ringbuf_reserve(&ringbuf, (1<<29) - 16, 0);
	if (!reservation) {
		return 0;
	}
	bpf_ringbuf_submit(reservation, 0);
	return 0;
}