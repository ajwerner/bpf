// SPDX-License-Identifier: GPL-2.0
#define _GNU_SOURCE
#include <linux/compiler.h>
#include <asm/barrier.h>
#include <test_progs.h>
#include <sys/mman.h>
#include <sys/epoll.h>
#include <unistd.h>
#include <time.h>
#include <sched.h>
#include <signal.h>
#include <pthread.h>
#include <sys/sysinfo.h>
#include <linux/perf_event.h>
#include <linux/ring_buffer.h>
#include "test_ringbuf.lskel.h"
#include "test_ringbuf_map_key.lskel.h"
#include "test_ringbuf_overflow.skel.h"

#define EDONE 7777

static int duration = 0;

struct sample {
	int pid;
	int seq;
	long value;
	char comm[16];
};

static int sample_cnt;

static void atomic_inc(int *cnt)
{
	__atomic_add_fetch(cnt, 1, __ATOMIC_SEQ_CST);
}

static int atomic_xchg(int *cnt, int val)
{
	return __atomic_exchange_n(cnt, val, __ATOMIC_SEQ_CST);
}

static int process_sample(void *ctx, void *data, size_t len)
{
	struct sample *s = data;

	atomic_inc(&sample_cnt);

	switch (s->seq) {
	case 0:
		CHECK(s->value != 333, "sample1_value", "exp %ld, got %ld\n",
		      333L, s->value);
		return 0;
	case 1:
		CHECK(s->value != 777, "sample2_value", "exp %ld, got %ld\n",
		      777L, s->value);
		return -EDONE;
	default:
		/* we don't care about the rest */
		return 0;
	}
}

static struct test_ringbuf_map_key_lskel *skel_map_key;
static struct test_ringbuf_lskel *skel;
static struct test_ringbuf_overflow *skel_overflow;
static struct ring_buffer *ringbuf;

static void trigger_samples()
{
	skel->bss->dropped = 0;
	skel->bss->total = 0;
	skel->bss->discarded = 0;

	/* trigger exactly two samples */
	skel->bss->value = 333;
	syscall(__NR_getpgid);
	skel->bss->value = 777;
	syscall(__NR_getpgid);
}

static void *poll_thread(void *input)
{
	long timeout = (long)input;

	return (void *)(long)ring_buffer__poll(ringbuf, timeout);
}

static void ringbuf_subtest(void)
{
	const size_t rec_sz = BPF_RINGBUF_HDR_SZ + sizeof(struct sample);
	pthread_t thread;
	long bg_ret = -1;
	int err, cnt, rb_fd;
	int page_size = getpagesize();
	void *mmap_ptr, *tmp_ptr;

	skel = test_ringbuf_lskel__open();
	if (CHECK(!skel, "skel_open", "skeleton open failed\n"))
		return;

	skel->maps.ringbuf.max_entries = page_size;

	err = test_ringbuf_lskel__load(skel);
	if (CHECK(err != 0, "skel_load", "skeleton load failed\n"))
		goto cleanup;

	rb_fd = skel->maps.ringbuf.map_fd;
	/* good read/write cons_pos */
	mmap_ptr = mmap(NULL, page_size, PROT_READ | PROT_WRITE, MAP_SHARED, rb_fd, 0);
	ASSERT_OK_PTR(mmap_ptr, "rw_cons_pos");
	tmp_ptr = mremap(mmap_ptr, page_size, 2 * page_size, MREMAP_MAYMOVE);
	if (!ASSERT_ERR_PTR(tmp_ptr, "rw_extend"))
		goto cleanup;
	ASSERT_ERR(mprotect(mmap_ptr, page_size, PROT_EXEC), "exec_cons_pos_protect");
	ASSERT_OK(munmap(mmap_ptr, page_size), "unmap_rw");

	/* bad writeable prod_pos */
	mmap_ptr = mmap(NULL, page_size, PROT_WRITE, MAP_SHARED, rb_fd, page_size);
	err = -errno;
	ASSERT_ERR_PTR(mmap_ptr, "wr_prod_pos");
	ASSERT_EQ(err, -EPERM, "wr_prod_pos_err");

	/* bad writeable data pages */
	mmap_ptr = mmap(NULL, page_size, PROT_WRITE, MAP_SHARED, rb_fd, 2 * page_size);
	err = -errno;
	ASSERT_ERR_PTR(mmap_ptr, "wr_data_page_one");
	ASSERT_EQ(err, -EPERM, "wr_data_page_one_err");
	mmap_ptr = mmap(NULL, page_size, PROT_WRITE, MAP_SHARED, rb_fd, 3 * page_size);
	ASSERT_ERR_PTR(mmap_ptr, "wr_data_page_two");
	mmap_ptr = mmap(NULL, 2 * page_size, PROT_WRITE, MAP_SHARED, rb_fd, 2 * page_size);
	ASSERT_ERR_PTR(mmap_ptr, "wr_data_page_all");

	/* good read-only pages */
	mmap_ptr = mmap(NULL, 4 * page_size, PROT_READ, MAP_SHARED, rb_fd, 0);
	if (!ASSERT_OK_PTR(mmap_ptr, "ro_prod_pos"))
		goto cleanup;

	ASSERT_ERR(mprotect(mmap_ptr, 4 * page_size, PROT_WRITE), "write_protect");
	ASSERT_ERR(mprotect(mmap_ptr, 4 * page_size, PROT_EXEC), "exec_protect");
	ASSERT_ERR_PTR(mremap(mmap_ptr, 0, 4 * page_size, MREMAP_MAYMOVE), "ro_remap");
	ASSERT_OK(munmap(mmap_ptr, 4 * page_size), "unmap_ro");

	/* good read-only pages with initial offset */
	mmap_ptr = mmap(NULL, page_size, PROT_READ, MAP_SHARED, rb_fd, page_size);
	if (!ASSERT_OK_PTR(mmap_ptr, "ro_prod_pos"))
		goto cleanup;

	ASSERT_ERR(mprotect(mmap_ptr, page_size, PROT_WRITE), "write_protect");
	ASSERT_ERR(mprotect(mmap_ptr, page_size, PROT_EXEC), "exec_protect");
	ASSERT_ERR_PTR(mremap(mmap_ptr, 0, 3 * page_size, MREMAP_MAYMOVE), "ro_remap");
	ASSERT_OK(munmap(mmap_ptr, page_size), "unmap_ro");

	/* only trigger BPF program for current process */
	skel->bss->pid = getpid();

	ringbuf = ring_buffer__new(skel->maps.ringbuf.map_fd,
				   process_sample, NULL, NULL);
	if (CHECK(!ringbuf, "ringbuf_create", "failed to create ringbuf\n"))
		goto cleanup;

	err = test_ringbuf_lskel__attach(skel);
	if (CHECK(err, "skel_attach", "skeleton attachment failed: %d\n", err))
		goto cleanup;

	trigger_samples();

	/* 2 submitted + 1 discarded records */
	CHECK(skel->bss->avail_data != 3 * rec_sz,
	      "err_avail_size", "exp %ld, got %ld\n",
	      3L * rec_sz, skel->bss->avail_data);
	CHECK(skel->bss->ring_size != page_size,
	      "err_ring_size", "exp %ld, got %ld\n",
	      (long)page_size, skel->bss->ring_size);
	CHECK(skel->bss->cons_pos != 0,
	      "err_cons_pos", "exp %ld, got %ld\n",
	      0L, skel->bss->cons_pos);
	CHECK(skel->bss->prod_pos != 3 * rec_sz,
	      "err_prod_pos", "exp %ld, got %ld\n",
	      3L * rec_sz, skel->bss->prod_pos);

	/* poll for samples */
	err = ring_buffer__poll(ringbuf, -1);

	/* -EDONE is used as an indicator that we are done */
	if (CHECK(err != -EDONE, "err_done", "done err: %d\n", err))
		goto cleanup;
	cnt = atomic_xchg(&sample_cnt, 0);
	CHECK(cnt != 2, "cnt", "exp %d samples, got %d\n", 2, cnt);

	/* we expect extra polling to return nothing */
	err = ring_buffer__poll(ringbuf, 0);
	if (CHECK(err != 0, "extra_samples", "poll result: %d\n", err))
		goto cleanup;
	cnt = atomic_xchg(&sample_cnt, 0);
	CHECK(cnt != 0, "cnt", "exp %d samples, got %d\n", 0, cnt);

	CHECK(skel->bss->dropped != 0, "err_dropped", "exp %ld, got %ld\n",
	      0L, skel->bss->dropped);
	CHECK(skel->bss->total != 2, "err_total", "exp %ld, got %ld\n",
	      2L, skel->bss->total);
	CHECK(skel->bss->discarded != 1, "err_discarded", "exp %ld, got %ld\n",
	      1L, skel->bss->discarded);

	/* now validate consumer position is updated and returned */
	trigger_samples();
	CHECK(skel->bss->cons_pos != 3 * rec_sz,
	      "err_cons_pos", "exp %ld, got %ld\n",
	      3L * rec_sz, skel->bss->cons_pos);
	err = ring_buffer__poll(ringbuf, -1);
	CHECK(err <= 0, "poll_err", "err %d\n", err);
	cnt = atomic_xchg(&sample_cnt, 0);
	CHECK(cnt != 2, "cnt", "exp %d samples, got %d\n", 2, cnt);

	/* start poll in background w/ long timeout */
	err = pthread_create(&thread, NULL, poll_thread, (void *)(long)10000);
	if (CHECK(err, "bg_poll", "pthread_create failed: %d\n", err))
		goto cleanup;

	/* turn off notifications now */
	skel->bss->flags = BPF_RB_NO_WAKEUP;

	/* give background thread a bit of a time */
	usleep(50000);
	trigger_samples();
	/* sleeping arbitrarily is bad, but no better way to know that
	 * epoll_wait() **DID NOT** unblock in background thread
	 */
	usleep(50000);
	/* background poll should still be blocked */
	err = pthread_tryjoin_np(thread, (void **)&bg_ret);
	if (CHECK(err != EBUSY, "try_join", "err %d\n", err))
		goto cleanup;

	/* BPF side did everything right */
	CHECK(skel->bss->dropped != 0, "err_dropped", "exp %ld, got %ld\n",
	      0L, skel->bss->dropped);
	CHECK(skel->bss->total != 2, "err_total", "exp %ld, got %ld\n",
	      2L, skel->bss->total);
	CHECK(skel->bss->discarded != 1, "err_discarded", "exp %ld, got %ld\n",
	      1L, skel->bss->discarded);
	cnt = atomic_xchg(&sample_cnt, 0);
	CHECK(cnt != 0, "cnt", "exp %d samples, got %d\n", 0, cnt);

	/* clear flags to return to "adaptive" notification mode */
	skel->bss->flags = 0;

	/* produce new samples, no notification should be triggered, because
	 * consumer is now behind
	 */
	trigger_samples();

	/* background poll should still be blocked */
	err = pthread_tryjoin_np(thread, (void **)&bg_ret);
	if (CHECK(err != EBUSY, "try_join", "err %d\n", err))
		goto cleanup;

	/* still no samples, because consumer is behind */
	cnt = atomic_xchg(&sample_cnt, 0);
	CHECK(cnt != 0, "cnt", "exp %d samples, got %d\n", 0, cnt);

	skel->bss->dropped = 0;
	skel->bss->total = 0;
	skel->bss->discarded = 0;

	skel->bss->value = 333;
	syscall(__NR_getpgid);
	/* now force notifications */
	skel->bss->flags = BPF_RB_FORCE_WAKEUP;
	skel->bss->value = 777;
	syscall(__NR_getpgid);

	/* now we should get a pending notification */
	usleep(50000);
	err = pthread_tryjoin_np(thread, (void **)&bg_ret);
	if (CHECK(err, "join_bg", "err %d\n", err))
		goto cleanup;

	if (CHECK(bg_ret <= 0, "bg_ret", "epoll_wait result: %ld", bg_ret))
		goto cleanup;

	/* due to timing variations, there could still be non-notified
	 * samples, so consume them here to collect all the samples
	 */
	err = ring_buffer__consume(ringbuf);
	CHECK(err < 0, "rb_consume", "failed: %d\b", err);

	/* 3 rounds, 2 samples each */
	cnt = atomic_xchg(&sample_cnt, 0);
	CHECK(cnt != 6, "cnt", "exp %d samples, got %d\n", 6, cnt);

	/* BPF side did everything right */
	CHECK(skel->bss->dropped != 0, "err_dropped", "exp %ld, got %ld\n",
	      0L, skel->bss->dropped);
	CHECK(skel->bss->total != 2, "err_total", "exp %ld, got %ld\n",
	      2L, skel->bss->total);
	CHECK(skel->bss->discarded != 1, "err_discarded", "exp %ld, got %ld\n",
	      1L, skel->bss->discarded);

	test_ringbuf_lskel__detach(skel);
cleanup:
	ring_buffer__free(ringbuf);
	test_ringbuf_lskel__destroy(skel);
}

static int process_map_key_sample(void *ctx, void *data, size_t len)
{
	struct sample *s;
	int err, val;

	s = data;
	switch (s->seq) {
	case 1:
		ASSERT_EQ(s->value, 42, "sample_value");
		err = bpf_map_lookup_elem(skel_map_key->maps.hash_map.map_fd,
					  s, &val);
		ASSERT_OK(err, "hash_map bpf_map_lookup_elem");
		ASSERT_EQ(val, 1, "hash_map val");
		return -EDONE;
	default:
		return 0;
	}
}

/* uprobe attach point */
static noinline void trigger_ringbuf_overflow(int v)
{
	asm volatile("");
}

struct process_overflow_ctx {
	uint64_t called;
	uint64_t desired;
	uint64_t prev_called;
	clock_t  prev_time;
};

static int process_overflow(void *ctx, void *data, size_t len)
{
	struct process_overflow_ctx *overflow_ctx = ctx;
	overflow_ctx->called += 1;
	const uint64_t threshold = 1 << 20;
	if (overflow_ctx->called % threshold == 0) {
		clock_t now = clock();
		double duration = ((double)now - overflow_ctx->prev_time) /
				  CLOCKS_PER_SEC;
		int processed =
			overflow_ctx->called - overflow_ctx->prev_called;
		const uint64_t reservation_size = (1 << 29) - 16;
		double throughput_bytes = (double)(reservation_size) *
					  ((double)(processed) / duration);
		double throughput_gibibytes =
			throughput_bytes / (double)(1 << 30);
		printf("throughput: %f GiB/s duration %fs (%lx/%lx; %f%%) \n",
		       throughput_gibibytes, duration, overflow_ctx->called,
		       overflow_ctx->desired,
		       100 * ((double)overflow_ctx->called) /
			       ((double)overflow_ctx->desired));
		overflow_ctx->prev_time = now;
		overflow_ctx->prev_called = overflow_ctx->called;
	}
	if (overflow_ctx->called > overflow_ctx->desired)
		return -42;
	trigger_ringbuf_overflow(1);
	return 0;
}

static void ringbuf_overflow_subtest(void)
{
	DECLARE_LIBBPF_OPTS(bpf_uprobe_opts, uprobe_opts);

	skel_overflow = test_ringbuf_overflow__open_and_load();
	if (!ASSERT_OK_PTR(skel_overflow,
			   "test_ringbuf_overflow_uint32_lskel__open"))
		return;

	ssize_t offset = get_uprobe_offset(&trigger_ringbuf_overflow);
	if (!ASSERT_GE(offset, 0, "uprobe_offset"))
		goto cleanup;
	uprobe_opts.retprobe = false;
	skel_overflow->links.trigger_ringbuf_overflow =
		bpf_program__attach_uprobe_opts(
			skel_overflow->progs.trigger_ringbuf_overflow, 0,
			"/proc/self/exe", offset, &uprobe_opts);
	if (!ASSERT_OK_PTR(skel_overflow->links.trigger_ringbuf_overflow,
			   "link"))
		goto cleanup;

	struct process_overflow_ctx ctx = {
		.called = 0,
		.desired = (ULONG_MAX / ((1ull<<29) - 16)) + (1<<30),
		.prev_called = 0,
		.prev_time = clock(),
	};
	ringbuf = ring_buffer__new(bpf_map__fd(skel_overflow->maps.ringbuf),
				   process_overflow, &ctx, NULL);
	if (!ASSERT_OK_PTR(ringbuf, "ring_buffer__new"))
		goto cleanup;

	trigger_ringbuf_overflow(1);
	int err = ring_buffer__consume(ringbuf);
	ASSERT_EQ(err, -42, "ring_buffer__consume");
	ring_buffer__free(ringbuf);
cleanup:
	test_ringbuf_overflow__destroy(skel_overflow);
}

static void ringbuf_map_key_subtest(void)
{
	int err;

	skel_map_key = test_ringbuf_map_key_lskel__open();
	if (!ASSERT_OK_PTR(skel_map_key, "test_ringbuf_map_key_lskel__open"))
		return;

	skel_map_key->maps.ringbuf.max_entries = getpagesize();
	skel_map_key->bss->pid = getpid();

	err = test_ringbuf_map_key_lskel__load(skel_map_key);
	if (!ASSERT_OK(err, "test_ringbuf_map_key_lskel__load"))
		goto cleanup;

	ringbuf = ring_buffer__new(skel_map_key->maps.ringbuf.map_fd,
				   process_map_key_sample, NULL, NULL);
	if (!ASSERT_OK_PTR(ringbuf, "ring_buffer__new"))
		goto cleanup;

	err = test_ringbuf_map_key_lskel__attach(skel_map_key);
	if (!ASSERT_OK(err, "test_ringbuf_map_key_lskel__attach"))
		goto cleanup_ringbuf;

	syscall(__NR_getpgid);
	ASSERT_EQ(skel_map_key->bss->seq, 1, "skel_map_key->bss->seq");
	err = ring_buffer__poll(ringbuf, -1);
	ASSERT_EQ(err, -EDONE, "ring_buffer__poll");

cleanup_ringbuf:
	ring_buffer__free(ringbuf);
cleanup:
	test_ringbuf_map_key_lskel__destroy(skel_map_key);
}

void test_ringbuf(void)
{
	if (test__start_subtest("ringbuf"))
		ringbuf_subtest();
	if (test__start_subtest("ringbuf_map_key"))
		ringbuf_map_key_subtest();
	if (test__start_subtest("ringbuf_overflow"))
		ringbuf_overflow_subtest();
}
