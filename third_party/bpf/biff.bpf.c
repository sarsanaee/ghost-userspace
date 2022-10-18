/*
 * Copyright 2022 Google LLC
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * version 2 or later as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * Biff: the bpf-only ghost scheduler.
 * brho@google.com
 *
 * The world's dumbest scheduler just needs to handle the messages in bpf-msg
 * for new, wakeup, preempt, and yield, and then enqueue those in a global
 * queue.  Pop tasks from the queue in bpf-pnt.  You only need a single map for
 * the global queue.  You can do all of this in probably 100 lines of code.
 * I've commented the policy bits with "POLICY" for easy grepping.
 *
 * But any real scheduler will want more, so Biff has a few extras:
 * - want to know when tasks block, run, etc, so handle the other message types
 * - want data structures to track that info, such as "which task is on which
 *   cpu", or "how much runtime has this task had".  generically, that's a
 *   per-cpu data structure and a per-task data structure, with lookup helpers.
 * - and example of how to preempt tasks based on some basic policy.
 *
 * FAQ:
 * - Do we need to request SEND_TASK_LATCHED?  Yes.  (This has the kernel
 *   generate a TASK_LATCHED message when we got on_cpu).  Arguably, if
 *   bpf_ghost_run_gtid() returns successfully, our task was latched, and we
 *   could run the contents of handle_latched() in bpf-pnt.  However, we gain
 *   two things from the message handler: the cpu_seqnum (used in resched) and
 *   synchronization.  bpf-msg runs with the RQ lock for the task
 *   held.  bpf-pnt does not.  By deferring the work to handle_latched(), we
 *   don't have to worry about concurrent changes to the task's data structures.
 *
 * - Can we do something smarter with dont_idle?  Yes!  Right now, we just tell
 *   the cpu to not idle.  The kernel will schedule the idle task, which will
 *   instantly yield back to the kernel, which will call bpf-pnt again.  A
 *   smarter scheduler could use the length of the runqueue to determine how
 *   many cpus to wake up.  (If you do this, make sure to handle the EBUSY case
 *   below by rescheding your cpu).
 *
 * - What happens if any of the bpf operations fail?  You're out of luck.  If
 *   the global_rq overflows (65k tasks) or bpf_ghost_run_gtid() fails with an
 *   esoteric error code, we might lose track of a task.  As far as the kernel
 *   is concerned, the task is sitting on the runqueue, but bpf will never run
 *   it.  There are a few ways out:
 *   - if we detect an error, add infrastructure to pass the task to userspace,
 *   which can try to handle it in a more forgiving environment than bpf.
 *   - userspace can periodically poll the status word table for runnable tasks
 *   that aren't getting cpu time.
 *   - make sure userspace sets an enclave runnable_timeout.  If bpf fails to
 *   schedule a runnable task, the kernel will destroy the enclave and this
 *   scheduler, and all of our tasks will fall back to CFS.
 *   - another option for userspace's recovery is to tell the kernel to generate
 *   a task new for every task.  We already do this for Discovery, during agent
 *   live update.
 *
 * - When do we receive messages without having had a task_new first?  During
 *   agent live update, which is when there are tasks already in the enclave
 *   when we start up.  Thanks to the existence of the 'agent task' on every
 *   enclave cpu that runs a ghost task, we know that no ghost tasks are running
 *   during the handoff.  This means we can only receive a few messages:
 *   new (for tasks that join while we are initializing), wakeup and departed.
 *   The handlers for all of these can deal with receiving an unexpected
 *   message.  e.g. handle_wakeup() will fail gtid_to_swd().  Note that we just
 *   ignore the wakeup message, knowing that we'll eventually receive a task_new
 *   for it (due to how Discovery works).
 *
 * - Why can't we receive a task_dead during an agent handoff?  I keep having to
 *   look this up.  The exit path is do_exit() -> __schedule() ->
 *   finish_task_switch() -> task_dead_ghost().  A task needs to be running to
 *   go do_exit().  (Incidentally, in __schedule(), the task blocks, so we'll
 *   get a task_blocked before task_dead).  Until we run a task, it can't exit.
 *   Additionally, we can't be in the middle of any context switches either.
 *   The last (ghost-class) task to run on a cpu from the old agent-process was
 *   that cpu's agent-task.  The next task to run is the agent-task from the new
 *   agent-process.  After all of that, we insert the bpf programs.  So we
 *   couldn't be context-switching from the dying task that ran from the old
 *   agent to the new agent or something like that.  There's a context switch
 *   from dying-task to old-agent-task in between.
 */


// vmlinux.h must be included before bpf_helpers.h
// clang-format off
#include "kernel/vmlinux_ghost_5_11.h"
#include "libbpf/bpf_helpers.h"
#include "libbpf/bpf_tracing.h"

// clang-format on

#include "third_party/iovisor_bcc/bits.bpf.h"
#include "third_party/bpf/biff_bpf.h"
#include "third_party/bpf/common.bpf.h"

#include <asm-generic/errno.h>

/*
 * Part of the ghost UAPI.  vmlinux.h doesn't include #defines, so we need to
 * add it manually.
 */
#define SEND_TASK_LATCHED (1 << 10)

// typedef __u8  __attribute__((__may_alias__))  __u8_alias_t;
// typedef __u16 __attribute__((__may_alias__)) __u16_alias_t;
// typedef __u32 __attribute__((__may_alias__)) __u32_alias_t;
// typedef __u64 __attribute__((__may_alias__)) __u64_alias_t;
// 
// static __always_inline void __read_once_size(const volatile void *p, void *res, int size)
// {
// 	switch (size) {
// 	case 1: *(__u8_alias_t  *) res = *(volatile __u8_alias_t  *) p; break;
// 	case 2: *(__u16_alias_t *) res = *(volatile __u16_alias_t *) p; break;
// 	case 4: *(__u32_alias_t *) res = *(volatile __u32_alias_t *) p; break;
// 	case 8: *(__u64_alias_t *) res = *(volatile __u64_alias_t *) p; break;
// 	default:
// 		asm volatile ("" : : : "memory");
// 		__builtin_memcpy((void *)res, (const void *)p, size);
// 		asm volatile ("" : : : "memory");
// 	}
// }
// 
// static __always_inline void __write_once_size(volatile void *p, void *res, int size)
// {
// 	switch (size) {
// 	case 1: *(volatile  __u8_alias_t *) p = *(__u8_alias_t  *) res; break;
// 	case 2: *(volatile __u16_alias_t *) p = *(__u16_alias_t *) res; break;
// 	case 4: *(volatile __u32_alias_t *) p = *(__u32_alias_t *) res; break;
// 	case 8: *(volatile __u64_alias_t *) p = *(__u64_alias_t *) res; break;
// 	default:
// 		asm volatile ("" : : : "memory");
// 		__builtin_memcpy((void *)p, (const void *)res, size);
// 		asm volatile ("" : : : "memory");
// 	}
// }
// 
// #define READ_ONCE(x)					\
// ({							\
// 	union { typeof(x) __val; char __c[1]; } __u =	\
// 		{ .__c = { 0 } };			\
// 	__read_once_size(&(x), __u.__c, sizeof(x));	\
// 	__u.__val;					\
// })
// 
// #define WRITE_ONCE(x, val)				\
// ({							\
// 	union { typeof(x) __val; char __c[1]; } __u =	\
// 		{ .__val = (val) }; 			\
// 	__write_once_size(&(x), __u.__c, sizeof(x));	\
// 	__u.__val;					\
// })
// 
#define PERIOD 1000

#define CHECK_BIT(var,pos) ((var) = (var) | (1<<(pos)))
// #define CHECK_BIT(var,pos) (__sync_fetch_and_and(var, (1<<(pos))))
// #define SET_BIT(var,pos) ((var) = (var) | (1<<(pos)))
#define SET_BIT(var,pos) (__sync_fetch_and_or(&var, (1<<(pos))))
#define CLEAR_BIT(var,pos) (__sync_fetch_and_and(&var, (1<<(pos))))

bool initialized;

__u32 num_tasks = 0;
__u64 hand_off = 0;
__u64 ts0 = 0;
__u64 ts1 = 0;
__u64 ts2 = 0;
__u64 ts3 = 0;
__u64 ts4 = 0;
__u64 ts5 = 0;

__u8 cpu_set = 0x00;


/* max_entries is patched at runtime to num_possible_cpus */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1024);
	__type(key, u32);
	__type(value, struct biff_bpf_cpu_data);
	__uint(map_flags, BPF_F_MMAPABLE);
} cpu_data SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, BIFF_MAX_GTIDS);
	__type(key, u32);
	__type(value, struct biff_bpf_sw_data);
	__uint(map_flags, BPF_F_MMAPABLE);
} sw_data SEC(".maps");

// This is only for tracing purposes
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, NR_HISTS);
	__type(key, u32);
	__type(value, struct hist);
} hists SEC(".maps");

/*
 * Hash map of task_sw_info, indexed by gtid, used for getting the SW info to
 * lookup the *real* per-task data: the sw_data.
 *
 * Also, we can't use BPF_MAP_TYPE_TASK_STORAGE since we don't have the
 * task_struct pointer.  Ghost BPF doesn't really have access to kernel
 * internals - it's more an extension of userspace.
 *
 * aligned(8) since this is a bpf map value.
 */
struct task_sw_info {
	uint32_t id;
	uint32_t index;
} __attribute__((aligned(8)));

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, BIFF_MAX_GTIDS);
	__type(key, u64);
	__type(value, struct task_sw_info);
} sw_lookup SEC(".maps");

// struct {
// 	__uint(type, BPF_MAP_TYPE_ARRAY);
// 	__type(key, u8);
// 	__type(value, long);
// 	__uint(max_entries, 10);
// } time_stamps SEC(".maps");

// This is for histograms
static void increment_hist(u32 hist_id, u64 value)
{
	u64 slot; /* Gotta love BPF.  slot needs to be a u64, not a u32. */
	struct hist *hist;

	hist = bpf_map_lookup_elem(&hists, &hist_id);
	if (!hist)
		return;
	slot = log2l(value);
	if (slot >= MAX_NR_HIST_SLOTS)
		slot = MAX_NR_HIST_SLOTS - 1;

	hist->slots[slot]++;

}

/* Helper, from gtid to per-task sw_data blob */
static struct biff_bpf_sw_data *gtid_to_swd(u64 gtid)
{
	struct task_sw_info *swi;

	swi = bpf_map_lookup_elem(&sw_lookup, &gtid);
	if (!swi)
		return NULL;
	return bpf_map_lookup_elem(&sw_data, &swi->index);
}

static void task_started(u64 gtid, int cpu, u64 cpu_seqnum)
{
	struct biff_bpf_cpu_data *pcpu;

	pcpu = bpf_map_lookup_elem(&cpu_data, &cpu);
	if (!pcpu)
		return;
	pcpu->current = gtid;
	pcpu->cpu_seqnum = cpu_seqnum;
}

static void task_stopped(int cpu)
{
	struct biff_bpf_cpu_data *pcpu;

	pcpu = bpf_map_lookup_elem(&cpu_data, &cpu);
	if (!pcpu)
		return;
	pcpu->current = 0;
}

static struct biff_bpf_sw_data *get_current(int cpu)
{
	struct biff_bpf_cpu_data *pcpu;

	pcpu = bpf_map_lookup_elem(&cpu_data, &cpu);
	if (!pcpu)
		return NULL;
	if (!pcpu->current)
		return NULL;
	return gtid_to_swd(pcpu->current);
}

/* Forces the cpu to reschedule and eventually call bpf-pnt. */
static int resched_cpu(int cpu)
{
	struct biff_bpf_cpu_data *pcpu;

	pcpu = bpf_map_lookup_elem(&cpu_data, &cpu);
	if (!pcpu)
		return -1;
	return bpf_ghost_resched_cpu(cpu, pcpu->cpu_seqnum);
}

/* Biff POLICY: dumb global fifo.  No locality, etc. */

struct rq_item {
	u64 gtid;
	u32 task_barrier;
};

// struct {
// 	__uint(type, BPF_MAP_TYPE_QUEUE);
// 	__uint(max_entries, BIFF_MAX_GTIDS);
// 	__type(value, struct rq_item);
// } global_rq SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_QUEUE);
	__uint(max_entries, BIFF_MAX_GTIDS);
	__type(value, struct rq_item);
} global_rq_0 SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_QUEUE);
	__uint(max_entries, BIFF_MAX_GTIDS);
	__type(value, struct rq_item);
} global_rq_1 SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_QUEUE);
	__uint(max_entries, BIFF_MAX_GTIDS);
	__type(value, struct rq_item);
} global_rq_2 SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_QUEUE);
	__uint(max_entries, BIFF_MAX_GTIDS);
	__type(value, struct rq_item);
} global_rq_3 SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_QUEUE);
	__uint(max_entries, BIFF_MAX_GTIDS);
	__type(value, struct rq_item);
} global_rq_4 SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_QUEUE);
	__uint(max_entries, BIFF_MAX_GTIDS);
	__type(value, struct rq_item);
} global_rq_5 SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_QUEUE);
	__uint(max_entries, BIFF_MAX_GTIDS);
	__type(value, struct rq_item);
} global_rq_6 SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_QUEUE);
	__uint(max_entries, BIFF_MAX_GTIDS);
	__type(value, struct rq_item);
} global_rq_7 SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_QUEUE);
	__uint(max_entries, BIFF_MAX_GTIDS);
	__type(value, struct rq_item);
} global_rq_8 SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_QUEUE);
	__uint(max_entries, BIFF_MAX_GTIDS);
	__type(value, struct rq_item);
} global_rq_9 SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_QUEUE);
	__uint(max_entries, BIFF_MAX_GTIDS);
	__type(value, struct rq_item);
} global_rq_10 SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_QUEUE);
	__uint(max_entries, BIFF_MAX_GTIDS);
	__type(value, struct rq_item);
} global_rq_11 SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_QUEUE);
	__uint(max_entries, BIFF_MAX_GTIDS);
	__type(value, struct rq_item);
} global_rq_12 SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_QUEUE);
	__uint(max_entries, BIFF_MAX_GTIDS);
	__type(value, struct rq_item);
} global_rq_13 SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_QUEUE);
	__uint(max_entries, BIFF_MAX_GTIDS);
	__type(value, struct rq_item);
} global_rq_14 SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_QUEUE);
	__uint(max_entries, BIFF_MAX_GTIDS);
	__type(value, struct rq_item);
} global_rq_15 SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_QUEUE);
	__uint(max_entries, BIFF_MAX_GTIDS);
	__type(value, struct rq_item);
} global_rq_16 SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_QUEUE);
	__uint(max_entries, BIFF_MAX_GTIDS);
	__type(value, struct rq_item);
} global_rq_17 SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_QUEUE);
	__uint(max_entries, BIFF_MAX_GTIDS);
	__type(value, struct rq_item);
} global_rq_18 SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_QUEUE);
	__uint(max_entries, BIFF_MAX_GTIDS);
	__type(value, struct rq_item);
} global_rq_19 SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_QUEUE);
	__uint(max_entries, BIFF_MAX_GTIDS);
	__type(value, struct rq_item);
} global_rq_20 SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_QUEUE);
	__uint(max_entries, BIFF_MAX_GTIDS);
	__type(value, struct rq_item);
} global_rq_21 SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_QUEUE);
	__uint(max_entries, BIFF_MAX_GTIDS);
	__type(value, struct rq_item);
} global_rq_22 SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_QUEUE);
	__uint(max_entries, BIFF_MAX_GTIDS);
	__type(value, struct rq_item);
} global_rq_23 SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_QUEUE);
	__uint(max_entries, BIFF_MAX_GTIDS);
	__type(value, struct rq_item);
} global_rq_24 SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_QUEUE);
	__uint(max_entries, BIFF_MAX_GTIDS);
	__type(value, struct rq_item);
} global_rq_25 SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_QUEUE);
	__uint(max_entries, BIFF_MAX_GTIDS);
	__type(value, struct rq_item);
} global_rq_26 SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_QUEUE);
	__uint(max_entries, BIFF_MAX_GTIDS);
	__type(value, struct rq_item);
} global_rq_27 SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_QUEUE);
	__uint(max_entries, BIFF_MAX_GTIDS);
	__type(value, struct rq_item);
} global_rq_28 SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_QUEUE);
	__uint(max_entries, BIFF_MAX_GTIDS);
	__type(value, struct rq_item);
} global_rq_29 SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_QUEUE);
	__uint(max_entries, BIFF_MAX_GTIDS);
	__type(value, struct rq_item);
} global_rq_30 SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_QUEUE);
	__uint(max_entries, BIFF_MAX_GTIDS);
	__type(value, struct rq_item);
} global_rq_31 SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_QUEUE);
	__uint(max_entries, BIFF_MAX_GTIDS);
	__type(value, struct rq_item);
} global_rq_32 SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_QUEUE);
	__uint(max_entries, BIFF_MAX_GTIDS);
	__type(value, struct rq_item);
} global_rq_33 SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_QUEUE);
	__uint(max_entries, BIFF_MAX_GTIDS);
	__type(value, struct rq_item);
} global_rq_34 SEC(".maps");

// struct {
// 	__uint(type, BPF_MAP_TYPE_QUEUE);
// 	__uint(max_entries, BIFF_MAX_GTIDS);
// 	__type(value, struct rq_item);
// } global_rq_9 SEC(".maps");
// 
// struct {
// 	__uint(type, BPF_MAP_TYPE_QUEUE);
// 	__uint(max_entries, BIFF_MAX_GTIDS);
// 	__type(value, struct rq_item);
// } global_rq_11 SEC(".maps");

/* POLICY */
static void enqueue_task(u64 gtid, u32 task_barrier)
{
	/*
	 * Need to explicitly zero the entire struct, otherwise you get
	 * "invalid indirect read from stack".  Explicitly setting .gtid and
	 * .task_barrier in the definition (whether p is an array or just a
	 * struct) isn't enough.  I guess the verifier can't tell we aren't
	 * passing uninitialized stack data to some function.
	 */
	struct rq_item p[1] = {0};
	int err;

        __u32 d_mapper;

	p->gtid = gtid;
	p->task_barrier = task_barrier;

        d_mapper = get_cpu();

        if (d_mapper < 8) {
                err = bpf_map_push_elem(&global_rq_0, p, 0);
        } else if (d_mapper < 16) {
                err = bpf_map_push_elem(&global_rq_1, p, 0);
        } else if (d_mapper < 24) {
                err = bpf_map_push_elem(&global_rq_2, p, 0);
        } else if (d_mapper < 32) {
                err = bpf_map_push_elem(&global_rq_3, p, 0);
        } else if (d_mapper < 40) {
                err = bpf_map_push_elem(&global_rq_4, p, 0);
        } else if (d_mapper < 48) {
                err = bpf_map_push_elem(&global_rq_5, p, 0);
        } else {
 		bpf_printk("Unable to find a right group %p, err %d\n", gtid, err);
        }
       

        // err = bpf_map_push_elem(&global_rq, p, 0);
	if (err) {
		/*
		 * If we fail, we'll lose the task permanently.  This is where
		 * it's helpful to have userspace involved, even if just epolled
		 * on a bpf ring_buffer map to handle it by trying to shove the
		 * task into the queue again.
		 */
		bpf_printk("failed to enqueue %p, err %d\n", gtid, err);
		return;
	}
}

/* POLICY */ 
// static void enqueue_task(u64 gtid, u32 task_barrier)
// {
// 	/*
// 	 * Need to explicitly zero the entire struct, otherwise you get
// 	 * "invalid indirect read from stack".  Explicitly setting .gtid and
// 	 * .task_barrier in the definition (whether p is an array or just a
// 	 * struct) isn't enough.  I guess the verifier can't tell we aren't
// 	 * passing uninitialized stack data to some function.
// 	 */
// 	struct rq_item p[1] = {0};
// 	int err;
// 
//         __u32 d_mapper;
// 
// 	p->gtid = gtid;
// 	p->task_barrier = task_barrier;
// 
//         d_mapper = get_cpu();
//         d_mapper = 0;
//         // d_mapper = d_mapper % 8;
// 
//         switch(d_mapper) {
//                 case 0:
//                         err = bpf_map_push_elem(&global_rq_0, p, 0);
//                         break;
//                 case 1:
//                         err = bpf_map_push_elem(&global_rq_1, p, 0);
//                         break;
//                 case 2:
//                         err = bpf_map_push_elem(&global_rq_2, p, 0);
//                         break;
//                 case 3:
//                         err = bpf_map_push_elem(&global_rq_3, p, 0);
//                         break;
//                 case 4:
//                         err = bpf_map_push_elem(&global_rq_4, p, 0);
//                         break;
//                 case 5:
//                         err = bpf_map_push_elem(&global_rq_5, p, 0);
//                         break;
//                 case 6:
//                         err = bpf_map_push_elem(&global_rq_6, p, 0);
//                         break;
//                 case 7:
//                         err = bpf_map_push_elem(&global_rq_7, p, 0);
//                         break;
//                 case 8:
//                         err = bpf_map_push_elem(&global_rq_8, p, 0);
//                         break;
//                 case 9:
//                         err = bpf_map_push_elem(&global_rq_9, p, 0);
//                         break;
//                 case 10:
//                         err = bpf_map_push_elem(&global_rq_10, p, 0);
//                         break;
//                 case 11:
//                         err = bpf_map_push_elem(&global_rq_11, p, 0);
//                         break;
//                 case 12:
//                         err = bpf_map_push_elem(&global_rq_12, p, 0);
//                         break;
//                 case 13:
//                         err = bpf_map_push_elem(&global_rq_13, p, 0);
//                         break;
//                 case 14:
//                         err = bpf_map_push_elem(&global_rq_14, p, 0);
//                         break;
//                 case 15:
//                         err = bpf_map_push_elem(&global_rq_15, p, 0);
//                         break;
//                 case 16:
//                         err = bpf_map_push_elem(&global_rq_16, p, 0);
//                         break;
//                 case 17:
//                         err = bpf_map_push_elem(&global_rq_17, p, 0);
//                         break;
//                 case 18:
//                         err = bpf_map_push_elem(&global_rq_18, p, 0);
//                         break;
//                 case 19:
//                         err = bpf_map_push_elem(&global_rq_19, p, 0);
//                         break;
//                 case 20:
//                         err = bpf_map_push_elem(&global_rq_20, p, 0);
//                         break;
//                 case 21:
//                         err = bpf_map_push_elem(&global_rq_21, p, 0);
//                         break;
//                 case 22:
//                         err = bpf_map_push_elem(&global_rq_22, p, 0);
//                         break;
//                 case 23:
//                         err = bpf_map_push_elem(&global_rq_23, p, 0);
//                         break;
//                 case 24:
//                         err = bpf_map_push_elem(&global_rq_24, p, 0);
//                         break;
//                 case 25:
//                         err = bpf_map_push_elem(&global_rq_25, p, 0);
//                         break;
//                 case 26:
//                         err = bpf_map_push_elem(&global_rq_26, p, 0);
//                         break;
//                 case 27:
//                         err = bpf_map_push_elem(&global_rq_27, p, 0);
//                         break;
//                 case 28:
//                         err = bpf_map_push_elem(&global_rq_28, p, 0);
//                         break;
//                 case 29:
//                         err = bpf_map_push_elem(&global_rq_29, p, 0);
//                         break;
//                 case 30:
//                         err = bpf_map_push_elem(&global_rq_30, p, 0);
//                         break;
//                 case 31:
//                         err = bpf_map_push_elem(&global_rq_31, p, 0);
//                         break;
//                 case 32:
//                         err = bpf_map_push_elem(&global_rq_32, p, 0);
//                         break;
//                 case 33:
//                         err = bpf_map_push_elem(&global_rq_33, p, 0);
//                         break;
//                 case 34:
//                         err = bpf_map_push_elem(&global_rq_34, p, 0);
//                         break;
//                 default:
//                         bpf_printk("failed to find a right group: %d, %p, err %d\n",
//                                   d_mapper, gtid, err);
// 
// 
//         }
//         // else if (d_mapper < 16)
//         //          err = bpf_map_push_elem(&global_rq_3, p, 0);
//         // else if (d_mapper < 24)
//         //           err = bpf_map_push_elem(&global_rq_5, p, 0);
//         // else if (d_mapper < 40)
//         //          err = bpf_map_push_elem(&global_rq_7, p, 0);
//         // // else if (d_mapper < 40) 
//         // //          err = bpf_map_push_elem(&global_rq_9, p, 0);
//         // // else if (d_mapper < 48)
//         // //          err = bpf_map_push_elem(&global_rq_11, p, 0);
//         //  else
//         
// 
//         // err = bpf_map_push_elem(&global_rq, p, 0);
// 	if (err) {
// 		/*
// 		 * If we fail, we'll lose the task permanently.  This is where
// 		 * it's helpful to have userspace involved, even if just epolled
// 		 * on a bpf ring_buffer map to handle it by trying to shove the
// 		 * task into the queue again.
// 		 */
// 		bpf_printk("failed to enqueue %p, err %d\n", gtid, err);
// 		return;
// 	}
// }

/* Avoid the dreaded "dereference of modified ctx ptr R6 off=3 disallowed" */
static void __attribute__((noinline)) set_dont_idle(struct bpf_ghost_sched *ctx)
{
	ctx->dont_idle = true;
}

// static int load_balance(struct bpf_map *queue, struct rq_item *next, int err) {
static int load_balance(void * queue, struct rq_item *next, int err, int group) {


        u64 now = bpf_ktime_get_us();
        u32 d_mapper = get_cpu();

        // __sync_synchronize();
        if (now - ts0 > PERIOD && !CHECK_BIT(cpu_set, group)) {
                SET_BIT(cpu_set, group);
	        // bpf_printk("load balancing %d\n", d_mapper);
                err = bpf_map_pop_elem((struct bpf_map*)queue, next);
                ts0 = now;
                CLEAR_BIT(cpu_set, group);
        }

        return err;

}

SEC("ghost_sched/pnt")
int biff_pnt(struct bpf_ghost_sched *ctx)
{
	struct rq_item next[1];
	int err;
        int d_mapper;

	if (!initialized) {
		/*
		 * Until the agent completes Discovery, don't schedule anything.
		 * Keeping the system quiescent makes it easier to handle corner
		 * cases.  Specifically, since tasks are not running, we don't
		 * need to deal with unexpected preempt/blocked/yield/switchtos.
		 */
		set_dont_idle(ctx);
		return 0;
	}

	/*
	 * Don't bother picking a task to run if any of these are true.  If the
	 * agent runs or CFS preempts us, we'll just get the latched task
	 * preempted.  next_gtid is a task we already scheduled (via txn or was
	 * previously running), but did not request a resched for.
	 *
	 * Note it is might_yield, not "will_yield", so there's a chance the CFS
	 * tasks gets migrated away while the RQ lock is unlocked.  It's always
	 * safer to set dont_idle.
	 */
	if (ctx->agent_runnable || ctx->might_yield || ctx->next_gtid) {
		set_dont_idle(ctx);
		return 0;
	}

	/* POLICY */

        // err = pick_from_a_group(12, next);
	// err = bpf_map_pop_elem(&global_rq, next);


        // if (1)
        // bpf_printk("hand_off %d\n", 8);

        d_mapper = get_cpu();
        // d_mapper = 0;
        //
        
        // can I do division?
        if (d_mapper < 8) {
	        err = bpf_map_pop_elem(&global_rq_0, next);
                err = load_balance((void *)&global_rq_1, next, err, 0);
        } else if (d_mapper < 16) {
	        err = bpf_map_pop_elem(&global_rq_1, next);
                err = load_balance((void *)&global_rq_2, next, err, 1);

                // if (err && bpf_ktime_get_us() - ts1 > PERIOD && !CHECK_BIT(cpu_set, 1)) {
                //         ts1 = bpf_ktime_get_us();
                //         SET_BIT(cpu_set, 1);
		//         bpf_printk("load balancing %d\n", d_mapper);
                //         CLEAR_BIT(cpu_set, 1);
                // }
        } else if (d_mapper < 24) {
	        err = bpf_map_pop_elem(&global_rq_2, next);
                err = load_balance((void *)&global_rq_3, next, err, 2);
                
                // if (err && bpf_ktime_get_us() - ts2 > PERIOD && !CHECK_BIT(cpu_set, 2)) {
                //         ts2 = bpf_ktime_get_us();
                //         SET_BIT(cpu_set, 2);
		//         bpf_printk("load balancing %d\n", d_mapper);
                //         CLEAR_BIT(cpu_set, 2);
                // }
        } else if (d_mapper < 32) {
	        err = bpf_map_pop_elem(&global_rq_3, next);
                err = load_balance((void *)&global_rq_4, next, err, 3);

                // if (err && bpf_ktime_get_us() - ts3 > PERIOD && !CHECK_BIT(cpu_set, 3)) {
                //         ts3 = bpf_ktime_get_us();
                //         SET_BIT(cpu_set, 3);
		//         bpf_printk("load balancing %d\n", d_mapper);
                //         CLEAR_BIT(cpu_set, 3);
                // }
        } else if (d_mapper < 40) {
	        err = bpf_map_pop_elem(&global_rq_4, next);
                err = load_balance((void *)&global_rq_0, next, err, 4);

                // if (err && bpf_ktime_get_us() - ts4 > PERIOD && !CHECK_BIT(cpu_set, 4)) {
                //         ts4 = bpf_ktime_get_us();
                //         SET_BIT(cpu_set, 4);
		//         bpf_printk("load balancing %d\n", d_mapper);
                //         CLEAR_BIT(cpu_set, 4);
                // }
        } else if (d_mapper < 48) {
	        err = bpf_map_pop_elem(&global_rq_5, next);

                if (err && bpf_ktime_get_us() - ts5 > PERIOD && !CHECK_BIT(cpu_set, 5)) {
                        ts5 = bpf_ktime_get_us();
		        bpf_printk("load balancing %d\n", d_mapper);
                }
        } else {
                bpf_printk("failed to dequeue, err %d\n", err);
        }

        
        // if (d_mapper < 16) {
	//         err = bpf_map_pop_elem(&global_rq_0, next);
        // } else if (d_mapper < 32) {
	//         err = bpf_map_pop_elem(&global_rq_1, next);
        // } else if (d_mapper < 48) {
	//         err = bpf_map_pop_elem(&global_rq_2, next);
        // } else {
	// 	bpf_printk("failed to dequeue, err %d\n", err);
        // }

	// bpf_printk("something is wrong %d\n", err);
        
	if (err) {
		switch (-err) {
		case ENOENT:
			// increment_hist(PNT_RQ_EMPTY, bpf_ktime_get_us() - pops);
			break;
		default:
			// bpf_printk("failed failed failed to dequeue, err %d\n", err);
			bpf_printk("failed failed failed to dequeue, err \n");
		}

		goto done;
	} 


	err = bpf_ghost_run_gtid(next->gtid, next->task_barrier,
				 SEND_TASK_LATCHED);


	if (err) {
		/* Three broad classes of error:
		 * - ignore it
		 * - ok, enqueue and try again
		 * - bad, enqueue and hope for the best.
		 *
		 * We could consider retrying, but we'd need to be careful for
		 * something like EBUSY, where we do not want to try again until
		 * we've returned to the kernel and context switched to the idle
		 * task.  Simplest to just return with dont_idle set.
		 */
		switch (-err) {
		case ENOENT:
			/* task departed, ignore */
			break;
		case ESTALE:
			/*
			 * task_barrier is old.  since we "had the ball", the
			 * task should be departed or dying.  it's possible for
			 * it to depart and be readded (which will generate a
			 * new message), so just ignore it.
			 */
			break;
		case EBUSY:
			/*
			 * task is still on_cpu.  this happens when it was
			 * preempted (we got the message early in PNT), and we
			 * are trying to pick what runs next, but the task
			 * hasn't actually gotten off cpu yet.  if we reenqueue,
			 * select the idle task, and then either set dont_idle
			 * or resched ourselves, we'll rerun bpf-pnt after the
			 * task got off cpu.
			 */
			enqueue_task(next->gtid, next->task_barrier);
			break;
		case ERANGE:
		case EXDEV:
		case EINVAL:
		case ENOSPC:
		default:
			/*
			 * Various issues, none of which should happen from PNT,
			 * since we are called from an online cpu in the
			 * enclave with an agent.  Though as we change the
			 * kernel, some of these may occur.  Reenqueue and hope
			 * for the best.
			 *   - ERANGE: cpu is offline
			 *   - EXDEV: cpu is not in the enclave
			 *   - EINVAL: Catchall, shouldn't happen.  Other than
			 *   stuff like "bad run flags", another scenario is "no
			 *   agent task".  That shouldn't happen, since we run
			 *   bpf-pnt only if there is an agent task
			 *   (currently!).
			 *   - ENOSPC: corner case in __ghost_run_gtid_on()
			 *   where CFS is present, though right now it shouldn't
			 *   be reachable from bpf-pnt.
			 */
			bpf_printk("failed to run %p, err %d\n", next->gtid, err);
			enqueue_task(next->gtid, next->task_barrier);
			break;
		}
	}

done:
	/*
	 * POLICY
	 *
	 * Alternatively, we could use bpf_ghost_resched_cpu() for fine-grained
	 * control of cpus idling or not.
	 */
	ctx->dont_idle = true;
    
	return 0;
}



// SEC("ghost_sched/pnt")
// int biff_pnt(struct bpf_ghost_sched *ctx)
// {
// 
//         // __u32 d_mapper = get_cpu();
//         // __u32 d_mapper_o = d_mapper;
// 
// 
//         // int printtest = d_mapper;
//         
// 	struct rq_item next[1];
// 	int err;
//         int d_mapper, d_mapper_o;
// 
// 	if (!initialized) {
// 		/*
// 		 * Until the agent completes Discovery, don't schedule anything.
// 		 * Keeping the system quiescent makes it easier to handle corner
// 		 * cases.  Specifically, since tasks are not running, we don't
// 		 * need to deal with unexpected preempt/blocked/yield/switchtos.
// 		 */
// 		set_dont_idle(ctx);
// 		return 0;
// 	}
// 
// 	/*
// 	 * Don't bother picking a task to run if any of these are true.  If the
// 	 * agent runs or CFS preempts us, we'll just get the latched task
// 	 * preempted.  next_gtid is a task we already scheduled (via txn or was
// 	 * previously running), but did not request a resched for.
// 	 *
// 	 * Note it is might_yield, not "will_yield", so there's a chance the CFS
// 	 * tasks gets migrated away while the RQ lock is unlocked.  It's always
// 	 * safer to set dont_idle.
// 	 */
// 	if (ctx->agent_runnable || ctx->might_yield || ctx->next_gtid) {
// 		set_dont_idle(ctx);
// 		return 0;
// 	}
// 
// 	/* POLICY */
// 
//         // err = pick_from_a_group(12, next);
// 	// err = bpf_map_pop_elem(&global_rq, next);
// 
// 
//         // if (1)
//         // bpf_printk("hand_off %d\n", 8);
// 
//         d_mapper = get_cpu();
//         d_mapper = d_mapper % 8;
//         // d_mapper = 0; 
// 
//         switch (d_mapper) {
//                 case 0:
// 	                err = bpf_map_pop_elem(&global_rq_0, next);
//                         break;
//                 case 1:
// 	                err = bpf_map_pop_elem(&global_rq_1, next);
//                         break;
//                 case 2:
// 	                err = bpf_map_pop_elem(&global_rq_2, next);
//                         break;
//                 case 3:
// 	                err = bpf_map_pop_elem(&global_rq_3, next);
//                         break;
//                 case 4:
// 	                err = bpf_map_pop_elem(&global_rq_4, next);
//                         break;
//                 case 5:
// 	                err = bpf_map_pop_elem(&global_rq_5, next);
//                         break;
//                 case 6:
// 	                err = bpf_map_pop_elem(&global_rq_6, next);
//                         break;
//                 case 7:
// 	                err = bpf_map_pop_elem(&global_rq_7, next);
//                         break;
//                 case 8:
// 	                err = bpf_map_pop_elem(&global_rq_8, next);
//                         break;
//                 case 9:
// 	                err = bpf_map_pop_elem(&global_rq_9, next);
//                         break;
//                 case 10:
// 	                err = bpf_map_pop_elem(&global_rq_10, next);
//                         break;
//                 case 11:
// 	                err = bpf_map_pop_elem(&global_rq_11, next);
//                         break;
//                 case 12:
// 	                err = bpf_map_pop_elem(&global_rq_12, next);
//                         break;
//                 case 13:
// 	                err = bpf_map_pop_elem(&global_rq_13, next);
//                         break;
//                 case 14:
// 	                err = bpf_map_pop_elem(&global_rq_14, next);
//                         break;
//                 case 15:
// 	                err = bpf_map_pop_elem(&global_rq_15, next);
//                         break;
//                 case 16:
// 	                err = bpf_map_pop_elem(&global_rq_16, next);
//                         break;
//                 case 17:
// 	                err = bpf_map_pop_elem(&global_rq_17, next);
//                         break;
//                 case 18:
// 	                err = bpf_map_pop_elem(&global_rq_18, next);
//                         break;
//                 case 19:
// 	                err = bpf_map_pop_elem(&global_rq_19, next);
//                         break;
//                 case 20:
// 	                err = bpf_map_pop_elem(&global_rq_20, next);
//                         break;
//                 case 21:
// 	                err = bpf_map_pop_elem(&global_rq_21, next);
//                         break;
//                 case 22:
// 	                err = bpf_map_pop_elem(&global_rq_22, next);
//                         break;
//                 case 23:
// 	                err = bpf_map_pop_elem(&global_rq_23, next);
//                         break;
//                 case 24:
// 	                err = bpf_map_pop_elem(&global_rq_24, next);
//                         break;
//                 case 25:
// 	                err = bpf_map_pop_elem(&global_rq_25, next);
//                         break;
//                 case 26:
// 	                err = bpf_map_pop_elem(&global_rq_26, next);
//                         break;
//                 case 27:
// 	                err = bpf_map_pop_elem(&global_rq_27, next);
//                         break;
//                 case 28:
// 	                err = bpf_map_pop_elem(&global_rq_28, next);
//                         break;
//                 case 29:
// 	                err = bpf_map_pop_elem(&global_rq_29, next);
//                         break;
//                 case 30:
// 	                err = bpf_map_pop_elem(&global_rq_30, next);
//                         break;
//                 case 31:
// 	                err = bpf_map_pop_elem(&global_rq_31, next);
//                         break;
//                 case 32:
// 	                err = bpf_map_pop_elem(&global_rq_32, next);
//                         break;
//                 case 33:
// 	                err = bpf_map_pop_elem(&global_rq_33, next);
//                         break;
//                 case 34:
// 	                err = bpf_map_pop_elem(&global_rq_34, next);
//                         break;
//                 default:
// 			bpf_printk("failed to dequeue, err %d\n", err);
//         }
// 
// 	bpf_printk("something is wrong %d\n", err);
// 
//         // if (d_mapper % 2 == 0) {
// 	//         err = bpf_map_pop_elem(&global_rq_1, next);
//         //         // if (err) 
// 	//         //         err = bpf_map_pop_elem(&global_rq_3, next);
//         // }
//         // else {
// 	//         err = bpf_map_pop_elem(&global_rq_3, next);
//         //         // if (err) 
// 	//         //         err = bpf_map_pop_elem(&global_rq_1, next);
//         // }
// 
// 	if (err) {
// 		switch (-err) {
// 		case ENOENT:
// 			// increment_hist(PNT_RQ_EMPTY, bpf_ktime_get_us() - pops);
// 			break;
// 		default:
// 			bpf_printk("failed to dequeue, err %d\n", err);
// 		}
// 		goto done;
// 	} 
// 
// 	err = bpf_ghost_run_gtid(next->gtid, next->task_barrier,
// 				 SEND_TASK_LATCHED);
// 
// 	if (err) {
// 		/* Three broad classes of error:
// 		 * - ignore it
// 		 * - ok, enqueue and try again
// 		 * - bad, enqueue and hope for the best.
// 		 *
// 		 * We could consider retrying, but we'd need to be careful for
// 		 * something like EBUSY, where we do not want to try again until
// 		 * we've returned to the kernel and context switched to the idle
// 		 * task.  Simplest to just return with dont_idle set.
// 		 */
// 		switch (-err) {
// 		case ENOENT:
// 			/* task departed, ignore */
// 			break;
// 		case ESTALE:
// 			/*
// 			 * task_barrier is old.  since we "had the ball", the
// 			 * task should be departed or dying.  it's possible for
// 			 * it to depart and be readded (which will generate a
// 			 * new message), so just ignore it.
// 			 */
// 			break;
// 		case EBUSY:
// 			/*
// 			 * task is still on_cpu.  this happens when it was
// 			 * preempted (we got the message early in PNT), and we
// 			 * are trying to pick what runs next, but the task
// 			 * hasn't actually gotten off cpu yet.  if we reenqueue,
// 			 * select the idle task, and then either set dont_idle
// 			 * or resched ourselves, we'll rerun bpf-pnt after the
// 			 * task got off cpu.
// 			 */
// 			enqueue_task(next->gtid, next->task_barrier);
// 			break;
// 		case ERANGE:
// 		case EXDEV:
// 		case EINVAL:
// 		case ENOSPC:
// 		default:
// 			/*
// 			 * Various issues, none of which should happen from PNT,
// 			 * since we are called from an online cpu in the
// 			 * enclave with an agent.  Though as we change the
// 			 * kernel, some of these may occur.  Reenqueue and hope
// 			 * for the best.
// 			 *   - ERANGE: cpu is offline
// 			 *   - EXDEV: cpu is not in the enclave
// 			 *   - EINVAL: Catchall, shouldn't happen.  Other than
// 			 *   stuff like "bad run flags", another scenario is "no
// 			 *   agent task".  That shouldn't happen, since we run
// 			 *   bpf-pnt only if there is an agent task
// 			 *   (currently!).
// 			 *   - ENOSPC: corner case in __ghost_run_gtid_on()
// 			 *   where CFS is present, though right now it shouldn't
// 			 *   be reachable from bpf-pnt.
// 			 */
// 			bpf_printk("failed to run %p, err %d\n", next->gtid, err);
// 			enqueue_task(next->gtid, next->task_barrier);
// 			break;
// 		}
// 	}
// 
// done:
// 	/*
// 	 * POLICY
// 	 *
// 	 * Alternatively, we could use bpf_ghost_resched_cpu() for fine-grained
// 	 * control of cpus idling or not.
// 	 */
// 	ctx->dont_idle = true;
//     
// 	return 0;
// }

/*
 * You have to play games to get the compiler to not modify the context pointer
 * (msg).  You can load X bytes off a ctx, but if you add to ctx, then load,
 * you'll get the dreaded: "dereference of modified ctx ptr" error.
 *
 * You can also sprinkle asm volatile ("" ::: "memory") to help reduce compiler
 * optimizations on the context.
 */
static void __attribute__((noinline)) handle_new(struct bpf_ghost_msg *msg)
{
	struct ghost_msg_payload_task_new *new = &msg->newt;
	struct task_sw_info swi[1] = {0};
	struct biff_bpf_sw_data *swd;
	u64 gtid = new->gtid;
	u64 now = bpf_ktime_get_us();

	swi->id = new->sw_info.id;
	swi->index = new->sw_info.index;

	if (bpf_map_update_elem(&sw_lookup, &gtid, swi, BPF_NOEXIST)) {
		/*
		 * We already knew about this task.  If a task joins the enclave
		 * during Discovery, we'll get a task_new message.  Then
		 * userspace asks for task_news for all tasks.  Use the bpf map
		 * as our synchronization point, similar to how userspace agents
		 * use the task's channel association.
		 *
		 * Note that if you use "send me task news" to handle failing to
		 * enqueue a task or something (which is essentially losing a
		 * wakeup), then you may need some other mechanism to track
		 * the actual runnability of the task.  i.e. make sure biff
		 * and new->runnable are in sync.
		 */
		return;
	}

	swd = gtid_to_swd(gtid);
	if (!swd)
		return;
	swd->ran_until = now;
	if (new->runnable) {
		swd->runnable_at = now;
		enqueue_task(gtid, msg->seqnum);
	}
}

static void __attribute__((noinline)) handle_latched(struct bpf_ghost_msg *msg)
{
	struct ghost_msg_payload_task_latched *latched = &msg->latched;
	struct biff_bpf_sw_data *swd;
	u64 gtid = latched->gtid;

	swd = gtid_to_swd(gtid);
	if (!swd)
		return;
	swd->ran_at = bpf_ktime_get_us();

	task_started(gtid, latched->cpu, latched->cpu_seqnum);
}

static void __attribute__((noinline)) handle_blocked(struct bpf_ghost_msg *msg)
{
	struct ghost_msg_payload_task_blocked *blocked = &msg->blocked;
	struct biff_bpf_sw_data *swd;
	u64 gtid = blocked->gtid;

	swd = gtid_to_swd(gtid);
	if (!swd)
		return;
	swd->ran_until = bpf_ktime_get_us();

	task_stopped(blocked->cpu);
}

static void __attribute__((noinline)) handle_wakeup(struct bpf_ghost_msg *msg)
{
	struct ghost_msg_payload_task_wakeup *wakeup = &msg->wakeup;
	struct biff_bpf_sw_data *swd;
	u64 gtid = wakeup->gtid;
	u64 now = bpf_ktime_get_us();

	swd = gtid_to_swd(gtid);
	if (!swd)
		return;
	swd->runnable_at = now;

	enqueue_task(gtid, msg->seqnum);
}

static void __attribute__((noinline)) handle_preempt(struct bpf_ghost_msg *msg)
{
	struct ghost_msg_payload_task_preempt *preempt = &msg->preempt;
	struct biff_bpf_sw_data *swd;
	u64 gtid = preempt->gtid;
	int cpu = preempt->cpu;
	u64 now = bpf_ktime_get_us();

	swd = gtid_to_swd(gtid);
	if (!swd)
		return;
	swd->ran_until = now;
	swd->runnable_at = now;

	task_stopped(cpu);

	enqueue_task(gtid, msg->seqnum);
}

static void __attribute__((noinline)) handle_yield(struct bpf_ghost_msg *msg)
{
	struct ghost_msg_payload_task_yield *yield = &msg->yield;
	struct biff_bpf_sw_data *swd;
	u64 gtid = yield->gtid;
	int cpu = yield->cpu;
	u64 now = bpf_ktime_get_us();

	swd = gtid_to_swd(gtid);
	if (!swd)
		return;
	swd->ran_until = now;
	swd->runnable_at = now;

	task_stopped(cpu);

	enqueue_task(gtid, msg->seqnum);
}

static void __attribute__((noinline)) handle_switchto(struct bpf_ghost_msg *msg)
{
	struct ghost_msg_payload_task_switchto *switchto = &msg->switchto;
	struct biff_bpf_sw_data *swd;
	u64 gtid = switchto->gtid;
	u64 now = bpf_ktime_get_us();

	swd = gtid_to_swd(gtid);
	if (!swd)
		return;
	swd->ran_until = now;

	/*
	 * If we knew who we switched to and if we got these messages for every
	 * switchto (instead of just the first), we could update pcpu->current.
	 */
}

static void __attribute__((noinline)) handle_dead(struct bpf_ghost_msg *msg)
{
	struct ghost_msg_payload_task_dead *dead = &msg->dead;
	u64 gtid = dead->gtid;

	bpf_map_delete_elem(&sw_lookup, &gtid);
}

static void __attribute__((noinline)) handle_departed(struct bpf_ghost_msg *msg)
{
	struct ghost_msg_payload_task_departed *departed = &msg->departed;
	u64 gtid = departed->gtid;

	if (departed->was_current)
		task_stopped(departed->cpu);

	bpf_map_delete_elem(&sw_lookup, &gtid);
}

static void __attribute__((noinline)) handle_cpu_tick(struct bpf_ghost_msg *msg)
{
	struct ghost_msg_payload_cpu_tick *cpu_tick = &msg->cpu_tick;
	struct biff_bpf_sw_data *swd;
	int cpu = cpu_tick->cpu;

	swd = get_current(cpu);
	if (!swd)
		return;

	/* Arbitrary POLICY: kick anyone off cpu after 50ms */
	if (bpf_ktime_get_us() - swd->ran_at > 50000)
		resched_cpu(cpu);
}

SEC("ghost_msg/msg_send")
int biff_msg_send(struct bpf_ghost_msg *msg)
{
	switch (msg->type) {
	case MSG_TASK_NEW:
		handle_new(msg);
		break;
	case MSG_TASK_LATCHED:
		handle_latched(msg);
		break;
	case MSG_TASK_BLOCKED:
		handle_blocked(msg);
		break;
	case MSG_TASK_WAKEUP:
		handle_wakeup(msg);
		break;
	case MSG_TASK_PREEMPT:
		handle_preempt(msg);
		break;
	case MSG_TASK_YIELD:
		handle_yield(msg);
		break;
	case MSG_TASK_SWITCHTO:
		handle_switchto(msg);
		break;
	case MSG_TASK_DEAD:
		handle_dead(msg);
		break;
	case MSG_TASK_DEPARTED:
		handle_departed(msg);
		break;
	case MSG_CPU_TICK:
		handle_cpu_tick(msg);
		break;
	}

	/* Never send the message to userspace: no one is listening. */
	return 1;
}

char LICENSE[] SEC("license") = "GPL";
