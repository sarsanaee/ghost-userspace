// Copyright 2022 Google LLC
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file or at
// https://developers.google.com/open-source/licenses/bsd

#include "schedulers/biff/biff_scheduler.h"

#include "absl/strings/str_format.h"
#include "bpf/user/agent.h"
#include <stdlib.h>

// Let's see if this works at all!
#include "third_party/iovisor_bcc/trace_helpers.h"
#include "libbpf/bpf.h"
#include "libbpf/libbpf.h"

// C STYLE
#define handle_error(msg) \
        do { perror(msg); exit(-1); } while (0)

static const char *titles[] = {
	[PNT_END_TO_END] = "PNT end to end latency",
	[PNT_POP_ELEMENT] = "PNT pop element latency",
	[PNT_TXN] = "PNT transaction submission latency",
	[PNT_ENQ_EBUSY] = "PNT transaction EBUSY, pop+push",
	[PNT_RQ_EMPTY] = "PNT BPF runq empty",
	// [LATCHED_TO_RUN] = "Latency from Latched to Run",
	// [RUNNABLE_TO_RUN] = "Latency from Runnable to Run",
};

static void print_hists(int fd)
{
	unsigned int nr_cpus = libbpf_num_possible_cpus();
	struct hist *hist;
	uint32_t total[MAX_NR_HIST_SLOTS];

	/*
	 * There are NR_HISTS members of the PERCPU_ARRAY.  Each one we read is
	 * an *array[nr_cpus]* of the struct hist, one for each cpu.  This
	 * differs from a accessing an element from within a BPF program, where
	 * we only get the percpu element.
	 */
	hist = static_cast<struct hist*>(calloc(nr_cpus, sizeof(struct hist)));
	if (!hist)
		handle_error("calloc");

	for (int i = 0; i < NR_HISTS; i++) {
		if (bpf_map_lookup_elem(fd, &i, hist))
			handle_error("lookup");
		memset(total, 0, sizeof(total));
		for (int c = 0; c < nr_cpus; c++) {
			for (int s = 0; s < MAX_NR_HIST_SLOTS; s++)
				total[s] += hist[c].slots[s];
		}
		fprintf(stderr, "\n%s:\n----------\n", titles[i]);
		print_log2_hist(total, MAX_NR_HIST_SLOTS, "usec");
	}

	free(hist);
}

// C STYLE ENDED

namespace ghost {

BiffScheduler::BiffScheduler(Enclave* enclave, CpuList cpulist,
                             const AgentConfig& config)
    : Scheduler(enclave, std::move(cpulist)),
      unused_channel_(GHOST_MAX_QUEUE_ELEMS, /*node=*/0) {

  bpf_obj_ = biff_bpf__open();
  CHECK_NE(bpf_obj_, nullptr);

  bpf_map__resize(bpf_obj_->maps.cpu_data, libbpf_num_possible_cpus());

  bpf_program__set_types(bpf_obj_->progs.biff_pnt,
                         BPF_PROG_TYPE_GHOST_SCHED, BPF_GHOST_SCHED_PNT);
  bpf_program__set_types(bpf_obj_->progs.biff_msg_send, BPF_PROG_TYPE_GHOST_MSG,
                         BPF_GHOST_MSG_SEND);

  CHECK_EQ(biff_bpf__load(bpf_obj_), 0);

  CHECK_EQ(agent_bpf_register(bpf_obj_->progs.biff_pnt, BPF_GHOST_SCHED_PNT),
           0);
  CHECK_EQ(agent_bpf_register(bpf_obj_->progs.biff_msg_send,
                              BPF_GHOST_MSG_SEND), 0);

  bpf_cpu_data_ = static_cast<struct biff_bpf_cpu_data*>(
      bpf_map__mmap(bpf_obj_->maps.cpu_data));
  CHECK_NE(bpf_cpu_data_, MAP_FAILED);

  bpf_sw_data_ = static_cast<struct biff_bpf_sw_data*>(
      bpf_map__mmap(bpf_obj_->maps.sw_data));
  CHECK_NE(bpf_sw_data_, MAP_FAILED);
}

BiffScheduler::~BiffScheduler() {
  print_hists(bpf_map__fd(bpf_obj_->maps.hists));

  bpf_map__munmap(bpf_obj_->maps.cpu_data, bpf_cpu_data_);
  bpf_map__munmap(bpf_obj_->maps.sw_data, bpf_sw_data_);
  biff_bpf__destroy(bpf_obj_);
}

void BiffScheduler::EnclaveReady() {
  // Biff has no cpu locality, so the remote wakeup is never worth it.
  enclave()->SetWakeOnWakerCpu(true);

  WRITE_ONCE(bpf_obj_->bss->initialized, true);
}

void BiffScheduler::DiscoverTasks() {
  enclave()->DiscoverTasks();
}

void BiffAgentTask::AgentThread() {
  gtid().assign_name("Agent:" + std::to_string(cpu().id()));

  SignalReady();
  WaitForEnclaveReady();

  while (!Finished()) {
    RunRequest* req = enclave()->GetRunRequest(cpu());
    req->LocalYield(status_word().barrier(), /*flags=*/0);
  }

}

}  //  namespace ghost
