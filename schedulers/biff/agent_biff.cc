// Copyright 2022 Google LLC
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file or at
// https://developers.google.com/open-source/licenses/bsd

#include <cstdint>
#include <string>
#include <vector>

#include "absl/debugging/symbolize.h"
#include "absl/flags/parse.h"
#include "lib/agent.h"
#include "lib/channel.h"
#include "lib/enclave.h"
#include "lib/topology.h"
#include "schedulers/biff/biff_scheduler.h"

ABSL_FLAG(int32_t, firstcpu, 1, "First cpu to start scheduling from.");
ABSL_FLAG(int32_t, globalcpu, -1,
          "Global cpu. If -1, then defaults to <firstcpu>)");
ABSL_FLAG(int32_t, ncpus, 9, "Schedule on <ncpus> starting from <firstcpu>");
ABSL_FLAG(std::string, enclave, "", "Connect to preexisting enclave directory");
ABSL_FLAG(absl::Duration, preemption_time_slice, absl::Microseconds(50),
          "Shinjuku preemption time slice");

void ParseBpfConfig(ghost::AgentConfig* config) {
        
  int firstcpu = absl::GetFlag(FLAGS_firstcpu);
  int ncpus = absl::GetFlag(FLAGS_ncpus);
  int lastcpu = firstcpu + ncpus - 1;

  fprintf(stderr, "testing %d\n", lastcpu);

  CHECK_GT(ncpus, 1);
  CHECK_GE(firstcpu, 0);
  CHECK_LT(lastcpu, ghost::MachineTopology()->num_cpus());


  std::vector<int> all_cpus_v;
  for (int c = firstcpu; c <= lastcpu; c++) {
    all_cpus_v.push_back(c);
  }

  // Should be easy to develop something that only works on a single NUMA node
  ghost::Topology* t = ghost::MachineTopology();
  ghost::CpuList ghost_cpus = t->ToCpuList(std::move(all_cpus_v));

  // ghost::AgentConfig config(t, ghost_cpus);
  std::string enclave = absl::GetFlag(FLAGS_enclave);
  if (!enclave.empty()) {
    int fd = open(enclave.c_str(), O_PATH);
    CHECK_GE(fd, 0);
    config->enclave_fd_ = fd;
  }

  config->topology_ = t;
  config->cpus_ = ghost_cpus;

}

int main(int argc, char* argv[]) {
  absl::InitializeSymbolizer(argv[0]);
  absl::ParseCommandLine(argc, argv);

  ghost::AgentConfig config;
  ParseBpfConfig(&config);

  auto uap = new ghost::AgentProcess<ghost::FullBiffAgent<ghost::LocalEnclave>,
                                     ghost::AgentConfig>(config);

  ghost::GhostHelper()->InitCore();

  printf("Initialization complete, ghOSt active.\n");
  fflush(stdout);

  ghost::Notification exit;
  static bool first = true;
  ghost::GhostSignals::AddHandler(SIGINT, [&exit](int) {
    if (first) {
      exit.Notify();
      first = false;
      return false;
    }
    return true;
  });

  exit.WaitForNotification();

  delete uap;

  printf("\nDone!\n");
  return 0;
}
