# Note: If you modify this BUILD file, please contact jhumphri@ first to ensure
# that you are not breaking the Copybara script.

load("//:bpf/bpf.bzl", "bpf_skeleton")

package(default_visibility = ["//:__pkg__"])

# Each license covers the code below:
#
# BSD 2: Just covers the IOVisor BCC code in third_party/iovisor_bcc/. This
# code was not written by Google.
#
# GPLv2: Just covers the eBPF code in third_party/bpf/. This code was written
# by Google. We need to license it under GPLv2 though so that the eBPF code
# can use kernel functionality restricted to code licensed under GPLv2.
#
# MIT: Just covers third_party/util/util.h. This code was not written by Google,
# but was modified by Google.
#
# Apache 2: All other code is covered by Apache 2. This includes the library
# code in lib/, the experiments, all code in bpf/user/, etc.
licenses(["notice"])

exports_files(["LICENSE"])

compiler_flags = [
    "-Wno-sign-compare",
    "-DGHOST_LOGGING",
]

bpf_linkopts = [
    "-lelf",
    "-lz",
]

cc_library(
    name = "agent",
    srcs = [
        "bpf/user/agent.c",
        "lib/agent.cc",
        "lib/channel.cc",
        "lib/enclave.cc",
        "lib/topology.cc",
    ],
    hdrs = [
        "bpf/user/agent.h",
        "bpf/user/schedghostidle_bpf.skel.h",
        "lib/agent.h",
        "lib/channel.h",
        "lib/enclave.h",
        "lib/scheduler.h",
        "lib/topology.h",
        "//third_party:iovisor_bcc/trace_helpers.h",
    ],
    copts = compiler_flags,
    linkopts = bpf_linkopts + ["-lnuma"],
    deps = [
        ":base",
        ":ghost",
        ":shared",
        "@com_google_absl//absl/base:core_headers",
        "@com_google_absl//absl/container:flat_hash_map",
        "@com_google_absl//absl/container:flat_hash_set",
        "@com_google_absl//absl/flags:flag",
        "@com_google_absl//absl/strings",
        "@com_google_absl//absl/strings:str_format",
        "@com_google_absl//absl/synchronization",
        "@linux//:libbpf",
    ],
)

cc_binary(
    name = "agent_cfs",
    srcs = [
        "schedulers/cfs/cfs_agent.cc",
        "schedulers/cfs/cfs_scheduler.cc",
        "schedulers/cfs/cfs_scheduler.h",
    ],
    copts = compiler_flags,
    deps = [
        ":agent",
        ":base",
        ":shared",
        "@com_google_absl//absl/debugging:symbolize",
        "@com_google_absl//absl/flags:parse",
        "@com_google_absl//absl/strings",
        "@com_google_absl//absl/time",
    ],
)

cc_binary(
    name = "agent_exp",
    srcs = [
        "schedulers/edf/agent_exp.cc",
    ],
    copts = compiler_flags,
    deps = [
        ":agent",
        ":edf_scheduler",
        "@com_google_absl//absl/debugging:symbolize",
        "@com_google_absl//absl/flags:parse",
    ],
)

cc_library(
    name = "shinjuku_scheduler",
    srcs = [
        "schedulers/shinjuku/shinjuku_orchestrator.cc",
        "schedulers/shinjuku/shinjuku_scheduler.cc",
    ],
    hdrs = [
        "schedulers/shinjuku/shinjuku_orchestrator.h",
        "schedulers/shinjuku/shinjuku_scheduler.h",
    ],
    copts = compiler_flags,
    deps = [
        ":agent",
        ":ghost",
        ":shared",
        "@com_google_absl//absl/container:flat_hash_map",
        "@com_google_absl//absl/functional:bind_front",
        "@com_google_absl//absl/strings:str_format",
        "@com_google_absl//absl/time",
    ],
)

cc_binary(
    name = "agent_shinjuku",
    srcs = [
        "schedulers/shinjuku/agent_shinjuku.cc",
    ],
    copts = compiler_flags,
    visibility = ["//experiments/scripts:__pkg__"],
    deps = [
        ":agent",
        ":shinjuku_scheduler",
        "@com_google_absl//absl/debugging:symbolize",
        "@com_google_absl//absl/flags:parse",
    ],
)

cc_library(
    name = "sol_scheduler",
    srcs = [
        "schedulers/sol/sol_scheduler.cc",
    ],
    hdrs = [
        "schedulers/sol/sol_scheduler.h",
    ],
    copts = compiler_flags,
    deps = [
        ":agent",
        "@com_google_absl//absl/strings:str_format",
        "@com_google_absl//absl/time",
    ],
)

cc_binary(
    name = "agent_sol",
    srcs = [
        "schedulers/sol/agent_sol.cc",
    ],
    copts = compiler_flags,
    deps = [
        ":agent",
        ":sol_scheduler",
        "@com_google_absl//absl/debugging:symbolize",
        "@com_google_absl//absl/flags:parse",
    ],
)

cc_binary(
    name = "sol_test",
    srcs = [
        "tests/sol_test.cc",
    ],
    copts = compiler_flags,
    deps = [
        ":ghost",
        "@com_google_absl//absl/random",
        "@com_google_absl//absl/synchronization",
    ],
)

cc_binary(
    name = "simple_exp",
    srcs = [
        "tests/simple_exp.cc",
    ],
    copts = compiler_flags,
    deps = [
        ":base",
        ":ghost",
    ],
)

cc_binary(
    name = "simple_edf",
    srcs = [
        "tests/simple_edf.cc",
    ],
    copts = compiler_flags,
    deps = [
        ":ghost",
        ":shared",
        "@com_google_absl//absl/flags:parse",
    ],
)

cc_test(
    name = "agent_test",
    size = "small",
    srcs = [
        "tests/agent_test.cc",
    ],
    copts = compiler_flags,
    deps = [
        ":agent",
        "@com_google_absl//absl/container:flat_hash_map",
        "@com_google_absl//absl/random",
        "@com_google_googletest//:gtest_main",
    ],
)

cc_test(
    name = "api_test",
    size = "small",
    srcs = [
        "tests/api_test.cc",
    ],
    copts = compiler_flags,
    deps = [
        ":agent",
        ":fifo_per_cpu_scheduler",
        "@com_google_absl//absl/random",
        "@com_google_googletest//:gtest_main",
    ],
)

# Makes vmlinux_ghost_*.h files visible to eBPF code.
exports_files(glob(["kernel/vmlinux_ghost_*.h"]))

cc_library(
    name = "base",
    srcs = [
        "lib/base.cc",
    ],
    hdrs = [
        "kernel/ghost_uapi.h",
        "lib/base.h",
        "lib/logging.h",
        "//third_party:util/util.h",
    ],
    copts = compiler_flags,
    deps = [
        "@com_google_absl//absl/base",
        "@com_google_absl//absl/base:core_headers",
        "@com_google_absl//absl/container:flat_hash_map",
        "@com_google_absl//absl/container:node_hash_map",
        "@com_google_absl//absl/debugging:stacktrace",
        "@com_google_absl//absl/debugging:symbolize",
        "@com_google_absl//absl/memory",
        "@com_google_absl//absl/strings:str_format",
        "@com_google_absl//absl/time",
    ],
)

cc_test(
    name = "base_test",
    size = "small",
    srcs = [
        "tests/base_test.cc",
    ],
    copts = compiler_flags,
    deps = [
        ":base",
        "@com_google_absl//absl/synchronization",
        "@com_google_googletest//:gtest_main",
    ],
)

cc_binary(
    name = "agent_biff",
    srcs = [
        "schedulers/biff/agent_biff.cc",
    ],
    copts = compiler_flags,
    visibility = ["//experiments/scripts:__pkg__"],
    deps = [
        ":agent",
        ":biff_scheduler",
        "@com_google_absl//absl/debugging:symbolize",
        "@com_google_absl//absl/flags:parse",
    ],
)

bpf_skeleton(
    name = "biff_bpf_skel",
    bpf_object = "//third_party/bpf:biff_bpf",
    skel_hdr = "schedulers/biff/biff_bpf.skel.h",
)

cc_library(
    name = "biff_scheduler",
    srcs = [
        "schedulers/biff/biff_scheduler.cc",
    ],
    hdrs = [
        "schedulers/biff/biff_bpf.skel.h",
        "schedulers/biff/biff_scheduler.h",
        "//third_party/bpf:biff_bpf.h",
    ],
    copts = compiler_flags,
    deps = [
        ":agent",
        ":ghost",
        ":shared",
        "@com_google_absl//absl/container:flat_hash_map",
        "@com_google_absl//absl/functional:bind_front",
        "@com_google_absl//absl/strings:str_format",
        "@linux//:libbpf",
    ],
)

cc_test(
    name = "biff_test",
    size = "small",
    srcs = [
        "tests/biff_test.cc",
    ],
    copts = compiler_flags,
    deps = [
        ":biff_scheduler",
        "@com_google_googletest//:gtest",
    ],
)

cc_test(
    name = "capabilities_test",
    size = "small",
    srcs = [
        "tests/capabilities_test.cc",
    ],
    copts = compiler_flags,
    deps = [
        ":agent",
        ":capabilities_test_lib",
        ":ghost",
    ],
)

cc_library(
    name = "capabilities_test_lib",
    testonly = 1,
    hdrs = [
        "tests/capabilities_test.h",
    ],
    copts = compiler_flags,
    linkopts = ["-lcap"],
    deps = ["@com_google_googletest//:gtest_main"],
)

cc_test(
    name = "channel_test",
    size = "small",
    srcs = [
        "tests/channel_test.cc",
    ],
    copts = compiler_flags,
    deps = [
        ":agent",
        "@com_google_googletest//:gtest_main",
    ],
)

bpf_skeleton(
    name = "edf_bpf_skel",
    bpf_object = "//third_party/bpf:edf_bpf",
    skel_hdr = "schedulers/edf/edf_bpf.skel.h",
)

cc_library(
    name = "edf_scheduler",
    srcs = [
        "schedulers/edf/edf_scheduler.cc",
        "schedulers/edf/orchestrator.cc",
    ],
    hdrs = [
        "schedulers/edf/edf_bpf.skel.h",
        "schedulers/edf/edf_scheduler.h",
        "schedulers/edf/orchestrator.h",
        "//third_party/bpf:edf.h",
    ],
    copts = compiler_flags,
    deps = [
        ":agent",
        ":ghost",
        ":shared",
        "@com_google_absl//absl/container:flat_hash_map",
        "@com_google_absl//absl/functional:bind_front",
        "@com_google_absl//absl/strings:str_format",
        "@linux//:libbpf",
    ],
)

cc_test(
    name = "edf_test",
    size = "small",
    srcs = [
        "tests/edf_test.cc",
    ],
    copts = compiler_flags,
    deps = [
        ":edf_scheduler",
        "@com_google_googletest//:gtest",
    ],
)

cc_test(
    name = "enclave_test",
    size = "small",
    srcs = [
        "tests/enclave_test.cc",
    ],
    copts = compiler_flags,
    deps = [
        ":agent",
        ":fifo_centralized_scheduler",
        "@com_google_googletest//:gtest_main",
    ],
)

cc_binary(
    name = "fifo_per_cpu_agent",
    srcs = [
        "schedulers/fifo/per_cpu/fifo_agent.cc",
    ],
    copts = compiler_flags,
    deps = [
        ":agent",
        ":fifo_per_cpu_scheduler",
        "@com_google_absl//absl/debugging:symbolize",
        "@com_google_absl//absl/flags:parse",
    ],
)

cc_library(
    name = "fifo_per_cpu_scheduler",
    srcs = [
        "schedulers/fifo/per_cpu/fifo_scheduler.cc",
        "schedulers/fifo/per_cpu/fifo_scheduler.h",
    ],
    hdrs = [
        "schedulers/fifo/per_cpu/fifo_scheduler.h",
    ],
    copts = compiler_flags,
    deps = [
        ":agent",
    ],
)

cc_binary(
    name = "fifo_centralized_agent",
    srcs = [
        "schedulers/fifo/centralized/fifo_agent.cc",
    ],
    copts = compiler_flags,
    deps = [
        ":agent",
        ":fifo_centralized_scheduler",
        "@com_google_absl//absl/debugging:symbolize",
        "@com_google_absl//absl/flags:parse",
    ],
)

cc_library(
    name = "fifo_centralized_scheduler",
    srcs = [
        "schedulers/fifo/centralized/fifo_scheduler.cc",
        "schedulers/fifo/centralized/fifo_scheduler.h",
    ],
    hdrs = [
        "schedulers/fifo/centralized/fifo_scheduler.h",
    ],
    copts = compiler_flags,
    deps = [
        ":agent",
        "@com_google_absl//absl/strings:str_format",
        "@com_google_absl//absl/time",
    ],
)

cc_library(
    name = "ghost",
    srcs = [
        "lib/ghost.cc",
        "lib/topology.cc",
    ],
    hdrs = [
        "kernel/ghost_uapi.h",
        "lib/ghost.h",
        "lib/topology.h",
    ],
    copts = compiler_flags,
    linkopts = ["-lnuma"],
    deps = [
        ":base",
        "@com_google_absl//absl/container:flat_hash_map",
        "@com_google_absl//absl/container:flat_hash_set",
        "@com_google_absl//absl/flags:flag",
        "@com_google_absl//absl/strings:str_format",
    ],
)

cc_test(
    name = "prio_table_test",
    size = "small",
    srcs = [
        "tests/prio_table_test.cc",
    ],
    copts = compiler_flags,
    deps = [
        ":shared",
        "@com_google_googletest//:gtest_main",
    ],
)

cc_library(
    name = "shared",
    srcs = [
        "shared/prio_table.cc",
        "shared/shmem.cc",
    ],
    hdrs = [
        "shared/prio_table.h",
        "shared/shmem.h",
    ],
    copts = compiler_flags,
    deps = [
        ":base",
        "@com_google_absl//absl/strings",
    ],
)

cc_binary(
    name = "enclave_watcher",
    srcs = [
        "util/enclave_watcher.cc",
    ],
    copts = compiler_flags,
    deps = [
        ":agent",
        ":ghost",
        "@com_google_absl//absl/flags:parse",
    ],
)

cc_binary(
    name = "pushtosched",
    srcs = [
        "util/pushtosched.cc",
    ],
    copts = compiler_flags,
    deps = [
        ":base",
        "@com_google_absl//absl/strings",
        "@com_google_absl//absl/strings:str_format",
    ],
)

cc_test(
    name = "topology_test",
    size = "small",
    srcs = [
        "tests/topology_test.cc",
    ],
    copts = compiler_flags,
    deps = [
        ":agent",
        "@com_google_absl//absl/container:flat_hash_set",
        "@com_google_absl//absl/flags:flag",
        "@com_google_absl//absl/flags:parse",
        "@com_google_absl//absl/strings",
        "@com_google_googletest//:gtest",
    ],
)

bpf_skeleton(
    name = "schedclasstop_bpf_skel",
    bpf_object = "//third_party/bpf:schedclasstop_bpf",
    skel_hdr = "bpf/user/schedclasstop_bpf.skel.h",
)

cc_binary(
    name = "schedclasstop",
    srcs = [
        "bpf/user/schedclasstop.c",
        "bpf/user/schedclasstop_bpf.skel.h",
        "//third_party:iovisor_bcc/trace_helpers.h",
    ],
    copts = compiler_flags,
    linkopts = bpf_linkopts,
    deps = [
        "@linux//:libbpf",
    ],
)

bpf_skeleton(
    name = "schedfair_bpf_skel",
    bpf_object = "//third_party/bpf:schedfair_bpf",
    skel_hdr = "bpf/user/schedfair_bpf.skel.h",
)

cc_binary(
    name = "schedfair",
    srcs = [
        "bpf/user/schedfair.c",
        "bpf/user/schedfair_bpf.skel.h",
        "//third_party:iovisor_bcc/trace_helpers.h",
        "//third_party/bpf:schedfair.h",
    ],
    copts = compiler_flags,
    linkopts = bpf_linkopts,
    deps = [
        "@linux//:libbpf",
    ],
)

bpf_skeleton(
    name = "schedghostidle_bpf_skel",
    bpf_object = "//third_party/bpf:schedghostidle_bpf",
    skel_hdr = "bpf/user/schedghostidle_bpf.skel.h",
)

cc_binary(
    name = "schedghostidle",
    srcs = [
        "bpf/user/schedghostidle.c",
        "bpf/user/schedghostidle_bpf.skel.h",
        "//third_party:iovisor_bcc/trace_helpers.h",
    ],
    copts = compiler_flags,
    linkopts = bpf_linkopts,
    deps = [
        "@linux//:libbpf",
    ],
)

bpf_skeleton(
    name = "schedlat_bpf_skel",
    bpf_object = "//third_party/bpf:schedlat_bpf",
    skel_hdr = "bpf/user/schedlat_bpf.skel.h",
)

cc_binary(
    name = "schedlat",
    srcs = [
        "bpf/user/schedlat.c",
        "bpf/user/schedlat_bpf.skel.h",
        "//third_party:iovisor_bcc/trace_helpers.h",
        "//third_party/bpf:schedlat.h",
    ],
    copts = compiler_flags,
    linkopts = bpf_linkopts,
    deps = [
        "@linux//:libbpf",
    ],
)

bpf_skeleton(
    name = "schedrun_bpf_skel",
    bpf_object = "//third_party/bpf:schedrun_bpf",
    skel_hdr = "bpf/user/schedrun_bpf.skel.h",
)

cc_binary(
    name = "schedrun",
    srcs = [
        "bpf/user/schedrun.c",
        "bpf/user/schedrun_bpf.skel.h",
        "//third_party:iovisor_bcc/trace_helpers.h",
        "//third_party/bpf:schedrun.h",
    ],
    copts = compiler_flags,
    linkopts = bpf_linkopts,
    deps = [
        "@linux//:libbpf",
    ],
)

# Shared library for ghOSt tests.

cc_library(
    name = "experiments_shared",
    srcs = [
        "experiments/shared/prio_table_helper.cc",
        "experiments/shared/thread_pool.cc",
        "experiments/shared/thread_wait.cc",
    ],
    hdrs = [
        "experiments/shared/prio_table_helper.h",
        "experiments/shared/thread_pool.h",
        "experiments/shared/thread_wait.h",
    ],
    copts = compiler_flags,
    deps = [
        ":base",
        ":ghost",
        ":shared",
    ],
)

cc_test(
    name = "thread_pool_test",
    size = "small",
    srcs = [
        "experiments/shared/thread_pool.cc",
        "experiments/shared/thread_pool.h",
        "experiments/shared/thread_pool_test.cc",
    ],
    copts = compiler_flags,
    deps = [
        ":base",
        ":ghost",
        "@com_google_absl//absl/functional:bind_front",
        "@com_google_absl//absl/synchronization",
        "@com_google_googletest//:gtest_main",
    ],
)

# The RocksDB binary and tests.

cc_binary(
    name = "rocksdb",
    srcs = [
        "experiments/rocksdb/cfs_orchestrator.cc",
        "experiments/rocksdb/cfs_orchestrator.h",
        "experiments/rocksdb/clock.h",
        "experiments/rocksdb/database.cc",
        "experiments/rocksdb/database.h",
        "experiments/rocksdb/ghost_orchestrator.cc",
        "experiments/rocksdb/ghost_orchestrator.h",
        "experiments/rocksdb/ingress.cc",
        "experiments/rocksdb/ingress.h",
        "experiments/rocksdb/latency.cc",
        "experiments/rocksdb/latency.h",
        "experiments/rocksdb/main.cc",
        "experiments/rocksdb/orchestrator.cc",
        "experiments/rocksdb/orchestrator.h",
        "experiments/rocksdb/request.h",
    ],
    copts = compiler_flags,
    visibility = ["//experiments/scripts:__pkg__"],
    deps = [
        ":base",
        ":experiments_shared",
        "@com_google_absl//absl/flags:parse",
        "@com_google_absl//absl/functional:bind_front",
        "@com_google_absl//absl/random",
        "@com_google_absl//absl/random:bit_gen_ref",
        "@com_google_absl//absl/synchronization",
        "@com_google_absl//absl/time",
        "@rocksdb",
    ],
)

cc_test(
    name = "latency_test",
    size = "small",
    srcs = [
        "experiments/rocksdb/latency.cc",
        "experiments/rocksdb/latency.h",
        "experiments/rocksdb/latency_test.cc",
        "experiments/rocksdb/request.h",
    ],
    copts = compiler_flags,
    deps = [
        ":base",
        "@com_google_absl//absl/random",
        "@com_google_absl//absl/time",
        "@com_google_googletest//:gtest_main",
    ],
)

cc_test(
    name = "rocksdb_options_test",
    size = "small",
    srcs = [
        "experiments/rocksdb/cfs_orchestrator.cc",
        "experiments/rocksdb/cfs_orchestrator.h",
        "experiments/rocksdb/clock.h",
        "experiments/rocksdb/database.cc",
        "experiments/rocksdb/database.h",
        "experiments/rocksdb/ghost_orchestrator.cc",
        "experiments/rocksdb/ghost_orchestrator.h",
        "experiments/rocksdb/ingress.cc",
        "experiments/rocksdb/ingress.h",
        "experiments/rocksdb/latency.cc",
        "experiments/rocksdb/latency.h",
        "experiments/rocksdb/options_test.cc",
        "experiments/rocksdb/orchestrator.cc",
        "experiments/rocksdb/orchestrator.h",
        "experiments/rocksdb/request.h",
    ],
    copts = compiler_flags,
    deps = [
        ":base",
        ":experiments_shared",
        "@com_google_absl//absl/functional:bind_front",
        "@com_google_absl//absl/random",
        "@com_google_absl//absl/random:bit_gen_ref",
        "@com_google_absl//absl/synchronization",
        "@com_google_absl//absl/time",
        "@com_google_googletest//:gtest_main",
        "@rocksdb",
    ],
)

cc_test(
    name = "rocksdb_orchestrator_test",
    size = "small",
    srcs = [
        "experiments/rocksdb/cfs_orchestrator.cc",
        "experiments/rocksdb/cfs_orchestrator.h",
        "experiments/rocksdb/clock.h",
        "experiments/rocksdb/database.cc",
        "experiments/rocksdb/database.h",
        "experiments/rocksdb/ghost_orchestrator.cc",
        "experiments/rocksdb/ghost_orchestrator.h",
        "experiments/rocksdb/ingress.cc",
        "experiments/rocksdb/ingress.h",
        "experiments/rocksdb/latency.cc",
        "experiments/rocksdb/latency.h",
        "experiments/rocksdb/orchestrator.cc",
        "experiments/rocksdb/orchestrator.h",
        "experiments/rocksdb/orchestrator_test.cc",
        "experiments/rocksdb/request.h",
    ],
    copts = compiler_flags,
    deps = [
        ":base",
        ":experiments_shared",
        "@com_google_absl//absl/functional:bind_front",
        "@com_google_absl//absl/random",
        "@com_google_absl//absl/random:bit_gen_ref",
        "@com_google_absl//absl/synchronization",
        "@com_google_absl//absl/time",
        "@com_google_googletest//:gtest_main",
        "@rocksdb",
    ],
)

cc_test(
    name = "database_test",
    size = "small",
    srcs = [
        "experiments/rocksdb/database.cc",
        "experiments/rocksdb/database.h",
        "experiments/rocksdb/database_test.cc",
    ],
    copts = compiler_flags,
    deps = [
        ":base",
        "@com_google_absl//absl/flags:flag",
        "@com_google_absl//absl/flags:parse",
        "@com_google_googletest//:gtest",
        "@rocksdb",
    ],
)

cc_test(
    name = "synthetic_network_test",
    size = "medium",
    srcs = [
        "experiments/rocksdb/clock.h",
        "experiments/rocksdb/database.h",
        "experiments/rocksdb/ingress.cc",
        "experiments/rocksdb/ingress.h",
        "experiments/rocksdb/request.h",
        "experiments/rocksdb/synthetic_network_test.cc",
    ],
    copts = compiler_flags,
    deps = [
        ":base",
        "@com_google_absl//absl/random",
        "@com_google_absl//absl/random:bit_gen_ref",
        "@com_google_absl//absl/time",
        "@com_google_googletest//:gtest_main",
        "@rocksdb",
    ],
)

# The Antagonist binary and tests.

cc_binary(
    name = "antagonist",
    srcs = [
        "experiments/antagonist/cfs_orchestrator.cc",
        "experiments/antagonist/cfs_orchestrator.h",
        "experiments/antagonist/ghost_orchestrator.cc",
        "experiments/antagonist/ghost_orchestrator.h",
        "experiments/antagonist/main.cc",
        "experiments/antagonist/orchestrator.cc",
        "experiments/antagonist/orchestrator.h",
        "experiments/antagonist/results.cc",
        "experiments/antagonist/results.h",
    ],
    copts = compiler_flags,
    visibility = ["//experiments/scripts:__pkg__"],
    deps = [
        ":base",
        ":experiments_shared",
        "@com_google_absl//absl/flags:flag",
        "@com_google_absl//absl/flags:parse",
        "@com_google_absl//absl/functional:bind_front",
        "@com_google_absl//absl/synchronization",
        "@com_google_absl//absl/time",
    ],
)

cc_test(
    name = "antagonist_options_test",
    size = "small",
    srcs = [
        "experiments/antagonist/options_test.cc",
        "experiments/antagonist/orchestrator.cc",
        "experiments/antagonist/orchestrator.h",
        "experiments/antagonist/results.cc",
        "experiments/antagonist/results.h",
    ],
    copts = compiler_flags,
    deps = [
        ":base",
        ":experiments_shared",
        "@com_google_absl//absl/time",
        "@com_google_googletest//:gtest_main",
    ],
)

cc_test(
    name = "antagonist_orchestrator_test",
    size = "small",
    srcs = [
        "experiments/antagonist/orchestrator.cc",
        "experiments/antagonist/orchestrator.h",
        "experiments/antagonist/orchestrator_test.cc",
        "experiments/antagonist/results.cc",
        "experiments/antagonist/results.h",
    ],
    copts = compiler_flags,
    deps = [
        ":base",
        ":experiments_shared",
        "@com_google_absl//absl/functional:bind_front",
        "@com_google_absl//absl/time",
        "@com_google_googletest//:gtest_main",
    ],
)

cc_test(
    name = "results_test",
    size = "small",
    srcs = [
        "experiments/antagonist/results.cc",
        "experiments/antagonist/results.h",
        "experiments/antagonist/results_test.cc",
    ],
    copts = compiler_flags,
    deps = [
        ":base",
        "@com_google_absl//absl/strings",
        "@com_google_absl//absl/time",
        "@com_google_googletest//:gtest_main",
    ],
)

cc_binary(
    name = "global_scalability",
    srcs = [
        "experiments/microbenchmarks/global_scalability.cc",
    ],
    copts = compiler_flags,
    deps = [
        ":edf_scheduler",
        ":shinjuku_scheduler",
        ":sol_scheduler",
        "@com_google_absl//absl/flags:parse",
        "@com_google_absl//absl/flags:usage",
    ],
)

cc_test(
    name = "ioctl_test",
    size = "small",
    srcs = ["experiments/microbenchmarks/ioctl_test.cc"],
    copts = compiler_flags,
    deps = [
        ":agent",
        ":ghost",
        "@com_google_benchmark//:benchmark",
        "@com_google_googletest//:gtest",
    ],
)
