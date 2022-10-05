# Copyright 2021 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""
Runs the RocksDB BPF centralized-queuing experiments.

This script runs the centralized-queuing RocksDB experiments on BPF ghOSt
. In these experiments, there is a centralized queue maintained for RocksDB
requests and the requests are not reordered or preempted. 
"""

from typing import Sequence
from absl import app
from experiments.scripts.options import CheckSchedulers
from experiments.scripts.options import GetGhostOptions
from experiments.scripts.options import GetRocksDBOptions
from experiments.scripts.options import Scheduler
from experiments.scripts.run import Experiment
from experiments.scripts.options import GhostWaitType
from experiments.scripts.options import CfsWaitType
from experiments.scripts.run import Run

_NUM_CPUS = 10
_NUM_CFS_WORKERS = _NUM_CPUS - 2
_NUM_GHOST_WORKERS = 200 
_NUM_CPU_RANGE_LIST = [4, 8, 16, 32, 48]


def RunGhost(bpf = False):
  """Runs the ghOSt experiment."""
  e: Experiment = Experiment()
  # Run throughputs 10000, 20000, 30000, ..., 420000.
  # e.throughputs = list(i for i in range(10000, 421000, 10000))
  e.throughputs = list(i for i in range(10000, 300000, 10000))
  # Toward the end, run throughputs 430000, 431000, 432000, ..., 460000.
  # e.throughputs.extend(list(i for i in range(430000, 461000, 1000)))
  e.rocksdb = GetRocksDBOptions(Scheduler.GHOST, _NUM_CPUS, _NUM_GHOST_WORKERS)
  e.rocksdb.get_exponential_mean = '1us'
  # We are using shinjuku as the ghost scheduler here
  e.rocksdb.ghost_wait_type = GhostWaitType.FUTEX if bpf else GhostWaitType.PRIO_TABLE
  e.antagonist = None

  # Enabling/Disabling BPF ghost agent
  e.bpf = bpf

  # Ghost BPF does not accept any parameters from the user at this point
  # However, the number of ghost threads is set here!
  e.ghost = GetGhostOptions(_NUM_CPUS)

  # There is no time-based preemption for centralized queuing, so set the
  # preemption time slice to infinity.
  e.ghost.preemption_time_slice = 'inf'

  Run(e)

  print(_NUM_CPUS)

def main(argv: Sequence[str]):
  global _NUM_CPUS

  if len(argv) > 2:
    raise app.UsageError('Too many command-line arguments.')
  elif len(argv) == 1:
    raise app.UsageError(
        'No experiment specified. Pass `ghost_bpf` as arguments.')

  # First check that all of the command line arguments are valid.
  if not CheckSchedulers(argv[1:]):
    raise ValueError('Invalid scheduler specified.')

  # Run the experiments.
  for i in range(1, len(argv)):
    scheduler = Scheduler(argv[i])
    if scheduler == Scheduler.GHOST_BPF:
      for i in _NUM_CPU_RANGE_LIST:
        _NUM_CPUS = i
        RunGhost(True)
    else:
      raise ValueError(f'Unknown scheduler {scheduler}.')


if __name__ == '__main__':
  app.run(main)
