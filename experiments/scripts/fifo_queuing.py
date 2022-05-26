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
Runs the RocksDB FIFO centralized-queuing experiments.

This script runs the FIFO centralized and FIFO per core queueing with RocksDB
ghOSt. In these experiments, there is a centralized queue maintained for
RocksDB requests and the requests are not reordered or preempted. This script
should be run on a machine with an Intel Xeon Platinum 8173M as that is what we
used in the paper. If another CPU is used, the throughput ranges below should
be adjusted.  
"""

from typing import Sequence
from absl import app
from experiments.scripts.options import CheckSchedulers
from experiments.scripts.options import GetGhostOptions
from experiments.scripts.options import GetRocksDBOptions
from experiments.scripts.options import Scheduler
from experiments.scripts.options import Policy
from experiments.scripts.options import GhostWaitType
from experiments.scripts.run import Experiment
from experiments.scripts.run import Run

_NUM_CPUS = 18
_NUM_CFS_WORKERS = _NUM_CPUS - 2
_NUM_GHOST_WORKERS = 18 


def RunGhostFIFOPerCore():
  """Runs the ghOSt experiment."""
  e: Experiment = Experiment()
  # Run throughputs 10000, 20000, 30000, ..., 420000.
  # e.throughputs = list(i for i in range(10000, 421000, 10000))
  # Toward the end, run throughputs 430000, 431000, 432000, ..., 460000.
  # e.throughputs.extend(list(i for i in range(430000, 461000, 1000)))
  e.throughputs = [700000]
  e.rocksdb = GetRocksDBOptions(Scheduler.GHOST, _NUM_CPUS, _NUM_GHOST_WORKERS)
  e.rocksdb.get_exponential_mean = '1us'
  e.rocksdb.ghost_wait_type = GhostWaitType.FUTEX
  e.antagonist = None
  e.ghost = GetGhostOptions(_NUM_CPUS)
  e.ghost.policy = Policy.FIFO_PER_CORE

  Run(e)

def RunGhostFIFOCentralized():
  """Runs the ghOSt experiment."""
  e: Experiment = Experiment()
  # Run throughputs 10000, 20000, 30000, ..., 420000.
  # e.throughputs = list(i for i in range(10000, 421000, 10000))
  # Toward the end, run throughputs 430000, 431000, 432000, ..., 460000.
  # e.throughputs.extend(list(i for i in range(430000, 461000, 1000)))
  e.throughputs = [700000]
  e.rocksdb = GetRocksDBOptions(Scheduler.GHOST, _NUM_CPUS, _NUM_GHOST_WORKERS)
  e.rocksdb.get_exponential_mean = '1us'
  e.rocksdb.ghost_wait_type = GhostWaitType.FUTEX
  e.antagonist = None
  e.ghost = GetGhostOptions(_NUM_CPUS)
  e.ghost.policy = Policy.FIFO_CENTRALIZED

  Run(e)

def main(argv: Sequence[str]):
  if len(argv) > 4:
    raise app.UsageError('Too many command-line arguments.')
  elif len(argv) == 2:
    raise app.UsageError(
        'No experiment specified. Pass `ghost` for the scheduler and\
        `fifo-centralized` and/or `fifo-per-core` for the ghost policy as\
        arguments')

  # Run the experiments.
  for i in range(1, len(argv), 2):
    scheduler = Scheduler(argv[i])

    # get the policy
    policy = Policy(argv[i+1])

    # check the schedulers/
    if scheduler != Scheduler.GHOST:
      raise ValueError(f'Unknown scheduler {scheduler}.')

    # It is a ghost scheduler
    # check the policies.
    if policy == Policy.FIFO_CENTRALIZED:
      RunGhostFIFOCentralized()
    # check the policies.
    elif policy == Policy.FIFO_PER_CORE:
      RunGhostFIFOPerCore()
    else:
      raise ValueError(f'Unknown policy {policy}.')



if __name__ == '__main__':
  app.run(main)
