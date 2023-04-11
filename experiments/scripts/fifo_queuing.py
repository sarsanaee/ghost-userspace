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
Runs the RocksDB Fifo centralized and per core queuing experiments.

This script runs the Fifo centralized and Fifo per core queueing with RocksDB
ghOSt. In these experiments, there is a centralized queue maintained for
RocksDB requests and the requests are not reordered or preempted. 
"""

from typing import Sequence
from absl import app
from experiments.scripts.options import CheckSchedulers
from experiments.scripts.options import GetGhostOptions
from experiments.scripts.options import GetRocksDBOptions
from experiments.scripts.options import Scheduler
from experiments.scripts.options import GhostWaitType
from experiments.scripts.run import Experiment
from experiments.scripts.run import Run

_NUM_CPUS = 3
_NUM_CFS_WORKERS = _NUM_CPUS - 2
_NUM_GHOST_WORKERS = 200 


def RunGhostFifoPerCore():
  """Runs the ghOSt experiment."""
  e: Experiment = Experiment()
  # Run throughputs 10000, 20000, 30000, ..., 420000.
  e.throughputs = list(i for i in range(10000, 421000, 10000))
  # Toward the end, run throughputs 430000, 431000, 432000, ..., 460000.
  e.throughputs.extend(list(i for i in range(430000, 461000, 1000)))
  e.rocksdb = GetRocksDBOptions(Scheduler.GHOST, _NUM_CPUS, _NUM_GHOST_WORKERS)
  e.throughputs = [80000] # added
  e.throughputs = list(i for i in range(10000, 100001, 10000))
  # e.throughputs = [50000] # added
  # e.throughputs = [25000] # added
  e.throughputs = [20000,40000,60000] # added
  e.throughputs = [20000] # added
  e.rocksdb.get_exponential_mean = '0us'
  e.rocksdb.get_duration = '0.5us'
  # Fifo per core scheduler does not need PRIO_TABLE and relies on FUTEX.
  e.rocksdb.ghost_wait_type = GhostWaitType.FUTEX
  e.antagonist = None
  e.ghost = GetGhostOptions(_NUM_CPUS)
  e.fifo_per_core = True

  Run(e)

def RunGhostFifoCentralized():
  """Runs the ghOSt experiment."""
  e: Experiment = Experiment()
  # Run throughputs 10000, 20000, 30000, ..., 420000.
  e.throughputs = list(i for i in range(10000, 421000, 10000))
  # Toward the end, run throughputs 430000, 431000, 432000, ..., 460000.
  e.throughputs.extend(list(i for i in range(430000, 461000, 1000)))
  e.throughputs = [50000] # added
  e.throughputs = list(i for i in range(10000, 100001, 10000))
  e.throughputs = [20000,40000,60000] # added
  e.throughputs = [30000] # added
  e.rocksdb = GetRocksDBOptions(Scheduler.GHOST, _NUM_CPUS, _NUM_GHOST_WORKERS)
  e.rocksdb.get_exponential_mean = '0us'
  e.rocksdb.get_duration = '0.5us'
  # Fifo centralized scheduler does not need PRIO_TABLE and relies on FUTEX.
  e.rocksdb.ghost_wait_type = GhostWaitType.FUTEX
  e.antagonist = None
  e.ghost = GetGhostOptions(_NUM_CPUS)
  e.fifo_centralized = True

  Run(e)

def main(argv: Sequence[str]):
  if len(argv) > 4:
    raise app.UsageError('Too many command-line arguments.')
  elif len(argv) == 2:
    # We do not need ghost parameter in this particular code, because we just
    # have fifo. However, I just put ghost parameter in case we wanted to add
    # CFS in this script as well.
    raise app.UsageError(
        'No experiment specified. Pass `ghost` for the scheduler and\
        `fifo-centralized` and/or `fifo-per-core` for the ghost policy as\
        arguments')

  # Run the experiments.
  for i in range(1, len(argv), 2):
    scheduler = Scheduler(argv[i])

    # get the policy
    policy = argv[i+1]

    # check the schedulers/
    if scheduler != Scheduler.GHOST:
      raise ValueError(f'Unknown scheduler {scheduler}.')

    # It is a ghost scheduler, let's check the policies.
    if policy == "fifo-centralized":
      RunGhostFifoCentralized()
    # check the policies.
    elif policy == "fifo-per-core":
      RunGhostFifoPerCore()
    else:
      raise ValueError(f'Unknown policy {policy}.')



if __name__ == '__main__':
  app.run(main)
