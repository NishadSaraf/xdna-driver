// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026, Advanced Micro Devices, Inc. All rights reserved.

#ifndef XDNA_SHIM_PROF_H
#define XDNA_SHIM_PROF_H

// Lightweight command-lifecycle profiler for the xdna shim.
//
// Records CLOCK_MONOTONIC timestamps at the shim stages of a command's
// lifecycle so they can be correlated offline with the kernel driver's
// ftrace "prof" markers (trace_amdxdna_debug_point). CLOCK_MONOTONIC and the
// kernel's ktime_get_ns() share a clock base, so set the kernel trace clock to
// "mono" (echo mono > /sys/kernel/tracing/trace_clock) before capturing.
//
// Disabled unless the environment variable XDNA_PROF is set. Output is appended
// to $XDNA_PROF_LOG (default /tmp/xdna_prof.log), one record per line:
//   PROF <stage> seq=<seq> handle=<cmd_bo_handle> t=<mono_ns> tid=<tid>
//
// Correlation keys: the command BO handle bridges the pre-seq stages (kernel
// tags "exec_ioctl_enter" with the handle), and seq keys everything from
// submission onward.

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <ctime>
#include <mutex>
#include <sys/syscall.h>
#include <unistd.h>

namespace shim_xdna::prof {

inline uint64_t
now_ns()
{
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return static_cast<uint64_t>(ts.tv_sec) * 1000000000ULL +
         static_cast<uint64_t>(ts.tv_nsec);
}

inline bool
enabled()
{
  static const bool on = (std::getenv("XDNA_PROF") != nullptr);
  return on;
}

// Record one lifecycle stamp. seq or handle may be 0 when not yet known.
inline void
stamp(const char *stage, uint64_t seq, uint64_t handle)
{
  if (!enabled())
    return;

  static std::mutex mtx;
  static FILE *fp = [] {
    const char *p = std::getenv("XDNA_PROF_LOG");
    return std::fopen(p ? p : "/tmp/xdna_prof.log", "a");
  }();
  if (!fp)
    return;

  uint64_t t = now_ns();
  long tid = static_cast<long>(syscall(SYS_gettid));

  std::lock_guard<std::mutex> lk(mtx);
  std::fprintf(fp, "PROF %s seq=%llu handle=%llu t=%llu tid=%ld\n", stage,
               static_cast<unsigned long long>(seq),
               static_cast<unsigned long long>(handle),
               static_cast<unsigned long long>(t), tid);
  std::fflush(fp);
}

} // namespace shim_xdna::prof

#endif // XDNA_SHIM_PROF_H
