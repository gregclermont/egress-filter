# TODO

## Done

- [x] DNS PID tracking via kprobe/udp_sendmsg (cgroup hooks don't fire for loopback)
- [x] Add comprehensive tests to workflow for all combinations

## Next Steps

- [ ] Fix edge cases identified by comprehensive tests (see `tests/test_pid_tracking.sh` results)
- [ ] Handle non-DNS UDP traffic PID tracking
