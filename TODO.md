# TODO

## Done

- [x] DNS PID tracking via kprobe/udp_sendmsg (cgroup hooks don't fire for loopback)
- [x] Add comprehensive tests to workflow for all combinations

## Next Steps

- [ ] DNS to external (e.g. 8.8.8.8) logs `pid=?` - kprobe only handles loopback UDP
- [ ] HTTP via direct proxy - loopback connection to proxy, no BPF hook fires
- [ ] Consider removing IPv6 code (untested, GitHub runners lack IPv6)
- [ ] Handle non-DNS UDP traffic PID tracking
