# TODO

## Next Steps

- [ ] DNS PID tracking: queries are logged but `pid=?` because BPF tracks sendmsg to 127.0.0.53, not the redirected port. Need to track original dest or use different approach.
- [ ] Do something about non-DNS UDP traffic
