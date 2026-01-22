# Poetry + Transparent Proxy Investigation

## Summary - RESOLVED ✅

Poetry 2.3.1 now works correctly through the transparent mitmproxy.

**Root Cause**: Cache directory permissions issue, NOT a network/proxy problem.

**Root Fix**: The action's `sudo -E` preserved `HOME=/home/runner`, causing root processes (uv, mitmproxy) to create root-owned directories in `/home/runner/.cache`. Fixed by using a controlled environment that excludes HOME, so root processes use `/root/` instead.

## Timeline

### Initial Symptoms
- Poetry failed with "All attempts to connect to pypi.org failed"
- Raw Python `requests.get()` from same venv worked fine
- pip package downloads worked fine
- Proxy logs showed 200 OK responses being sent to Poetry

### Investigation Findings
1. **Proxy was working correctly**: HTTP responses (200 OK) were successfully sent
2. **Poetry was disconnecting early**: Client disconnect happened ~3ms after response started
3. **Same venv's raw requests worked**: Ruled out CA cert, SSL, venv-specific issues
4. **Manual Poetry-style tests passed**: CacheControlAdapter + FileCache + session.send() all worked

### The Real Issue
The `/home/runner/.cache` directory was owned by root, not the runner user. This happened because our action used `sudo -E` which preserved `HOME=/home/runner`. When uv and mitmproxy ran as root, they created directories in `/home/runner/.cache` owned by root.

When Poetry tried to use its cache, the permissions failure manifested as apparent network failures:
1. Receive the HTTP response successfully
2. Fail to write to cache (permission denied)
3. Consider the request failed
4. Retry (creating a new connection)
5. Repeat until exhausting retries

### The Fix
Changed from `sudo -E` to `sudo env VAR=value ...` with a controlled set of environment variables that **excludes HOME**:
- Root processes now use `/root/` for caches (uv → `/root/.local/bin`, mitmproxy → `/root/.mitmproxy`)
- `/home/runner/.cache` stays runner-owned
- No workarounds needed (POETRY_CACHE_DIR, chown, etc.)

## What Now Works
- Raw Python `requests.get()` ✅
- pip package downloads ✅
- Raw requests from Poetry venv ✅
- CacheControlAdapter + FileCache ✅
- **Poetry lock ✅**
- **Poetry install ✅**

## Lessons Learned

1. **Misleading error messages**: "All attempts to connect failed" was actually a cache write failure
2. **Symptom vs. cause**: The fast client disconnect wasn't a network issue - it was Poetry aborting after a cache failure
3. **Environment matters**: `sudo -E` is dangerous - it passes HOME which causes root to create files in the user's home directory
4. **Controlled environments**: Use explicit `sudo env VAR=value` instead of `sudo -E` to control exactly what gets passed

## Relevant Files
- `src/action/pre.js` - Uses controlled sudo environment
- `src/action/post.js` - Uses controlled sudo environment
- `src/setup/proxy.sh` - Uses explicit `/root/` paths
- `.github/workflows/test-sfw-free.yml` - Test workflow

## Environment
- Poetry version: 2.3.1
- Python: 3.12.3
- Ubuntu: 24.04
- mitmproxy: via transparent mode + iptables REDIRECT
