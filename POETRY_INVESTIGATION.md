# Poetry + Transparent Proxy Investigation

## Summary - RESOLVED ✅

Poetry 2.3.1 now works correctly through the transparent mitmproxy.

**Root Cause**: Cache directory permissions issue, NOT a network/proxy problem.

**Solution**: Set `POETRY_CACHE_DIR` to a writable location before running Poetry:
```bash
export POETRY_CACHE_DIR=/tmp/poetry-cache
poetry lock -v
```

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
The `/home/runner/.cache` directory was not writable. This caused Poetry's internal cache system to fail, which manifested as apparent network failures.

When Poetry's cache failed to write, it would:
1. Receive the HTTP response successfully
2. Fail to cache the response
3. Consider the request failed
4. Retry (creating a new connection)
5. Repeat until exhausting retries

### The Fix
Simply set `POETRY_CACHE_DIR` to a writable location:
```bash
export POETRY_CACHE_DIR=/tmp/poetry-cache
```

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
3. **Environment matters**: GitHub Actions runners have specific permission constraints on ~/.cache

## Relevant Files
- `.github/workflows/test-sfw-free.yml` - Test workflow with the fix
- `src/proxy/main.py` - mitmproxy addon (works correctly)

## Environment
- Poetry version: 2.3.1
- Python: 3.12.3
- Ubuntu: 24.04
- mitmproxy: via transparent mode + iptables REDIRECT
