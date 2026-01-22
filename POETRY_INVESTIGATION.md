# Poetry + Transparent Proxy Investigation

## Summary
Poetry 2.3.1 fails to connect to pypi.org through the transparent mitmproxy, while all other clients and manual tests succeed.

## What Works
- Raw Python `requests.get()` ✅
- pip package downloads ✅
- Raw requests from Poetry venv ✅
- CacheControlAdapter + FileCache ✅
- Prepared requests + session.send() ✅
- Multiple rapid requests (same session) ✅
- New session per request (Test 5) ✅
- pool_maxsize=10 configuration ✅

## What Fails
- `poetry install` ❌

## Key Findings

### 1. Response Hook Never Called for Poetry
- For working clients (pip, raw requests): `response()` hook is called after `request()` hook
- For Poetry: `response()` hook is NEVER called
- Poetry's client disconnects ~6-20ms after sending the request, before the response arrives

### 2. mitmproxy Internal Logs Show Fast Disconnect
```
21:12:22,845 client connect
21:12:22,851 server connect 151.101.192.223:443
21:12:22,861 request() hook called (our addon)
21:12:22,867 client disconnect (only 6ms after request hook!)
```

### 3. Same Venv Works
- Raw `requests.get()` from the same Poetry venv WORKS
- This rules out CA certificate issues, SSL/TLS config, venv-specific issues

### 4. Content-Length vs Body Size is NOT the Issue
- `raw_content` length matches Content-Length header
- mitmproxy is correctly forwarding compressed content

### 5. Poetry's HTTP Pattern is Reproduced Successfully
Our test script reproduces Poetry's exact HTTP pattern:
- CacheControlAdapter with FileCache
- pool_maxsize=10
- session.prepare_request() + session.send()
- merge_environment_settings() with verify=True
- JSON Accept header
- Same User-Agent
- New session per retry

All tests pass, but actual Poetry fails.

## Theories

### Theory 1: Threading/Multiprocessing Issue
Poetry might be making requests from a different thread or process that doesn't inherit the environment properly, or there's a race condition.

### Theory 2: Hidden Poetry Configuration
Poetry might have some internal configuration or certificate handling that differs from the standard requests library behavior.

### Theory 3: Poetry's Authenticator Session Cache
Poetry caches sessions per netloc. When a connection fails, it might be reusing a "poisoned" session state.

### Theory 4: Signal Handling or Async Issues
Poetry uses asyncio internally. The transparent proxy might be interfering with some async mechanism.

## What's NOT the Issue
- ❌ CA Certificate (REQUESTS_CA_BUNDLE is correctly set and used)
- ❌ Content-Length mismatch (raw bytes match header)
- ❌ CacheControlAdapter configuration
- ❌ pool_maxsize setting
- ❌ Prepared request pattern
- ❌ FileCache
- ❌ JSON Accept header
- ❌ User-Agent string

## Next Steps to Investigate
1. Check if Poetry spawns subprocesses that don't inherit environment
2. Add strace/ltrace to see what Poetry is doing at the syscall level
3. Try instrumenting Poetry's authenticator.py directly
4. Check if Poetry uses `certifi` package and ignores REQUESTS_CA_BUNDLE
5. Test if disabling Poetry's cache changes behavior

## Relevant Files
- `.tmp/poetry/src/poetry/utils/authenticator.py` - Poetry's HTTP client
- `src/proxy/main.py` - Our mitmproxy addon
- `.github/workflows/test-sfw-free.yml` - Test workflow

## Environment
- Poetry version: 2.3.1
- Python: 3.12.3
- Ubuntu: 24.04
- mitmproxy: via transparent mode + iptables REDIRECT
