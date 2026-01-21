const cache = require('@actions/cache');
const core = require('@actions/core');
const exec = require('@actions/exec');
const fs = require('fs');
const path = require('path');

// Compute action root at runtime (2 levels up from dist/post/)
// Use array join to prevent ncc from transforming the path
const getActionPath = () => [__dirname, '..', '..'].reduce((a, b) => path.resolve(a, b));

async function saveVenvCache(actionPath) {
  const cacheHit = core.getState('cache-hit');
  const cacheKey = core.getState('cache-key');

  if (!cacheKey) {
    core.info('No cache key found, skipping cache save');
    return;
  }

  if (cacheHit === 'true') {
    core.info(`Cache hit on key ${cacheKey}, skipping save`);
    return;
  }

  const venvPath = path.join(actionPath, '.venv');
  if (!fs.existsSync(venvPath)) {
    core.info('.venv does not exist, skipping cache save');
    return;
  }

  core.info(`Saving .venv cache with key: ${cacheKey}`);
  try {
    await cache.saveCache([venvPath], cacheKey);
    core.info('Cache saved successfully');
  } catch (error) {
    // Cache save can fail if the key already exists (race condition)
    if (error.message.includes('already exists')) {
      core.info('Cache already exists, skipping');
    } else {
      core.warning(`Cache save failed: ${error.message}`);
    }
  }
}

async function run() {
  const actionPath = getActionPath();
  const scriptsDir = actionPath + path.sep + 'scripts';
  const env = { ...process.env, EGRESS_FILTER_ROOT: actionPath };

  // IMPORTANT: Clean iptables FIRST, before stopping proxy
  // Otherwise traffic is still redirected to port 8080 after proxy dies,
  // which breaks runner communication with GitHub (jobs appear stuck)
  core.info('Cleaning up iptables...');
  await exec.exec('sudo', ['-E', scriptsDir + path.sep + 'iptables.sh', 'cleanup'], {
    ignoreReturnCode: true,
    env
  });

  core.info('Stopping proxy...');
  await exec.exec('sudo', ['-E', scriptsDir + path.sep + 'setup-proxy.sh', 'stop'], {
    ignoreReturnCode: true,
    env
  });

  // Save cache after cleanup (proxy owns .venv files as root)
  await saveVenvCache(actionPath);

  core.info('Egress filter cleanup complete');
}

run();
