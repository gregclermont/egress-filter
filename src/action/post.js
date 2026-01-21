const cache = require('@actions/cache');
const core = require('@actions/core');
const exec = require('@actions/exec');
const fs = require('fs');
const path = require('path');

// Compute action root at runtime (2 levels up from dist/post/)
const getActionPath = () => [__dirname, '..', '..'].reduce((a, b) => path.resolve(a, b));

async function saveVenvCache(actionPath) {
  const cacheKey = core.getState('cache-key');
  const matchedKey = core.getState('cache-matched-key');

  if (!cacheKey) {
    core.info('No cache key found, skipping cache save');
    return;
  }

  // Don't save if we had an exact cache hit
  if (matchedKey === cacheKey) {
    core.info(`Cache hit on key ${cacheKey}, skipping save`);
    return;
  }

  const venvPath = path.join(actionPath, '.venv');
  if (!fs.existsSync(venvPath)) {
    core.info('.venv does not exist, skipping cache save');
    return;
  }

  core.info(`Saving cache with key: ${cacheKey}`);
  try {
    await cache.saveCache([venvPath], cacheKey);
    core.info('Cache saved successfully');
  } catch (error) {
    // Don't fail the action on cache errors
    if (error.name === 'ReserveCacheError') {
      core.info('Cache already exists, skipping');
    } else {
      core.warning(`Cache save failed: ${error.message}`);
    }
  }
}

async function run() {
  const actionPath = getActionPath();
  const scriptsDir = path.join(actionPath, 'scripts');
  const env = { ...process.env, EGRESS_FILTER_ROOT: actionPath };

  // IMPORTANT: Clean iptables FIRST, before stopping proxy
  // Otherwise traffic is still redirected to port 8080 after proxy dies,
  // which breaks runner communication with GitHub (jobs appear stuck)
  core.info('Cleaning up iptables...');
  await exec.exec('sudo', ['-E', path.join(scriptsDir, 'iptables.sh'), 'cleanup'], {
    ignoreReturnCode: true,
    env
  });

  core.info('Stopping proxy...');
  await exec.exec('sudo', ['-E', path.join(scriptsDir, 'setup-proxy.sh'), 'stop'], {
    ignoreReturnCode: true,
    env
  });

  // Save cache after cleanup
  await saveVenvCache(actionPath);

  core.info('Egress filter cleanup complete');

  // Exit explicitly to avoid hanging on unresolved promises
  process.exit(0);
}

run();
