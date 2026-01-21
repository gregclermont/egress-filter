const cache = require('@actions/cache');
const core = require('@actions/core');
const exec = require('@actions/exec');
const glob = require('@actions/glob');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

// Compute action root at runtime (2 levels up from dist/pre/)
// Use array join to prevent ncc from transforming the path
const getActionPath = () => [__dirname, '..', '..'].reduce((a, b) => path.resolve(a, b));

async function hashFile(filePath) {
  const content = fs.readFileSync(filePath);
  return crypto.createHash('sha256').update(content).digest('hex').slice(0, 16);
}

async function restoreVenvCache(actionPath) {
  const venvPath = path.join(actionPath, '.venv');
  const lockFile = path.join(actionPath, 'uv.lock');

  if (!fs.existsSync(lockFile)) {
    core.info('No uv.lock found, skipping cache restore');
    return false;
  }

  const lockHash = await hashFile(lockFile);
  const cacheKey = `egress-filter-venv-${process.platform}-${lockHash}`;

  core.info(`Attempting to restore .venv cache with key: ${cacheKey}`);

  try {
    const matchedKey = await cache.restoreCache([venvPath], cacheKey);
    if (matchedKey) {
      core.info(`Cache restored from key: ${matchedKey}`);
      core.saveState('cache-hit', 'true');
      core.saveState('cache-key', cacheKey);
      return true;
    } else {
      core.info('No cache found');
      core.saveState('cache-hit', 'false');
      core.saveState('cache-key', cacheKey);
      return false;
    }
  } catch (error) {
    core.warning(`Cache restore failed: ${error.message}`);
    core.saveState('cache-hit', 'false');
    core.saveState('cache-key', cacheKey);
    return false;
  }
}

async function run() {
  try {
    const actionPath = getActionPath();
    const setupScript = [actionPath, 'scripts', 'setup-proxy.sh'].join(path.sep);

    // Pass action path so script doesn't need to calculate it
    const env = { ...process.env, EGRESS_FILTER_ROOT: actionPath };

    // Try to restore .venv from cache before installing dependencies
    const cacheHit = await restoreVenvCache(actionPath);

    core.info('Installing dependencies...');
    await exec.exec('sudo', ['-E', setupScript, 'install-deps'], { env });

    core.info('Starting proxy...');
    await exec.exec('sudo', ['-E', setupScript, 'start'], { env });

    core.info('Egress filter proxy is running');
  } catch (error) {
    core.setFailed(error.message);
  }
}

run();
