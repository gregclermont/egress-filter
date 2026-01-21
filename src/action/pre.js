const cache = require('@actions/cache');
const core = require('@actions/core');
const exec = require('@actions/exec');
const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');

// Compute action root at runtime (2 levels up from dist/pre/)
const getActionPath = () => [__dirname, '..', '..'].reduce((a, b) => path.resolve(a, b));

function checkPlatform() {
  // This action only supports GitHub-hosted Ubuntu runners
  if (os.platform() !== 'linux') {
    core.setFailed(`This action only supports Linux runners, got: ${os.platform()}`);
    process.exit(1);
  }

  // Check for Ubuntu specifically
  try {
    const osRelease = fs.readFileSync('/etc/os-release', 'utf8');
    if (!osRelease.includes('Ubuntu')) {
      core.setFailed('This action only supports Ubuntu runners');
      process.exit(1);
    }
  } catch (e) {
    core.warning('Could not verify Ubuntu, proceeding anyway');
  }
}

function hashFile(filePath) {
  const content = fs.readFileSync(filePath);
  return crypto.createHash('sha256').update(content).digest('hex').slice(0, 16);
}

async function restoreVenvCache(actionPath) {
  if (!cache.isFeatureAvailable()) {
    core.info('Cache feature not available, skipping');
    return false;
  }

  const venvPath = path.join(actionPath, '.venv');
  const lockFile = path.join(actionPath, 'uv.lock');

  if (!fs.existsSync(lockFile)) {
    core.info('No uv.lock found, skipping cache restore');
    return false;
  }

  const lockHash = hashFile(lockFile);
  const cacheKey = `egress-filter-venv-${lockHash}`;

  core.saveState('cache-key', cacheKey);
  core.info(`Cache key: ${cacheKey}`);

  try {
    const matchedKey = await cache.restoreCache([venvPath], cacheKey);
    if (matchedKey) {
      core.info(`Cache restored from key: ${matchedKey}`);
      core.saveState('cache-matched-key', matchedKey);
      return true;
    }
    core.info('Cache not found, will save after install');
    return false;
  } catch (error) {
    core.warning(`Cache restore failed: ${error.message}`);
    return false;
  }
}

async function run() {
  try {
    checkPlatform();

    const actionPath = getActionPath();
    const setupScript = path.join(actionPath, 'scripts', 'setup-proxy.sh');
    const env = { ...process.env, EGRESS_FILTER_ROOT: actionPath };

    // Try to restore .venv from cache
    await restoreVenvCache(actionPath);

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
