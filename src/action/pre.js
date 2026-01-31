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
  // This action only supports GitHub-hosted Ubuntu 24.04 runners
  if (os.platform() !== 'linux') {
    core.setFailed(`This action only supports Linux runners, got: ${os.platform()}`);
    process.exit(1);
  }

  if (process.env.RUNNER_ENVIRONMENT !== 'github-hosted') {
    core.setFailed(`This action only supports GitHub-hosted runners, got: ${process.env.RUNNER_ENVIRONMENT || 'unknown'}`);
    process.exit(1);
  }

  const imageOS = process.env.ImageOS;
  if (imageOS !== 'ubuntu24') {
    core.setFailed(`This action only supports Ubuntu 24.04 (ubuntu24), got: ${imageOS || 'unknown'}`);
    process.exit(1);
  }

  core.info(`Runner: ${process.env.RUNNER_ENVIRONMENT}, image: ${imageOS}`);
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
  const imageOS = process.env.ImageOS || 'linux';
  const arch = process.arch;
  const cacheKey = `egress-filter-venv-${imageOS}-${arch}-${lockHash}`;

  core.saveState('cache-key', cacheKey);
  core.info(`Cache key: ${cacheKey}`);

  try {
    const matchedKey = await cache.restoreCache([venvPath], cacheKey);
    if (matchedKey) {
      core.saveState('cache-matched-key', matchedKey);
      return true;
    }
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
    const setupScript = path.join(actionPath, 'src', 'setup', 'proxy.sh');

    // Try to restore .venv from cache
    await restoreVenvCache(actionPath);

    // Read action inputs
    const policy = core.getInput('policy') || '';
    const audit = core.getInput('audit') === 'true';

    // Write policy to temp file (multiline string)
    const policyFile = '/tmp/egress-policy.txt';
    fs.writeFileSync(policyFile, policy);

    // Build environment variables to pass through sudo.
    // We exclude HOME so that root uses its own home directory (/root),
    // preventing cache/config directories from being created as root-owned
    // in /home/runner (which breaks pip/poetry/etc for subsequent steps).
    // We use 'sudo env VAR=value ...' because sudo doesn't pass env vars by default.
    const sudoEnv = [
      `PATH=${process.env.PATH}`,
      `GITHUB_ENV=${process.env.GITHUB_ENV}`,
      `GITHUB_REPOSITORY=${process.env.GITHUB_REPOSITORY || ''}`,
      `GITHUB_ACTION=${process.env.GITHUB_ACTION || ''}`,
      `EGRESS_FILTER_ROOT=${actionPath}`,
      `EGRESS_POLICY_FILE=${policyFile}`,
      `EGRESS_AUDIT_MODE=${audit ? '1' : '0'}`,
    ];

    core.info('Installing dependencies...');
    await exec.exec('sudo', ['env', ...sudoEnv, setupScript, 'install-deps']);

    core.info('Starting proxy...');
    await exec.exec('sudo', ['env', ...sudoEnv, setupScript, 'start']);

    core.info('Egress filter proxy is running');
  } catch (error) {
    core.setFailed(error.message);
    process.exit(1);
  }

  // Exit explicitly to avoid hanging on unresolved promises from @actions/cache
  process.exit(0);
}

run();
