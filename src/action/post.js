const artifact = require('@actions/artifact');
const cache = require('@actions/cache');
const core = require('@actions/core');
const exec = require('@actions/exec');
const fs = require('fs');
const net = require('net');
const path = require('path');

// Compute action root at runtime (2 levels up from dist/post/)
const getActionPath = () => [__dirname, '..', '..'].reduce((a, b) => path.resolve(a, b));

const CONTROL_SOCKET_PATH = '/tmp/egress-filter-control.sock';

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

/**
 * Send shutdown command to proxy via authenticated control socket.
 * The proxy verifies our identity (exe, parent exe, cgroup, GITHUB_ACTION)
 * before accepting the shutdown request.
 */
async function shutdownProxy() {
  return new Promise((resolve, reject) => {
    if (!fs.existsSync(CONTROL_SOCKET_PATH)) {
      core.warning('Control socket not found, proxy may not be running');
      resolve(false);
      return;
    }

    const socket = net.createConnection(CONTROL_SOCKET_PATH);
    let response = '';

    socket.setTimeout(10000); // 10 second timeout

    socket.on('connect', () => {
      core.info('Connected to control socket, sending shutdown...');
      socket.write('shutdown\n');
    });

    socket.on('data', (data) => {
      response += data.toString();
    });

    socket.on('end', () => {
      response = response.trim();
      if (response.startsWith('ok:')) {
        core.info(`Proxy shutdown initiated: ${response}`);
        resolve(true);
      } else {
        core.error(`Proxy shutdown failed: ${response}`);
        reject(new Error(response));
      }
    });

    socket.on('timeout', () => {
      socket.destroy();
      reject(new Error('Control socket timeout'));
    });

    socket.on('error', (err) => {
      reject(err);
    });
  });
}

const CONNECTION_LOG_PATH = '/tmp/connections.jsonl';

/**
 * Check if any connections were blocked (policy: 'deny') or had errors
 * (e.g., TLS failures) in the log.
 */
function hasBlockedOrErrorConnections() {
  if (!fs.existsSync(CONNECTION_LOG_PATH)) return { blocked: false, errors: false };
  const content = fs.readFileSync(CONNECTION_LOG_PATH, 'utf8');
  let blocked = false;
  let errors = false;
  for (const line of content.split('\n')) {
    if (!line.trim()) continue;
    try {
      const entry = JSON.parse(line);
      if (entry.policy === 'deny') blocked = true;
      if (entry.error) errors = true;
      if (blocked && errors) break; // No need to continue
    } catch {
      // Ignore malformed lines
    }
  }
  return { blocked, errors };
}

async function uploadConnectionLog() {
  const uploadLog = core.getInput('upload-log');

  // Explicit 'false' - never upload
  if (uploadLog === 'false') {
    core.info('Connection log upload disabled');
    return;
  }

  if (!fs.existsSync(CONNECTION_LOG_PATH)) {
    core.warning('Connection log not found, skipping upload');
    return;
  }

  // Default (empty) - conditional upload based on audit mode, blocks, or errors
  if (uploadLog !== 'true') {
    const auditMode = core.getInput('audit') === 'true';
    const { blocked, errors } = hasBlockedOrErrorConnections();

    if (!auditMode && !blocked && !errors) {
      core.info('Skipping connection log upload (no audit mode, no blocks, no errors)');
      return;
    }
    core.info(`Uploading connection log (audit=${auditMode}, blocks=${blocked}, errors=${errors})`);
  } else {
    core.info('Uploading connection log (upload-log=true)');
  }
  try {
    const client = new artifact.DefaultArtifactClient();
    const { id, size } = await client.uploadArtifact(
      'egress-connections',
      [CONNECTION_LOG_PATH],
      '/tmp',
      { retentionDays: 30 }
    );
    core.info(`Uploaded artifact (id: ${id}, size: ${size} bytes)`);
  } catch (error) {
    core.warning(`Failed to upload connection log: ${error.message}`);
  }
}

async function run() {
  const actionPath = getActionPath();
  const setupDir = path.join(actionPath, 'src', 'setup');

  // Step 1: Request authenticated shutdown via control socket
  // This restores sudo access so we can call proxy.sh stop
  core.info('Requesting proxy shutdown via control socket...');
  try {
    await shutdownProxy();
    core.info('Proxy acknowledged shutdown, sudo restored');
  } catch (error) {
    core.warning(`Control socket shutdown failed: ${error.message}`);
    // Continue anyway - try the cleanup steps
  }

  // Wait for proxy to restore sudo and exit
  await new Promise(resolve => setTimeout(resolve, 500));

  // Step 2: Full cleanup via proxy.sh stop (iptables, sysctl, etc.)
  core.info('Running proxy.sh stop...');
  await exec.exec('sudo', [path.join(setupDir, 'proxy.sh'), 'stop'], {
    ignoreReturnCode: true,
  });

  // Upload connection log (after iptables removed, so no policy restrictions)
  await uploadConnectionLog();

  // Save cache after cleanup
  await saveVenvCache(actionPath);

  core.info('Egress filter cleanup complete');

  // Exit explicitly to avoid hanging on unresolved promises
  process.exit(0);
}

run();
