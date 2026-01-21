const core = require('@actions/core');
const exec = require('@actions/exec');
const path = require('path');

async function run() {
  try {
    // Action root is 2 levels up from dist/pre/
    const actionPath = path.resolve(__dirname, '..', '..');
    const setupScript = path.join(actionPath, 'scripts', 'setup-proxy.sh');

    // Pass action path so script doesn't need to calculate it
    const env = { ...process.env, EGRESS_FILTER_ROOT: actionPath };

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
