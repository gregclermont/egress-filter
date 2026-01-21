const core = require('@actions/core');
const exec = require('@actions/exec');
const path = require('path');

async function run() {
  // Action root is 2 levels up from dist/post/
  const actionPath = path.resolve(__dirname, '..', '..');
  const env = { ...process.env, EGRESS_FILTER_ROOT: actionPath };

  core.info('Stopping proxy...');
  await exec.exec('sudo', ['-E', path.join(actionPath, 'scripts', 'setup-proxy.sh'), 'stop'], {
    ignoreReturnCode: true,
    env
  });

  core.info('Cleaning up iptables...');
  await exec.exec('sudo', ['-E', path.join(actionPath, 'scripts', 'iptables.sh'), 'cleanup'], {
    ignoreReturnCode: true,
    env
  });

  core.info('Egress filter cleanup complete');
}

run();
