const net = require('net');

const SOCKET_PATH = '/tmp/egress-filter-control.sock';

async function run() {
  return new Promise((resolve, reject) => {
    const client = net.createConnection(SOCKET_PATH, () => {
      client.write('disable-sudo\n');
    });

    let response = '';
    client.on('data', (data) => {
      response += data.toString();
    });

    client.on('end', () => {
      response = response.trim();
      if (response.startsWith('ok:')) {
        console.log(`✓ ${response.slice(4)}`);
        resolve();
      } else {
        console.error(`::error::${response}`);
        process.exit(1);
      }
    });

    client.on('error', (err) => {
      console.error(`::error::Failed to connect to control socket: ${err.message}`);
      process.exit(1);
    });
  });
}

run();
