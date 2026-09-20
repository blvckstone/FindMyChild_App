// Test helper: hand out a port the operating system says is free.
//
// The test files run in parallel, and each used to pick from its own fixed numeric range. Two of
// those ranges overlapped (9450-9650 and 9600-9800), so on a bad draw two files spawned servers
// on the same port: one test then either failed to bind or quietly talked to a *different* test
// file's server, which showed up as a flaky failure unrelated to the code under test.
//
// Asking the OS avoids the guessing. There is still a tiny window between releasing the probe
// socket and the server binding it, which is far smaller than a 200-port lottery.
const net = require('node:net');

const freePort = () => new Promise((resolve, reject) => {
    const probe = net.createServer();
    probe.unref();
    probe.once('error', reject);
    probe.listen(0, '127.0.0.1', () => {
        const address = probe.address();
        const port = address && typeof address === 'object' ? address.port : 0;
        probe.close(() => {
            if (port) resolve(port);
            else reject(new Error('the OS did not assign a port'));
        });
    });
});

module.exports = { freePort };
