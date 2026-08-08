'use strict';

const path = require('node:path');

/**
 * Build the environment for the long-lived desktop API sidecar.
 *
 * The sidecar is a supervisor, not a restricted scan worker.  Explicitly
 * remove an inherited worker marker so it never receives the scan worker's
 * irreversible RLIMIT/Job Object policy.
 */
function buildBackendEnv(baseEnv, {
    port,
    token,
    masterKey = '',
    masterKeyBackend = '',
}) {
    const env = { ...baseEnv };
    delete env.BASILISK_RESTRICTED_WORKER;
    env.BASILISK_DESKTOP_BACKEND = '1';
    env.BASILISK_PORT = String(port);
    env.BASILISK_TOKEN = token;
    if (masterKey) {
        env.BASILISK_MASTER_KEY = masterKey;
        env.BASILISK_MASTER_KEY_SOURCE = masterKeyBackend;
    }
    return env;
}

function buildPackagedBackendOptions(env, userDataDir) {
    if (!userDataDir || !path.isAbsolute(userDataDir)) {
        throw new Error('Packaged backend user-data directory must be an absolute path');
    }
    return {
        cwd: userDataDir,
        stdio: 'pipe',
        env,
    };
}

module.exports = { buildBackendEnv, buildPackagedBackendOptions };
