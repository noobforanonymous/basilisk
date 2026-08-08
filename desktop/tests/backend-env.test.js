'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

const { buildBackendEnv } = require('../backend-env');

test('desktop backend cannot inherit restricted scan-worker mode', () => {
    const baseEnv = {
        PATH: '/usr/bin',
        BASILISK_RESTRICTED_WORKER: '1',
    };
    const env = buildBackendEnv(baseEnv, {
        port: 8741,
        token: 'test-token',
        masterKey: 'test-master-key',
        masterKeyBackend: 'test-key-store',
    });

    assert.equal(env.BASILISK_RESTRICTED_WORKER, undefined);
    assert.equal(env.BASILISK_DESKTOP_BACKEND, '1');
    assert.equal(env.BASILISK_PORT, '8741');
    assert.equal(env.BASILISK_TOKEN, 'test-token');
    assert.equal(env.BASILISK_MASTER_KEY, 'test-master-key');
    assert.equal(env.BASILISK_MASTER_KEY_SOURCE, 'test-key-store');
    assert.equal(baseEnv.BASILISK_RESTRICTED_WORKER, '1');
});
