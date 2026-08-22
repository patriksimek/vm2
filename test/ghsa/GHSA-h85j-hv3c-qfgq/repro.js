/**
 * GHSA-h85j-hv3c-qfgq — https.globalAgent exposes host credentials / traffic
 *
 * ## Vulnerability
 * A NodeVM allowing `https` exposes the real process-wide `https.globalAgent`
 * singleton through the read-only wrap. `.on('free', ...)` is a subscribe, which
 * the wrap forwards to the host object, so a sandbox listener receives live host
 * request options (Authorization tokens, private host/port) and the released host
 * TLSSocket whenever an unrelated host HTTPS request completes.
 *
 * ## Fix
 * lib/builtin.js replaces the exposed `globalAgent` (http and https) with a fresh
 * sandbox-dedicated Agent, so the sandbox can never subscribe to the host
 * singleton. The module's own request()/get() still work.
 *
 * Sound oracle: after a host HTTPS request carrying a secret Authorization header
 * completes, the sandbox listener must have captured nothing.
 */

'use strict';

const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { execFileSync } = require('child_process');
const https = require('https');
const { NodeVM } = require('../../../lib/main.js');

function makeCert(dir) {
	const cert = path.join(dir, 'srv.pem');
	const key = path.join(dir, 'srv.key');
	try {
		execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes',
			'-keyout', key, '-out', cert, '-days', '1', '-subj', '/CN=localhost'],
			{ stdio: 'ignore' });
		return { cert: fs.readFileSync(cert, 'utf8'), key: fs.readFileSync(key, 'utf8') };
	} catch (e) { return null; }
}

describe('GHSA-h85j-hv3c-qfgq — https.globalAgent host exposure', function () {
	this.timeout(20000);
	let dir, tlsMat, server, port;
	const SECRET = 'Bearer VM2_HOST_TOKEN_h85j';

	before(function (done) {
		dir = fs.mkdtempSync(path.join(os.tmpdir(), 'vm2-h85j-'));
		tlsMat = makeCert(dir);
		if (!tlsMat) { this.skip(); return; }
		server = https.createServer({ cert: tlsMat.cert, key: tlsMat.key }, (req, res) => {
			res.writeHead(200); res.end('ok');
		});
		server.listen(0, '127.0.0.1', () => { port = server.address().port; done(); });
	});

	after(function () {
		if (server) try { server.close(); } catch (e) {}
		if (dir) try { fs.rmSync(dir, { recursive: true, force: true }); } catch (e) {}
	});

	it('sandbox cannot observe host requests via https.globalAgent', function (done) {
		const vm = new NodeVM({ require: { builtin: ['https'] } });
		// Sandbox subscribes to what it sees as https.globalAgent and records any
		// leaked host request option / socket.
		const state = vm.run(`
			const https = require('https');
			const s = { sawFree: false, token: null, gotSocket: false };
			https.globalAgent.on('free', (socket, options) => {
				s.sawFree = true;
				s.gotSocket = !!socket;
				try { s.token = (options && options.headers && options.headers.Authorization) || null; } catch (e) {}
			});
			module.exports = s;
		`, 'listener.js');

		// Host makes a request through the *real* shared globalAgent with a secret.
		const req = https.get({
			hostname: '127.0.0.1', port, path: '/',
			ca: tlsMat.cert, servername: 'localhost',
			headers: { Authorization: SECRET },
			agent: https.globalAgent
		}, (res) => {
			res.resume();
			res.on('end', () => {
				// Give the agent's 'free' event a tick to propagate.
				setTimeout(() => {
					assert.strictEqual(state.token, null,
						'sandbox captured the host Authorization token via globalAgent');
					assert.strictEqual(state.sawFree, false,
						'sandbox received the host agent free event (reached the shared singleton)');
					done();
				}, 50);
			});
		});
		req.on('error', done);
	});

	it('cannot reach the host globalAgent via req.agent either (variant)', function (done) {
		// Hardening variant found by red-teaming: a no-agent https.request() would
		// set req.agent to the real host globalAgent, re-exposing the singleton.
		const vm = new NodeVM({ require: { builtin: ['https'] }, sandbox: { PORT: port } });
		const state = vm.run(`
			const https = require('https');
			const s = { token: null };
			const probe = https.request({ host: '127.0.0.1', port: PORT, method: 'GET' });
			probe.on('error', () => {});
			const ag = probe.agent;
			if (ag && typeof ag.on === 'function') {
				ag.on('free', (socket, options) => {
					try { s.token = (options && options.headers && options.headers.Authorization) || s.token; } catch (e) {}
				});
			}
			probe.destroy();
			module.exports = s;
		`, 'variant.js');

		const req = https.get({
			hostname: '127.0.0.1', port, path: '/',
			ca: tlsMat.cert, servername: 'localhost',
			headers: { Authorization: SECRET },
			agent: https.globalAgent
		}, (res) => {
			res.resume();
			res.on('end', () => setTimeout(() => {
				assert.strictEqual(state.token, null,
					'sandbox captured the host token via req.agent (host globalAgent reachable through a request object)');
				done();
			}, 50));
		});
		req.on('error', done);
	});

	it('does not over-block: the sandbox can still make its own https requests', function () {
		const vm = new NodeVM({ require: { builtin: ['https'] } });
		const out = vm.run(`const https = require('https');
			module.exports = { get: typeof https.get, request: typeof https.request, agentIsAgent: https.globalAgent instanceof https.Agent };`, 'ok.js');
		assert.strictEqual(out.get, 'function');
		assert.strictEqual(out.request, 'function');
		assert.strictEqual(out.agentIsAgent, true); // globalAgent is a real (fresh) Agent, not removed
	});
});
