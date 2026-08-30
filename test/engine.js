'use strict';

// Engine detection for the regression suites.
//
// Bun reports `process.versions.node` as '26.3.0', so every version gate in
// this suite sees "Node 26" when running on Bun. Most of those gates are lower
// bounds meaning "not ancient Node", which Bun legitimately satisfies -- but a
// Node version number is the wrong axis for a question about a different
// engine, and an UPPER bound (`NODE_VERSION < 26`) silently means the opposite
// of what its author intended.
//
// Following test/fs-compat.js: prefer feature detection to either of these.
// Reach for ENGINE only where the divergence is genuinely about the engine
// rather than about a capability that can be probed directly.

const IS_BUN = typeof Bun !== 'undefined';

// 'jsc' (JavaScriptCore, via Bun) or 'v8' (Node). Derived from the runtime's
// own identity, never from a version string.
const ENGINE = IS_BUN ? 'jsc' : 'v8';

// The real Node major version, or null when not running on Node at all.
// Deliberately null rather than a number so that arithmetic comparisons
// against it are visibly wrong on Bun instead of quietly claiming Node 26.
const NODE_MAJOR = IS_BUN ? null : parseInt(process.versions.node.split('.')[0], 10);

// "The runtime is at least this modern." True on Bun: it is a current runtime,
// and these gates exist to skip tests on genuinely ancient Node.
function atLeastNode(n) {
	return IS_BUN ? true : NODE_MAJOR >= n;
}

// "The runtime is Node, older than n." False on Bun, which is not Node at any
// version. Use this for upper-bound gates, where treating Bun as Node 26 would
// silently invert the author's intent.
function nodeOlderThan(n) {
	return IS_BUN ? false : NODE_MAJOR < n;
}

module.exports = {IS_BUN, ENGINE, NODE_MAJOR, atLeastNode, nodeOlderThan};
