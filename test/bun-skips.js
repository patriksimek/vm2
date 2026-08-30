'use strict';

// Tests skipped when running under Bun.
//
// This list IS the phase-2 backlog. Every entry is a divergence between
// JavaScriptCore and V8 that phase 1 deliberately does not fix -- fixing them
// is security work, and Bun has no threat model yet (see
// docs/specs/2026-08-30-bun-support-design.md section 6).
//
// The goal is to drive this list to zero. Run with VM2_BUN_NO_SKIP=1 to
// ignore it entirely and see what now passes.
//
// `security: true` marks a divergence where a vm2 defence does not hold on
// JSC, as opposed to a functional or Bun-Node-compat difference.

const SKIPS = [
	{
		// DELIBERATELY BROAD: this matches all 7 tests in the file, including
		// ones that might otherwise pass. Any test here can construct a sandbox
		// prepareStackTrace, and doing so terminates the Bun process outright --
		// so the whole file is quarantined rather than risk losing the run.
		// Phase 2 should narrow this once the crash is understood.
		match: 'GHSA-v27g-jcqj-v8rw',
		reason:
			'CallSite objects handed to a sandbox Error.prepareStackTrace have no ' +
			'methods on JSC (getFileName is undefined), so the host-frame redaction ' +
			'this advisory added is untestable there. The resulting TypeError also ' +
			'terminates the Bun process, taking the whole run with it. Whole file ' +
			'quarantined (7 tests).',
		phase: 2,
		security: true,
	},
	{
		match: 'Error.captureStackTrace re-capture on the caught error',
		reason:
			'JSC repopulates .stack with host frames including absolute paths, ' +
			'bypassing the GHSA-x6m4 redactor. Information disclosure.',
		phase: 2,
		security: true,
	},
	{
		match: 'custom Error.prepareStackTrace + captureStackTrace over the caught error',
		reason: 'Same root cause as the GHSA-x6m4 re-capture entry above.',
		phase: 2,
		security: true,
	},
	{
		match: "a sandbox buffer's .buffer never exceeds its own length",
		reason:
			'Buffer.from(arrayLike) returns a zero-length buffer on Bun, so the ' +
			'pool-ownership invariant cannot be exercised.',
		phase: 2,
		security: false,
	},
	{
		match: 'legitimate small Buffer.from(arrayLike) works',
		reason: 'Buffer.from(arrayLike) returns length 0 on Bun. Same root cause.',
		phase: 2,
		security: false,
	},
	{
		match: 'default (Infinity) bufferAllocLimit leaves Buffer.from(arrayLike) unrestricted',
		reason: 'Buffer.from(arrayLike) returns length 0 on Bun. Same root cause.',
		phase: 2,
		security: false,
	},
	{
		match: 'does not throw a proxy-invariant error (regression)',
		reason:
			'Object.freeze on a frozen host object with a non-configurable accessor ' +
			'throws a proxy-invariant TypeError on JSC where V8 does not.',
		phase: 2,
		security: false,
	},
	{
		match: 'allowExtension is forced off',
		reason:
			"Bun's node:sqlite refuses extension loading with its own error, so " +
			"vm2's forced allowExtension:false is not what blocks it. Still blocked, " +
			'but the defence is unverified on Bun.',
		phase: 2,
		security: true,
	},
	{
		match: 'a FUNCTION options arg with allowExtension:true',
		reason:
			"Bun's node:sqlite blocks loadExtension even when allowExtension:true " +
			"is passed as a function property. Blocked by Bun, not vm2's forced " +
			'allowExtension:false, so vm2\'s defence remains unverified on Bun.',
		phase: 2,
		security: true,
	},
	{
		match: 'enableLoadExtension(true) is also disabled',
		reason:
			"Bun's node:sqlite refuses enableLoadExtension(true) with its own error. " +
			"Blocked by Bun's implementation, not vm2's forced allowExtension:false, " +
			'leaving vm2\'s defence unverified on Bun.',
		phase: 2,
		security: true,
	},
	{
		match: 'isDangerousSymbol covers full nodejs.* set',
		reason:
			"Bun's node:assert deepStrictEqual does not treat a cross-realm array as " +
			'equal to a host array. A Bun Node-compat gap, not a vm2 defect.',
		phase: 2,
		security: false,
	},
	{
		match: '.next/.return/.throw on async generator instances all sanitize results',
		reason: "Bun's node:assert cross-realm reference equality. Same class as above.",
		phase: 2,
		security: false,
	},
	{
		match: 'Object.getOwnPropertyNames does not expose the state name',
		reason: "Bun's node:assert deepStrictEqual cross-realm array handling.",
		phase: 2,
		security: false,
	},
	{
		match: 'does not block sandbox-local writes (negative control)',
		reason: "Bun's node:assert deepStrictEqual cross-realm array handling.",
		phase: 2,
		security: false,
	},
	{
		match: 'inspect array (issue #566)',
		reason:
			"Bun's util.inspect renders cross-realm arrays as \"Array { '0': 1 }\" " +
			'rather than "[ 1, 2, 3 ]". A Bun Node-compat gap.',
		phase: 2,
		security: false,
	},
	{
		match: 'inspect nested object and array (issue #566)',
		reason: "Bun's util.inspect cross-realm array rendering. Same root cause.",
		phase: 2,
		security: false,
	},
	{
		match: 'VMScript options',
		reason:
			'CallSite getFileName() returns undefined on JSC, so VMScript filename / ' +
			'lineOffset / columnOffset metadata is not observable.',
		phase: 2,
		security: false,
	},
	{
		match: 'default is permissive (Infinity): large allocations are allowed',
		reason:
			'Buffer.allocUnsafe(64MB) across the bridge takes >400s on Bun versus ' +
			'1.7s on Node - a >240x divergence that reads as a hang.',
		phase: 2,
		security: false,
	},
	{
		// Gap found during Step 8 verification: this is the SAME
		// Buffer.allocUnsafe(64MB)-with-no-cap operation as the entry above,
		// exercised from a second call site (bufferAllocLimit: Infinity rather
		// than the default). A full Bun run hung on it for >17 minutes with no
		// sign of returning -- far past the sibling test's already-bad >400s --
		// so it is quarantined here too rather than risk the run never finishing.
		match: 'bufferAllocLimit: Infinity disables the cap',
		reason:
			'Same Buffer.allocUnsafe(64MB)-across-the-bridge divergence as ' +
			'"default is permissive (Infinity)" above, from a second call site. ' +
			'Missing from the original list; a full run hung on it indefinitely.',
		phase: 2,
		security: false,
	},
	{
		match: 'Node internal prepareStackTrace attack',
		reason:
			'The payload recurses until a stack overflow terminates it. JSC does not ' +
			'overflow promptly, so the VM runs unbounded and the test hits mocha\'s ' +
			'timeout instead. Adding a VM timeout would change the error the test ' +
			'asserts on, so this is left for phase 2 to re-express without relying ' +
			'on a fast RangeError.',
		phase: 2,
		security: false,
	},
	{
		match: 'transformer attack',
		reason:
			'Same unbounded-recursion shape as the prepareStackTrace attack above: ' +
			'JSC does not stack-overflow promptly, so the test times out.',
		phase: 2,
		security: false,
	},
];

const NO_SKIP = process.env.VM2_BUN_NO_SKIP === '1';

// Returns the reason this test is skipped under Bun, or null to run it.
// `fullTitle` is the suite path plus the test name, so an entry may match
// either a describe block (quarantining a whole file) or a single test.
function skipReason(fullTitle) {
	if (NO_SKIP) return null;
	for (let i = 0; i < SKIPS.length; i++) {
		if (fullTitle.indexOf(SKIPS[i].match) !== -1) return SKIPS[i].reason;
	}
	return null;
}

module.exports = {SKIPS, skipReason, NO_SKIP};
