import globals from 'globals';

export default [
	// Global ignores must be their own config object. Listing `ignores`
	// alongside other keys makes it a per-config exclusion instead, which
	// silently lints the files anyway -- `.claude/worktrees/**` was in the
	// config below and had no effect, so a worktree's copy of lib/ and test/
	// was being reported as a second set of errors.
	{
		ignores: ['eslint.config.mjs', '.claude/worktrees/**', '.superpowers/**'],
	},
	// Everything is CommonJS. `sourceType: 'commonjs'` is what allows the
	// top-level `return` in lib/setup-sandbox.js and lib/setup-node-sandbox.js
	// (the old `ecmaFeatures.globalReturn` flag stopped being honoured once a
	// per-file `sourceType: 'module'` override existed alongside it).
	{
		languageOptions: {
			ecmaVersion: 2022,
			sourceType: 'commonjs',
			globals: {
				...globals.node,
			},
		},
	},
	// Test fixtures that are real ES modules (`"type": "module"` in their
	// package.json) must be parsed as modules, not scripts.
	{
		files: ['test/additional-modules/my-es-module/index.js'],
		languageOptions: {
			sourceType: 'module',
		},
	},
];
