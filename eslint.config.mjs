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
	{
		languageOptions: {
			ecmaVersion: 2022,
			sourceType: 'script',
			globals: {
				...globals.node,
			},
			parserOptions: {
				ecmaFeatures: {
					globalReturn: true,
				},
			},
		},
	},
];
