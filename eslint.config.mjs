import globals from 'globals';

export default [
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
		ignores: ['eslint.config.mjs', '.claude/worktrees/**'],
	},
];
