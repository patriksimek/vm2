import globals from 'globals';

export default [
	{
		languageOptions: {
			ecmaVersion: 2017,
			sourceType: "module",
			globals: {
				...globals.node
			},
			parserOptions: {
				ecmaFeatures: {
					globalReturn: true,
				}
			}
		},
		ignores: ["eslint.config.mjs"],
	},
];