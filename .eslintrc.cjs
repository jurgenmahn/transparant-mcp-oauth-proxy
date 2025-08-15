module.exports = {
  root: true,
  env: { node: true, es2022: true, browser: true },
  parserOptions: { ecmaVersion: 2022, sourceType: 'module' },
  extends: ['eslint:recommended'],
  rules: {
    'no-unused-vars': ['warn', { args: 'none', ignoreRestSiblings: true }],
    'no-undef': 'error',
    'no-var': 'error',
    'prefer-const': 'warn',
    'semi': ['warn', 'always'],
    'quotes': ['warn', 'single', { avoidEscape: true }]
  },
  ignorePatterns: ['node_modules/', 'dist/', 'build/']
};

