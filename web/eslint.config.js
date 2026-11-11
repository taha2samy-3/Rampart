import js from '@eslint/js';
import tseslint from 'typescript-eslint';
import reactHooks from 'eslint-plugin-react-hooks';
import globals from 'globals';

export default tseslint.config(
  { ignores: ['dist', 'node_modules'] },
  js.configs.recommended,
  ...tseslint.configs.recommended,
  {
    files: ['src/**/*.{ts,tsx}'],
    languageOptions: { globals: globals.browser },
    plugins: { 'react-hooks': reactHooks },
    rules: {
      ...reactHooks.configs.recommended.rules,
      '@typescript-eslint/no-explicit-any': 'error',
      // Only api/ talks to the network (doc 13 section 7).
      'no-restricted-globals': ['error', 'fetch', 'XMLHttpRequest'],
    },
  },
  { files: ['src/api/**', 'src/**/*.test.{ts,tsx}'], rules: { 'no-restricted-globals': 'off' } },
  { files: ['dev/**/*.mjs', 'vite.config.ts'], languageOptions: { globals: globals.node } },
);
