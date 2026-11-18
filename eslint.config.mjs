// static/app.js ships to every visitor and nothing linted it: the Python
// suite runs `node --check`, which only parses. These are the bug-finding
// rules (undeclared names, unreachable code, shadowed bindings, == vs ===),
// not a style opinion -- formatting is left alone on purpose.
//
//   npx eslint static tests
import globals from 'globals';

export default [
  {
    files: ['static/**/*.js'],
    languageOptions: {
      ecmaVersion: 2022,
      sourceType: 'script',
      globals: { ...globals.browser },
    },
    linterOptions: { reportUnusedDisableDirectives: true },
    rules: {
      'no-undef': 'error',
      // `catch (_)` is a deliberate discard, not an oversight.
      'no-unused-vars': ['error', {
        args: 'none',
        varsIgnorePattern: '^_',
        caughtErrorsIgnorePattern: '^_',
      }],
      'no-implicit-globals': 'error',
      'no-shadow': 'error',
      'no-redeclare': 'error',
      'no-unreachable': 'error',
      'no-constant-condition': 'error',
      'no-dupe-keys': 'error',
      'no-dupe-args': 'error',
      'no-duplicate-case': 'error',
      'no-self-compare': 'error',
      'no-template-curly-in-string': 'error',
      'no-unsafe-negation': 'error',
      'no-fallthrough': 'error',
      'require-atomic-updates': 'error',
      'eqeqeq': ['error', 'smart'],
      'no-var': 'error',
      'prefer-const': 'error',
      'no-eval': 'error',
      'no-implied-eval': 'error',
      'no-new-func': 'error',
      'no-script-url': 'error',
      'no-return-assign': 'error',
      'no-throw-literal': 'error',
    },
  },
  {
    files: ['tests/**/*.js'],
    languageOptions: {
      ecmaVersion: 2022,
      sourceType: 'script',
      globals: { ...globals.node },
    },
    rules: {
      'no-undef': 'error',
      'no-unused-vars': ['error', { args: 'none' }],
      'no-var': 'error',
      'prefer-const': 'error',
    },
  },
];
