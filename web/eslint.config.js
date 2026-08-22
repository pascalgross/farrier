// @ts-check
//
// ESLint configuration for the Farrier control plane's web application.
//
// The rule that matters here is jsdoc/require-jsdoc with publicOnly disabled. Farrier requires a doc
// comment on every type and every function, exported or not, and for TypeScript that has to include
// private class members: a private field holding an injected service is exactly the kind of declaration
// whose reason for existing is invisible from its signature. `tools/doccheck` enforces the same rule on
// the Go side, because no off-the-shelf Go linter does.
//
// What no linter can check is whether the comment explains *why* the declaration exists. That is left
// to code review, and CONTRIBUTING.md says so rather than pretending otherwise.

const eslint = require('@eslint/js');
const tseslint = require('typescript-eslint');
const angular = require('angular-eslint');
const jsdoc = require('eslint-plugin-jsdoc');

module.exports = tseslint.config(
  {
    files: ['**/*.ts'],
    extends: [
      eslint.configs.recommended,
      ...tseslint.configs.recommended,
      ...tseslint.configs.stylistic,
      ...angular.configs.tsRecommended,
    ],
    processor: angular.processInlineTemplates,
    plugins: { jsdoc },
    rules: {
      '@angular-eslint/directive-selector': [
        'error',
        { type: 'attribute', prefix: 'farrier', style: 'camelCase' },
      ],
      '@angular-eslint/component-selector': [
        'error',
        { type: 'element', prefix: 'farrier', style: 'kebab-case' },
      ],

      // Presence and shape only. Private members are included deliberately; see the note above.
      'jsdoc/require-jsdoc': [
        'error',
        {
          publicOnly: false,
          require: {
            ClassDeclaration: true,
            ClassExpression: true,
            FunctionDeclaration: true,
            FunctionExpression: true,
            MethodDefinition: true,
          },
          contexts: [
            'TSInterfaceDeclaration',
            'TSTypeAliasDeclaration',
            'TSEnumDeclaration',
            'TSEnumMember',
            'TSPropertySignature',
            'TSMethodSignature',
            'PropertyDefinition',
          ],
        },
      ],
      'jsdoc/require-description': ['error', { checkConstructors: false }],
      'jsdoc/no-undefined-types': 'off',
      'jsdoc/require-param': 'off',
      'jsdoc/require-returns': 'off',
    },
  },
  {
    files: ['**/*.html'],
    extends: [...angular.configs.templateRecommended, ...angular.configs.templateAccessibility],
    rules: {},
  },
);
