/**
 * Extends the @wordpress/scripts default config with `no-undef`.
 *
 * A dangling reference to a deleted variable shipped in 2.20.0 and white-screened
 * the entire settings app: the default config does not flag undefined variables,
 * so `npm run lint:js` passed on code that threw a ReferenceError at render.
 * `no-unused-vars` catches the opposite mistake; this catches this one.
 */
module.exports = {
	extends: [ 'plugin:@wordpress/eslint-plugin/recommended' ],
	env: {
		browser: true,
		es2022: true,
	},
	rules: {
		'no-undef': 'error',
	},
};
