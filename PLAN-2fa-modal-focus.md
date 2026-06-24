# Fix: 2FA Modal Cursor Focus on wp-login.php

**File:** `assets/js/gswp-2fa-modal.js` (plain asset, no build) · **Branch:** `claude/wonderful-edison-b8cz5p` · **Version:** 2.2.2 → 2.2.3

## Root cause
wp-login.php runs core `wp_attempt_focus()` = `setTimeout(focus #user_login, 200)`. Modal focuses input at next rAF (~32ms), core steals it back at 200ms. Only reproduces on login screen (front-end forms lack `wp_attempt_focus`). Single timed focus can't win; need a focus trap.

## Edits to `assets/js/gswp-2fa-modal.js`

### Edit 1 — add `trapFocus` + replace focus logic in `open()` (current lines 110–128)
Replace the existing `open()` body's focus block with:

```js
function open() {
	if ( isOpen ) {
		return;
	}
	build();
	isOpen = true;
	overlay.classList.add( 'is-open' );
	document.body.classList.add( 'gswp-2fa-lock' );
	document.addEventListener( 'focusin', trapFocus );
	focusInput();
	// Re-assert past core wp_attempt_focus() (setTimeout 200ms on wp-login.php).
	setTimeout( focusInput, 250 );
	setTimeout( focusInput, 400 );
}

function focusInput() {
	if ( isOpen && input && document.activeElement !== input ) {
		input.focus();
	}
}

function trapFocus( e ) {
	if ( isOpen && overlay && ! overlay.contains( e.target ) ) {
		input.focus();
	}
}
```

### Edit 2 — remove the listener in `close()` (current lines 130–136)
Add inside `close()`:

```js
document.removeEventListener( 'focusin', trapFocus );
```

### Edit 3 — empty-submit re-focus (current line ~147, `submit()`)
Already calls `input.focus()`; leave as-is. No change.

> Note: the old double-rAF block in `open()` (lines 120–127) is fully replaced by `focusInput()` + the two `setTimeout`s — delete it. Keep `var isOpen = false;` declaration where it is.

## Version bumps (exact)
- `google-security-for-wordpress.php`: header `Version: 2.2.3` + `define( 'GSWP_VERSION', '2.2.3' )`
- `package.json` + `package-lock.json`: `"version": "2.2.3"` (root + lockfile `packages[""]`)
- `readme.txt`: `Stable tag: 2.2.3` + changelog line `= 2.2.3 = Fix 2FA modal focus on wp-login.php (focus trap beats core wp_attempt_focus).`
- `STATE.md`: Phase 16 note — root cause (core `wp_attempt_focus()` 200ms steal) + fix (focus trap + delayed re-focus).

## Verify (local WP only — remote can't run wp-login.php)
2FA-enrolled test user:
1. wp-login.php: correct user+pass → modal opens, cursor in code input, stays there at 200ms+, typing fills field with no click.
2. Front-end/AJAX login (Xootix / WC My Account): no regression.
3. Cancel → modal closes, normal login fields focusable (trap removed).
4. Tab inside modal does not escape to page behind.

## Commit
`fix: trap focus in 2FA modal to beat wp-login focus steal; bump to 2.2.3`

## Don't
Don't override the core `wp_attempt_focus()` global (inlined, timing-dependent, absent on front-end). Keep vanilla `var`-style JS, no jQuery.
