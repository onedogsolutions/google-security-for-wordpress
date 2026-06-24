# Implementation Plan: Fix 2FA Authenticator Modal Cursor Focus on the Login Screen

**Target file:** `assets/js/gswp-2fa-modal.js` (plain asset, no webpack build required)
**Branch:** `claude/wonderful-edison-b8cz5p`
**Version to bump to:** 2.2.3 (this is a behavior fix on top of the 2.2.2 attempt)

---

## 1. Problem

When a 2FA-enrolled user signs in, the held-login flag cookie triggers the
authenticator modal. The code input is supposed to receive cursor focus so the
user can immediately type the 6-digit code. This works on front-end login forms
but **fails on `wp-login.php`** — the cursor lands in (or jumps back to) the
WordPress username/password field instead of the modal input.

The previous fix (commit `9bb4208`, v2.2.2) added `autofocus`, a double
`requestAnimationFrame` focus call, and an empty-submit re-focus. It did not
fix the login screen.

## 2. Root cause

`wp-login.php` emits WordPress core's `wp_attempt_focus()` in its footer, which
runs:

```js
setTimeout( function () { document.getElementById('user_login').focus(); ... }, 200 );
```

That timer fires **200 ms after load** and focuses the core username/password
field. Our modal focuses its input on the next animation frame(s) — only
~16–32 ms after `open()`. Sequence of events on the login screen:

1. Page loads with the held-login flag cookie present.
2. `init()` → `open()` → double-rAF → `input.focus()` succeeds (~32 ms).
3. **200 ms:** core `wp_attempt_focus()` fires and steals focus back to
   `#user_login` / `#user_pass`.

Because core's focus is on a longer timer, it always wins the race. This is why
the bug is specific to the login screen — front-end pages have no
`wp_attempt_focus()`.

## 3. Fix

Make the modal's focus authoritative for as long as the modal is open, rather
than firing once and hoping nothing steals it. Implement **both** of the
following in `assets/js/gswp-2fa-modal.js`:

### 3a. Re-assert focus past core's 200 ms timer
In `open()`, in addition to the existing rAF focus, schedule a delayed
re-focus that lands **after** `wp_attempt_focus()` (use ~250 ms to clear the
200 ms core timer, plus one more at ~400 ms for slow devices). Guard each with
`isOpen` and `document.activeElement !== input` so they no-op when the user has
intentionally moved focus (e.g. clicked Cancel) or already typing.

### 3b. Add a focus trap while the modal is open (primary, robust fix)
A modal that sets `aria-modal="true"` should keep focus inside it anyway. Add a
document-level `focusin` listener, installed when `open()` runs and removed in
`close()`, that pulls focus back to the code input whenever focus escapes the
overlay while `isOpen` is true:

```js
function trapFocus( e ) {
    if ( isOpen && overlay && ! overlay.contains( e.target ) ) {
        input.focus();
    }
}
```

This neutralizes `wp_attempt_focus()` regardless of its exact timing, and also
correctly handles Tab-ing out of the modal. The timed re-focus in 3a covers the
initial paint; the trap covers everything after.

### 3c. Keep `close()` clean
Ensure `close()` removes the `focusin` listener so the login form is usable
again after Cancel (the user abandons the challenge and should be able to focus
the normal login fields).

## 4. Acceptance criteria (verify locally — requires a real WP install)

This must be tested on a real `wp-login.php`, which the remote environment
cannot run. On a local WordPress site with the plugin active and a 2FA-enrolled
test user:

1. **Login screen (`wp-login.php`):** Submit correct username + password. When
   the modal appears, the cursor is in the code input and stays there — typing
   digits immediately fills the field with no extra click. Confirm focus does
   **not** jump to the username/password field at ~200 ms.
2. **Front-end / AJAX login** (Xootix popup or WooCommerce My Account): modal
   still focuses correctly (no regression).
3. **Cancel:** Clicking Cancel closes the modal and the normal login fields can
   be focused/typed again (focus trap fully removed).
4. **Tab key:** With the modal open, pressing Tab does not let focus escape to
   the page behind the overlay.
5. **bfcache:** Navigate away and use the browser Back button while a challenge
   is pending; the modal re-opens and focuses correctly (`pageshow` path).

## 5. Version + metadata bookkeeping

- `assets/js/gswp-2fa-modal.js` — the fix (cache-busted automatically by the
  `GSWP_VERSION` query arg, so the version bump is what forces caches/CDN to
  refetch — do not skip it).
- `google-security-for-wordpress.php` — header `Version:` and `GSWP_VERSION`
  constant → `2.2.3`.
- `package.json` + `package-lock.json` (root entries) → `2.2.3`.
- `readme.txt` — `Stable tag` + a changelog entry for 2.2.3.
- `STATE.md` — add a Phase 16 note describing the root cause (core
  `wp_attempt_focus()` race) and the focus-trap + delayed-refocus fix.
- No webpack rebuild needed — the modal assets are plain files served from
  `assets/`.

## 6. Commit

One commit on `claude/wonderful-edison-b8cz5p`, e.g.:
`fix: trap focus in 2FA modal to beat wp-login focus steal; bump to 2.2.3`

## 7. Notes / things to avoid

- Do **not** try to disable core `wp_attempt_focus()` by overriding the global
  function — it is inlined and timing-dependent, and front-end forms don't have
  it. The focus trap is form-agnostic and the correct fix.
- Keep the script dependency-free vanilla JS (no jQuery) and IE-safe `var`
  style to match the existing file.
- Reading `document.activeElement` and calling `input.focus()` repeatedly is
  cheap; the trap only acts when focus actually leaves the overlay.
