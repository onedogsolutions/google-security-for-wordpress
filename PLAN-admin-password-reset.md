# PLAN — Admin-initiated password reset failures (v2.27.2)

**Status:** investigation complete, implementation not started.
**Reported against:** v2.27.2, `gswp_enable_wp_lostpassword = 1`, Enterprise keys.
**Symptoms:**

1. `user-edit.php` / `profile.php` → **Send Reset Link** → inline notice
   *"Error: Anti-spam verification token is missing. Please refresh the page and try again."*
2. `users.php` → **Send password reset** (per-row link under the name, and the bulk
   action) → *"Password reset links sent to 0 users."*

---

## 0. Summary

Four defects, all in this plugin. Three of them explain the two reported symptoms
exactly; the fourth is a hardening item found on the way.

| # | Defect | Symptom it causes | File |
|---|---|---|---|
| D1 | Row-action guard tests `$_GET['user']`; core sends `users` | users.php → 0 users | `class-gswp-login.php:497` |
| D2 | `users.php` list form is `method="get"`, so the bulk token never reaches `$_POST` | users.php → 0 users | `class-gswp-login.php:390`, `class-gswp-verifier.php:285` |
| D3 | Inline JS matches `action=send_password_reset`; the wire action is `send-password-reset` | profile → "token is missing" | `class-gswp-login.php:299` |
| D4 | `XMLHttpRequest.prototype.addEventListener` patch never fires (jQuery assigns `xhr.onload`) | dead code + global side effect | `class-gswp-login.php:329-357` |

Plus one pre-existing hardening item in the verifier's token cache (§5).

**This is not a WordPress regression.** The three core behaviours the plugin gets
wrong (`<form method="get">` on `users.php`, the `users=` row-action parameter,
and the `send-password-reset` AJAX action name) are byte-identical across the
6.4, 6.7, 6.8 and 6.9 branches. What changed is this plugin: before v2.26.2
(Phase 54) it never enforced a token on these admin screens at all. The failures
arrived with Phases 54–56, not with a core update.

---

## 1. D1 — the row-action guard has never matched

`GSWP_Login::validate_lostpassword()` tries to exempt the per-user row action:

```php
// includes/class-gswp-login.php:497
if ( is_admin() && isset( $_GET['action'] ) && 'resetpassword' === $_GET['action'] && isset( $_GET['user'] ) ) {
    return;
}
```

Core builds that link as (`wp-admin/includes/class-wp-users-list-table.php:507`):

```php
$actions['resetpassword'] = "<a class='resetpassword' href='"
    . wp_nonce_url( "users.php?action=resetpassword&amp;users=$user_object->ID", 'bulk-users' )
    . "'>" . __( 'Send password reset' ) . '</a>';
```

The parameter is **`users`**, not `user`. `isset( $_GET['user'] )` is therefore
always false, the guard never returns, `verify_token()` runs on a GET request
that carries no `$_POST` at all, and returns `recaptcha_missing`.
`retrieve_password()` propagates that `WP_Error`, `users.php:259` never
increments `$reset_count`, and the redirect renders *"Password reset links sent
to 0 users."*

Verified against 6.4-branch, 6.7-branch, 6.8-branch and 6.9-branch — the `users=`
spelling is unchanged in all four.

## 2. D2 — the Users bulk-action form is a GET form

Even with D1 fixed, the bulk action cannot work as currently built.
`wp-admin/users.php:806-816`:

```php
<form method="get">
    <?php $wp_list_table->search_box( __( 'Search Users' ), 'user' ); ?>
    ...
    <?php $wp_list_table->display(); ?>
</form>
```

`restrict_manage_users` fires from `WP_Users_List_Table::extra_tablenav()`
(`class-wp-users-list-table.php:330`), which is inside `display()` — so
`inject_admin_users_field()` does place the hidden field inside the right form.
But that form submits by **GET**, so the token arrives as
`$_GET['g-recaptcha-response']`.

`GSWP_Verifier::verify_token()` reads only `$_POST`:

```php
// includes/class-gswp-verifier.php:285
$token = isset( $_POST['g-recaptcha-response'] ) ? sanitize_text_field( wp_unslash( $_POST['g-recaptcha-response'] ) ) : '';
```

So the bulk path returns `recaptcha_missing` on every user, every time. The
docblock at `class-gswp-login.php:385` ("restrict_manage_users fires inside the
bulk-action form, and the shared bootstrap keeps the field populated") is
accurate about the form and wrong about the transport.

Note the consequence for D1's shape: the row-action link and the bulk action are
handled by the *same* `case 'resetpassword'` in `users.php:231`, both read
`$_REQUEST['users']`, and both arrive as GET with `action=resetpassword` and a
`bulk-users` nonce. They are not distinguishable from the request, and they do
not need to be — one guard covers both.

Also note this means the v2.27.2 request-scoped token cache in `GSWP_Verifier`,
added specifically so bulk reset would not trip Google's `DUPE`, has never been
reachable on that path: the bulk request fails at the empty-token check before
any API call.

## 3. D3 — the admin inline script matches the wrong AJAX action name

`print_admin_reset_inline_js()` gates its `XMLHttpRequest.prototype.send`
interception on:

```js
// includes/class-gswp-login.php:299
body.indexOf('action=send_password_reset') === -1) {
    return origSend.apply(this, arguments);   // pass through, no token appended
}
```

Core's button handler (`wp-admin/js/user-profile.js:131`) sends:

```js
var resetAction = wp.ajax.post( 'send-password-reset', data );
```

WordPress AJAX actions are **hyphenated on the wire**; `admin-ajax.php:144` lists
`'send-password-reset'` in `$core_actions_post`, and line 166 maps it to the
handler function name by `str_replace( '-', '_', $action )`. The underscore form
`send_password_reset` is the *PHP function* name (`wp_ajax_send_password_reset()`,
`ajax-actions.php:5612`) and never appears in the request body.

So the substring never matches, the request passes through untouched, no
`g-recaptcha-response` is appended, and the server answers with the "token is
missing" message shown in the screenshot. The `waitForApi()` polling added in
v2.27.2 populates the hidden field correctly — the field value simply never
leaves the browser, because the profile form is not serialized into the AJAX
payload and the interception that was supposed to carry it is looking for a
string that does not exist.

Verified across 6.4/6.7/6.8/6.9: `wp.ajax.post( 'send-password-reset', ... )` is
unchanged.

## 4. D4 — the post-failure refresh patch is dead code

`class-gswp-login.php:329-357` patches `XMLHttpRequest.prototype.addEventListener`
to attach a `load` observer that refreshes the token after a failed response.
jQuery 3.7.1 (the version WordPress bundles) never calls `addEventListener` on
its XHR — `jquery/src/ajax/xhr.js:118-127` assigns handlers as properties:

```js
xhr.onload = callback();
errorCallback = xhr.onerror = xhr.ontimeout = callback( "error" );
if ( xhr.onabort !== undefined ) { xhr.onabort = errorCallback; }
else { xhr.onreadystatechange = function() { ... }; }
```

`wp.ajax.post()` goes through `$.ajax`, so the observer is never installed for
the request it was written for. The patch still replaces the prototype method on
**every** XHR in wp-admin (heartbeat, autosave, list-table AJAX, every other
plugin), adding a `JSON.parse` of every POST response body for no benefit.

A related hazard in the same block: the `send` override defers the real
`origSend()` into a promise. jQuery calls `xhr.abort()` on timeout
(`xhr.js:82`), and an abort during the token fetch leaves the deferred
`origSend.call()` to throw `InvalidStateError` inside a promise handler — the
request is never sent, the rejection is swallowed, and the button stays disabled
with no message.

---

## 5. Hardening item — the token cache is keyed on the token alone

Not a cause of either reported symptom; found while tracing D2.

```php
// includes/class-gswp-verifier.php:301
if ( isset( $this->token_cache[ $token ] ) ) {
    $cached                  = $this->token_cache[ $token ];
    $this->last_score        = $cached['score'];
    $this->last_token_action = $cached['token_action'];
    return $cached['result'];
}
```

The cache key ignores `$context` and `$expected_action`, but the verdict it
stores was computed against both: the action check happens inside
`assess_enterprise_token()` (skipped on a cache hit) and the threshold is read as
`gswp_threshold_ . $context`. So within a single request, a token verified once
for a permissive context satisfies a second, stricter context without either
check being re-run. The window is one PHP request and needs two verifications of
the same token in different contexts, which no current code path does — but the
cache exists precisely to make repeat verification legitimate, so the guard
should be in place before another caller is added.

---

## 6. Recommended fix

Two parts. Part A is required either way. Part B is a choice, and I recommend
option A2.

### Part A — exempt the `users.php` reset paths (fixes symptom 2)

Both `users.php` entry points are GET requests already protected by
`check_admin_referer( 'bulk-users' )` (`users.php:232`) and an `edit_users`
capability check (`users.php:234`, plus a per-user `edit_user` check at line
248). One of them is a plain `<a href>` that cannot carry a token under any
design; the other is a core-owned GET form we do not control. Enforce nothing
there and say so explicitly.

In `includes/class-gswp-login.php`, replace the guard at line 497 with a named
predicate:

```php
/**
 * Whether this request is an admin-initiated reset from the Users screen.
 *
 * Both entry points on users.php — the per-row "Send password reset" link
 * (a plain <a href> at class-wp-users-list-table.php:507) and the bulk
 * action (the list-table form, which core renders as <form method="get">
 * at users.php:806) — arrive as GET. Neither can carry a POSTed reCAPTCHA
 * token, and the row link cannot carry one at all.
 *
 * This is not a request-body opt-out of the A4 kind: the caller must
 * already hold edit_users and present a valid bulk-users nonce, both of
 * which core has verified before retrieve_password() is reached.
 *
 * @return bool
 */
private function is_users_screen_reset() {
    if ( ! is_admin() || wp_doing_ajax() ) {
        return false;
    }

    if ( ! isset( $GLOBALS['pagenow'] ) || 'users.php' !== $GLOBALS['pagenow'] ) {
        return false;
    }

    // The bulk dropdown posts `action` at the top of the table and
    // `action2` at the bottom; the row link uses `action`.
    $action  = isset( $_REQUEST['action'] ) ? sanitize_key( wp_unslash( $_REQUEST['action'] ) ) : '';
    $action2 = isset( $_REQUEST['action2'] ) ? sanitize_key( wp_unslash( $_REQUEST['action2'] ) ) : '';
    if ( 'resetpassword' !== $action && 'resetpassword' !== $action2 ) {
        return false;
    }

    if ( ! current_user_can( 'edit_users' ) ) {
        return false;
    }

    // wp_verify_nonce() rather than check_admin_referer(): core has already
    // run the latter, and re-running it would fire its action a second time
    // and wp_die() instead of returning false.
    $nonce = isset( $_REQUEST['_wpnonce'] ) ? sanitize_text_field( wp_unslash( $_REQUEST['_wpnonce'] ) ) : '';

    return (bool) wp_verify_nonce( $nonce, 'bulk-users' );
}
```

and at the top of `validate_lostpassword()`:

```php
if ( $this->is_users_screen_reset() ) {
    return;
}
```

Then remove what that exemption makes dead, so the render gate and the
enforcement gate agree (the A4 invariant, in the direction of not printing a
field we will never read):

- Delete `inject_admin_users_field()` and its `restrict_manage_users` hook
  (`class-gswp-login.php:67`, `:390-405`).
- Drop `users.php` from the `enqueue_admin_assets()` screen list
  (`class-gswp-login.php:177`).

**Consequence to accept knowingly:** admin-sent resets from `users.php` no longer
produce an Account Defender lost-password assessment, so
`GSWP_Account_Defender::store_pending()` records nothing for them and the later
`after_password_reset` annotation has nothing to annotate. That is the correct
outcome — the assessment would have described the *administrator's* browser and
IP while carrying the *target account's* `accountId`, which poisons the
behavioural model rather than informing it.

### Part B — choose one for the profile "Send Reset Link" button

#### Option A2 (recommended): exempt it too, and delete the admin JS

The profile button is the one admin path that *can* carry a POST token, but the
request already requires the `edit_user` capability and a per-user
`reset-password-for-{id}` nonce (`ajax-actions.php:5616-5621`). A reCAPTCHA v3
score adds essentially nothing on top of that: the actor is an authenticated
administrator inside wp-admin, not anonymous traffic. Against that, keeping it
costs ~160 lines of `XMLHttpRequest.prototype` patching in wp-admin, a Google
API call per click, the same misattributed Account Defender assessment described
above, and three releases of this class of bug so far.

Changes:

- Extend the predicate above (rename to `is_admin_initiated_reset()`) to also
  return true for `wp_doing_ajax()` requests where
  `$_POST['action'] === 'send-password-reset'`, `current_user_can( 'edit_user', $user_id )`
  and `wp_verify_nonce( $_POST['nonce'], 'reset-password-for-' . $user_id )`.
- Delete `print_admin_reset_inline_js()` and its `admin_footer` hook
  (`class-gswp-login.php:72`, `:186-366`).
- Delete `inject_admin_reset_field()` and its `show_user_profile` /
  `edit_user_profile` hooks (`class-gswp-login.php:65-66`, `:371-380`).
- Delete `enqueue_admin_assets()` and its `admin_enqueue_scripts` hook entirely
  (`class-gswp-login.php:64`, `:176-184`), since Part A already removed its last
  remaining screen.
- Leave `GSWP_Recaptcha_Loader::print_bootstrap()`'s `admin_print_footer_scripts`
  hook (`class-gswp-recaptcha-loader.php:108`) in place — it is inert unless some
  other integration requests the bootstrap in wp-admin, and removing it would
  regress any that does.

Net effect: `includes/class-gswp-login.php` loses roughly 200 lines, wp-admin
stops carrying a reCAPTCHA loader and an `XMLHttpRequest` prototype patch, and
both reported symptoms go away.

#### Option B2: keep enforcement on the profile button and make it work

If the operator wants the profile button scored, the fix is small — but it keeps
the prototype patching, so items 3–5 below are not optional.

1. `class-gswp-login.php:299` — match the real wire action:

   ```js
   // wp-admin/admin-ajax.php registers core actions hyphenated
   // ($core_actions_post) and derives the PHP handler name by
   // str_replace('-','_'). The body carries the hyphenated form.
   body.indexOf('action=send-password-reset') === -1) {
   ```

   Update the two docblock references at lines 191 and 279 to match.

2. Update the manual-test assertion at
   `tests/manual/29-password-reset-assets.php` ("admin reset inline JS targets
   send_password_reset") to assert the hyphenated string — as written it passes
   on the broken code and would pass on the fix too, since `send-password-reset`
   does not contain `send_password_reset`. **This assertion is why the bug
   shipped:** it was written from the PHP function name and never checked against
   a request body.

3. Delete the `XMLHttpRequest.prototype.addEventListener` patch
   (`class-gswp-login.php:329-357`) — see D4. With a fresh token minted per send
   it is redundant even if it worked.

4. Add abort safety to the deferred send:

   ```js
   var origAbort = XMLHttpRequest.prototype.abort;
   XMLHttpRequest.prototype.abort = function() {
       this._gswpAborted = true;
       return origAbort.apply(this, arguments);
   };
   ```

   and inside both `fetchToken` continuations: `if (xhr._gswpAborted) { return; }`,
   with the `origSend.call()` wrapped in `try { } catch (e) { }`.

5. Scope the script to the screens that need it. It is currently hooked to
   `admin_footer` on every admin page (`class-gswp-login.php:72`); after Part A
   the field only exists on profile screens, so gate explicitly rather than
   relying on the `querySelector` early return:

   ```php
   $screen = function_exists( 'get_current_screen' ) ? get_current_screen() : null;
   if ( ! $screen || ! in_array( $screen->base, array( 'profile', 'user-edit' ), true ) ) {
       return;
   }
   ```

Under option B2 the Account Defender misattribution described in Part A still
applies to this path; either accept it or skip `screen_lost_password()` and
`store_pending()` when `wp_doing_ajax() && 'send-password-reset' === $_POST['action']`.

### Part C — key the verifier cache on context and action

`includes/class-gswp-verifier.php`, all five cache sites (lines 301, 302, 332,
341, 352):

```php
$cache_key = $token . '|' . $context . '|' . ( is_array( $expected_action ) ? implode( ',', $expected_action ) : (string) $expected_action );
```

This keeps the v2.27.2 behaviour intact for any repeat verification within one
context — which is the only case it was built for — while preventing a verdict
computed under one context's threshold and action from satisfying another's.

---

## 7. Verification

### Static (do before handing over a ZIP)

- `php -l` on `includes/class-gswp-login.php`, `includes/class-gswp-verifier.php`.
- `node --check` on the generated inline script, if option B2 keeps one.
- `npm run build`.
- `wp eval-file tests/manual/29-password-reset-assets.php` — note the file needs
  rewriting either way: under option A2 most of its assertions describe deleted
  code, and under option B2 the action-string assertion is wrong (§6, item 2).

### Live (this is what has been missing for three releases)

Everything from Phase 54 onward has shipped on `php -l`, `node --check` and a
webpack build. None of these four defects is detectable by any of those, and
two of them (D1, D3) are single wrong strings that a lint pass will never see.
The checks below are the ones that settle it, on a site with
`gswp_enable_wp_lostpassword = 1` and Enterprise keys configured:

1. `users.php` → per-row **Send password reset** on another user → expect
   *"Password reset link sent."* and a delivered email.
2. `users.php` → select 3 users → bulk **Send password reset** → expect
   *"Password reset links sent to 3 users."* and three delivered emails.
3. `user-edit.php` for another user → **Send Reset Link** → expect the green
   *"A password reset link was emailed to …"* inline notice. Under option B2,
   also confirm in DevTools that the admin-ajax POST body carries a
   `g-recaptcha-response` value, and that clicking a second time still succeeds
   (the two-click degradation v2.27.2 was meant to remove).
4. Front-end `wp-login.php?action=lostpassword` → confirm **unchanged**: still
   scored, still blocks a low score. This is the path that must not regress —
   none of the changes above touch it, and that is the point of the check.
5. With `gswp_ad_block_lostpw` on, repeat 1–3 and confirm no admin action is
   blocked by an Account Defender label attributed to the wrong actor.
6. Check the plugin log for `recaptcha_missing` entries during 1–3; there should
   be none.

---

## 8. Risk and rollback

Every change is confined to `includes/class-gswp-login.php` plus a five-line key
change in `includes/class-gswp-verifier.php`. The front-end lost-password,
login, register and password-reset-form paths are untouched, as are all form
providers.

The one deliberate reduction in coverage is that admin-initiated resets are no
longer scored. They remain protected by capability checks and nonces, which is
what actually guards them; reCAPTCHA was never the control doing the work there.
If that trade is unacceptable, option B2 restores scoring on the single admin
path where it is technically achievable — but not on `users.php`, where core's
GET transport makes it impossible without rewriting core-owned markup.

Rollback is a revert of the single commit. Note that reverting restores the
broken state, not a known-good one: there is no released version in which these
admin paths both work and are enforced.
