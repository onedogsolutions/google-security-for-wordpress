# AALP support ticket: "the spam something has expired"

Investigation of the reported login failure on the AALP PowerPack login form, and of
the "Require 2FA on suspicious logins" feature it was attributed to.

**Short answer.** The suspicious-login 2FA step-up is not the cause and is not buggy —
on a site with no 2FA-enrolled users it is a complete no-op, and it cannot produce a
code prompt for a user who has not enrolled. The message Angela saw is
`recaptcha_expired`, and there **is** a real defect behind it: after any rejected login
attempt on an AJAX login form, the spent single-use reCAPTCHA token stays in the form
and is resubmitted, so every retry for up to 100 seconds fails with "Anti-spam
verification expired" regardless of what the visitor does. That is why two attempts
failed and why it then "just worked" a few minutes later.

---

## 1. Mapping the client's words to actual strings

There are exactly four visitor-facing reCAPTCHA messages in the plugin. Only one
mentions spam *and* expiry:

| Reported as | Actual string | Source |
| --- | --- | --- |
| "the spam something has expired" | `<strong>Error:</strong> Anti-spam verification expired. Please try again.` | `includes/class-gswp-verifier.php:411` (classic), `includes/class-gswp-verifier.php:531` (Enterprise) |

For completeness, the others are "Anti-spam verification token is missing…"
(`class-gswp-verifier.php:271`), "Verification score too low. Submission rejected as
potential spam." (`:296`), and "We could not verify this submission…" (`:430`, `:550`,
`:557`). None of them mention expiry.

The 2FA challenge message is `Enter the code from your authenticator app to finish
signing in.` (`includes/class-gswp-two-factor.php:508`). It says nothing about spam, so
it is not what was quoted — though it is possible Angela saw both, and "giving her a
code" may be describing the error message rather than a 2FA prompt. Section 2 shows
that on this site's configuration it cannot have been a 2FA prompt.

`recaptcha_expired` is returned in exactly three situations, all of them about the
token and none of them a judgement about the visitor:

- Enterprise: `invalidReason` is `EXPIRED`, `DUPE`, or `BROWSER_ERROR`
  (`class-gswp-verifier.php:526`)
- Classic: `error-codes` contains `timeout-or-duplicate`
  (`class-gswp-verifier.php:406`)

`DUPE` — a token already spent on an earlier request — is the one that matters here.

---

## 2. Is the suspicious-login 2FA step-up a bug?

No. I traced the whole path; the implementation matches its documentation and its admin
copy, and it is inert on this site.

**What the toggle actually does.** `gswp_ad_step_up` has exactly one effect: it sets a
request-scoped flag when Google returns a `SUSPICIOUS_LOGIN_ACTIVITY` label
(`includes/class-gswp-account-defender.php:220-223`), and that flag is read in exactly
one place — the trusted-browser bypass inside the 2FA challenge:

```php
// includes/class-gswp-two-factor.php:481
if ( $this->is_trusted_device( $user->ID ) && ! $this->step_up_forced() ) {
    return $user;
}
```

So its only behavioural effect is: *a user who has 2FA enrolled and previously ticked
"Remember this browser" is challenged anyway when the login looks suspicious.* That is
precisely what it is for.

**Why it cannot have prompted Angela.** The challenge method returns early before any of
this for a user with no second factor:

```php
// includes/class-gswp-two-factor.php:462-465
public function enforce_second_factor( $user, $username, $password ) {
    if ( ! ( $user instanceof WP_User ) || ! self::user_has_2fa( $user->ID ) ) {
        return $user;
    }
```

The full precondition chain for a step-up to change anything is:

1. `gswp_key_type` is `enterprise`, and
2. `gswp_account_defender` is `1`, and
3. Account Defense is enabled *on the key in the Google Cloud console* (see
   `readme.txt:65` — without it Google returns no labels at all), and
4. Google actually returned `SUSPICIOUS_LOGIN_ACTIVITY` for this attempt, and
5. `gswp_ad_step_up` is `1`, and
6. **the user has already enrolled in 2FA**, and
7. the user is on a browser they previously marked as trusted.

Break any link and the toggle does nothing. On a site where no roles are enforced and
nobody has enrolled voluntarily, condition 6 fails for everyone, so `gswp_ad_step_up`
is dead code — it cannot block, prompt, or delay a single login.

**The admin copy is accurate**, which is worth noting since it would be the natural
place for this to mislead: *"When a login is flagged as suspicious, force the two-factor
challenge for users who have 2FA enrolled. Users without 2FA are logged only, never
blocked."* (`src/components/AccountDefender.jsx:117`). No change needed.

**Verdict: leave it on.** It is correct, it is cheap, and it costs nothing today. The
only thing worth knowing is that it will not do anything until people are actually
enrolled — so it should not be treated as a control that is currently protecting
anything.

---

## 3. What actually went wrong: spent tokens are resubmitted

reCAPTCHA v3 tokens are **single use** and live 120 seconds. Google returns `DUPE` the
second time it sees one, which the plugin correctly surfaces as "Anti-spam verification
expired."

On the PowerPack login form, the token is verified **before** authentication:

```php
// includes/class-gswp-powerpack.php:241-253  (hooked to pp_login_form_process_login_errors)
public function validate_login( $validation_error, $user_login = '', $user_password = '' ) {
    ...
    $result = $this->verifier->verify_token( 'wp_login', 'login', array(), $identifier );
```

That filter runs before `wp_signon()`. **So the token is consumed on every attempt,
including attempts that then fail for an unrelated reason** — a typo'd password, a held
2FA login, anything.

Now look at what maintains the token in the browser. The shared bootstrap
(`includes/class-gswp-recaptcha-loader.php:605-802`) refreshes every
`.g-recaptcha-response` field:

- once on page load (`:692`)
- on a 100-second interval, and only while the tab is visible (`:694-698`)
- on `visibilitychange` back to visible (`:701-705`)
- when a **new** `.g-recaptcha-response` node is inserted into the DOM (`:716-719`)
- when a WooCommerce error notice appears — checkout only (`:720-723`, `:758-761`)

and there is a submit-time fallback that only fires when the field is **empty**:

```js
// includes/class-gswp-recaptcha-loader.php:733-748
document.addEventListener('submit', function(e) {
    var form = e.target;
    if (!form.matches || !form.matches('form.login, form.register')) {
        return;
    }
    var input = form.querySelector('.g-recaptcha-response');
    if (input && !input.value && api()) {
```

Neither condition helps here. The PowerPack login form is not `form.login` or
`form.register`, and after a failed attempt the field is not empty — it holds the old,
now-spent token. The form is submitted over AJAX and stays in the DOM, so nothing is
re-inserted.

The two WooCommerce-specific paths are structurally dead on this site — **AALP has no
WooCommerce installed** — so of the five refresh triggers only three can ever fire here:
the 100-second interval, `visibilitychange`, and DOM insertion. None of them is tied to
a submission, which is the only event that actually spends a token.

**Result: after any rejected login attempt, the same spent token sits in the form until
the 100-second interval happens to fire.** Every retry inside that window is
deterministically rejected with "Anti-spam verification expired", no matter what the
visitor types.

This is a regression in behaviour relative to `wp-login.php`, which does not have the
bug — its own inline script fetches a fresh token on *every* submit and resubmits
(`includes/class-gswp-login.php:445-464`) — and relative to the Blocks checkout script,
which explicitly refreshes on the edges of the processing state because "single-use
tokens need a fresh one for retries" (`STATE.md:617`). The generic front-end bootstrap
is the one place that never got the equivalent.

### The reported sequence, explained

1. Angela submits the login form. The token is spent by `validate_login`. The attempt
   fails for some reason — most likely a mistyped password; the ticket does not say, and
   it does not matter to the diagnosis.
2. She retries within 100 seconds. The form still carries the spent token → Google
   returns `DUPE` → **"Anti-spam verification expired."** This is the message she
   reported, and it is now unrelated to whatever she types.
3. She retries again, still inside the window → same message.
4. She calls Michelle. During the call, the 100-second interval fires (or she switched
   tabs and back, firing the `visibilitychange` refresh, or she reloaded the page).
   A fresh token is minted.
5. Her next attempt succeeds — "before I could do so it just worked for her."

Michelle's puzzlement is well founded: from the user's side nothing changed, and nothing
she did fixed it. Time did.

Ryan's read — "the page needs a refresh to reload the captcha to attempt a login" — is
exactly right about the mechanism. The fix is to make that refresh unnecessary.

### One assumption to confirm

I could not verify against PowerPack's own source (not in this repo) that its Login Form
module leaves the hidden input in place when it renders an inline error. `STATE.md:514`
and `includes/class-gswp-powerpack.php:6-11` document that the module serializes with
`FormData` and never reloads, which strongly implies it. If it *does* re-render the
field, the MutationObserver would catch it — but only after a 250 ms debounce plus a
network round trip to Google, which an impatient second click still beats. The fix below
is correct either way.

---

## 4. How to confirm this on the live site

The plugin already logs exactly what is needed. `log_rejection()`
(`includes/class-gswp-verifier.php:322-345`) writes at warning level via `GSWP_Log`.

**AALP has no WooCommerce**, so the usual WooCommerce → Status → Logs viewer does not
exist here. `GSWP_Log::write()` (`includes/class-gswp-log.php:81-102`) falls back for
exactly this case — it is the configuration the class was written for
(`includes/class-gswp-log.php:5-12`). Two sinks are available:

1. **The PHP error log.** Warnings are written unconditionally on a non-WooCommerce
   site — the `WP_DEBUG` gate applies only to `info` level — prefixed `GSWP [warning]`.
   Wherever the host writes `error_log()` output (often `wp-content/debug.log`, or the
   host's PHP error log).
2. **The in-database tail**, the last 50 events, in the `gswp_log_tail` option:
   ```
   wp option get gswp_log_tail --format=json
   ```
   Nothing in the admin UI reads this yet (see the note below), so WP-CLI or a DB query
   is the only way in. On this site it is likely the easier of the two.

Look for lines from around the time of the call:

```
reCAPTCHA rejected a submission: token not usable. context=wp_login expected_action=login invalidReason: DUPE site_key=...
```

- `invalidReason: DUPE` confirms this diagnosis exactly — a resubmitted spent token.
- `invalidReason: EXPIRED` means the page sat open too long instead; the same fix
  applies, with the `pageshow` handler in step 4 below being the relevant part.
- `score below threshold` would mean something different and we should revisit.

If the step-up did fire, there will also be
`Account Defender flagged SUSPICIOUS_LOGIN_ACTIVITY; 2FA step-up requested.`
(`includes/class-gswp-account-defender.php:222`). I would expect this to be absent.

**Follow-up worth scheduling:** `GSWP_Log::tail()` (`includes/class-gswp-log.php:133`)
is never called anywhere — not in the REST API, not in `Diagnostics.jsx`. The tail is
written and then unreadable without WP-CLI. That is tolerable on a WooCommerce site with
its own log viewer; on a site like this one it means the plugin's own record of what it
rejected is effectively invisible to the operator. Surfacing the tail on the Diagnostics
tab is a small, self-contained improvement and answers precisely the "what happened to
my customer ten minutes ago" question this ticket is.

---

## 5. Implementation plan

All changes are in `get_bootstrap_js()` in
`includes/class-gswp-recaptcha-loader.php`. No PHP behaviour, no options, no admin
surface, no build step — the bootstrap is inline JS printed from PHP, so `src/` and
`build/` are untouched.

**1. Treat a submitted token as spent.** Add a helper that blanks a field's value and
queues a refresh:

```js
function markSpent(input) {
    if (input && input.value) {
        input.value = '';
        queueRefresh();
    }
}
```

Blanking matters as much as refetching: it re-arms the existing empty-field submit
fallback, and it guarantees a resubmit inside the refresh round trip fails as
`recaptcha_missing` ("please refresh the page") rather than as a spam accusation.

**2. Refresh after every submit, on any form carrying a token field.** Widen the
existing capture-phase `submit` listener from `form.login, form.register` to any form
containing `.g-recaptcha-response`, and schedule `markSpent` on the next tick so the
current submission still serializes the valid token:

```js
document.addEventListener('submit', function(e) {
    var form = e.target;
    if (!form.querySelector) { return; }
    var input = form.querySelector('.g-recaptcha-response');
    if (!input) { return; }

    // Existing behaviour: a missing token blocks a standard submit until we have one.
    if (!input.value && api()) {
        e.preventDefault();
        e.stopPropagation();
        var submit = function() { form.submit(); };
        fetchToken(input).then(submit, submit);
        return;
    }

    // New: the token just left with this request. Replace it for the next attempt.
    setTimeout(function() { markSpent(input); }, 0);
}, true);
```

Keep the `preventDefault`/`form.submit()` branch scoped to `form.login, form.register`
as today if we want zero risk of altering an unrelated non-AJAX form's submit path; the
post-submit refresh is the part that must be universal.

**3. Backstop for modules that never emit a `submit` event.** Some modules bind a click
handler on the button and `preventDefault` there, so no `submit` event fires. When
jQuery is present, refresh spent tokens whenever any AJAX request completes — outside
the WooCommerce checkout form, which already has its own handling:

```js
$(document).on('ajaxComplete', function() {
    var inputs = document.querySelectorAll('.g-recaptcha-response');
    for (var i = 0; i < inputs.length; i++) {
        if (!inputs[i].closest('form.woocommerce-checkout')) {
            markSpent(inputs[i]);
        }
    }
});
```

An extra token mint is harmless — `grecaptcha.execute` is designed to be called freely,
and the field is only read at submit time.

**4. Handle bfcache restores.** The bootstrap has no `pageshow` handler (the 2FA modal
script at `assets/js/gswp-2fa-modal.js:262` does). A back-button restore resurrects a
page whose token expired while it was frozen:

```js
window.addEventListener('pageshow', function(e) {
    if (e.persisted) { refreshAll(); }
});
```

**5. Regression-guard the checkout.** `clearCheckoutTokens()` and the
`updated_checkout` / `checkout_error` / `checkout_place_order` bindings stay exactly as
they are. Step 3 explicitly skips checkout fields so the two mechanisms cannot fight.

### Verification

- Unit-level: none available — this is browser behaviour in inline JS with no test
  harness in the repo.
- Staging (requires the operator's Beaver Builder + PowerPack site, same constraint
  noted for Phase 26 at `STATE.md:522`):
  1. PowerPack login form, deliberately wrong password, then immediately retry with the
     correct one. **Before:** second attempt shows "Anti-spam verification expired."
     **After:** second attempt logs in.
  2. Same on the Xootix Login/Signup Popup — it uses the same bootstrap
     (`includes/class-gswp-xootix.php:228-229`) and has the identical gap.
  3. `wp-login.php`: unchanged, it uses its own inline script.
  4. Gravity Forms AJAX form: failed validation → retry still works. GF re-renders the
     form so the MutationObserver already covered it; confirm nothing double-fires.
     This is the retry path that matters most on a Gravity-Forms-and-no-WooCommerce
     site, so it carries the regression risk that checkout would carry elsewhere.
- Check the log after each (`wp option get gswp_log_tail --format=json`, or the PHP
  error log): no `invalidReason: DUPE` lines should remain.
- **Not testable on this site:** the WooCommerce checkout regression case. The
  checkout bindings are untouched by this change and step 3 of the plan explicitly
  skips checkout fields, but the plugin ships to WooCommerce sites, so this needs a
  separate Woo staging install before release — it cannot be signed off from AALP.

### Scope

| Affected | Not affected |
| --- | --- |
| PowerPack Login Form (the reported case) | `wp-login.php` — has its own submit-time refresh |
| PowerPack Registration / Lost Password | WooCommerce Blocks checkout — has its own script |
| Xootix Login/Signup Popup | Anything server-side: no PHP logic, options, or REST changes |
| Any AJAX form using the shared bootstrap | The 2FA step-up — no change proposed |

Version bump to 2.22.1 (patch: bug fix, no new surface) across the main plugin header,
`GSWP_VERSION`, `readme.txt` stable tag + changelog, and `package.json`.

---

## 6. Reply to send to Michelle

> Thanks for passing this along — that was worth reporting, and Angela didn't do
> anything wrong.
>
> The message she saw was our anti-spam check, not a password problem. Every login
> attempt uses a one-time security token, and after a failed attempt the page was
> holding onto the used one instead of getting a new one. So her second try got rejected
> for the token rather than for anything she typed. The page fetches a fresh token
> automatically about every minute and a half, which is why it started working on its
> own while you were on the phone — nothing you or she did fixed it, it just came round.
>
> It also means a password reset wouldn't have helped, so good instinct holding off.
>
> We've found the cause and have a fix. If it happens to anyone else before that ships,
> reloading the login page and trying again will clear it immediately.
