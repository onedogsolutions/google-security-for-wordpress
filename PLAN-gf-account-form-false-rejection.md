# Implementation plan — Gravity Forms account-form false rejection

**Reported symptom:** a real, known-good customer submitting the "User Profile —
Update your account information" Gravity Form in the account dashboard is
rejected with:

> **Error:** Verification failed. You have been flagged as potential spam. Please try again.

The client has spoken to this person. She is not a spammer, and the plugin is
not saying she is — that message is being shown for a condition that has nothing
to do with her behaviour or her score.

**Target releases: 2.21.2** (unblock + honest messaging + diagnosability) and
**2.22.0** (classification and threshold corrections).

---

## 1. Where the message comes from

The string is ours, not Gravity Forms'. It is emitted from exactly three places,
all in `GSWP_Verifier`:

| Site | Condition |
|---|---|
| `includes/class-gswp-verifier.php:316` | Classic siteverify returned `success: false` with any error code that is not a credential-configuration error |
| `includes/class-gswp-verifier.php:408` | Enterprise `tokenProperties.valid` is false for a reason other than `EXPIRED` / `DUPE` |
| `includes/class-gswp-verifier.php:415` | Enterprise `tokenProperties.action` does not equal the `expectedAction` we sent |

The important negative result: **a low reCAPTCHA score is not one of them.** A
score below threshold produces a different string —
"Verification score too low. Submission rejected as potential spam."
(`includes/class-gswp-verifier.php:254-257`). So whatever happened to this user,
Google did not judge her traffic as low quality. The token itself was rejected,
or its action label did not match. The message is misleading, and it caused the
client to doubt a genuine customer.

---

## 2. Root cause

### 2.1 Primary: the rendered action and the expected action disagree (deterministic)

`GSWP_Provider_Gravity_Forms` decides the reCAPTCHA action twice, in two places,
with two different expressions.

**At render** (`includes/class-gswp-provider-gravity-forms.php:653-659`):

```php
esc_attr( $this->form_has_payment( $form_id ) ? 'checkout' : 'submit' )
```

**At validation** (`includes/class-gswp-provider-gravity-forms.php:744-745`):

```php
$context = $payment ? 'checkout' : 'wp_register';
$action  = $payment ? 'checkout' : ( $this->form_creates_account( $form_id ) ? 'register' : 'submit' );
```

The browser mints the token with whatever `data-recaptcha-action` says — the
shared bootstrap reads that attribute verbatim
(`includes/class-gswp-recaptcha-loader.php:644-645`):

```js
var action = input.getAttribute('data-recaptcha-action') || 'submit';
client.execute(siteKey, { action: action })
```

So for a **non-payment form that has an active Gravity Forms User Registration
feed**:

- rendered action → `submit`
- expected action → `register`
- Enterprise assessment → `tokenProperties.action` (`submit`) `!== expectedAction`
  (`register`) → `recaptcha_failed` → **the exact message in the report**

This is not intermittent and not user-specific. On an Enterprise key, **every
submission of that form by every visitor fails, 100% of the time.** The customer
in the screenshot is simply the person who reported it.

The form in the screenshot — "User Profile / Update your account information",
rendered inside an account dashboard, collecting name, email, phone and a
professional licence number — is precisely the User Registration-feed case.
`form_creates_account()` (`includes/class-gswp-provider-gravity-forms.php:288-309`)
matches on `addon_slug === 'gravityformsuserregistration'`, which is the slug for
both *create* and *update* feeds, so a profile-update form trips it.

Note the contrast with every other integration in this plugin, all of which pair
the two correctly:

- `class-gswp-login.php:109` renders `register` / `:197` expects `register`
- `class-gswp-powerpack.php:113-114` renders `register` / `:138` expects `register`
- `class-gswp-xootix.php:41-42` renders `register` / `:152` expects `register`

The Gravity Forms provider is the only one where the two expressions were
written separately, and it is the only one that drifted.

**Why now:** `GSWP_Form_Provider_Registry::maybe_migrate()`
(`includes/class-gswp-form-provider-registry.php:169-197`) turns the Gravity
Forms provider **on automatically during upgrade** on any site with Gravity Forms
active and a site key configured. A site that had never opted in to form
replacement acquired this defect silently at the 2.20.0 upgrade. If the client
can date the onset of complaints to that upgrade window, that corroborates the
diagnosis.

### 2.2 Secondary: classic keys have no "expired token" branch

The Enterprise path treats `EXPIRED` and `DUPE` as "just try again"
(`includes/class-gswp-verifier.php:400-406`). The classic path has no
equivalent: `timeout-or-duplicate` — by far the most common siteverify failure —
falls straight through to the spam message
(`includes/class-gswp-verifier.php:304-320`).

reCAPTCHA v3 tokens expire after 120 seconds and are single-use. The bootstrap
refreshes on a 100-second timer, but only while the tab is visible
(`class-gswp-recaptcha-loader.php:694-698`), and the `visibilitychange` refresh
is asynchronous with no submit interception for Gravity Forms — the submit
interceptor only matches `form.login, form.register`
(`class-gswp-recaptcha-loader.php:733-748`). The report is from a phone. A mobile
user who fills a long form, backgrounds the tab, returns and taps Submit
immediately can post a stale token, and on a classic key gets accused of spam
for it.

This is a second, independent path to the same wrong message, and it will
survive the fix in §2.1 unless addressed.

### 2.3 Tertiary: nothing is logged when a submission is rejected

`recaptcha_failed` returns a `WP_Error` and writes nothing anywhere. Not the
`error-codes` from siteverify, not the Enterprise `invalidReason`, not the
observed-vs-expected action. The operator sees a customer complaint and has no
way to distinguish five materially different causes.

That is why this ticket arrived as "is she a spammer?" rather than "form #N is
rejecting on action mismatch". Diagnosability is part of the defect.

### 2.4 Also wrong: every non-payment form is scored under the WP registration threshold

`$context = $payment ? 'checkout' : 'wp_register'`
(`class-gswp-provider-gravity-forms.php:744`) means every non-payment Gravity
Form on the site — contact forms, enquiry forms, and this logged-in
profile-update form — is scored against `gswp_threshold_wp_register`.

A site that raised that threshold to fight fake signups is silently applying
signup-grade strictness to its contact forms, and judging an **already
authenticated** user editing her own profile as if she were a stranger creating
an account. This produces the "score too low" message rather than the one
reported, so it is not the cause here — but it is the same class of false
positive and belongs in the same pass.

---

## 3. Immediate mitigation (no code, today)

In order:

1. **Confirm the branch.** Read the recent-events tail (plugin admin panel), or
   WooCommerce → Status → Logs, source `gswp`, or the PHP error log. If nothing
   is there, that is expected — see §2.3 — and step 2 stands alone.
2. **Check the key type** in the plugin settings. If it is **Enterprise**, and
   the form has an active User Registration feed, §2.1 is confirmed without
   further evidence: the failure is deterministic.
3. **Unblock now.** Turn the Gravity Forms provider off — option
   `gswp_provider_gravity_forms_enabled` → `0`, via the settings screen. Gravity
   Forms' own reCAPTCHA resumes on the very next request and nothing needs
   undoing; this plugin never writes to GF's settings (that mechanism was removed
   in 2.21.0). If wp-admin is unreachable, `define( 'GSWP_DISABLE_FORM_PROVIDERS', true );`
   in `wp-config.php` does the same for all providers.
4. **Confirm with the customer** that the form now submits, so the fix below is
   validated against a real reproduction rather than a theory.

Turning the provider off is the right call until 2.21.2 ships. It does not leave
the forms unprotected — it hands them back to Gravity Forms' own reCAPTCHA.

---

## 4. Code changes

### Chunk A — one source of truth for the action (2.21.2, required)

Add a single resolver to `GSWP_Provider_Gravity_Forms` and use it on both sides:

```php
/**
 * The reCAPTCHA action for a form. Called at render to label the token and
 * at validation to check it, so the two can never disagree — the divergence
 * between these two decisions is what rejected every account form.
 */
private function action_for( $form_id ) {
    if ( $this->form_has_payment( $form_id ) ) {
        return 'checkout';
    }
    if ( $this->form_creates_account( $form_id ) ) {
        return 'register';
    }
    return 'submit';
}
```

- `token_field()` (`:653-659`) uses `$this->action_for( $form_id )`.
- `validate_submission()` (`:745`) uses `$this->action_for( $form_id )`.

Delete both ternaries. The point is not to correct one of them — it is to make
it structurally impossible for them to drift again.

**Memoize.** `action_for()` now calls `GFAPI::get_feeds()` on the render path.
`form_has_payment()` already does, so this is not a new cost class, but add a
per-request static cache keyed by form id across `form_has_payment()`,
`form_creates_account()` and `action_for()` so a page with several forms does not
re-query per render hook.

**Cached-page grace.** A page cached before the fix still carries
`data-recaptcha-action="submit"` on an account form. For one release, accept a
token whose action is `submit` where `register` was expected, on **non-payment
forms only**, and log it at warning level. This is not a bypass: both labels are
strings we mint ourselves, the token still has to be valid for our site key and
still has to clear the score threshold, and an attacker gains nothing by
preferring one of our own labels over the other. Payment forms get no such
latitude. Remove the allowance in 2.22.0.

### Chunk B — stop calling non-spam failures spam (2.21.2)

Split the single message by cause, in `GSWP_Verifier`:

| Cause | Classic code | Enterprise reason | New behaviour |
|---|---|---|---|
| Stale / reused token | `timeout-or-duplicate` | `EXPIRED`, `DUPE` | "Your verification expired. Please try again." **New for classic** — see §2.2 |
| Client could not produce a token | `browser-error` | `BROWSER_ERROR` | Same retry message; not a judgement about the visitor |
| Site key / host mismatch | `invalid-input-response`, hostname mismatch | `SITE_MISMATCH` | Log at **error** level with the masked site key; keep blocking, honest message |
| Action mismatch | n/a (classic does not check) | — | Log at error level with observed vs expected; see Chunk A2 |
| Genuine low score | — | — | Unchanged (`:254-257`) — this is the only place a spam judgement is honest |
| Anything else | — | — | "We could not verify this submission. Please try again." No spam accusation |

**Do not fail open on `SITE_MISMATCH`**, despite the precedent at `:307-314`
where a bad *secret* fails open. The reasoning does not transfer: our stored
secret is not attacker-controllable, but a token minted against an attacker's own
site key is. Failing open there would let anyone with a reCAPTCHA account walk
past verification. Log it loudly instead — now that §2.3 is fixed, the operator
will see it.

### Chunk A2 — an action mismatch must not silently block a human (2.21.2)

Even after Chunk A, a mismatch can still occur legitimately: a stale cached page,
another plugin's bootstrap filling our field first, a form that gains a
User Registration feed after render. Today that is a hard block with a spam
accusation and no log line.

- Give it its own error code, `recaptcha_action_mismatch`, distinct from
  `recaptcha_failed`, and record the observed action on the verifier so callers
  can report it (alongside the existing `get_last_assessment_name()` /
  `get_last_context()` accessors).
- In `validate_submission()`, apply the policy already used for a missing token
  (`:693-742`): **strict** forms (payment or account-creating) reject with an
  accurate message; **non-strict** forms fall through to the score check, are
  admitted, and the entry is flagged `gswp_unverified` exactly as the existing
  fail-open path does.

Note plainly: this does **not** fix the reported case on its own. The form in the
screenshot is strict, so it would still be blocked — just honestly, and with a
log line naming the cause. Chunk A is the fix; A2 is what turns the next
misconfiguration into a diagnosis instead of a support ticket.

### Chunk C — log every rejection with its reason (2.21.2)

Every rejection path in `GSWP_Verifier` gets a `GSWP_Log::warning()` (or
`error()` for configuration causes) carrying: context, expected action, observed
action, `invalidReason` or `error-codes`, score against threshold, and the masked
site key. `GSWP_Provider_Gravity_Forms` adds the form id.

This is the change that would have made the original report self-diagnosing.

### Chunk D — dedicated thresholds per form class (2.22.0)

Replace the `wp_register` reuse at `:744` with contexts of our own:

| Form class | Context (threshold option) | Action | Strict? |
|---|---|---|---|
| Takes payment | `checkout` (`gswp_threshold_checkout`) | `checkout` | yes |
| Creates an account | `gf_register` (`gswp_threshold_gf_register`) | `register` | yes |
| Updates an account | `gf_account_update` (`gswp_threshold_gf_account_update`) | `account_update` | no |
| Everything else | `gf_submit` (`gswp_threshold_gf_submit`) | `submit` | no |

All new thresholds default to `0.5`, matching every other context. Surface them
in the settings UI and REST payload alongside the existing ones
(`includes/class-gswp-admin.php:99-122`, `includes/class-gswp-rest-api.php:79-102`).

`account_update` is already an accepted Account Defender context in the verifier
(`class-gswp-verifier.php:953-961`), so it slots in without widening that list.

### Chunk E — a logged-in user editing her own profile is not a signup (2.22.0)

Split `form_creates_account()` by feed type:

- `form_creates_account()` → true only for User Registration feeds of type
  **create**
- `form_updates_account()` → true for feeds of type **update**
- `form_is_strict()` (`:318-320`) = payment **or** creates-account. An update feed
  is scored but never hard-rejected for a missing token.

Rationale: WordPress has already authenticated the person editing her own
profile. reCAPTCHA is defence in depth there, not the gate, and refusing a
logged-in user access to her own account details is a worse outcome than
admitting an unscored profile edit.

> **UNVERIFIED against installed source.** The Gravity Forms User Registration
> feed's type is expected at `meta['feedType']` with values `create` / `update`.
> This must be confirmed on the live install before shipping, per this file's
> standing rule. **Guard:** if the feed type cannot be read, assume `create` —
> the stricter answer, and identical to today's behaviour.

### Chunk F — make it visible in wp-admin (2.22.0)

Add to the coverage report (`GSWP_Form_Provider_Registry::audit()`, `:210-257`),
per form: the resolved action, the resolved threshold context, and the most
recent rejection reason. The operator should be able to answer "why is form #12
rejecting?" from the settings screen without reading a log.

---

## 5. Test plan

New chunk **`tests/manual/19-gf-action-pairing.php`**, in the existing house
style (run context header, no network calls, no entries created):

1. **The regression guard.** For every eligible form, assert that the
   `data-recaptcha-action` value `token_field()` renders is identical to the
   action `validate_submission()` would send. This is a pure local comparison —
   it catches the reported defect with no Google round trip and no test
   submission.
2. Assert each form's resolved threshold context maps to an option that exists.
3. Print each form's User Registration feed type, so Chunk E's UNVERIFIED
   binding is confirmed against the live install rather than assumed.

Extend **`tests/manual/13-gf-enforcement.php`** with two cases:

- account-**create** form, no token → **rejected** (unchanged policy)
- account-**update** form, no token → **allowed**, entry flagged (Chunk E)

Manual verification on staging, in this order:

1. Reproduce first: submit the profile form on Enterprise keys with the current
   build and capture the failure. A fix validated against a defect nobody
   reproduced is a guess.
2. Apply Chunk A, resubmit, confirm success.
3. Confirm the log now names the cause for a deliberately mismatched action
   (Chunks A2 + C).
4. Confirm a payment form still rejects a missing token (no regression in the
   property that matters most).

---

## 6. Release sequencing

**2.21.2 — Chunks A, A2, B, C.** No new options, no schema change, no settings
UI. This is the release that unblocks the customer and makes the next failure
diagnosable. It should ship on its own.

**2.22.0 — Chunks D, E, F.** New threshold options, changed form classification,
settings UI. Gated on confirming the `feedType` binding against the installed
Gravity Forms source (§4, Chunk E).

---

## 7. Out of scope

- The mobile submit-race in §2.2 (returning to a backgrounded tab and submitting
  before the async refresh completes) is *mitigated* by Chunk B — the user gets
  an accurate "expired, try again" instead of a spam accusation — but not
  eliminated. Extending the bootstrap's submit interceptor to cover Gravity Forms
  submissions is a separate change with its own render-path risk, and should be
  planned once 2.21.2 has confirmed how often this actually fires.
- The auto-enable-on-upgrade behaviour in
  `GSWP_Form_Provider_Registry::maybe_migrate()` is what put this defect on a
  live site without the operator opting in. Whether that should continue is worth
  a decision, but it is a policy question, not part of this correction.
