# Implementation Plan — Fluent Forms provider (parity with Gravity Forms)

**Target release:** 2.23.0
**Deliverable:** `GSWP_Provider_Fluent_Forms`, implementing `GSWP_Form_Provider`,
reaching feature parity with `GSWP_Provider_Gravity_Forms` (2.22.0).
**Status: IMPLEMENTED, UNVERIFIED.** All of §6 and §8 are written and shipped on
this branch. §5's discovery chunks are written but **have not been run** — no
part of this has met a live Fluent Forms install.

That inverts the sequencing this plan originally proposed ("§6 does not begin
until 20–23 are answered"), and the inversion is the reason §7 matters: the
provider ships **off**, `maybe_migrate()` will not switch it on, and the coverage
table reports every form's classification before anything intercepts a
submission. The discovery chunks are how it gets turned on, not a gate that was
skipped. Nothing here reaches a visitor until an operator runs
`tests/manual/20-26` and clicks the switch.

Where the code diverged from the plan, §11 records it.

---

## 0. Research access — read this first

`developers.fluentforms.com` and `fluentforms.com` are **both blocked by this
session's egress policy** (403 on CONNECT, a policy denial rather than a network
fault). Every binding below was therefore assembled from search-result excerpts
of those same pages plus facts this repository already records from the retired
Smart Key Scavenger work (`readme.txt` 2.13.x entries, `STATE.md` Phase ~30).

That is exactly the evidential position that produced Phases 43–45 and 47 — one
plugin, one version, four wrong guesses, with settings corruption as the failure
mode. So this plan does not pretend the bindings are settled. It does two things
instead:

1. Every host-plugin binding is marked **VERIFIED**, **PARTIAL** (named in
   vendor documentation, not confirmed against installed source) or
   **UNVERIFIED**, and every one of them fails to the pessimistic answer.
2. §5 is a discovery suite that runs on the operator's install and settles the
   bindings **before** §6 writes any of them into a request path.

If someone can open the docs site from an unrestricted network, §5 shrinks
considerably. It does not disappear: the docs describe hook names, not the
`$_POST` shape of an AJAX submission, and the shape is where the risk is.

---

## 1. What "the same functionality" means

The Gravity Forms surface to reach parity with, as shipped in 2.22.0:

| # | Capability | GF mechanism |
|---|---|---|
| 1 | Enumerate forms for the coverage table | `GFAPI::get_forms()` |
| 2 | Inject a hidden token field into every rendered form | `gform_submit_button` + full-markup backstop |
| 3 | Record that injection actually happened, per form | `INJECTION_OPTION`, day-throttled |
| 4 | Score the submission and reject when warranted | `gform_validation` |
| 5 | Show the visitor a truthful message | `gform_validation_message` |
| 6 | Classify: payment / creates account / updates account / changes password | feeds + field types |
| 7 | One resolver for the reCAPTCHA action, shared by render and validation | `action_for()` |
| 8 | Per-class score thresholds | `gswp_threshold_gf_*` |
| 9 | Asymmetric enforcement — strict forms fail closed, others fail open + flag | `form_is_strict()` |
| 10 | Coverage assertion — never punish a missing token on a form we never injected into | `last_injection()` |
| 11 | "Not public" operator declaration suppressing the missing-token alarm only | `INTERNAL_OPTION` |
| 12 | Per-form rejection reason, surfaced in wp-admin | `REJECTION_OPTION` |
| 13 | Detect the host plugin's own captcha, report it, never write to it | `native_captcha_state()` |
| 14 | Transaction Defense: `transactionData` on payment forms | payment feed field mapping |
| 15 | Annotate the assessment LEGITIMATE / FRAUDULENT on payment lifecycle | `gform_post_payment_*` |
| 16 | Persist assessment name + unverified flag on the entry | `gform_update_meta` |
| 17 | Reversibility — one switch restores the host plugin's own reCAPTCHA | registry, no host writes |

Items 3, 8, 9, 10, 11, 12 and 17 are **already provider-agnostic**: they live in
`GSWP_Form_Provider_Registry`, `GSWP_Verifier` and `GSWP_Recaptcha_Loader`, or
they are private option-keyed state the new provider gets by writing four
constants. Items 1, 2, 4, 5, 6, 13, 14, 15, 16 are the actual work.

---

## 2. What transfers unchanged

Confirmed by reading the existing code, not assumed:

- **The registry.** `GSWP_Form_Provider_Registry::init()` needs one line:
  `self::register( new GSWP_Provider_Fluent_Forms() );`. Kill switch, per-provider
  option (`gswp_provider_fluent_forms_enabled`), `audit()`/`audit_all()`, the
  `method_exists()`-guarded diagnostics (`form_policy`, `last_rejection`,
  `form_is_internal`) and `maybe_migrate()`'s "never overrule a stored decision"
  guard all work for a second provider with no changes.
- **The loader.** `GSWP_Recaptcha_Loader` is generic by design and already names
  Fluent Forms as a case it handles without special-casing. The footer bootstrap
  fills every `.g-recaptcha-response` on the page, refreshes before the 120 s
  expiry, watches for late-added nodes via `MutationObserver`, and refreshes on
  `visibilitychange` and on `submit`. **The MutationObserver is what makes an
  AJAX-rendered or modal Fluent Form work at all** — this is load-bearing for
  Fluent Forms in a way it never was for Gravity Forms.
- **The verifier.** `verify_token( $context, $actions, $event_extra, null, $token )`
  is already parameterised over the token string, so a provider that reads its
  token from somewhere other than `$_POST` needs nothing from it.
- **Foreign reCAPTCHA detection.** `GSWP_Foreign_Recaptcha` already labels
  `fluentform_` and `_fluentform_` option prefixes as "Fluent Forms". The
  operator notice needs no change.
- **Transaction Defense.** `GSWP_Transaction_Defense::annotate_assessment()` is
  already provider-neutral.

**Nothing in the plan below writes to a Fluent Forms option.** That prohibition
is the whole content of Phase 43–45 and is restated in the interface docblock.
Reads of Fluent Forms settings go through the same `raw_option()` pattern —
straight to `$wpdb`, never `get_option()` — so nothing we do can colour what we
report about another plugin.

---

## 3. Where Fluent Forms is genuinely not Gravity Forms

Three real differences. Everything else is renaming.

### 3.1 The submission is AJAX, so the token is probably not in `$_POST`

**This is the highest-risk item in the plan and the reason it is not a two-day
port.**

Gravity Forms posts the form natively; `$_POST['gswp_gf_token']` is simply there.
Fluent Forms submits over AJAX, serialising the form and sending it as a single
`data` parameter (**PARTIAL**: the `fluentform_submit` admin-ajax action and the
serialised-`data` envelope are consistent with the vendor's Submission Lifecycle
page, but the exact parameter name and whether 5.x has moved to a REST route are
not confirmed). If that is right, `$_POST[ TOKEN_FIELD ]` is **empty**, and a
naïve port of `validate_submission()` would read no token on every single
submission of every form.

The failure mode of getting this wrong is not subtle, and it is asymmetric in
the worst direction: every payment and account form on the site would fail
closed, permanently, for every visitor — the 2.22.0 defect again, delivered by
`maybe_migrate()` to sites that never asked for it. It is exactly why §7 gates
`maybe_migrate()` for this provider.

**Design.** One private resolver, `submitted_token()`, tried in order:

1. The `$formData` array handed to the validation filter, if our key survives
   Fluent Forms' sanitisation of unrecognised inputs (**UNVERIFIED** — Fluent
   Forms maps submitted data against the form's registered fields, and a hidden
   input we injected is not one).
2. `parse_str()` over the raw serialised envelope, if present.
3. `$_POST[ TOKEN_FIELD ]`, for any non-AJAX render path.

Returns `''` when none yields a token, which routes into the existing
coverage-assertion branch rather than into a rejection. Three transports because
we do not yet know which one is real, and a resolver that tries all three is
correct under any of them — this is the same reasoning as
`native_v3_option_candidates()`.

**The 2.17.0 rule still holds.** Reading the *token* from the request is fine;
it is request data. What must never be request-derived is the *enforcement
decision* — whether a form is strict is read from the stored form definition, so
a caller cannot opt out by omitting a field.

### 3.2 Fluent Forms' own captcha is not necessarily reCAPTCHA

`native_captcha_state()` returns one of `off` / `v3` / `v2` / `unknown`. Fluent
Forms ships **reCAPTCHA, hCaptcha and Turnstile**, all configured the same way.
None of the four return values can express "this form has a visible hCaptcha
challenge", and each available answer is wrong in a distinct way:

- `off` is a lie that would let the settings screen claim the form has no captcha.
- `v2` is behaviourally right (a visible challenge we decline to replace, so the
  form is ineligible) but reports the wrong product to the operator, who will go
  looking for reCAPTCHA settings that do not exist.
- `unknown` is honest but leaves the form *eligible*, so we would take over a
  form that is also running Turnstile.

**This is the interface stress §7.4 of `PLAN-form-provider-replacement.md` asked
us to record.** The interface did not over-fit — the classification, eligibility,
enforcement and coverage model all transfer intact — but its captcha-state enum
assumed the host's captcha is Google's.

**Recommended fix:** widen the enum with `other` — "a captcha we neither provide
nor recognise". `form_is_eligible()` then excludes `v2` *and* `other`, which is
the behaviourally correct answer, and the UI can say "hCaptcha / Turnstile"
instead of misnaming it. Cost: one `case` in `nativeLabel()` in
`FormProtection.jsx`, one docblock line in `class-gswp-form-provider.php`. The GF
provider never returns it and needs no change.

Rejected alternative: a second provider method (`native_captcha_product()`)
guarded by `method_exists()`, like `form_policy()`. That pattern is right for
*diagnostics* a provider may not have. This is not a diagnostic — it changes
whether we cover the form — and eligibility logic must not be optional.

### 3.3 Classification comes from better places

Genuinely easier than Gravity Forms, in one case:

- **Payment.** The `fluentform_forms` table carries a `has_payment` column
  (**PARTIAL** — named in the vendor's database-schema page). That is a direct,
  authoritative, one-column answer where GF has to sniff eight add-on slugs and
  fall back to pricing-field types. Keep the fallback anyway: read `has_payment`,
  and if it cannot be read, scan `form_fields` for payment field types, and if
  *that* fails, return `true` — the standing rule that an unclassifiable form is
  treated as a payment form.
- **Account.** User Registration / User Update are Pro integration feeds stored
  in `fluentform_form_meta` (**UNVERIFIED**: the `meta_key` is not confirmed; the
  create/update distinction is a feed setting whose key is not confirmed either).
  This is the direct analogue of GF's `meta['feedType']`, which is *also* still
  unverified in the GF provider. Same treatment: fail to `create` (the stricter
  answer), and ship a `gswp_ff_account_feed_type` filter so a site can correct it
  without waiting for a release. Chunk 24 (§5) prints the raw meta rows so this
  gets settled on the operator's install rather than guessed twice.
- **Password.** Same as GF: a password field type in the form's field definition.
  Read from `form_fields` (JSON) rather than an object array.

---

## 4. Bindings inventory

Everything the provider will touch, with its evidential status. **This table is
the plan's contract with §5**: nothing marked PARTIAL or UNVERIFIED reaches a
request path until a discovery chunk has printed its real value.

### Rendering

| Binding | Status | Note |
|---|---|---|
| `fluentform/form_element_start` (action, `$form`) | PARTIAL | Fires before the input elements; echoing here puts our field inside `<form>`. Primary injection point — the analogue of `gform_submit_button`. |
| `fluentform/render_item_submit_button` (action) | PARTIAL | Alternative injection point, closer to GF's. Chunk 21 decides between them. |
| `fluentform/before_form_render`, `fluentform/after_form_render` (actions, `$form`) | PARTIAL | Bracket the form. Usable to open an output buffer for the full-markup backstop. |
| `fluentform/rendering_form` (filter, `$form`) | PARTIAL | Form *object*, not markup — cannot carry the field. Useful only to observe render. |
| A filter over the finished form HTML | **UNVERIFIED / likely absent** | GF's `gform_get_form_filter` has no documented Fluent Forms equivalent. See §4.1. |

#### 4.1 The coverage backstop has to be built differently

`inject_into_markup()` is not decoration in the GF provider — with the staged
rollout gone, it is what makes coverage independent of having guessed the render
paths right. Fluent Forms appears to offer no whole-markup filter, so the
equivalent is an **output buffer** opened on `fluentform/before_form_render` and
closed on `fluentform/after_form_render`, injecting before the last `</form>` if
the primary hook did not fire.

Output buffering around a third-party render is more invasive than a filter and
can be left unbalanced by a fatal inside the form render. It is therefore
**gated**: the buffer is only opened when the primary injection point has been
observed to miss for that form, and `ob_get_level()` is checked on close. If the
levels do not match, we log the coverage gap and leave the markup alone rather
than emitting a half-buffer. Chunk 21 must confirm both actions fire, in pairs,
on every render path — shortcode, Gutenberg block, Elementor widget, conditional
and multi-step forms — before this ships.

### Validation

| Binding | Status | Note |
|---|---|---|
| `fluentform/validation_errors` (filter, 4 args: `$errors, $formData, $form, $fields`) | PARTIAL | Documented as living in `FormValidationService::validateSubmission()`. The rejection point. |
| Shape of `$errors` | **UNVERIFIED** | Believed keyed by field name → array of messages. Load-bearing; see §4.2. |
| Whether `$formData` carries unregistered inputs | **UNVERIFIED** | Decides transport 1 of `submitted_token()`. |

#### 4.2 A rejection nobody can see is worse than no rejection

Fluent Forms attaches validation errors to fields. Our token field is not a
registered Fluent Forms field, so an error keyed to it may be delivered to the
browser and then dropped, because the JS has no DOM node to attach it to. The
visitor sees the submit button spin and then stop, with nothing on screen.

That precise symptom already cost this project a debugging cycle in Phase 48 —
where it turned out to be Gravity Forms refusing on hidden required fields — and
STATE.md records the lesson: this plugin must have **no branch that hangs a
submission**. Every rejection path either shows the visitor a message or does not
reject.

So: chunk 22 must establish how Fluent Forms renders an error under an
unrecognised key. If it renders nothing, the message is attached to the form's
first visible field instead. **If neither can be made to display a message, the
provider does not reject at all on that path** — it flags the entry unverified
and logs. Failing open with a loud log beats a silent spinner, because the
spinner is indistinguishable from a site outage to the person experiencing it.

### Enumeration, classification, meta

| Binding | Status | Note |
|---|---|---|
| `fluentform_forms` table: `id`, `title`, `has_payment`, `form_fields` | PARTIAL | `form_fields` is JSON. |
| `fluentform_form_meta`: integration feeds | UNVERIFIED | `meta_key` unknown. |
| `\FluentForm\App\Helpers\Helper::setSubmissionMeta( $submissionId, $key, $value )` | PARTIAL | Documented; returns meta id or null. GF's `gform_update_meta` analogue. |
| `getSubmissionMeta` counterpart | PARTIAL | Assumed symmetric. |
| Activity check: `defined( 'FLUENTFORM' )` / `class_exists( '\FluentForm\App\Modules\Form\Form' )` | UNVERIFIED | Chunk 20 prints what actually exists. Must not rely on a namespaced `class_exists()` alone — that is the Phase 45 defect verbatim. Prefer a constant plus a table check. |

### Payment lifecycle

| Binding | Status | Note |
|---|---|---|
| `fluentform/after_payment_status_change` (5 args: `$submission, $transaction, $formId, $oldStatus, $newStatus`) | PARTIAL | One hook covers both LEGITIMATE (`paid`) and FRAUDULENT (`refunded`) — simpler than GF's two. |
| `fluentform/payment_refunded` | PARTIAL | Redundant with the above; use one, not both, or annotations double-fire. |
| Currency / total on the transaction object | UNVERIFIED | Chunk 25. Returning nothing is safe — `GSWP_Verifier` degrades to a plain score. |

### Native captcha

| Binding | Status | Note |
|---|---|---|
| `_fluentform_reCaptcha_details` | **VERIFIED** (by this repo, 2.13.x) | `readme.txt`: "keys are now read from the `_fluentform_reCaptcha_details` option that Fluent Forms actually uses". The strongest binding in this plan, because we were burned into confirming it once already. |
| `fluentform_settings` | PARTIAL | Legacy shape, retained as fallback — same reasoning as `native_v3_option_candidates()`. |
| `_fluentform_hCaptcha_details`, `_fluentform_turnstile_details` | UNVERIFIED | Naming inferred by symmetry. Drives the `other` state from §3.2. |
| Per-form reCAPTCHA *field* on the form | PARTIAL | Fluent Forms has a reCAPTCHA field type as well as global settings — so, like GF, the answer is per-form **and** global. A v2 field on a form makes it ineligible regardless of global settings. |

All of these are read through a filterable candidate list
(`gswp_ff_native_captcha_options`) so a site can correct them without a release.

---

## 5. Discovery — chunks 20–26

Extends `tests/manual/`, continuing the numbering after `19-gf-action-pairing.php`
and following its conventions: standalone PHP, no network calls, prints a
labelled block the operator pastes back. Each chunk answers questions that cannot
be answered from this repository. **20–23 must be answered before the provider
is switched on anywhere** — see the status note at the head of this document for
why they were written alongside §6 rather than before it.

- **`20-ff-preflight.php`** — Fluent Forms present? Version, Pro present, which
  constants and classes actually exist, which tables exist. Settles the
  `is_active()` binding without a namespaced `class_exists()` guess.
- **`21-ff-render-coverage.php`** — renders each form through every path
  available on the install (shortcode, block, Elementor if present, multi-step,
  conditional) and reports, per path: did `fluentform/form_element_start` fire,
  did `render_item_submit_button` fire, did `before/after_form_render` fire **in
  balanced pairs**, and is there a `</form>` in the captured markup. Decides the
  primary injection point and whether the §4.1 buffer backstop is viable.
- **`22-ff-submission-shape.php`** — the critical one. Captures a real
  submission and prints: the top-level `$_POST` keys, whether a hidden field
  injected into the form survives into `$_POST` / into the serialised envelope /
  into `$formData`, the exact `$errors` structure Fluent Forms expects, and what
  the browser displays for an error keyed to an unregistered field versus a real
  one. Settles §3.1 and §4.2 together.
- **`23-ff-native-captcha.php`** — dumps every `_fluentform_*` and `fluentform_*`
  option row verbatim (keys masked), plus per-form captcha field types. Settles
  §3.2 and the `other` state. Read-only, straight from `$wpdb`.
- **`24-ff-classification.php`** — per form: `has_payment`, the field types in
  `form_fields`, and every `fluentform_form_meta` row with its `meta_key`
  verbatim. Settles account create/update and password detection.
- **`25-ff-payment-lifecycle.php`** — for a form with payment configured, the
  shape of `$transaction` and `$submission` at `after_payment_status_change`, and
  whether the card is authorised client-side before submission. **The last
  question is not academic**: if the card is authorised in the browser, a
  server-side rejection stops the entry but not the authorisation, and the
  provider needs an explicit void step or must not block on transaction risk at
  all. This is the 2.16.0 Stripe question, asked once rather than discovered in
  production.

- **`26-ff-enforcement.php`** — the offline regression guards from §8: action
  pairing, the coverage assertion exercised behaviourally, "Not public"
  semantics, and provider isolation from Gravity Forms. Needs no network, no
  submission and no entry, and detaches the coverage-gap alert listeners so
  running it never emails the operator.

Chunks 24 and 25 gate only the Transaction Defense and account-classification
features (§6.3, §6.4), not the core provider.

---

## 6. Implementation stages

### 6.1 Interface widening (small, lands first)

- `native_captcha_state()` docblock gains `other`; `FormProtection.jsx`
  `nativeLabel()` gains the case.
- Registry: register the new provider.
- Bootstrap: `require_once` for `class-gswp-provider-fluent-forms.php`.
- No behaviour change for Gravity Forms. Verifiable in isolation.

### 6.2 Core provider — reporting only, no interception

`GSWP_Provider_Fluent_Forms` implementing `id()`, `label()`, `is_active()`,
`forms()`, `form_is_eligible()`, `form_has_payment()`, `form_is_strict()`,
`native_captcha_state()`, `last_injection()`, plus the guarded diagnostics
`form_policy()`, `last_rejection()`, `form_is_internal()`.

`register_hooks()` is a no-op at this stage.

The coverage table now shows Fluent Forms forms, their classification and their
native captcha state, with the provider off. **The operator can check every
classification against reality before anything intercepts a submission.** This
is the shadow period the 2.19.0 ladder used to provide, reduced to the one part
that was actually load-bearing, and costing nothing because the provider ships
off by default (§7).

Constants: `TOKEN_FIELD = 'gswp_ff_token'`, `INJECTION_OPTION`,
`REJECTION_OPTION`, `INTERNAL_OPTION`, `META_*` — all distinct from the GF ones,
so the two providers' state never collides.

### 6.3 Injection and validation

- `inject_token_field()` on the primary hook chosen by chunk 21, gated on
  `GSWP_Recaptcha_Loader::will_load()` and `form_is_eligible()`, calling
  `GSWP_Recaptcha_Loader::enqueue()` and `record_injection()`. Identical shape to
  the GF provider.
- The §4.1 buffered backstop, gated as described.
- `action_for()` — **one resolver, called by both `token_field()` and
  `validate_submission()`.** Not two expressions. This is the Phase 48 lesson and
  it is not re-learnable cheaply.
- `submitted_token()` per §3.1.
- `validate_submission()` on `fluentform/validation_errors`, mirroring the GF
  logic exactly: skip if already invalid; skip if ineligible; missing token →
  internal-declaration check → coverage assertion → strict/non-strict split;
  present token → verify, action-mismatch tolerance for non-strict forms, score
  check, rejection recording.
- Contexts `ff_submit`, `ff_register`, `ff_account_update`, `ff_password`,
  defaulting to 0.5 — **separate options from the GF ones**. A site tuning its
  Gravity Forms registration threshold must not silently retune Fluent Forms.
  That is the same defect 2.22.0 fixed when GF forms stopped borrowing
  `gswp_threshold_wp_register`.
- Rejection messages reuse the existing translated strings verbatim, including
  the Phase 48 correction that only a genuine low score says "spam".

### 6.4 Payments and Transaction Defense

Gated on chunk 25. If the card is authorised client-side, `gswp_txn_block` does
**not** block Fluent Forms payments — the assessment is still made and still
annotated, and the operator is told plainly in the UI why blocking is
unavailable on this provider. Scoring a payment we cannot actually stop and
claiming we stopped it is worse than not claiming it.

- `payment_context()` building `transactionData` from the payment field mapping.
- Annotation on `fluentform/after_payment_status_change` — one hook, `paid` →
  LEGITIMATE, `refunded` → FRAUDULENT, guarded by the same `META_ANNOTATED`
  double-annotation check.
- Assessment name and unverified flag persisted via `Helper::setSubmissionMeta`.

### 6.5 UI and settings

- `FormProtection.jsx` is already a loop over providers and needs no structural
  change. Two edits: the `other` native-captcha label, and the threshold dial
  block — currently hard-coded to `threshold_gf_*` — keyed off the provider id.
- The empty-state copy ("When Gravity Forms is installed…") names both plugins.
- `gf_internal_forms` gains an `ff_internal_forms` sibling in the REST read,
  write and sanitise paths. The React `internalForms` state is likewise
  currently GF-specific and must be keyed per provider.
- New threshold options registered in the REST settings allowlist.

### 6.6 Documentation

- `readme.txt` changelog and the supported-plugins list.
- `STATE.md` phase entry, including §3.2 recorded as the interface finding
  §7.4 of the prior plan asked for.
- `tests/manual/README-ff-replacement.md`, mirroring the GF one.

---

## 7. Rollout — the provider ships OFF

`maybe_migrate()` currently enables any active provider the operator has never
expressed an opinion about. **The Fluent Forms provider must be excluded from
that on its first release.**

The reasoning is specific, not general caution. `maybe_migrate()` is what
delivered the Phase 48 defect to sites that never opted into form replacement,
and it did so for a provider whose bindings had been wrong four times. The
Fluent Forms bindings are less verified than the Gravity Forms ones were at
2.20.0, and §3.1 has a plausible failure mode that closes every payment and
account form on the site. Auto-enabling that on upgrade is not a risk worth
taking to save one click.

Mechanism: a `migrates_by_default()` check in the registry loop — returning
`false` for a provider in its first release — rather than a hard-coded id list.
It flips to `true` in the release after field reports come back clean.

The operator-facing story is unchanged and honest: the coverage table shows
Fluent Forms with everything classified, the switch is one click, and turning it
off restores Fluent Forms' own reCAPTCHA on the next request because we never
wrote to it.

---

## 8. Test plan

Regression guards, added alongside the code:

- **Action pairing** — the chunk-19 equivalent for Fluent Forms: render the real
  field, compare its `data-recaptcha-action` against `action_for()`. Offline, no
  submission required, and it would have caught Phase 48 on any install. Ship it
  with §6.3, not after.
- **Token transport** — assert `submitted_token()` recovers the token from each
  of the three envelopes in §3.1, including the two that turn out not to be real.
  The point is that the resolver stays correct when Fluent Forms changes its
  transport, which it has done before.
- **Rejection visibility** — assert every rejection path produces a message the
  browser actually renders (§4.2). No silent spinners.
- **Coverage assertion** — a form never injected into is never punished.
- **"Not public"** — a declared form with a token is still scored. The Phase 48
  same-day fix, ported, because the mistake is easy to re-make.
- **Provider isolation** — enabling Fluent Forms does not alter any GF option,
  threshold or coverage row, and vice versa.
- **Reversibility** — switching off restores Fluent Forms' own captcha with no
  residue in its settings, verified by diffing its option rows before and after.

---

## 9. Non-goals

- **FluentCart.** Separate feature. It is a cart, not a form plugin, and belongs
  to the checkout-adapter work in
  `PLAN-gravity-forms-stripe-and-integration-architecture.md` §6.3, not here.
  Same vendor, but the interface is the wrong one.
- **Switching Fluent Forms' own captcha off for the operator.** Prohibited, for
  the reasons in the interface docblock. Detect, report, let the operator decide.
- **Covering forms with a visible v2 checkbox, hCaptcha or Turnstile.** Partial
  takeover is a supported end state.
- **Replacing Fluent Forms' spam protection generally** (Akismet integration,
  keyword filters). We provide reCAPTCHA scoring, not spam policy.

---

## 10. Estimate

| Stage | Work |
|---|---|
| §5 discovery chunks 20–23 | 1.0 d to write, plus an operator round-trip |
| §6.1 interface widening | 0.25 d |
| §6.2 core provider (reporting) | 0.75 d |
| §6.3 injection + validation | 1.5 d |
| §5 chunks 24–25 + §6.4 payments | 1.0 d |
| §6.5 UI + settings | 0.5 d |
| §8 tests | 0.75 d |
| §6.6 docs | 0.25 d |

**~6 days of work plus one operator discovery round-trip**, against the 2.5 d the
superseded plan estimated. The difference is §3.1, §4.1 and §4.2 — three places
where Fluent Forms' architecture differs from Gravity Forms' in ways that reach
the request path, and which the earlier estimate assumed away.

---

## 11. What the implementation changed from this plan

Recorded because a plan that silently diverges from its code is worse than no
plan.

- **Chunk numbering ran to 26, not 25.** §8's regression guards needed a home;
  they are `26-ff-enforcement.php` and they run offline. Its coverage assertion
  is behavioural — it calls `validate_submission()` on a never-injected form and
  asserts the submission is admitted — rather than the source-text inspection an
  earlier draft used. It detaches the `gswp_form_coverage_gap` listeners for the
  duration so running the test does not email the operator, which would have
  reproduced the cry-wolf problem the branch exists to prevent.

- **The buffered backstop needed a third failure mode.** §4.1 said the buffer
  refuses to close when the nesting level does not match. That is necessary but
  not sufficient: simply *returning* at that point abandons our own open buffer
  and swallows the rest of the page — a far worse outcome than the missing token
  field it was reporting. `close_backstop_buffer()` now unwinds to the level it
  found before reporting the gap.

- **`payment_context()` was implemented rather than stubbed.** The plan's own
  contract says nothing UNVERIFIED reaches a request path before discovery. This
  is the exception, and it is a principled one: the function requires billing
  region **and** postal code before it emits anything, and returns an empty
  array otherwise. The empty return is the pessimistic path — `GSWP_Verifier`
  degrades to a plain score — so an inferred field mapping that is wrong
  produces exactly the same behaviour as no mapping at all.

- **Transaction blocking is off by default, not merely "gated on chunk 25".**
  `may_block_payment()` returns false and is overridden per site with
  `gswp_ff_txn_block_allowed`. The settings screen says so in plain language:
  claiming to have blocked a payment we did not block is worse than not
  claiming it.

- **`reject()` can decline to reject.** §4.2 anticipated this; the code makes it
  explicit. When no field can be resolved to display the message, the submission
  is admitted and flagged rather than rejected, because a rejection the visitor
  cannot see is indistinguishable from a site outage.

- **Two things outside the stated scope were fixed.** The `Changes a password`
  threshold has existed as an option since 2.22.0 but was never rendered, so the
  class of form most worth tuning could only be reached through the database —
  both providers now show the dial. And `gf_internal_forms` was a single global
  list; it is now keyed per provider, because form ids are only unique within
  their own plugin and Gravity Form #3 would otherwise have silenced the alarm
  on Fluent Form #3.

- **`native_captcha_state()` never returns `off` for Fluent Forms.** Proving
  absence would mean trusting that the candidate option-name list is complete,
  and it is not confirmed. A site with no captcha configured therefore reads
  `unknown`. Noisier, but `unknown` can never let the settings screen claim
  another plugin's captcha is off while it is running. Eligibility is identical
  either way.

## 12. What remains before this can be switched on for anybody

1. Run `tests/manual/20-26` on a live install and report each block.
2. Settle the three UNVERIFIED bindings the chunks target: the submission
   transport (§3.1), the account feed meta key (§3.3), and the captcha option
   names (§4).
3. Answer the charge-timing question (chunk 25) per gateway before enabling
   `gswp_ff_txn_block_allowed`.
4. Only then remove `'fluent-forms'` from the holdback list in
   `GSWP_Form_Provider_Registry::migrates_by_default()` — and only with field
   reports to justify it, not because the code looks finished.


## Sources

Vendor documentation, reached via search-result excerpts only — the sites
themselves are blocked from this session (§0):

- [Filter Hooks | Fluent Forms Developers](https://developers.fluentforms.com/hooks/filters/)
- [Submission Lifecycle | Fluent Forms Developers](https://developers.fluentforms.com/submission-lifecycle/)
- [Fluent Forms Database Schema | Fluent Forms Developers](https://developers.fluentforms.com/database/)
- [Helper Classes | Fluent Forms Developers](https://developers.fluentforms.com/helpers/)
- [fluentform/validation_errors](https://fluentforms.com/docs/fluentform_validation_errors/)
- [fluentform/form_element_start](https://fluentforms.com/docs/fluentform_form_element_start/)
- [fluentform/before_form_render](https://fluentforms.com/docs/fluentform_before_form_render/)
- [fluentform/after_form_render](https://fluentforms.com/docs/fluentform_after_form_render/)
- [fluentform/rendering_form](https://fluentforms.com/docs/fluentform_rendering_form/)
- [fluentform/after_payment_status_change](https://fluentforms.com/docs/fluentform_after_payment_status_change/)
- [fluentform/payment_refunded](https://fluentforms.com/docs/fluentform_payment_refunded/)
- [PHP Action Hooks](https://fluentforms.com/docs/php-action-hooks/) / [PHP Filter Hooks](https://fluentforms.com/docs/php-filter-hooks/)

In-repository evidence:

- `readme.txt` (2.13.x) — `_fluentform_reCaptcha_details` confirmed against a live install.
- `STATE.md` Phases 43–48 — the binding-verification discipline this plan inherits.
- `includes/class-gswp-form-provider.php`, `…-registry.php`, `…-provider-gravity-forms.php`.
