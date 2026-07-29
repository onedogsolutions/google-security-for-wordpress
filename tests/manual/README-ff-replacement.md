# Verification runbook — Fluent Forms reCAPTCHA replacement (v2.23.0)

For an operator or a local LLM with PHP execution against a **staging** site.
Written to be executed without any other context.

## What changed, in one paragraph

v2.23.0 adds a Fluent Forms provider alongside the Gravity Forms one. When it is
switched on, this plugin scores every eligible Fluent Form and the operator can
then retire Fluent Forms' own captcha. **Unlike the Gravity Forms provider, it
does not switch itself on at upgrade.** Its bindings to Fluent Forms were written
from vendor documentation that could not be opened directly during development,
and this runbook is how they get confirmed before anybody relies on them. Nothing
in Fluent Forms' settings is ever written by this plugin, so turning the provider
off restores its own captcha on the very next request with nothing to re-enter.

## Before starting

- **Staging only.** Chunks 21 and 26 exercise render and validation paths.
- **Gateway in test mode** for anything involving payment (chunk 25).
- If something goes wrong at any point, switch Form Protection off in
  **Settings → Google Security → Form Protection**, or add
  `define( 'GSWP_DISABLE_FORM_PROVIDERS', true );` to `wp-config.php`.

## Chunks, in order

Run one at a time. Report each block of output verbatim before moving on.

| # | File | What it decides |
|---|------|-----------------|
| 20 | `20-ff-preflight.php` | Is the site in a state where the rest means anything, and what does the Fluent Forms detection surface actually look like? Read-only. **Stop if it fails.** |
| 21 | `21-ff-render-coverage.php` | **The important one.** Renders every form and checks our token field is in the markup. Also reports whether the render hooks fire, and whether `before`/`after_form_render` fire in balanced pairs — the buffered coverage backstop depends on that. |
| 22 | `22-ff-submission-shape.php` | **The critical one.** Which request envelope carries the token, and whether a rejection message can actually be displayed to the visitor. |
| 23 | `23-ff-native-captcha.php` | What Fluent Forms' own captcha is, where it is stored, and whether any form running a visible challenge is wrongly marked eligible. |
| 24 | `24-ff-classification.php` | Per-form payment / account / password classification, printed beside the raw evidence it was derived from. |
| 25 | `25-ff-payment-lifecycle.php` | Only if the site takes payment through Fluent Forms. **Includes the charge-timing test, the one question here that can cost a customer money.** |
| 26 | `26-ff-enforcement.php` | Offline regression guards: action pairing, coverage assertion, "Not public" semantics, provider isolation. |

### Pass criteria

- **Chunk 20** — every `OK` line, no `FAIL`. Report the DETECTION SURFACE and
  TABLES sections whatever the result: those settle bindings, not just this run.
- **Chunk 21** — `Renders passed` > 0 and `failed: 0`, and the HOOK OBSERVATION
  section shows something firing. *Nothing fired* means every hook name is wrong
  for this version; report it and do not enable the provider.
- **Chunk 22** — transport cases 1–4 all `RECOVERED`, case 5 empty, and no form
  in the REJECTION TARGET table showing `NO FIELD`.
- **Chunk 23** — no form with a non-empty CAPTCHA FIELDS column is eligible.
- **Chunk 24** — every STRICT row is one you would want to fail closed. A
  profile-edit form showing `ACCOUNT = create` is the dangerous misreading; fix
  it immediately with `gswp_ff_account_feed_type` and report the meta keys.
- **Chunk 25** — see the charge-timing test. Result (a) means blocking is safe to
  enable; result (b) means leave it off.
- **Chunk 26** — `failed: 0`. Section A failing rejects every visitor on an
  account form; section B failing blocks people for our own coverage bug.

## Enabling the provider

Only after 20–24 (and 25, if the site takes payment) come back clean:

1. **Settings → Google Security → Form Protection** → turn Fluent Forms on.
2. Load every form on the front end once, then reload the settings page. The
   "Token seen" column should read *yes* for every eligible form.
3. Submit one non-payment form from a real browser and confirm the entry is not
   flagged `gswp_unverified`.
4. Only then retire Fluent Forms' own captcha, in Fluent Forms' own settings.
   Until you do, both run and each submission is assessed twice.

## What these chunks cannot answer

1. **Token population.** They confirm the *field* is present; only a browser
   confirms JavaScript fills it. This matters more for Fluent Forms than for
   Gravity Forms, because Fluent Forms renders into the DOM after page load in
   modals and conditionals — the loader's MutationObserver is what covers that,
   and only a browser exercises it.
2. **Render paths other than the shortcode.** Chunk 21 renders through
   `[fluentform]`. If the site also uses the Gutenberg block, the Elementor
   widget, or a modal, load one of each in a browser and re-check chunk 20.
3. **Charge timing.** Chunk 25 tells you how to test it; the gateway dashboard
   is the only thing that can answer it.
4. **Whether a rejection is legible.** Chunk 22 reports which field the message
   will be attached to. Whether that reads sensibly to a customer is a judgement
   call — use `gswp_ff_error_field` to move it.

## Filters this release adds

| Filter | Purpose |
|---|---|
| `gswp_ff_account_feed_type` | Correct a form's create/update account classification without waiting for a release. |
| `gswp_ff_form_is_internal` | Declare a form programmatic in code rather than in the UI. |
| `gswp_ff_native_captcha_options` | Correct the reCAPTCHA settings option name. |
| `gswp_ff_native_other_captcha_options` | Correct the hCaptcha / Turnstile option names. |
| `gswp_ff_error_field` | Choose which field a rejection message is displayed against. |
| `gswp_ff_txn_block_allowed` | Permit blocking high-risk payments, once chunk 25 says it is safe. |
| `gswp_provider_migrates_by_default` | Override the first-release auto-enable holdback. |
