# Verification runbook — Fluent Forms reCAPTCHA replacement (v2.23.2)

For an operator or a local LLM with PHP execution against a **staging** site.
Written to be executed without any other context.

## What changed, in one paragraph

v2.23.0 added a Fluent Forms provider alongside the Gravity Forms one. When it
is switched on, this plugin scores every eligible Fluent Form and the operator
can then retire Fluent Forms' own captcha. **It does not switch itself on at
upgrade.** Its bindings were originally written from vendor documentation that
could not be opened directly during development (2.23.0), partially corrected
against one live install (2.23.1), and then corrected against the actual
Fluent Forms and Fluent Forms Pro source directly (2.23.2) — see
`docs/plans/PLAN-fluent-forms-source-corrections.md` for the full defect list. **2.23.2
fixed eight defects, three of them in the request path**, the most serious
being that every Fluent Forms User Update (profile-edit) form was classified
as an account-creation form and rejected a signed-in visitor's own edit on a
missing token — the Phase 48 incident, reproduced. None of the 2.23.2 fixes
has run against a live install; that is what this runbook is for. Nothing in
Fluent Forms' settings is ever written by this plugin, so turning the provider
off restores its own captcha on the very next request with nothing to
re-enter.

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
| 21 | `21-ff-render-coverage.php` | **The important one.** Renders every form and checks our token field is in the markup. Also reports whether the render hooks fire, whether `before`/`after_form_render` fire in balanced pairs, and (2.23.2) reports conversational forms as unsupported rather than a false coverage gap. |
| 22 | `22-ff-submission-shape.php` | **The critical one.** Whether `gswp_ff_token` is actually on Fluent Forms' own submission allow-list (2.23.2), which envelope carries the token, and whether a rejection message can actually be displayed to the visitor. |
| 23 | `23-ff-native-captcha.php` | What Fluent Forms' own captcha is, where it is stored, whether any form running a visible challenge is wrongly marked eligible, and (2.23.2) whether a site's global reCAPTCHA keys wrongly make every form ineligible. |
| 24 | `24-ff-classification.php` | Per-form payment / account / password classification, printed beside the **verified** feed-row evidence (2.23.2: `list_id`, not the four guessed keys) it was derived from. |
| 25 | `25-ff-payment-lifecycle.php` | The payment status hook's argument order (2.23.2 regression guard), and — only if the site takes payment through Fluent Forms — the charge-timing confirmation. Blocking is **on by default** as of 2.23.2. |
| 26 | `26-ff-enforcement.php` | Offline regression guards: action pairing, coverage assertion, "Not public" semantics, provider isolation, and (2.23.2) that a rejection can never be delivered to our own token field, and that a synthetic profile-edit feed classifies as `update`. |

### Pass criteria

- **Chunk 20** — every `OK` line, no `FAIL`. Report the DETECTION SURFACE and
  TABLES sections whatever the result: those settle bindings, not just this run.
- **Chunk 21** — `Renders passed` > 0 and `failed: 0`, and the HOOK OBSERVATION
  section shows something firing. *Nothing fired* means every hook name is wrong
  for this version; report it and do not enable the provider. A row reading
  `skipped (not eligible: unsupported)` is a conversational form — expected,
  not a failure.
- **Chunk 22** — the TOKEN FIELD WHITELIST REGISTRATION table shows `yes` for
  every eligible form; transport cases 1–4 all `RECOVERED`, case 5 empty; and
  the REJECTION DELIVERY table shows no `DANGEROUS` row.
- **Chunk 23** — no form with a non-empty CAPTCHA FIELDS column is eligible,
  and any form reporting `off` genuinely has no field and no auto-include
  filter returning true (cross-check the AUTO-INCLUDE FILTERS section).
- **Chunk 24** — every STRICT row is one you would want to fail closed. **The
  one that matters this release:** any form whose only active feed has
  `list_id = 'user_update'` must show `ACCOUNT = update`, never `create`. If
  it shows `create`, this is a regression — stop and report it, do not enable
  the provider.
- **Chunk 25** — Part A: `accepted_args` reads `2`, not `5`. Part B: see the
  charge-timing confirmation. Result (a) confirms the 2.23.2 default (blocking
  on) is correct; result (b) means override with
  `gswp_ff_txn_block_allowed` returning `false` for that gateway.
- **Chunk 26** — `failed: 0`. Section A failing rejects every visitor on an
  account form; section B failing blocks people for our own coverage bug;
  section E failing means a rejection can be delivered and never seen;
  section F failing — case 1 especially — means a real customer editing her
  own profile can be rejected as spam.

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
2. **Render paths other than the shortcode, observed live.** Chunk 21 renders
   through `[fluentform]`. The Gutenberg block, Elementor widget, and Fluent
   Forms Pro's modal are now *source-verified* (2.23.2) to route through the
   same call — but that is not yet an observation on this site. If any are in
   use, load one of each in a browser and re-check chunk 20.
3. **Charge timing, observed live.** Chunk 25 is source-verified for every
   gateway shipped in Fluent Forms and Fluent Forms Pro 6.2.7 — the gateway
   dashboard confirmation in chunk 25 is what turns that into an observation
   on this site's actual gateway. A gateway from a third-party add-on was not
   examined at all.
4. **Whether a rejection is legible on screen.** Chunk 22 confirms the
   delivery *key* is safe and reports the form's placement setting; it cannot
   render a browser. See chunk 22's "HOW TO CAPTURE A REAL SUBMISSION"
   section for the manual step, including the PayPal-inline special case.
5. **The account create/update binding for a Pro version other than 6.2.7.**
   The `list_id` discriminator is verified at that version; a future Pro
   release could rename it, and the sticky `_has_user_*` fallback would
   silently absorb the difference rather than announcing it clearly.

## Filters this release adds or changes

| Filter | Purpose |
|---|---|
| `gswp_ff_account_feed_type` | Correct a form's create/update account classification without waiting for a release. |
| `gswp_ff_form_is_internal` | Declare a form programmatic in code rather than in the UI. |
| `gswp_ff_native_captcha_options` | Correct the reCAPTCHA settings option name. |
| `gswp_ff_error_field` | Choose which key a rejection message is delivered under. Refuses `TOKEN_FIELD` regardless of what this returns — see chunk 26 section E. |
| `gswp_ff_txn_block_allowed` | **2.23.2: inverted in role.** Defaults `true`. Return `false` to turn high-risk payment blocking back OFF for a gateway chunk 25's confirmation did not clear. |
| `gswp_provider_migrates_by_default` | Override the first-release auto-enable holdback. |

`gswp_ff_native_other_captcha_options` (hCaptcha/Turnstile option-name
correction) was **removed in 2.23.2** — those option names are now
source-verified rather than guessed, so there is nothing left to correct
through a filter. If a future Fluent Forms version renames them, that needs a
code change, not a filter.
