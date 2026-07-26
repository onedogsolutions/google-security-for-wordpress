# Verification runbook — Gravity Forms reCAPTCHA replacement (v2.20.0)

For an operator or a local LLM with PHP execution against a **staging** site.
Written to be executed without any other context.

## What changed, in one paragraph

From v2.20.0 this plugin replaces Gravity Forms' own reCAPTCHA: when Form
Protection is on, GF's reCAPTCHA is switched off and this plugin scores every
eligible Gravity Form. It is enabled automatically on upgrade wherever it can
work. The risk that follows is simple — **a form this plugin fails to inject a
token field into now has no bot protection at all**, because GF's own is off.
Most of this runbook exists to detect that.

## Before starting

- **Staging only.** These chunks write plugin options and drive validation.
- **Stripe in test mode** for anything involving payment.
- If something goes wrong at any point, the immediate fix is to switch Form
  Protection off in **Settings → Google Security → Form Protection**, or add
  `define( 'GSWP_DISABLE_FORM_PROVIDERS', true );` to `wp-config.php`. Either
  restores Gravity Forms' own reCAPTCHA on the next page load; nothing in GF's
  settings was ever modified, so there is nothing to re-enter.

## Chunks, in order

Run one at a time. Report each block of output verbatim before moving on.

| # | File | What it decides |
|---|------|-----------------|
| 1 | `11-gf-preflight.php` | Is the site in a state where the rest means anything? Read-only. **Stop if it fails.** |
| 2 | `12-gf-render-coverage.php` | **The important one.** Renders every form server-side, both AJAX and standard, and checks the token field is actually in the markup. A FAIL here means that form is live and unprotected. |
| 3 | `13-gf-enforcement.php` | Are submissions handled per policy — and, critically, is a form we never injected into *allowed* rather than rejected? |
| — | `10-form-provider-takeover.php` | Optional one-shot summary of switch state, reversibility and policy. Larger; run only if the chunks above raise questions. |
| — | `09-recaptcha-coexistence.php` | Optional. Covers the v2.18.x loader work this release sits on. |

### Pass criteria

- **Chunk 1** — every `OK` line, no `FAIL`.
- **Chunk 2** — `Renders passed` > 0 and `failed: 0`. Any failure is a live
  coverage gap; report the table and switch Form Protection off.
- **Chunk 3** — all three checks PASS. The third (*never-injected form is
  ALLOWED even when it takes payment*) is the one that matters most; if it
  fails, switch Form Protection off before leaving the site.

## What still needs a real browser or the Stripe dashboard

The chunks cover rendering and validation logic. Three things they cannot:

1. **Token population.** The chunks confirm the *field* is present; only a
   browser confirms JavaScript fills it. Load one form, submit it, and confirm
   the entry is not flagged `gswp_unverified`.
2. **Stripe charge timing — the one that can cost money.** Trigger a high-risk
   rejection on a payment form and then **check the Stripe dashboard for an
   authorisation**. In some GF Stripe modes the card is authorised client-side
   before submission, in which case a server-side rejection stops the entry but
   not the hold on the customer's card. This is the single most important
   unknown in the release.
3. **Broken token generation.** Block `www.google.com/recaptcha` in the browser
   and submit: a non-payment form should still submit (entry flagged), a
   payment form should reject with a readable message.

## Known unverified areas

The Gravity Forms integration points — which hooks fire on which render paths,
the payment feed meta keys, GF's reCAPTCHA add-on option name, the payment
lifecycle actions — were written without the installed Gravity Forms source to
hand and are marked `UNVERIFIED` in
`includes/class-gswp-provider-gravity-forms.php`.

They are built to fail safe: a wrong option name means GF keeps running
alongside us rather than anything breaking, and a missed render path shows up
as a FAIL in chunk 2 rather than as a silently unprotected form. **Chunk 2 is
the check that turns those assumptions into evidence**, which is why it is not
optional.

## Reporting back

For each chunk: the verbatim output block, plus whether you stopped or
continued. If chunk 2 or 3 failed, also state whether Form Protection was left
on or switched off.
