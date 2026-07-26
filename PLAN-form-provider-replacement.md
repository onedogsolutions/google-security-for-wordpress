# Implementation plan — become the reCAPTCHA implementation for third-party form plugins

**Decision (2026-07-26):** this plugin replaces Gravity Forms' own reCAPTCHA
rather than coexisting with it, and the same approach extends to Fluent Forms and
subsequent form plugins. Rationale: the product is a Google Security *suite*, and
a suite that shares bot-scoring duty with three other implementations has no
coherent policy, no unified signal, and a permanent conflict surface.

**Supersedes `PLAN-gravity-forms-stripe-assessment.md`.** S5a (Transaction Defense
on GF Stripe payments) is no longer a standalone feature — it becomes stage 2 of
this plan, §7.2. That document remains useful for its dead-end analysis (§2) and
its transaction-data design, both of which carry over unchanged.

**Releases: 2.19.0 → 2.22.0.** Four stages, each independently shippable, with the
irreversible-feeling step deliberately last and gated on evidence.

---

## 1. What changes, and the risk that comes with it

Today Gravity Forms scores its own submissions and we score ours. After this work,
**we score Gravity Forms' submissions and GF's reCAPTCHA is switched off.**

That is a genuine transfer of responsibility, and it must be stated plainly
because it drives every design decision below:

> When this plugin misbehaves, Gravity Forms forms are affected. Today GF's own
> reCAPTCHA is a backstop; after replacement there is no backstop.

This is not hypothetical. In 2.16.0 this plugin broke GF's Stripe element, and its
emergency fix would have hard-failed WooCommerce submissions with "token missing" —
both while GF's implementation was still present and protecting GF's forms.

Five structural mitigations, each specified below, and none optional:

| Risk | Mitigation |
|---|---|
| We miss a form and it silently loses protection | **Coverage audit** (§4) — enumerate every form, prove coverage before takeover |
| A JS failure stops customers submitting | **Asymmetric enforcement** (§5) — fail-open on non-payment forms, fail-closed only where money is at stake |
| We take over before we are ready | **Staged takeover** (§6) — Shadow → Active → Sole, advancement gated on evidence |
| Something goes wrong in production | **Kill switch** (§8) — one option reverts all interception without deactivating the plugin |
| A form type we cannot cover | **Eligibility gating** (§4.3) — ineligible forms keep GF's reCAPTCHA, permanently if need be |

## 2. Cost: replacement is roughly cost-neutral

Worth correcting a framing from the superseded plan, which assumed permanent
coexistence and therefore permanent double assessment.

| State | Assessments per GF submission |
|---|---|
| Today | 1 (GF's, carrying no useful data) |
| Transitional (stage 2–3) | 2 (GF's + ours) |
| **Sole (stage 4)** | **1 (ours, carrying transaction data and annotated)** |

So the end state costs the same as today and produces materially better signal.
Only the transition period doubles, and it is bounded. This materially strengthens
the case for replacement over coexistence.

## 3. Architecture — build the provider abstraction now

Fluent Forms is already committed, and FluentCart after it. A bespoke
`GSWP_Gravity_Forms_Payments` class would be the third hand-rolled integration in
this codebase and would guarantee a fourth. Build the abstraction with the first
implementation, not after the third.

This is Option B's `GSWP_Integration` (B2), arriving here.

```php
interface GSWP_Form_Provider {
    public function id();                       // 'gravity-forms', 'fluent-forms'
    public function label();                    // 'Gravity Forms'
    public function is_active();                // plugin present

    // Coverage audit (§4)
    public function forms();                    // [ form_id => title ]
    public function form_is_eligible( $form_id );      // can we cover it at all?
    public function form_has_payment( $form_id );      // drives enforcement policy
    public function native_captcha_state( $form_id );  // 'off'|'v3'|'v2'|'unknown'

    // Runtime
    public function register_hooks( GSWP_Verifier $verifier );
    public function inject_token_field( $form_id );
    public function payment_context( $submission );    // transactionData, or []
    public function store_assessment( $submission_id, $name );
    public function annotation_hooks();                // lifecycle → LEGITIMATE/FRAUDULENT
}
```

`GSWP_Form_Provider_Registry` holds the instances, drives the coverage audit UI,
and is the single place a new form plugin is added.

Gravity Forms is implementation #1. Fluent Forms is #2 and should require no
changes to the interface — if it does, the interface was wrong.

## 4. Coverage audit — the guard against silent gaps

**This is the most important new component in the plan.** GF's add-on covers every
GF form automatically. Our replacement covers only what we hook. A missed render
path means a form silently loses protection, which is the exact failure class this
codebase has spent three releases eliminating.

### 4.1 What it does

Enumerate every form the provider knows about and, for each, report:

- whether we inject a token field into it,
- whether we validate its submissions,
- whether it has a payment feed (→ enforcement policy),
- what its native captcha state is (`off` / `v3` / `v2` / `unknown`),
- **eligibility**: can we cover this form at all?

### 4.2 Where it surfaces

- A **Form Protection** panel in the settings UI, listing every form with a
  per-form status.
- The existing `POST /gswp/v1/diagnose` endpoint, as a `form_coverage` section.
- A WP-CLI-friendly manual test script.

### 4.3 Eligibility gating

A form is **ineligible** when we cannot provide equivalent protection. Known cases:

- **v2 checkbox forms.** Our implementation is score-only (invisible v3/Enterprise).
  A form deliberately using the visible "I'm not a robot" challenge has different
  UX and a different threat model. We do not replace those. They keep GF's
  reCAPTCHA, and the audit says so.
- **Render paths we cannot hook**, if discovery finds any.

Ineligible forms are excluded from takeover permanently and visibly. Partial
takeover is a supported end state, not a failure.

### 4.4 The gate

**Stage 4 (Sole) cannot be enabled for a form until the audit reports it covered.**
This is enforced in code, not documentation.

## 5. Asymmetric enforcement — the fail-open/fail-closed split

Our current rule is uniform: missing token → reject. As a second layer that is
fine. As the only layer it turns any client-side failure into a customer-facing
outage.

| Form type | Missing token | Low score | Rationale |
|---|---|---|---|
| **Payment form** (has an active payment feed) | **Reject** | Reject | Money at stake; a blocked payment beats a fraudulent one |
| **Non-payment form** | **Accept, log, flag entry** | Reject | A contact form that will not submit is worse than a spam entry |

Critically, and following the A4 lesson from 2.18.0: **this policy is derived from
the form definition, not from the request.** "Does this form have a payment feed"
is stable server-side state, readable identically when rendering and when
validating. Nothing in the POST body influences enforcement — that is the bypass
class removed in 2.17.0 and it must not return through this door.

Non-payment fail-open submissions are logged and the entry is flagged, so a real
JS breakage shows up as a burst of unverified entries rather than silence.

## 6. Staged takeover

Three per-provider states, modelled explicitly in the UI and in the option value.
Never flip GF off and us on in one step.

### Shadow (stage 1)
We inject tokens and create assessments. **We never block.** GF's reCAPTCHA stays
active and remains the real protection. Every assessment is logged with its score.

Purpose: prove coverage and calibrate thresholds against live traffic with zero
customer risk. If our token generation is broken, nothing happens except log lines.

**Exit criteria:** coverage audit clean for the forms in scope; ≥2 weeks of data;
score distribution inspected and thresholds set from it rather than guessed.

### Active (stage 2)
We block per §5. GF's reCAPTCHA is **still on** — both layers run. This is the
transitional double-assessment state from §2.

Purpose: exercise our blocking path with a backstop still present. If we
over-block, GF's presence does not prevent that, so this stage is about watching
rejection rates, not about safety net — the safety net is the kill switch.

**Exit criteria:** rejection rate consistent with the shadow-stage prediction; no
support reports; payment forms verified end-to-end against Stripe test mode.

### Sole (stage 3)
GF's reCAPTCHA is switched off, per form or globally as discovery determines. We
are the only layer.

The UI **must not offer this** for a form the audit reports as uncovered or
ineligible.

**Rollback:** re-enable GF's reCAPTCHA. Documented, and tested as part of §10.

## 7. Per-stage scope

### 7.1 — 2.19.0: provider abstraction, GF provider, Shadow mode, coverage audit

- `GSWP_Form_Provider` + registry.
- `GSWP_Provider_Gravity_Forms`: form enumeration, eligibility, payment-feed
  detection, native captcha state, token field injection, validation hook.
- Assessment created, **scoring only, never blocking**.
- Coverage audit + Form Protection settings panel + `form_coverage` diagnostic.
- Option `gswp_provider_gravity_forms` = `off` (default) | `shadow`.

Nothing in this release can reject a submission. That is the point.

### 7.2 — 2.20.0: Active mode, payment transaction data (absorbs S5a)

- Asymmetric enforcement (§5).
- `payment_context()` for GF Stripe: `transactionData` + `fraudPrevention`, with
  the mapping derived from the GF Stripe feed as designed in the superseded plan
  §3.3.
- Decouple `GSWP_Transaction_Defense::annotate()` from WooCommerce (superseded plan
  §3.5) — it is currently `private` and takes a `WC_Order`, so without this a GF
  payment can be assessed but never annotated.
- Assessment name stored on the GF entry; payment lifecycle → `LEGITIMATE` /
  `FRAUDULENT`.
- `gswp_txn_block` and `gswp_checkout_blocked` reused unchanged, so the alert
  pipeline needs no changes.
- Option value gains `active`.

### 7.3 — 2.21.0: Sole mode and the takeover workflow

- Option value gains `sole`, gated on the coverage audit.
- Takeover UI: per-form state, what GF still has enabled, and a guided path.
- Whether we can programmatically disable GF's native reCAPTCHA, or only instruct
  the operator, is a discovery outcome (§9). Default to instructing — editing
  someone's live payment form from our settings screen is a large claim to make.
- Post-takeover monitoring: alert if a form's submission volume drops sharply
  after takeover, which is what a silent breakage looks like from the outside.

### 7.4 — 2.22.0: Fluent Forms provider

- `GSWP_Provider_Fluent_Forms` implementing the same interface.
- If the interface needs changes to accommodate it, that is a finding worth
  recording — it means stage 1 over-fitted to Gravity Forms.
- Same Shadow → Active → Sole ladder, same audit, same enforcement policy.
- **Schedule alongside FluentCart discovery.** Same vendor, likely shared
  conventions for settings storage and hook naming; doing them together saves
  most of a discovery pass.

## 8. Kill switch

A single option — `gswp_form_providers_enabled`, default `1` — that disables **all**
provider interception immediately: no token fields injected, no validation hooks,
no assessments. It does not deactivate the plugin, so 2FA, WooCommerce protection,
Account Defender and Password Defense keep running.

Also honour a `GSWP_DISABLE_FORM_PROVIDERS` constant, so recovery is possible from
`wp-config.php` when wp-admin is unreachable.

This is required infrastructure for a plugin that owns form submission, not a
nice-to-have. It ships in 2.19.0, before there is anything to kill.

## 9. Discovery required before 2.19.0

Extends the list in the superseded plan. All answerable on staging; none from this
repository. Writing this code from guesswork is defect D5, which is what produced
the original incident.

**Gravity Forms — coverage and injection**
1. Single choke point for injecting markup inside every rendered form, including
   multi-page, AJAX and conditional-logic forms.
2. Form enumeration API, and how to read a form's field list and settings.
3. How the native reCAPTCHA is configured: global add-on setting, per-form field,
   or both. **This determines whether takeover is one click or a form edit per
   form**, and it is the single biggest unknown for stage 3.
4. Whether any existing form uses the **v2 checkbox** — those are ineligible (§4.3).
5. Can the native reCAPTCHA be disabled programmatically, and should it be?

**Gravity Forms — validation and payments**
6. The validation hook that runs after GF's own validation and before payment feed
   processing, and whether it can reject with a customer-visible error.
7. **Charge timing.** Which Stripe mode is in use, and is the card authorised
   client-side before submission? If so a server-side block stops the order but not
   the authorisation, and stage 2 needs an explicit void step.
8. Payment feed detection, and its billing/email field mappings.
9. Payment lifecycle actions for completed / refunded / chargeback.
10. Entry meta API for storing the assessment name.

**Fluent Forms** — deferred to 2.22.0, bundled with FluentCart discovery.

Deliverable: a findings note with file and line references into the installed
source, committed before implementation starts.

## 10. Test plan

Per stage, in `tests/manual/`. Beyond the obvious per-form cases, three scenarios
matter most because they test the *transfer*, not the feature:

| # | Scenario | Expect |
|---|---|---|
| A | **Shadow mode, our token generation deliberately broken** (block the loader via CSP) | GF still protects; submissions succeed; our log records the failure; no customer impact |
| B | **Sole mode, our token generation deliberately broken** | Non-payment forms still submit (fail-open, logged, entries flagged); payment forms reject cleanly with a clear error |
| C | **Kill switch thrown mid-traffic** | All interception stops immediately; forms submit; no fatals; GF's reCAPTCHA can be re-enabled and works |
| D | Coverage audit vs reality | Every form the audit calls covered actually receives a token field; spot-check by view-source, not by trusting the audit |
| E | v2 checkbox form | Reported ineligible; excluded from takeover; GF's reCAPTCHA untouched |
| F | Payment form, high transaction risk, blocking on | Rejected **before** the card is charged — verify in the Stripe dashboard that no authorisation exists |
| G | Rollback from Sole | Re-enabling GF's reCAPTCHA restores protection; no double-loader regression (2.18.x dedup still holds) |

A and B are the tests that justify the whole design. If B fails, the enforcement
split in §5 is wrong and stage 3 must not ship.

## 11. Work breakdown

| Stage | Item | Est. |
|---|---|---|
| 0 | Discovery (§9) + findings note | 1.5 d |
| 2.19.0 | Provider interface + registry | 1 d |
| | GF provider: enumeration, eligibility, injection, validation | 2 d |
| | Coverage audit + settings panel + diagnostic section | 1.5 d |
| | Kill switch (option + constant) | 0.25 d |
| | Shadow-mode scoring + logging | 0.5 d |
| | Tests + staging | 1 d |
| 2.20.0 | Asymmetric enforcement | 0.5 d |
| | GF payment transaction data (from feed mappings) | 1 d |
| | Decouple annotation from WooCommerce | 1 d |
| | Entry meta + lifecycle annotation | 0.75 d |
| | Tests + staging with Stripe test mode | 1 d |
| 2.21.0 | Sole mode, takeover UI, audit gating | 1.5 d |
| | Post-takeover volume monitoring | 0.5 d |
| | Tests incl. rollback | 0.75 d |
| 2.22.0 | Fluent Forms provider | 2.5 d |
| | Tests + staging | 1 d |

**Total ≈ 19 days**, of which ≈ 6.75 is 2.19.0 and ≈ 4.25 is 2.20.0.

Considerably more than the 6 days estimated for S5a alone — because this is a
different and larger commitment: S5a added a signal, this transfers ownership of
form protection. The coverage audit, staged takeover, kill switch and enforcement
split are all cost that exists solely to make that transfer safe, and none of it
is removable without reintroducing the risk in §1.

## 12. Open questions

1. **Non-payment fail-open — agreed?** §5 accepts spam entries over blocked
   submissions on contact forms. The alternative is uniform fail-closed, which is
   stricter but makes any JS failure a site-wide form outage. Recommend as
   specified.
2. **Scope of takeover.** All GF forms, or payment forms first and others later?
   The plan supports partial takeover natively (§4.3), so "payment forms first" is
   free if wanted.
3. **Programmatic disable of GF's native reCAPTCHA** (§7.3) — do it for the
   operator, or instruct them? Recommend instruct, at least initially.
4. **Threshold policy per form.** One global threshold for all GF forms, or
   per-form? Recommend global initially, with per-form deferred until shadow data
   shows it is needed.
5. **Shadow duration before advancing.** §6 says ≥2 weeks. Confirm that suits the
   release cadence.

## 13. Explicitly out of scope

- **v2 checkbox support.** Would make ineligible forms eligible and is arguably
  in scope for a "security suite" long term, but it is a distinct feature with its
  own UX. Recorded as a candidate, not planned.
- **WPForms, Elementor Forms, CF7.** The provider interface makes each one a
  bounded addition; none is scheduled.
- **FluentCart.** Separate feature. Shares discovery with 2.22.0 and shares the
  cart-adapter slice extracted in 2.20.0.
