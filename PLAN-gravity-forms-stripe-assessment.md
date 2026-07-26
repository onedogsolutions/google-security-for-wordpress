# Implementation plan — Transaction Defense for Gravity Forms + Stripe payments (S5a)

Closes finding **S5a** from `PLAN-gravity-forms-stripe-and-integration-architecture.md` §2.

> ## SUPERSEDED (2026-07-26) by `PLAN-form-provider-replacement.md`
>
> The operator has decided this plugin should **replace** Gravity Forms' reCAPTCHA
> rather than run alongside it. S5a is no longer a standalone feature: it becomes
> stage 2 (release 2.20.0) of that plan.
>
> What carries over unchanged and is still the reference for implementation:
> **§2** (why GF's token cannot be reused and its assessment cannot be read),
> **§3.3** (deriving transaction-data field mappings from the existing GF Stripe
> feed) and **§3.5** (decoupling the annotation layer from WooCommerce).
>
> What changed: the two-assessment cost model in §3.6 assumed permanent
> coexistence. Under replacement the end state is one assessment per submission —
> the same count as today, with better data — and only the transition period
> doubles. See the replacement plan §2.
>
> Read the rest of this document as design background, not as the plan of record.

**Target release: 2.19.0** *(superseded — now 2.20.0)*.
**Depends on: 2.18.0** (shared loader). That dependency is already satisfied and
does real work here — see §3.1.

**Out of scope:** FluentCart (separate feature); bot-scoring of *non-payment*
Gravity Forms (a different feature with a different cost profile — §9); Option B's
full integration registry, though §3.5 deliberately builds the first piece of it.

---

## 1. The gap

Gravity Forms runs its own server-side reCAPTCHA Enterprise assessment against
**the same GCP project** this plugin uses. So every GF payment submission already
produces an assessment — it is simply the wrong one:

| | GF's assessment | What Transaction Defense needs |
|---|---|---|
| `transactionData` | absent | billing address, amount, currency, items, payment method |
| `fraudPrevention` | absent | `ENABLED` |
| `userInfo` | absent | account identifier |
| Threshold | GF's own | `gswp_threshold_*` |
| Assessment name | never exposed | required to annotate the outcome |
| Outcome feedback | none | `:annotate` LEGITIMATE / FRAUDULENT |

The consequence is worse than "GF covers the form": **the project is billed for
assessments on real card payments while receiving none of the fraud signal those
assessments exist to produce, and no outcome labels to train on.** GF + Stripe is
precisely the flow Transaction Defense is for.

2.18.0 restored our coverage on GF *pages*. It did nothing for the GF *payment*,
which is still scored as a bare bot check.

## 2. What we cannot do, and why

Two approaches look attractive and are dead ends. Recording them so they are not
re-proposed:

**We cannot reuse GF's token.** reCAPTCHA tokens are single-use — the second
assessment of a token returns `DUPE`. If we assessed GF's token first, GF's own
assessment would fail and its form would break. Whoever assesses first wins.

**We cannot read GF's assessment.** GF does not expose the assessment resource
name it receives, so there is nothing to annotate and no way to attach
`transactionData` to it after the fact. The Enterprise API has no "amend an
existing assessment" operation.

Therefore: **we mint our own token and create our own assessment.** Two tokens,
two independent assessments, no interference. The cost of that is real and is
addressed in §3.6.

---

## 3. Design

### 3.1 Token minting — already free

Inject one hidden input into the GF form:

```html
<input type="hidden" name="gswp_gf_token" class="g-recaptcha-response"
       data-recaptcha-action="checkout" value="" />
```

The class is what matters: the 2.18.0 bootstrap already fills every
`.g-recaptcha-response` on the page from the shared loader, refreshes before the
120-second expiry, and re-fills after DOM replacement. No new JavaScript.

The `name` is deliberately **not** `g-recaptcha-response`: that field name is read
by `GSWP_Verifier` for WooCommerce and may be read by GF for its own reCAPTCHA
field. The token is passed explicitly to `verify_token( …, $token )`, which
already accepts one (the Store API path uses it).

Before 2.18.0 this would have required a second loader for our key on GF pages —
i.e. the original bug. The shared loader is what makes this cheap.

### 3.2 Where to validate — two candidates, decision is a discovery deliverable

The hook must fire **after** GF's own validation and **before** the card is
charged, and must be able to reject with a customer-visible error.

**Candidate A — `gform_validation`.**
GF's canonical validation filter. Runs before the entry is created and before
payment feeds process, and rejection is idiomatic (set `is_valid` false, attach a
field error). Downside: no `$entry` exists yet, so transaction data must be
assembled from `$_POST` plus the form definition.

**Candidate B — an early-priority hook on entry save, before feed processing.**
The entry exists, so field values are trivially readable. Downside: the entry is
already created, so rejection means marking it spam or deleting it — messier, and
the exact ordering against the Stripe add-on's charge must be proven, not assumed.

**Recommendation: A**, because blocking is clean and because §3.3 removes most of
its disadvantage. But this is the single highest-risk unknown in the plan and
**must be settled by reading the installed GF and GF Stripe add-on source before
implementation starts** (§4).

A specific ordering question applies to whichever is chosen: GF Stripe has several
modes (Stripe Field / Payment Element, Stripe Checkout redirect). In some, the
card is authorised **client-side before submission**. If that is true for the
site's configuration, a server-side block after submission stops the *order*, not
the *authorisation* — and the plan must add an explicit void/cancel step, or move
the check earlier. Confirming which mode this site uses is a discovery item.

### 3.3 Transaction data — derive the mapping from the existing Stripe feed

This is the crux. Gravity Forms fields are arbitrary: there is no guaranteed
"billing postcode" field, and Google's documented minimum for `transactionData` is
billing `regionCode` + `postalCode` + `paymentMethod`. `GSWP_Verifier` already
enforces that minimum and omits transaction data entirely when it is unmet
(`class-gswp-verifier.php:455`), so a bad mapping degrades to a plain score rather
than an API error — a useful safety property to keep.

The naive answer is a new settings UI mapping GF fields to transaction slots. The
better answer: **the operator has already done that mapping.** A GF Stripe feed
stores billing-address and email field mappings so Stripe can be told who is
paying. Reading the feed meta gives us the operator's own mapping for free — no
new UI, no drift between two mappings, and it is idiomatic GF.

Plan:

- Locate the active payment feed for the submitted form.
- Read its billing/email field mappings from feed meta; resolve each to the
  submitted value.
- Total and currency from GF's order-total API and the feed's currency setting.
- Line items from the form's product/option/shipping fields.
- `paymentMethod` — a constant identifying the gateway (`'stripe'`), matching how
  the WooCommerce path passes the gateway id.

Exact feed meta keys are a discovery item (§4). If they prove unreadable or
inconsistent across add-on versions, the fallback is a minimal mapping UI on the
plugin's own settings screen for **just** region code and postal code — the two
fields Google requires — which is a much smaller build than a general mapper.

### 3.4 Assessment, threshold, blocking

Reuse `GSWP_Verifier::verify_token()` unchanged:

```php
$verifier->verify_token( 'checkout', 'checkout', $event_extra, $email, $token );
```

- Context `checkout` reuses `gswp_threshold_checkout`. A dedicated
  `gf_payment` context and threshold is deferred — see §8 Q1.
- `$event_extra` carries `transactionData` + `fraudPrevention: ENABLED`, built by
  the adapter in §3.5.
- Low score → reject via the chosen hook.
- Transaction risk → the existing `gswp_txn_block` toggle and `gswp_threshold_txn`
  apply, and `gswp_checkout_blocked` fires so the alert pipeline works with no
  changes to `GSWP_Alerts`.

Gating is unchanged from WooCommerce: Enterprise key + `gswp_txn_defense` on.
Classic keys get a plain score, which is still an improvement (GF's threshold no
longer solely decides a payment).

### 3.5 Annotation — requires decoupling the feedback loop from WooCommerce

`GSWP_Transaction_Defense` is currently Woo-only: `annotate()` is `private` and
takes a `WC_Order` (`class-gswp-transaction-defense.php:150`), and the hooks are
`woocommerce_checkout_order_processed` and `woocommerce_order_status_changed`.
Without changing this, a GF payment can be *assessed* but never *annotated* — and
annotation is where the model actually learns.

Minimum viable decoupling, which is deliberately the first slice of Option B's
`GSWP_Cart_Adapter`:

1. Extract the API call into a public, source-agnostic method:
   `annotate_assessment( $name, $annotation, $event_type, $context = array() )`.
   The Woo path keeps its order note by passing the order in `$context`.
2. Store our assessment name on the GF entry (`gform_update_meta`) instead of the
   Woo session/order meta.
3. Map GF payment lifecycle events onto annotations:
   - payment completed → `LEGITIMATE`
   - payment refunded / chargeback → `FRAUDULENT`
   GF payment add-ons fire dedicated actions for these; confirm names in discovery.
4. Guard against double annotation with an entry meta flag, mirroring
   `META_ANNOTATED`.

This is ~a day of refactoring that Option B would otherwise have to do anyway.

### 3.6 Scoping and cost control

The honest trade: **one additional assessment per GF payment submission**, on top
of the one GF already creates.

Controls:

- **Only forms with an active payment feed** are touched. A newsletter form costs
  nothing. This is automatic, not a setting.
- **Feature toggle** `gswp_gf_payments` (default `0`) so the whole path is opt-in
  and the cost is never a surprise on upgrade.
- **Recommended operator configuration, documented not enforced:** disable GF's
  own reCAPTCHA on payment forms once this is live. Our assessment then *replaces*
  GF's rather than adding to it — one assessment per payment instead of two, a
  single threshold, and one policy. This is the configuration to aim for; it is
  not coded because removing a field from someone's live payment form is the
  operator's call, not ours.

Before committing, check current assessment volume against the project's billing
tier — flagged as §8 Q3.

### 3.7 Settings UI

One new panel on the Enterprise Defense tab:

- Toggle: "Score Gravity Forms payments" (`gswp_gf_payments`).
- Read-only status: forms detected with an active payment feed, and whether the
  billing mapping resolved for each — so a broken mapping is visible *before* a
  customer hits it, rather than silently degrading to a plain score.
- Inline note stating the two-assessment cost and the recommended configuration
  from §3.6.

---

## 4. Discovery required before implementation

None of this can be settled from this repository; all of it is answerable on
staging in a few hours. **This must happen first** — writing GF integration code
from guesswork is defect D5, and it is what produced the original incident.

1. **Pre-charge hook.** Does `gform_validation` reliably run before the Stripe
   add-on authorises the card, in the mode this site uses? If not, what does?
2. **Charge timing.** Which Stripe mode is configured (Stripe Field / Payment
   Element / Stripe Checkout)? Is the card authorised client-side before
   submission? If so, what must be voided when we block?
3. **Feed meta keys** for billing address and email mappings, and how to fetch the
   active feed for a form/submission.
4. **Order total and currency** APIs at the chosen hook's point in the lifecycle.
5. **Field injection point** that lands inside the `<form>` element and survives
   AJAX-enabled forms.
6. **Payment lifecycle actions** for completed, refunded and chargeback, and their
   payload shapes.
7. **Entry meta API** for storing and reading the assessment name.
8. **Multi-page and AJAX forms** — does the token field survive page transitions,
   and is it re-filled? (2.18.0's MutationObserver should handle it; verify.)

Deliverable: a short findings note appended to this plan, with file and line
references into the installed GF source, before any code is written.

---

## 5. Work breakdown

| # | Item | Est. |
|---|---|---|
| 0 | Discovery (§4), findings written up | 1 d |
| 1 | `GSWP_Gravity_Forms_Payments` — feed detection, field injection, token plumbing | 0.75 d |
| 2 | Transaction data builder from feed mappings | 1 d |
| 3 | Validation hook, scoring, blocking, alert wiring | 0.75 d |
| 4 | Decouple `annotate()` from WooCommerce; entry meta; lifecycle mapping | 1 d |
| 5 | Settings panel + mapping status readout | 0.5 d |
| 6 | Manual test script + staging verification with real test-mode payments | 1 d |

**Total ≈ 6 days**, of which 1 is discovery. Higher than the 3–5 estimated in the
analysis document: the field-mapping problem (§3.3) and the WooCommerce coupling
in the annotation layer (§3.5) were both underestimated there.

Webpack rebuild required (item 5).

---

## 6. Test plan

`tests/manual/10-gf-payment-assessment.php` plus staging runs against **Stripe
test mode**.

| # | Scenario | Expect |
|---|---|---|
| 1 | GF Stripe payment, feature off | unchanged from 2.18.0; no extra assessment |
| 2 | GF Stripe payment, feature on, good score | payment completes; assessment carries `transactionData` and `fraudPrevention`; `fraudPreventionAssessment` returned |
| 3 | Same, `gswp_txn_block` on, risk above threshold | payment blocked **before** the card is charged; customer sees an error; `gswp_checkout_blocked` fires; alert email sent |
| 4 | Payment completes | entry meta carries the assessment name; `LEGITIMATE` annotation sent |
| 5 | Payment refunded | `FRAUDULENT` annotation sent; no double annotation on repeat status changes |
| 6 | Billing mapping incomplete | degrades to a plain score, no API 400; settings panel shows the mapping as unresolved |
| 7 | Non-payment GF form | untouched, no assessment, no token field |
| 8 | Multi-page / AJAX GF form | token present and fresh at final submit |
| 9 | Classic (non-Enterprise) key | plain score only, no transaction data, no fatal |
| 10 | WooCommerce checkout unaffected | Woo assessment + annotation still work (regression) |

Scenario 3 is the acceptance test and the one most likely to expose the §3.2
charge-timing risk: **verify against the Stripe dashboard that no authorisation
was created**, not just that the form showed an error.

---

## 7. Rollback

The feature is behind `gswp_gf_payments`, default off, so rollback is a toggle
rather than a downgrade. The §3.5 annotation refactor is the only change that
touches an existing code path; it is behaviour-preserving for WooCommerce and is
covered by scenario 10.

Persistent artefacts: one option, plus entry meta on GF entries. Both inert if the
code is absent.

---

## 8. Open questions

1. **Dedicated threshold?** Reuse `gswp_threshold_checkout`, or add a `gf_payment`
   context with its own threshold? Reuse is simpler and assumes GF payments carry
   the same risk appetite as Woo checkout. Recommend reuse until there is evidence
   otherwise.
2. **Block or observe first?** Ship with blocking available but default off
   (`gswp_txn_block` already defaults off), so the first weeks produce risk data
   without any chance of rejecting a good customer. Recommended.
3. **Assessment volume and billing.** What is current monthly assessment volume,
   and does doubling it on payment forms cross a tier? Answer before committing to
   §3.6's two-assessment default.
4. **Should GF's own reCAPTCHA be retired on payment forms** once this is live
   (§3.6)? Halves the cost and unifies policy, but it is a change to a live
   payment form and should be a deliberate operator decision.

---

## 9. Explicitly not included

- **Bot-scoring non-payment Gravity Forms.** Different feature, different cost
  profile (every form submission on the site), and GF's own reCAPTCHA already
  covers it adequately for non-payment flows. If wanted, it is a small addition
  once §3.1–3.2 exist, but it should be costed and toggled separately.
- **Other GF payment add-ons** (PayPal, Square, Authorize.net). The design is
  gateway-agnostic — feed detection and mapping are the only gateway-specific
  parts — but only Stripe is in scope and only Stripe will be tested.
- **The full `GSWP_Cart_Adapter` interface.** §3.5 extracts only the annotation
  slice that S5a needs. The rest stays with Option B / FluentCart.
