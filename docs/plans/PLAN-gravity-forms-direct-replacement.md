# Implementation plan — replace the Gravity Forms reCAPTCHA implementation

**Target release: 2.20.0.**

**Decision:** this plugin *is* the reCAPTCHA implementation for Gravity Forms.
Not a second opinion running beside GF's, not a staged approach to one day being
it — GF's reCAPTCHA is switched off by us, and we score every Gravity Form.

This supersedes the staged-takeover design in
`PLAN-form-provider-replacement.md` §6 and the machinery shipped in 2.19.0 that
implements it. That release delivered a mechanism for *gradually approaching*
replacement, defaulted to off, which is not what was asked for and changes
nothing on a live site.

Most of the 2.19.0 code survives — the provider abstraction, the GF bindings,
the enforcement policy, the coverage reporting and the kill switch are all
reusable. What goes is the staging.

---

## 1. Delta from 2.19.0

| 2.19.0 | 2.20.0 |
|---|---|
| Four stages: `off` → `shadow` → `active` → `sole` | **One switch: on / off. On by default.** |
| Default `off`; upgrading changes nothing | **Enabled on upgrade** when GF is active and a site key is set |
| Coverage audit *gates* the final stage | Coverage audit becomes **reporting**, not a gate |
| Operator manually switches GF's reCAPTCHA off | **We switch it off**, programmatically |
| Injection via one hook, coverage unproven | **Choke point + HTML fallback + server-side assertion** |
| Asymmetric enforcement (payment/non-payment) | Unchanged |
| v2 checkbox forms ineligible | Unchanged |
| Kill switch | Unchanged |

The two substantive additions are §3 (guaranteed coverage) and §4 (we disable
GF's own implementation). Everything else is subtraction.

## 2. Why coverage becomes the whole problem

Staging existed to buy discovery time: run in shadow, watch the logs, find the
forms we missed before it mattered. Removing it removes that safety period, so
the coverage question has to be answered **in code** rather than **over weeks**.

That is the real engineering shift in this release. Direct replacement is not
harder because it is bolder; it is harder because "we hook most render paths"
stops being good enough.

## 3. Guaranteed coverage

Three layers, so no single wrong assumption about Gravity Forms' internals can
leave a form unprotected.

### 3.1 Primary injection

`gform_submit_button` — the conventional injection point, already implemented in
2.19.0. Fast, clean, and correct whenever it fires.

### 3.2 Fallback injection on the rendered HTML

`gform_get_form_filter` receives the complete rendered form markup. If our token
field is not already present, inject it before the closing `</form>` tag.

This is the layer that makes coverage robust: it does not depend on knowing
which render paths call the submit-button filter, which button markup a theme
overrides, or how multi-page forms assemble their pages. If the form reached the
browser as HTML, the field is in it.

Implementation notes:
- Idempotent — check for `name="gswp_gf_token"` before injecting.
- Operates on the last `</form>` in the fragment.
- If the markup contains no `</form>` (an edge case worth logging), record a
  coverage failure for that form rather than silently doing nothing.

### 3.3 Server-side coverage assertion

At validation, a submission for an eligible form arriving with no token is
either a bot or a coverage bug — and those need different responses.

Record, per form, whether injection succeeded on render (a short-lived
transient keyed by form id, written by the injection layer). At validation:

- **Token missing, injection recorded as successful** → treat as adversarial.
  Apply the enforcement policy in §5.
- **Token missing, no successful injection recorded** → coverage bug. Log at
  error level naming the form id, fire an admin alert, and **fail open** for
  that submission regardless of form type. Never punish a visitor for our gap.

This converts the silent failure mode into a loud one, which is what the shadow
stage was supposed to buy and what a live replacement cannot wait for.

### 3.4 Coverage report

The audit built in 2.19.0 stays, minus its gating role. It gains a
**last-observed-injection** column fed by §3.3, so the settings screen shows
what has actually happened on the front end rather than only what we predict.

## 4. Disabling Gravity Forms' own reCAPTCHA

We do this. Not "the operator is instructed to" — that was the 2.19.0 position
and it is why nothing was replaced.

Two mechanisms, both needed because GF has two implementations:

### 4.1 The reCAPTCHA add-on (v3 / Enterprise)

Remove its hooks at runtime rather than editing its stored settings, so the
change is fully reversible by disabling our feature and nothing is left behind
in GF's own configuration.

The add-on is a `GFAddOn` subclass with a singleton accessor; unhooking its
script enqueue and its validation callback disables it without touching the
database. **Exact class name, accessor and hook signatures are a discovery
item (§7).** If unhooking proves unreliable across add-on versions, the
fallback is to suppress its script (already possible via the loader owner) and
neutralise its validation filter by short-circuiting it.

### 4.2 CAPTCHA fields on individual forms

GF's built-in CAPTCHA field is part of the form definition. Filter it out of the
form object on `gform_pre_render` and `gform_pre_validation` so it neither
renders nor validates. The stored form is never modified — remove our feature
and the field is back on the next page load.

**Exception: v2 checkbox fields are left alone.** See §6.

### 4.3 Reversibility is the safety property

Neither mechanism writes to Gravity Forms' stored configuration. Turning our
feature off — or throwing the kill switch — restores GF's implementation on the
next request, with no re-configuration and no form editing. That is what makes
shipping this on-by-default defensible.

## 5. Enforcement

Unchanged from 2.19.0, and unchanged by this plan:

| Form | Missing token | Low score / high risk |
|---|---|---|
| Payment | Reject | Reject |
| Non-payment | Accept, log, flag the entry | Reject |

Plus §3.3's override: a submission we can prove we never injected into is always
accepted, whatever the form type.

Derived from the stored form definition, never the request.

## 6. What stays limited, and why it is not caution

**v2 checkbox forms are still excluded, and GF's captcha stays on for them.**
This is a capability gap, not a staged rollout: our implementation scores
invisibly and has no visible-challenge equivalent. Replacing a deliberate
"prove you are human" interaction with a silent score changes both the UX and
the threat model, and we cannot do it because we have not built it.

If those forms should also be ours, the work is a v2 checkbox mode — a distinct
feature, costed separately. Say so and it goes on the list.

## 7. Discovery

Smaller than before, because 2.19.0's bindings are already written and the risky
ones now fail loudly under §3.3 rather than silently. What remains:

1. **The reCAPTCHA add-on's class name, singleton accessor and hook
   registrations**, so §4.1 can unhook it. This is the only genuinely new
   unknown in this release.
2. `gform_get_form_filter`'s signature and whether it fires for every render
   path including AJAX and multi-page (§3.2).
3. Confirmation of the 2.19.0 bindings still marked UNVERIFIED: validation hook
   ordering against payment feed processing, feed meta keys for billing
   mappings, payment lifecycle action names.
4. **Stripe charge timing** — whether the card is authorised client-side before
   submission in the configured mode. If so, a server-side rejection stops the
   entry but not the authorisation, and §5 needs an explicit void step.

Item 4 is the one that can cost a customer real money. It is the only discovery
item I would treat as blocking.

## 8. Upgrade behaviour

On upgrade to 2.20.0, replacement is **enabled automatically** when Gravity
Forms is active and a reCAPTCHA site key is configured.

An admin notice states plainly what changed, that GF's reCAPTCHA is now off,
and links to both the coverage report and the off switch. The notice is
dismissible and does not re-arm.

This is a deliberate behaviour change on upgrade — the alternative is another
release that ships an off switch and replaces nothing. Sites where it is
unwanted have a one-click revert that restores GF's implementation immediately
(§4.3).

## 9. Work breakdown

| # | Item | Est. |
|---|---|---|
| 0 | Discovery (§7), findings note | 0.75 d |
| 1 | Collapse four stages to one switch; migrate the option | 0.5 d |
| 2 | Fallback HTML injection (§3.2) | 0.5 d |
| 3 | Server-side coverage assertion + alerting (§3.3) | 0.75 d |
| 4 | Disable GF's add-on (§4.1) | 1 d |
| 5 | Filter out CAPTCHA fields (§4.2) | 0.5 d |
| 6 | Coverage report: drop the gate, add last-observed column | 0.5 d |
| 7 | Upgrade path + admin notice (§8) | 0.5 d |
| 8 | Tests + staging | 1.5 d |

**Total ≈ 6 days**, of which most is reuse of 2.19.0.

## 10. Test plan

`tests/manual/11-gf-replacement.php`, plus staging.

| # | Scenario | Expect |
|---|---|---|
| 1 | Replacement on, ordinary GF form | Our token field present; submission scored; GF's own reCAPTCHA absent from the page |
| 2 | Multi-page form | Token present and fresh at final submit — the case §3.2 exists for |
| 3 | AJAX-enabled form | As above |
| 4 | Theme overriding the submit button | Token still present, via the HTML fallback |
| 5 | GF Stripe payment, good score | Completes; assessment carries `transactionData`; annotated on completion |
| 6 | GF Stripe payment, risk above threshold | Rejected **before** the card is charged — confirm in the Stripe dashboard that no authorisation exists |
| 7 | Token generation deliberately broken (block reCAPTCHA via CSP) | Non-payment forms still submit, flagged; payment forms reject cleanly; coverage assertion logs it |
| 8 | Form we never injected into (simulate by filtering our field out) | Submission **accepted**, error logged naming the form, admin alerted |
| 9 | v2 checkbox form | Untouched — GF's captcha still renders and still validates |
| 10 | Kill switch thrown | GF's reCAPTCHA returns on the next request; forms submit; no fatals |
| 11 | Feature switched off after being on | Same as 10, no residue in GF's settings |
| 12 | WooCommerce checkout | Unaffected (regression) |

Scenarios 2, 3 and 4 are the ones that decide whether §3.2 works. Scenario 8 is
the one that decides whether §3.3 works, and it is the difference between a
coverage gap being noisy or silent.

## 11. Rollback

Off switch or kill switch, either of which restores GF's implementation on the
next request. No GF configuration is modified, so there is nothing to undo in
Gravity Forms itself and no forms to re-edit.

## 12. Residual risk

Recorded once, as the record, not as an argument:

When this plugin's token generation fails, Gravity Forms is affected — GF's own
reCAPTCHA is no longer there to catch it. §3.3 makes that loud instead of
silent, §5 keeps non-payment forms submitting, and §11 makes recovery a single
switch. Those are the mitigations; they reduce the blast radius, they do not
remove the dependency.

That dependency is the point. A security suite that owns bot scoring owns the
consequences of getting it wrong.
