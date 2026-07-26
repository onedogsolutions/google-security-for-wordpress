# Gravity Forms / Stripe failure — root cause, security review, and integration architecture

Status: analysis and options. No plugin code changed by this document.
Scope reviewed: v2.16.0 (`ca2b1b6`, `c9b7560`, `0d89322`, `dabd588`).

---

## Part 1 — What actually broke, and why we should not have had this issue

### 1.1 The original failure

On a site running this plugin and a Gravity Forms page with a Stripe payment
field, GF's Stripe element (`#stripe-payment-link`) never mounted and
transactions failed. Two mechanisms were in play, and the shipped fix never
distinguished between them (`STATE.md` Phase 33 still says "Conflict Guard
**and/or** dual reCAPTCHA Enterprise script loading"):

**(a) The Conflict Guard stripped GF's loader.** `GSWP_Conflict_Guard::filter_tag()`
suppresses *any* script tag whose `src` contains `google.com/recaptcha`,
`recaptcha.net/recaptcha`, or `gstatic.com/recaptcha`
(`includes/class-gswp-conflict-guard.php:58-62`). The site's mode was `active`,
which suppresses on pages where our own script is enqueued. On a page carrying
both a GF form and any surface we protect, GF's `enterprise.js` tag was removed
from the output. GF's field initialisation depends on `grecaptcha` resolving;
when it throws, GF's downstream field rendering — including the Stripe element —
never runs.

**(b) Two Enterprise loaders, two site keys.** Even with the guard off, GF loads
`enterprise.js?render=<GF_KEY>` and we load `enterprise.js?render=<OUR_KEY>`.
Google documents reCAPTCHA as one-load-per-page; two loaders with two different
site keys is unsupported, and `grecaptcha.enterprise.execute(K)` for a key that
was not the one rendered fails.

Mechanism (b) is the real root cause, and it is the one the fix never addressed.
(a) is a symptom of the same blind spot.

### 1.2 The six design defects that made this inevitable

**D1 — The Conflict Guard encodes a policy it cannot be right about.**
It was written (`STATE.md:424`) as a generalisation of a hand-rolled
`wp_dequeue_script()` snippet: "suppress anything that looks like reCAPTCHA so we
are the only one." It has no model of *who else* is on the page or *why* they
need reCAPTCHA. Every plugin that legitimately depends on its own reCAPTCHA is
collateral damage, and payment flows are the highest-cost collateral. This was
shipped as the option labelled **"Recommended."**

**D2 — No site-key arbitration anywhere in the codebase.**
The only question that determines whether two reCAPTCHA consumers can coexist is
*"are they using the same site key?"* — and the plugin never asks it. If GF's key
and ours are the same key (the common case on a single-GCP-project site),
coexistence is trivial: one loader, both callers. If they differ, no amount of
suppression fixes it and the admin needs to be told. Neither branch is
implemented.

**D3 — Script loading and field printing are on separate, ungated code paths.**
`GSWP_Frontend::register_scripts()` decides whether the loader exists;
`inject_recaptcha_field()` prints `<input name="g-recaptcha-response" value="">`
unconditionally (`class-gswp-frontend.php:114-118`, same pattern at
`class-gswp-login.php:130-133` and `class-gswp-powerpack.php:110-113`). Nothing
guarantees these two agree. It is structurally possible — and after v2.16.0,
actual — to print a token field that nothing on the page will ever fill.

**D4 — Fail-closed server, fail-silent client.**
`GSWP_Verifier::verify_token()` returns `recaptcha_missing` on an empty token
(`class-gswp-verifier.php:232-237`). Combined with D3, *any* client-side
condition that stops our bootstrap becomes a hard, customer-facing checkout or
login failure. The plugin already fails **open** for the site's own
misconfiguration (bad secret key, HTTP 500 from Google — `:304-308`, `:368-375`)
but fails **closed** for its own asset-pipeline failures. That asymmetry is
backwards.

**D5 — The GF integration was written without reading GF's source.**
The evidence is in the code: `is_recaptcha_configured()` checks `site_key` **or**
`public_key` because the author did not know which one GF uses
(`class-gswp-gravity-forms.php:66`); `$gf_handles` lists five candidate handles
on the same speculative basis (`:26-32`); detection falls back to string-sniffing
`post_content` for `gform_wrapper` and `gf-form` (`:102-103`). Compare commit
`3030595`, "Verify implementation plan against PowerPack 2.42.3 source" — that
discipline existed in this repo and was not applied here.

**D6 — No compatibility test coverage.**
`tests/manual/` covers 2FA and XML-RPC. Nothing covers "another plugin also loads
reCAPTCHA on this page," which is the plugin's single largest interaction risk
surface and the entire premise of the Compatibility settings tab.

### 1.3 How the fix was made

Four commits in 87 minutes (15:21 → 16:48), all shipped under one version number
(2.16.0), each one broadening the previous:

| Commit | Change | Direction |
|---|---|---|
| `ca2b1b6` | Defer when GF has reCAPTCHA **and** a form is rendered | scoped |
| `0d89322` | Add `registered` state, more handles, content sniffing, two Conflict Guard safety nets | broader |
| `dabd588` | Conflict Guard off entirely when GF is merely **installed**; JS bails on any GF markup | broadest |

Each step widened the blast radius rather than narrowing the diagnosis. Nothing
was re-tested against the original failure; `STATE.md` still records the cause as
undetermined. That is the process finding: an emergency mitigation was allowed to
become the permanent design.

---

## Part 2 — Security review of what shipped

Five findings. **S1 is live and exploitable in v2.16.0.**

### S1 — Attacker-controlled bypass of all checkout verification (critical)

```php
// includes/class-gswp-verifier.php:148-152
public function validate_checkout( $data, $errors ) {
    // Gravity Forms handles its own reCAPTCHA validation.
    if ( GSWP_Gravity_Forms::is_form_submission() ) {
        return;
    }
```

```php
// includes/class-gswp-gravity-forms.php:147-150
public static function is_form_submission() {
    return isset( $_POST['gform_submit'] );
}
```

The predicate is a raw `isset()` on an attacker-supplied POST field. It is not
gated on Gravity Forms being installed, on the field having a valid form ID, on a
GF nonce, or on anything server-authoritative.

**Exploit:** add `gform_submit=1` to any WooCommerce classic checkout POST. This
skips the reCAPTCHA score check, the action check, Transaction Defense scoring,
the `gswp_txn_block` high-risk block, and the `gswp_checkout_blocked` alert — on
every site running v2.16.0, whether or not Gravity Forms is installed. For a
plugin whose stated purpose is stopping carding attacks on checkout, this is a
complete bypass of the control, reachable by adding one form field.

This should be removed before anything else in this document is decided.

### S2 — Silent, site-wide disablement of our own protection (high)

`is_form_rendered()` returns true when a GF handle is merely **registered**:

```php
// class-gswp-gravity-forms.php:81-85
if ( wp_script_is( $handle, 'enqueued' ) || wp_script_is( $handle, 'registered' ) ) {
    return true;
}
```

`registered` means "this script *could* be loaded," not "this page uses it."
Gravity Forms registers its script library on front-end requests and enqueues
conditionally, so on a GF site with reCAPTCHA configured, `should_defer()` is
true on **pages that contain no Gravity Form at all**.

Consequence chain:

1. `GSWP_Frontend::register_scripts()` bails → handle `google-recaptcha-v3` never registered.
2. `inject_recaptcha_field()` still prints the empty hidden input (D3), calls
   `wp_enqueue_script()` on an unregistered handle (no-op), and
   `wp_add_inline_script()` returns false — the bootstrap is dropped.
3. The form submits with an empty token.
4. `verify_token()` returns `recaptcha_missing` (D4).

So on any GF site with reCAPTCHA configured and our WooCommerce login /
registration / checkout toggles on, those forms hard-fail with *"Anti-spam
verification token is missing."* WooCommerce **login and registration have no
`gform_submit` bypass at all** — only checkout does. The emergency fix plausibly
traded a GF/Stripe outage for a WooCommerce account-flow outage, with the
checkout leg masked by the S1 bypass.

### S3 — Conflict Guard is inert whenever Gravity Forms is installed (medium)

```php
// class-gswp-conflict-guard.php:97-99
if ( GSWP_Gravity_Forms::is_active() ) {
    return $tag;
}
```

`is_active()` is presence-only — no reCAPTCHA configuration required. If GF is
installed anywhere on the site, conflict suppression is disabled on every page
for every plugin, including PowerPack's `g-recaptcha`. The settings screen still
shows "On this plugin's reCAPTCHA pages" selected with a "Recommended" badge. The
UI asserts a protection that the code has unconditionally switched off, and
nothing tells the admin. A setting that silently means nothing is worse than a
setting that is off.

### S4 — DOM-presence kill switch on the client (medium)

Both bootstraps abort on:

```js
if (document.querySelector('.gform_wrapper, .gf-form, [id^="gform_"]')) { return; }
```
(`class-gswp-frontend.php:152`, `class-gswp-assets.php:123`)

Three problems:

- **Wrong scope.** This is page-level; the thing it disables is form-level. A GF
  newsletter form in a sitewide footer stops us filling the token on the
  WooCommerce checkout on the same page. GF's reCAPTCHA protects GF's form only —
  it does not and cannot cover ours. Net effect: that page has *no* bot scoring
  on the checkout, and (per D4) the checkout fails closed.
- **Attacker-influenceable.** The selector is broad — `[id^="gform_"]` matches any
  element whose id starts with `gform_`. Any surface where a visitor influences
  page markup (a comment body, a profile field, a reflected parameter, a
  user-supplied block) becomes a way to switch off token generation for that page.
- **Belongs on the server.** A client-side decision about whether to run a
  security control is not enforceable.

### S5 — Delegating bot scoring to Gravity Forms is not equivalent protection

This is the concern raised directly, and it is correct. When we defer, the
security posture changes in five ways that are not visible to the operator:

| Capability | GSWP | GF reCAPTCHA add-on |
|---|---|---|
| Bot score on the GF form | — | yes |
| Bot score on non-GF forms on the same page | disabled by deferral | never covered |
| Account Defender labels / `userInfo` | yes | no |
| Transaction Defense `transactionData` + `fraudPrevention` | yes | no |
| Our thresholds (`gswp_threshold_*`) | yes | GF's own, separate |
| Our logging, alerts, order annotation, feedback loop | yes | no |

The last row matters most for the Stripe case specifically. GF + Stripe is
exactly the flow Transaction Defense exists to score — a real payment, with a
real amount, a real billing address, and a real card. Deferring hands that flow
to a plain v3 score with no transaction data, no fraud assessment, no
`gswp_txn_block`, no order annotation, and therefore **no feedback into Google's
model**. We did not just lose a check; we stopped teaching the model on the
highest-value events on the site.

And because deferral is page-scoped, the loss is not confined to the GF form: on
that page, Woo checkout, Woo login, wp-login, Xootix, and PowerPack surfaces are
all unprotected too (S2/S4), while GF covers only its own form.

**Conclusion:** "GF handles bot scoring" is defensible for the GF form in
isolation. It is not defensible as a page-wide opt-out of our entire stack, and
it is not defensible for a payment flow where Transaction Defense is the whole
point of the Enterprise key.

---

## Part 3 — Option A: surgical correction

Keep the current architecture. Fix the six things that are wrong. **~1–2 days.**

**A1. Delete `is_form_submission()` and its call site.** (S1)
A WooCommerce checkout submission is not a Gravity Forms submission. If a genuine
need to skip a Woo hook for a GF request ever appears, it must be decided from
server-authoritative state (GF's own request context), never a POST field. One
line in, one line out; ship independently of everything else here.

**A2. Replace deferral with site-key arbitration.** (D2, root cause)
New method `GSWP_Gravity_Forms::site_key()` reads GF's configured key. Then:

- **Keys match** (expected default): do **not** print a second `enterprise.js`
  tag. Reuse the loader already on the page and keep our bootstrap running —
  `grecaptcha.enterprise.execute(ourKey, …)` works because the key is rendered.
  Both plugins get their tokens, one loader, no conflict, full GSWP coverage
  retained. This is the case that broke, and it is fully solvable.
- **Keys differ**: one page cannot render two Enterprise keys via `?render=`.
  Load ours without `render=` and call `grecaptcha.enterprise.render()`
  explicitly, or — simpler and safer as a first cut — keep ours and raise a
  dismissible admin notice plus a Compatibility-tab warning naming both keys and
  telling the admin to align them. Do not silently pick a winner.

**A3. Make detection mean what it says.** (S2)
Drop `'registered'`. Drop the `post_content` string sniffing. Evaluate at render
time (`script_loader_tag` / `wp_print_footer_scripts`), not at
`wp_enqueue_scripts`. Verify the handle list and the option key against the
installed Gravity Forms source before shipping (D5) — it is on the target site.

**A4. Single gate for "will our token be filled."** (D3, D4)
Add `GSWP_Assets::will_load()`. `inject_recaptcha_field()` prints nothing when it
is false, and `verify_token()` skips enforcement (logging a warning) for a
context whose field was never printed. Server and client stop being able to
disagree. This deletes the entire "token missing" outage class permanently, and
matches the fail-open posture the plugin already takes for its own
misconfiguration.

**A5. Remove both DOM kill switches.** (S4)
If our field is on the page, we fill it. Page-level presence of a third-party
form is never a reason to abandon our own fields.

**A6. Restore the Conflict Guard to a defensible rule.** (S3)
Delete the blanket `is_active()` escape. Suppress a third-party loader only when
it would be a *second, different* site key **and** we are loading ours. Never
suppress a loader whose key matches ours — reuse it (A2). Surface the actual
runtime state in the Compatibility tab ("Suppression is currently inactive on
this site because …") so the UI stops asserting protection that isn't running.

**A7. Coverage.** (D6)
Add `tests/manual/09-recaptcha-coexistence.php`: GF + Woo on one page, same key
and different keys, guard on and off; assert one loader tag, both tokens
populated, checkout completes, and Transaction Defense still produces an
assessment.

**Result:** the original bug is fixed at its cause, all five security findings
close, and — importantly — GSWP protection is *retained* on GF pages instead of
surrendered. GF's Stripe checkout keeps working *and* gets scored.

**Limits:** still hard-coded to Gravity Forms by name. FluentCart, WPForms,
Elementor Forms, Fluent Forms, EDD each need their own bespoke class. The next
plugin that loads reCAPTCHA repeats this incident.

---

## Part 4 — Option B: integration registry and loader arbiter

Option A's fixes, restructured so they generalise. **~1.5–2.5 weeks**, best done
as A first (ship the security fixes now), then B.

### B1. One owner of the reCAPTCHA script — `GSWP_Loader_Arbiter`

The structural cause of this incident is that nothing owns the page's reCAPTCHA
loader. The arbiter does: every consumer (ours and every detected third party)
registers the site key it needs; at render time the arbiter emits exactly one
loader, renders every distinct key that was requested, and exposes
`gswp.token(key, action)` for consumers to call. Key collisions become a
non-event. The Conflict Guard degrades from "a suppression policy" to "a
diagnostic that reports what else asked for a key," which is what an admin
actually needs.

This single component would have prevented the incident regardless of which
plugin was involved.

### B2. `GSWP_Integration` — form surfaces

```php
interface GSWP_Integration {
    public function id();                  // 'gravity-forms', 'fluentcart', 'woocommerce'
    public function is_active();           // plugin present
    public function detect_site_key();     // key it loads itself, or '' — feeds the arbiter
    public function surfaces();            // [ ['id','type','enable_option','threshold_context','action'], … ]
    public function renders_on_request();  // authoritative, evaluated late
    public function register_hooks( GSWP_Verifier $verifier );
}
```

Existing `GSWP_Xootix`, `GSWP_Powerpack`, `GSWP_Login`, `GSWP_Frontend`, and
`GSWP_Blocks` already follow this shape informally — B2 is mostly extraction, not
new logic. New targets become a class plus a registry entry rather than
edits scattered across five files.

### B3. `GSWP_Cart_Adapter` — checkout and Transaction Defense

This is the piece FluentCart actually requires. Today
`GSWP_Verifier::build_checkout_event_extra()` is hard-wired to `WC()->cart` and
`$_POST['billing_*']` (`class-gswp-verifier.php:431-486`), and
`build_checkout_event_extra_from_order()` to `WC_Order`
(`:572-645`). Both must move behind:

```php
interface GSWP_Cart_Adapter {
    public function total(); public function currency(); public function items();
    public function billing_address(); public function shipping_address();
    public function payment_method(); public function customer();
    public function annotate( $assessment_name, $risk );   // order note / meta
    public function reject( $message );                    // block the checkout
}
```

Implementations: `Woo_Classic`, `Woo_Store_API`, `FluentCart`, and — the answer
to the original incident — `GF_Stripe`, so a Gravity Forms Stripe payment gets
the same `transactionData` + `fraudPrevention` treatment as a Woo order instead
of being waved through.

`GSWP_Transaction_Defense`'s annotation/feedback layer becomes adapter-driven,
so the Google feedback loop works for every cart, not just WooCommerce.

### B4. Capability declaration and honest UI

Each integration declares what it supports (score / Account Defender /
Transaction Defense / annotation). The Compatibility tab renders a live matrix:
detected plugins, the key each requests, which surfaces we cover, which we
deliberately do not, and why. This replaces the current static note that says we
"automatically defer" while the code has actually disabled itself sitewide.

---

## Part 5 — Recommendation

1. **Now, independently:** A1 (remove the `gform_submit` bypass). It is a live
   checkout-verification bypass on every install of v2.16.0.
2. **This cycle:** the rest of Option A, shipped as 2.16.1, with A2 (site-key
   arbitration) as the actual bug fix and A3/A4 closing the outage class the
   emergency fix introduced. Verify handles and option keys against the GF source
   on the staging site first.
3. **Next cycle:** Option B, driven by the FluentCart requirement — B1 and B3
   are the load-bearing pieces; B2 is refactoring of code that already exists.

Option A alone leaves the plugin correct but still one-off per integration.
Option B is what makes FluentCart, and the plugin after FluentCart, a bounded
piece of work.

---

## Part 6 — Full integration into other form and cart plugins

### 6.1 What an integration actually costs

Per target, in dependency order:

1. **Source verification** — read the plugin's source for its reCAPTCHA option
   keys, script handles, and enqueue timing. Non-negotiable; skipping it is D5
   and is what produced this incident.
2. **Key detection** (`detect_site_key`) — feeds the arbiter. Small.
3. **Field injection** — a server-rendered form action, or (for SPA/REST
   checkouts) a request-payload extension in the manner of `GSWP_Blocks`.
4. **Validation hook** — must fire *after* the plugin's own nonce/field
   validation and *before* the irreversible action (user created, order placed,
   card charged). Finding this hook is usually the bulk of the work.
5. **Cart adapter** — carts only. Address/items/total mapping plus annotation
   and rejection.
6. **Manual test script** in `tests/manual/`.

Roughly: a form surface with clean filters ≈ 0.5–1 day once B2 exists; a cart
integration ≈ 3–5 days; an SPA/REST checkout ≈ 5–8 days.

### 6.2 FluentCart

FluentCart is the new target and the most involved, because it is not a
classic-form checkout. Treat `GSWP_Blocks` (Store API) as the template, not
`GSWP_Frontend`.

**Discovery required before any estimate is firm** — do not assume hook names:

- Does the checkout submit over REST/AJAX rather than a POST form? (Expected:
  yes.) If so, the token must ride in the request payload and be read at the
  order-creation hook — a `GSWP_Blocks`-shaped integration.
- What is the server-side hook that fires after FluentCart's own validation and
  before the order/payment is committed, and can it abort with a customer-visible
  error?
- What are the order object's accessors for total, currency, line items,
  billing/shipping address, payment method, and customer? These map onto
  `GSWP_Cart_Adapter`.
- Does FluentCart persist order meta and order notes? Transaction Defense
  annotation and the Google feedback loop both need somewhere to write the
  assessment name and risk.
- Does FluentCart ship its own reCAPTCHA? If so, which option key holds the site
  key, and does it support Enterprise? This determines whether the arbiter has a
  second key to reconcile.
- Are there separate login/registration surfaces, and do they fire core hooks (in
  which case `GSWP_Login` may already cover them) or their own?

**Deliverables once answered:** `GSWP_Fluentcart` (integration) +
`GSWP_Fluentcart_Cart_Adapter` (Transaction Defense) + a manual test. Estimate
**5–8 days** after B1/B3 exist, or 8–12 as a standalone bespoke class without them
— which is the concrete argument for doing B3 first.

### 6.3 Suggested target order

| Target | Type | Why | Notes |
|---|---|---|---|
| Gravity Forms | forms + GF Stripe cart | Live incident; Stripe flow currently unscored | Fix via A2, then `GF_Stripe` adapter under B3 |
| FluentCart | cart | Committed requirement | REST checkout; needs B3 |
| Fluent Forms | forms | Same vendor; ships its own reCAPTCHA → arbiter case | Clean validation filters expected |
| WPForms / Elementor Forms | forms | Highest install base after GF | Both ship reCAPTCHA → arbiter cases |
| Easy Digital Downloads | cart | Second most common non-Woo cart | Classic form checkout; simpler than FluentCart |
| Contact Form 7 | forms | Ubiquitous; ships reCAPTCHA v3 | Arbiter case, low validation complexity |

Every one of these except EDD and CF7 ships its own reCAPTCHA. That is six more
chances to repeat this incident, and it is the reason B1 (loader arbiter) is
worth more than any individual integration.

---

## Appendix — files and lines referenced

| Finding | Location |
|---|---|
| S1 bypass call site | `includes/class-gswp-verifier.php:148-152` |
| S1 bypass predicate | `includes/class-gswp-gravity-forms.php:147-150` |
| S2 `registered` check | `includes/class-gswp-gravity-forms.php:81-93` |
| S2 field printed regardless | `includes/class-gswp-frontend.php:114-118` |
| S3 blanket guard escape | `includes/class-gswp-conflict-guard.php:97-99` |
| S4 DOM kill switches | `includes/class-gswp-frontend.php:152`, `includes/class-gswp-assets.php:123` |
| D2 no key arbitration | `includes/class-gswp-gravity-forms.php:58-67` |
| D4 fail-closed on empty token | `includes/class-gswp-verifier.php:232-237` |
| B3 Woo-coupled transaction data | `includes/class-gswp-verifier.php:431-486`, `:572-645` |
