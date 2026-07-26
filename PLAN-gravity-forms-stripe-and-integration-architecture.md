# Gravity Forms / Stripe failure — root cause, security review, and integration architecture

Status: analysis and options.
Scope reviewed: v2.16.0 (`ca2b1b6`, `c9b7560`, `0d89322`, `dabd588`).

**Progress:** A1 shipped in **v2.17.0** (`31c611f`, merged to `main` at `86e47b7`).
A2–A7 are now specified for implementation in
**`PLAN-recaptcha-loader-corrections.md`** — that document supersedes Part 3 and
Part 5 of this one for sequencing and estimates. This document remains the record
of *why*.

**FluentCart is out of scope here** and tracked as a separate feature; §6.3 below
is retained only as background for that work.

**Site facts confirmed by the operator (2026-07-26), which A2 now assumes:**
Gravity Forms and this plugin use **the same reCAPTCHA Enterprise site key**, in
**the same GCP project**, and **Gravity Forms performs its own server-side
Enterprise API assessments**. Part 3 (A2) and Part 6.2 are written to those
facts; the divergent-key handling is retained only as a guard against future
misconfiguration.

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

**(b) Two Enterprise loaders for the same key.** Even with the guard off, GF emits
`enterprise.js?render=K` and we emit `enterprise.js?render=K` — the operator has
since confirmed both plugins use **the same** site key in the same project, so
these are two tags with an identical `src` under different handles. The browser
fetches once and executes twice. Google documents reCAPTCHA as one-load-per-page;
re-executing the loader can re-initialise the invisible widget and disrupt
`grecaptcha.ready()` callback delivery, which is what GF's field rendering waits
on.

**Revised attribution (after the shared-key confirmation).** The original draft of
this document assumed the keys differed and named (b) as the root cause. They do
not differ, which makes (b) a duplicate-execution problem rather than an
unsatisfiable one — disruptive, but not a guaranteed break. **(a) is therefore the
probable primary mechanism**: with conflict mode set to `active` and our script
enqueued on that page, GF's loader tag was removed from the output outright, which
is a certain and total failure of GF's initialisation.

Both still need fixing, and they map to different remedies: A2.1 deduplicates the
loader, A6 stops the suppression. Neither was addressed by the emergency fix,
which instead disabled our own plugin around the symptom.

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
*"are they using the same site key?"* — and the plugin never asks it. On this site
the answer is **yes**, which means coexistence was always trivially achievable:
one loader, both callers, full protection on both sides. The plugin instead
suppressed one and then disabled the other. Had the question been asked, neither
the outage nor the emergency fix would have happened.

(If two consumers *did* use different keys, no amount of suppression would fix it
and the admin would need to be told. That branch is also not implemented — see
A2.3.)

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

Six findings. **S1 was live and exploitable in v2.16.0; fixed in v2.17.0.**
S2–S5a remain open.

### S1 — Attacker-controlled bypass of all checkout verification (critical) — FIXED v2.17.0

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

Removed in v2.17.0 (`31c611f`). Retained here as the record of what shipped in
2.16.0 and why. Note that its removal un-masks S2 on the checkout leg — see
Part 5.

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

### S5a — What the shared key and shared project actually mean

The operator has confirmed both plugins use the same Enterprise site key in the
same GCP project, and that Gravity Forms makes its own server-side assessment
calls. That resolves several open questions and sharpens the finding:

**What is *not* a problem.** Each `grecaptcha.enterprise.execute()` call returns a
distinct token, and each token is assessable exactly once (reuse returns
`DUPE`). GF assessing its token and us assessing ours do not interfere, share
state, or invalidate each other. A shared key is not a correctness hazard — it is
the condition that makes clean coexistence *possible*. `execute()` itself is a
client-side call and is not billed; only assessments are.

**What is a problem.** Because GF runs its own assessment against the same
project, every Gravity Form submission already produces an Enterprise assessment
— it is simply the wrong assessment:

- It carries **no `transactionData` and no `fraudPrevention`**, so a GF + Stripe
  payment produces a bare bot score. Transaction Defense is enabled on the
  project and returns nothing for the site's real card payments.
- It carries **no `userInfo`**, so Account Defender sees nothing for GF-originated
  account events.
- It is scored against **GF's threshold**, configured in GF's settings, invisible
  to `gswp_threshold_*` and to the operator's mental model of "our" policy.
- Its **assessment name is never exposed** by GF, so `GSWP_Transaction_Defense`
  cannot annotate the outcome. The project therefore receives **no feedback** on
  its highest-value events, and the fraud model never learns from them.

So the current state is worse than "GF covers the form." The project is being
charged for assessments on payment flows while receiving none of the signal those
assessments exist to produce, and no outcome labels to train on. Deferral did not
hand protection to GF — it left the site paying for a downgraded assessment.

This is why the fix is **not** to defer more cleanly. With a shared key we can
always mint our own token, so there is no scenario in which stepping aside is
required. See A2.

---

## Part 3 — Option A: surgical correction

Keep the current architecture. Fix the six things that are wrong.
**~2–3 days** — see the revised estimate at the end of this section.

**A1. Delete `is_form_submission()` and its call site.** (S1) — **SHIPPED v2.17.0.**
A WooCommerce checkout submission is not a Gravity Forms submission. Confirmed
during implementation that the guard was also inert for its stated purpose:
`woocommerce_after_checkout_validation` fires from `WC_Checkout::process_checkout()`,
which a Gravity Forms submission never invokes, so the bypass could only ever have
fired for a crafted WooCommerce checkout POST. Removal carried no functional risk.

**A2. Delete deferral outright; arbitrate the loader, not the protection.**
(D2, root cause)

With a shared site key, deferral has no justification left. We can always mint our
own token from the loader that is already on the page, so there is no scenario in
which our protection must step aside. The only thing that must be arbitrated is
**how many `<script>` tags load `enterprise.js`** — which was the real defect all
along.

**A2.1 — Single-loader reuse (the fix for the original failure).**
`GSWP_Assets`/`GSWP_Frontend` stop unconditionally registering their own loader.
Before registering, check whether a reCAPTCHA loader for our key is already
present on the page (a registered/enqueued script whose src matches a Google
reCAPTCHA loader and whose `render=` parameter equals `gswp_site_key`). If one
is, **do not register a second tag** — mark the loader satisfied and let our
bootstrap run against the global `grecaptcha`. Our bootstrap already only needs
`grecaptcha.enterprise.execute(ourKey, {action})`, which resolves because the key
is rendered.

Result: one loader, both plugins get tokens, GF's Stripe element mounts, and
**GSWP coverage is fully retained on GF pages** rather than surrendered. This is
the difference between A2 as originally drafted and A2 now: the matched-key branch
is no longer one of two paths, it is the design.

**A2.2 — Bootstrap sequencing.**
Our inline bootstrap is currently attached to our own handle via
`wp_add_inline_script()`. When we reuse someone else's loader there is no handle
of ours to attach to. Two options, pick at implementation time:
- attach the inline script to the *detected* handle (simple, but couples us to
  another plugin's handle lifecycle); or
- print the bootstrap on `wp_print_footer_scripts` guarded on `typeof grecaptcha`,
  with a short poll for late loaders (more robust, marginally more code).

Prefer the second. It also removes our dependency on `wp_add_inline_script()`
succeeding, which is one of the failure modes behind S2.

**A2.3 — Divergent-key detection and warning (first-class requirement).**
Not this site's configuration *today*, but GF's key can be changed in GF's own
settings at any time, and other installs and environments will differ. A silent
divergence must become a visible one — see §3.5 of the corrections plan.
If a loader is detected whose `render=` key differs from ours, do not suppress it
and do not silently drop ours. Raise a dismissible admin notice plus a
Compatibility-tab warning naming both keys and the plugin that requested the other
one. Two different Enterprise keys cannot both be pre-rendered via `?render=`;
telling the operator is correct and cheap, guessing a winner is what produced this
incident. The `grecaptcha.enterprise.render()` multi-key path is explicitly out of
scope until someone actually needs it.

**A2.4 — Verify against the installed Gravity Forms source before writing any of
this.** (D5) The current detection code guesses. Confirm on staging:
- Which option key GF's **Enterprise** integration stores its site key under.
  `gravityformsaddon_recaptcha_settings` with `site_key`/`public_key` was inferred,
  not verified, and GF's Enterprise integration may not share storage with the
  classic reCAPTCHA add-on at all.
- Where GF stores its own **project ID and API key** — needed to confirm the
  shared-project assumption programmatically rather than trusting configuration.
- The real script handle and `src` GF emits for the Enterprise loader, and at what
  hook/priority. This determines whether A2.1's detection can run at
  `wp_enqueue_scripts` priority 20 or must move to render time.

Everything in A2 depends on these three answers. Budget the discovery separately
from the implementation.

**A3. Make detection mean what it says.** (S2)
Once A2 lands, `should_defer()` and `is_form_rendered()` have no callers and can
be **deleted entirely** — there is nothing left that needs to know whether a GF
form is on the page, only whether a loader for our key is. That removes the
`'registered'` check, the `post_content` string sniffing, and the speculative
handle list in one move. `GSWP_Gravity_Forms` shrinks to key detection plus
whatever Part 6.2 needs.

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

**A6. Narrow the Conflict Guard to divergent keys; keep `active` Recommended.** (S3)
Delete the blanket `is_active()` escape. Dedup becomes unconditional and
mode-independent — a loader carrying **our** key is always reused, never stripped,
in every mode — which is what makes the configuration that broke Stripe (same key,
`active`) a no-op. `active` keeps a real but narrow job: suppressing a *different*
key on pages where our reCAPTCHA runs.

**Operator decision (2026-07-26): `active` remains the Recommended mode, with loud
warnings rather than a default change.** This supersedes the earlier draft here,
which moved "Recommended" to `off`. Suppression of a divergent key is still
destructive to the other plugin's forms; it is now impossible to do silently. See
§3.5 and §3.7 of `PLAN-recaptcha-loader-corrections.md`.

**A7. Coverage.** (D6)
Add `tests/manual/09-recaptcha-coexistence.php`: GF + Woo on one page, same key
and different keys, guard on and off; assert one loader tag, both tokens
populated, checkout completes, and Transaction Defense still produces an
assessment.

**Result:** the original bug is fixed at its cause, all five security findings
close, and — importantly — GSWP protection is *retained* on GF pages instead of
surrendered. GF's Stripe checkout keeps working *and* gets scored.

**Revised estimate: ~2–3 days** (up from 1–2). A2 grew from a branch into the
central change, A2.2 (bootstrap sequencing off our own handle) is new work, and
A2.4 adds a discovery pass against the GF source. A3 shrank to a deletion, which
offsets some of it.

**Limits:** A2 gives GF pages *our* protection back, but it does **not** give the
GF + Stripe payment `transactionData`. Closing S5a requires Part 6.2. Still
hard-coded to Gravity Forms by name; FluentCart, WPForms, Elementor Forms, Fluent
Forms, EDD each need their own bespoke class, and the next plugin that loads
reCAPTCHA repeats this incident.

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

Revised after A1 shipped and after the shared-key facts were confirmed.

1. ~~A1 — remove the `gform_submit` bypass.~~ **Done, v2.17.0.**
2. **Immediately next: A4, then A5.** A1's removal un-masked S2 on the checkout
   leg (login and registration were already exposed in 2.16.0). A4 — the single
   `will_load()` gate, so we never print a token field nothing will fill — kills
   the entire fail-closed "token missing" class on its own, is self-contained, and
   needs no Gravity Forms knowledge. A5 (delete the DOM kill switches) is minutes
   and removes the injectable client-side disable. Ship these two as **2.17.1**
   without waiting for the GF source review.
3. **Then A2.4 (discovery), then A2 + A3 + A6 + A7 as 2.18.0.** A2 is now the
   central change rather than one branch of it, and it is gated on reading the
   installed GF Enterprise integration. A3 becomes a deletion once A2 lands.
4. **Then Part 6.2 — the GF Stripe assessment.** This is what actually closes
   S5a: A2 restores our coverage on GF *pages*, but the GF + Stripe *payment*
   still produces a bare score with no `transactionData` and no annotation. On a
   project that is already paying for Transaction Defense, this is the highest
   security value remaining in this document.
5. **Then Option B**, driven by FluentCart — B1 and B3 are the load-bearing
   pieces; B2 is refactoring of code that already exists.

The split at step 2 is deliberate: A4 and A5 are availability-critical and
knowledge-free, while everything from step 3 on is blocked on facts we do not yet
have about Gravity Forms. Do not let the second set hold up the first.

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

### 6.2 Gravity Forms — the Stripe payment assessment

> **Specified for implementation in `PLAN-gravity-forms-stripe-assessment.md`
> (target 2.19.0).** That document supersedes this section for design, sequencing
> and estimates; the estimate there is ~6 days rather than the 3–5 below, because
> the GF field-mapping problem and the WooCommerce coupling in the annotation
> layer were both underestimated here.

A2 fixes the loader conflict and restores our coverage on GF pages. It does not
fix S5a: GF's own assessment for a Stripe payment still carries no
`transactionData`, no `fraudPrevention`, no `userInfo`, and exposes no assessment
name to annotate. On a project already enabled for Transaction Defense, that is
the remaining gap and it sits on the site's real card payments.

Because the key and project are shared, the fix is available to us without any
cooperation from GF: **mint our own token for the GF payment submission and create
our own assessment carrying the transaction data.** We own that assessment's name,
so `GSWP_Transaction_Defense` can annotate the outcome and the feedback loop
closes. GF continues doing whatever it does; we stop being blind to the payment.

Shape of the work:

- Our bootstrap already fills every `.g-recaptcha-response` field on the page.
  Inject one into the GF form (GF exposes form-render hooks for this) with
  action `checkout`, and it is populated by the loader A2.1 already reuses.
- Validate server-side at a GF hook that fires **after** GF's own validation and
  **before** the Stripe charge is authorised. Identifying that hook — and
  confirming it can abort with a customer-visible error — is the main unknown.
  GF's Stripe add-on feed processing is the place to look.
- Map the GF entry plus the Stripe feed onto `GSWP_Cart_Adapter` (B3) —
  total, currency, billing address, payment method, customer — so the same
  `transactionData` builder serves Woo, FluentCart, and GF.

This is the `GF_Stripe` adapter referenced in B3, and the shared-project fact is
what makes it straightforward: no second key, no second project, no separate
credentials, and the assessments land alongside the Woo ones in the same console.

**Cost:** one additional assessment per GF payment submission, on top of the one
GF already creates. That is the honest trade — it is a real line item, and it buys
transaction risk scoring plus outcome feedback on flows that currently produce
neither. Worth confirming against current assessment volume before committing.

**Estimate:** 3–5 days once B3 exists, most of it in locating and proving the
pre-charge validation hook. Depends on A2 landing first.

### 6.3 FluentCart

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

### 6.4 Suggested target order

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
