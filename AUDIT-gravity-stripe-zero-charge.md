# Audit: $0.00 entries and Stripe 400s on the Registration form

**Date:** 21 August 2026
**Plugin version audited:** 2.27.3 (`main` @ 138e751)
**Reported symptoms:** Gravity Forms entries with a `$0.00` total and no payment status (e.g. entry 6051);
`400 parameter_invalid_integer` on `POST /v1/payment_intents` in the Stripe logs; several $0.00 entries with
no corresponding Stripe activity at all.

---

## Verdict

**The security plugin did not cause either symptom, and it is not blocking these transactions.**

Three independent facts settle it:

1. **The plugin has exactly one lever over a Gravity Forms submission** — it sets
   `$validation_result['is_valid'] = false` on the `gform_validation` filter
   (`includes/class-gswp-provider-gravity-forms.php:894`, `:1199`). It never modifies `$_POST`, never writes
   to an entry, never touches an order total, and never makes a Stripe API call. Its only outbound calls go to
   `recaptchaenterprise.googleapis.com` / `google.com/recaptcha`.
2. **When it pulls that lever, no entry is created and no card is touched.** Gravity Forms' payment framework
   returns immediately when validation has already failed
   (`GFPaymentAddOn::maybe_validate()`, `class-gf-payment-addon.php:673-675`), so the gateway is never reached;
   and `GFFormDisplay::validate()` propagates the filtered `is_valid`, so no entry is saved. A submission this
   plugin rejects leaves **nothing** — no entry, no customer, no PaymentIntent.
3. **A `$0.00` entry is therefore proof of the opposite.** The entry exists, so validation passed, so the plugin
   admitted the submission.

What follows is where the two symptoms actually come from, both verified against Gravity Forms source.

---

## Where the $0.00 entries come from

Gravity Forms refuses to process a payment for a zero total, and **still saves the entry**:

```php
// gravityforms/includes/addon/class-gf-payment-addon.php:880
public function is_valid_payment_amount( $submission_data, $feed, $form, $entry ) {
    $is_valid = floatval( $submission_data['payment_amount'] ) > 0;
    ...
}

// :812 — called from GFPaymentAddOn::validation()
if ( ! $this->is_valid_payment_amount( $submission_data, $feed, $form, $entry ) ) {
    $this->log_debug( __METHOD__ . '(): Aborting. Payment amount not valid for processing.' );
    return $validation_result;   // <- still valid; entry gets saved
}
```

That produces exactly the shape of entry 6051: every other field populated, **"Select Your Courses" blank**,
total `$0.00`, payment status and payment date empty, and **no Stripe request at all** — which is precisely the
"never called to process the credit card" observation.

So the real question is upstream of both plugins: **why did the submission arrive with no product selected?**
Candidates, in the order worth checking (see *What to check on the site* below): the product field is not
required; a 100%-discount coupon; or conditional logic hiding the product field, its section, or its page at
submit time (Gravity Forms strips values from conditionally hidden fields before pricing).

## Where the Stripe 400s come from

The failing request at 11:47:53 came from the **site's own server** (IP `64.177.123.151`, user agent
`Gravity Forms Stripe/6.0.3`), not from the customer's browser. Gravity Forms Stripe exposes a public AJAX
endpoint that creates a PaymentIntent with an amount taken **directly from the browser**, with no zero or
minimum-amount guard:

```php
// gravityformsstripe/class-gf-stripe.php:459 (verified on add-on 3.8)
add_action( 'wp_ajax_nopriv_gfstripe_create_payment_intent', array( $this, 'create_payment_intent' ) );

// :6084
public function create_payment_intent() {
    check_ajax_referer( 'gf_stripe_create_payment_intent', 'nonce' );
    ...
    $data = [
        'amount'         => intval( rgpost( 'amount' ) ),   // <- straight from the client
        'capture_method' => 'manual',
        ...
    ];
    $intent = $this->api->create_payment_intent( $data );
}
```

This is the card-field / payment-element path, and it runs **before** `is_valid_payment_amount()` is ever
consulted — that gate lives on the submission path, not this one. If the browser posts `amount=0` (card field
mounting before a course is selected, or the selection being changed), Stripe answers with exactly the observed
error: `parameter_invalid_integer` on `amount`, with the "use a Setup Intent instead" hint that Stripe emits for
a zero amount.

It also explains the orphaned Stripe activity: these intents are created with `capture_method: manual`, so a
visitor who never completes the form leaves an uncaptured authorization behind with no entry attached.

**Caveat:** this endpoint is verified against the mirrored add-on 3.8; the site runs 6.0.3. The mechanism is
almost certainly unchanged, but confirm it with the one-line check in the site checklist below before quoting
it to the client as settled.

---

## Defects found in the plugin during this audit

None of these caused the reported incident. All are real, and two of them are worth fixing promptly.

### A — Transaction Defense reports every payment to Google as $0.00 · **High**

`order_total()` passes an empty array where Gravity Forms expects an entry:

```php
// includes/class-gswp-provider-gravity-forms.php:1432
// GFCommon::get_order_total() accepts the submitted values during
// validation via GF's own field-value resolution.
$total = GFCommon::get_order_total( $form, array() );
```

The comment is wrong. `get_order_total()` reads values out of the entry array it is given, and
`GFFormsModel::get_lead_field_value()` short-circuits on an empty one:

```php
// gravityforms/forms_model.php:6356
public static function get_lead_field_value( $lead, $field ) {
    if ( empty( $lead ) || ! is_array( $lead ) ) {
        return null;
    }
```

So every product resolves to `null`, and **`order_total()` returns `0.0` on every submission**. Every Enterprise
assessment for a Gravity Forms payment form has been sending `transactionData.value = 0`. Google's fraud model
is being scored and trained on a zero-value transaction for every payment taken through the site, silently — and
`gswp_txn_block`, if it is ever switched on, would act on a verdict derived from that.

**Fix:** pass the entry Gravity Forms builds from the submission — the same one the payment add-on uses at
`class-gf-payment-addon.php:804`. It is memoized, so this costs nothing:

```php
$lead  = GFFormsModel::get_current_lead( $form );
$total = GFCommon::get_order_total( $form, is_array( $lead ) ? $lead : array() );
```

### B — Validation priority collides with every Gravity Forms payment add-on · **High (latent)**

Both filters register at priority 20 on the same hook:

```php
// includes/class-gswp-provider-gravity-forms.php:894
add_filter( 'gform_validation', array( $this, 'validate_submission' ), 20 );

// gravityforms/includes/addon/class-gf-payment-addon.php:220
add_filter( 'gform_validation', array( $this, 'maybe_validate' ), 20, 2 );
```

At equal priority WordPress runs callbacks in registration order, and registration order here is decided by
nothing more than the alphabet: `active_plugins` is stored sorted, `google-security-for-wordpress` sorts before
`gravityforms`, so this plugin's callback is registered first and therefore runs first. That is why a rejection
currently precedes authorization and no card is ever touched — **luck, not design.**

Anything that reorders plugin loading (a load-order plugin, a rename, a must-use loader) flips it. On the other
side of that flip, the add-on authorizes the card first and this plugin then invalidates the submission: an
uncaptured PaymentIntent on the customer's card, no entry, and no code path that voids it. The file's own header
names this as the open risk ("*a rejection here stops the entry but not the authorisation*"); it is now answered,
and the answer is that we are one plugin-order change away from it.

**Fix:** register at priority 9, so this plugin always precedes any payment add-on regardless of load order.

### C — A present-but-empty token field hard-blocks payment forms · **High**

This is the mechanism by which the plugin genuinely *can* block a transaction. Once a form has ever received a
token field, a payment submission arriving with an empty one is rejected outright
(`:1037`, `:1051`, `:1080`) — no entry, no Stripe call, and the visitor gets
*"We could not verify this submission. Please refresh the page and try again."*

The field is filled by JavaScript from Google's API. Anything that stops that fills it with nothing: reCAPTCHA
blocked at the network, an ad blocker, a script optimizer that defers or combines scripts, or `grecaptcha` simply
not arriving inside the bootstrap's 10-second poll (`READY_TIMEOUT_MS`). The same applies server-side —
`recaptcha_api_failed` (a failed `wp_remote_post()` to Google on a 10-second timeout,
`class-gswp-verifier.php:437` and `:551`) is also a hard reject on a payment form, so a blip in outbound
connectivity to Google blocks live payments.

This is worth knowing about, but note it does **not** fit the reported symptoms: it leaves no entry.

### D — Tokens are spent on every page of a multi-page form · **Medium**

Gravity Forms only runs payment validation on the last page
(`GFFormDisplay::is_last_page()`, `class-gf-payment-addon.php:681-686`). This plugin's `validate_submission()`
runs on **every** page transition and verifies — and therefore spends — the token each time. The footer bootstrap
re-mints on click, but if the replacement has not resolved before the next *Next* or *Submit*, Google returns
`DUPE` → `recaptcha_expired` → and on a payment form that is a hard reject with no latitude. A visitor clicking
briskly through a multi-page registration is the exact profile.

### E — The rejection log is written but never displayed · **Medium**

`GSWP_Log::tail()` has **no callers anywhere** in the plugin — not in the REST API, not in the React admin
(verified by grep across `includes/`, `src/` and the main file). Every rejection reason, coverage gap and
`SITE_MISMATCH` warning is written into the `gswp_log_tail` option and then shown to nobody.

The only in-admin evidence is `gswp_gf_last_rejection`, which keeps **one row per form** (last reason only) and
throttles same-reason writes to one per five minutes (`:1229`) — so forty blocked checkouts and one blocked
checkout look identical. With no WooCommerce on this site there is no WC log viewer either, so the messages reach
the PHP error log and nowhere else.

This is the reason this question could not be answered from wp-admin and needed a source audit instead.

### F — A same-key/different-family loader conflict is logged but never surfaced · **Low–Medium**

`filter_tag()` deduplicates reCAPTCHA loaders on `family|key`. When the same site key is loaded as both
`api.js` (classic) and `enterprise.js`, both tags are deliberately kept and `$family_conflict` is set — which
only ever reaches `GSWP_Log::error()`. Divergent *keys* get a transient and an admin notice; this case gets
neither, and per finding E the log it writes to is invisible.

That matters because two reCAPTCHA scripts fighting on a payment page is the configuration that caused the
original 2.16.0 Gravity Forms / Stripe outage recorded in `STATE.md:830`. Gravity Forms' own reCAPTCHA add-on
(2.2.2) is configured on this site with a v3 key, so the conflict is reachable.

---

## What to check on the site

In order. The first three are where the actual bug almost certainly is.

1. **Is "Select Your Courses" a required field on form #2?** If it is not, a visitor can submit with nothing
   selected and Gravity Forms will do exactly what entry 6051 shows. This alone may be the whole story.
2. **Coupons or discounts.** A 100%-discount coupon produces a $0.00 total, a saved entry and no Stripe call —
   the same signature.
3. **Conditional logic** on the product field, on its section, or on its page. A field hidden by conditional
   logic at submit time has its value stripped before pricing.
4. **Gravity Forms logging** (Forms → Settings → Logging, enable for Gravity Forms Core and Stripe, then
   reproduce). Look for `Aborting. Payment amount not valid for processing.` — that line is the confirmation of
   the $0.00 path, printed by the code quoted above.
5. **Confirm the 400 source on add-on 6.0.3:** grep the installed add-on for
   `wp_ajax_nopriv_gfstripe_create_payment_intent` and check whether `create_payment_intent()` still takes
   `intval( rgpost( 'amount' ) )` without a minimum-amount guard.
6. **Read what this plugin has actually rejected** (the two options that hold it, neither of which has a UI):

   ```bash
   wp option get gswp_gf_last_rejection --format=json
   wp option get gswp_log_tail --format=json
   wp option get gswp_gf_injection_log --format=json
   ```

   If form #2 shows `missing token` or `recaptcha_expired`, the plugin *is* rejecting some submissions — that is
   findings C and D, a real problem worth fixing, but a separate one: those submissions left no entry.
7. **In Stripe**, filter for incomplete/uncaptured PaymentIntents. Those are the AJAX-created ones from abandoned
   or re-edited forms, and they are expected noise rather than lost money.

**To rule the plugin out empirically in one step**, add this to `wp-config.php`:

```php
define( 'GSWP_DISABLE_FORM_PROVIDERS', true );
```

It removes this plugin from the Gravity Forms path immediately, on the next request, without deactivating
anything and without touching any stored settings — 2FA, Account Defender and Password Defense keep running
(`class-gswp-form-provider-registry.php:110-116`). If $0.00 entries keep appearing with it set, the plugin is
conclusively excluded.

---

## Recommended changes

Not applied — these touch the payment path on a live site and are the operator's call.

| # | Change | Risk |
|---|--------|------|
| A | Pass `GFFormsModel::get_current_lead( $form )` to `get_order_total()` | Low — restores an intended value; no enforcement change |
| B | Move `gform_validation` registration from priority 20 to 9 | Low — removes an ordering race; no behaviour change today |
| E | Surface `GSWP_Log::tail()` on the Diagnostics tab | Low — additive, read-only |
| D | Skip verification on non-final pages of multi-page forms | Medium — narrows enforcement; needs a decision |
| F | Give the same-key/different-family conflict the admin notice the divergent-key case already gets | Low — additive |

A and B are one-line changes and are worth shipping together. C is a design question rather than a bug: the
fail-closed posture on payment forms is deliberate and documented, and softening it trades a blocked customer
for an unscored payment — worth a conversation, not a patch.
