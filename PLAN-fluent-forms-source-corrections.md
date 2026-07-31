# Implementation Plan — correcting the Fluent Forms bindings against installed source

**Target release:** 2.23.2
**Predecessor:** `PLAN-fluent-forms-provider.md` (2.23.0), Phase 50 addendum in `STATE.md` (2.23.1)
**Evidence base:** Fluent Forms **6.2.9** free **and Fluent Forms Pro 6.2.7**,
both read directly. Every binding below cites the file and line it was read from.
**Status: PLANNED. No code changed yet.**

*Revision 2 — Pro 6.2.7 obtained after revision 1 was written. It changed two
conclusions and made a third worse. D2 was understated: the defect is not
confined to forms carrying both feed kinds, it hits **every** User Update form
deterministically. D8 inverts: no Fluent Forms gateway authorises a card before
our validation runs, so blocking is safe and the default should change. The last
render path (modal) is settled. Revision 1's reasoning is superseded where the
two disagree; nothing from revision 1 is left standing unmarked.*

---

## 0. What this document is, and what changed

The Phase 50 addendum listed nine open bindings (§5 of the handoff) that could
not be settled from documentation or from the live install. Fluent Forms 6.2.9
and Fluent Forms Pro 6.2.7 have now both been read. **All nine are settled.**

The review found **eight defects in the shipped provider**, three of which are in
a request path. It also found **one claim recorded as settled that is false**,
which matters more than any single defect because it is the mechanism by which
the others get missed.

**The headline is D2.** Every Fluent Forms **User Update** form — a profile-edit
form for signed-in users — is classified by the shipped provider as an account
**creation** form, and is therefore STRICT, and therefore rejects a submission
with a missing or stale token. Not "a form configured a certain way", and not
half the time: deterministically, on every User Update form, because both feed
kinds share one `meta_key` and the provider's discriminator looks for four key
names that Fluent Forms does not use. This is the Phase 48 incident reproduced in
shipped code, on the same class of form, with the same message shown to the same
kind of person. It is the reason this release exists.

### 0.1 The retraction

> *"Transport 1 also works, and that was the open question. `$formData` carries
> `_wp_http_referer` and Fluent Forms' own nonce — neither is a registered field
> — so it is the whole serialised payload, not a list filtered to known fields.
> Our hidden input survives into it."*
> — `STATE.md`, Phase 50 addendum, "Settled by the run"

**This is wrong.** `$formData` *is* filtered, and our hidden input does *not*
survive into it.

`SubmissionHandlerService::prepareHandler()` (`app/Services/Form/SubmissionHandlerService.php:125-127`):

```php
$formData = fluentFormSanitizer($formDataRaw, null, $this->fields);
$acceptedFieldKeys = array_merge($this->fields, array_flip(Helper::getWhiteListedFields($formId)));
$this->formData = array_intersect_key($formData, $acceptedFieldKeys);
```

`fluentFormSanitizer()` keeps every key — that part of the reasoning was sound.
The `array_intersect_key()` on the next line then drops everything that is not a
registered field **or** a member of a fixed 14-entry allow-list
(`Helper::getWhiteListedFields()`, `app/Helpers/Helper.php:1425`). That
allow-list is why `_wp_http_referer` and `_fluentform_{id}_fluentformnonce`
appeared in the capture. They are not evidence that unregistered keys survive;
they are the two named exceptions that prove they do not.

`gswp_ff_token` is neither registered nor whitelisted, so **transport 1 returns
empty on every submission, on every form, always.** It has been dead since it was
written and nothing has noticed, because transport 2 (re-parsing `$_POST['data']`)
catches it one line later.

The failure is not the wrong answer. It is that the observation "the payload
contains two keys that are not fields" was treated as proof of a general property
("unregistered keys survive") when the source shows those two keys are enumerated
by name. **A capture shows you what is in the payload. It does not show you why.**
That is the same shape as the 2.23.1 root cause — a binding verified along one
axis and assumed along another — recurring one release later, on the very run
that was written to catch it.

The fix (D1) makes transport 1 true rather than deleting it, because the
mechanism Fluent Forms provides for exactly this is a filter, and using it is
cheaper and more durable than re-parsing a request envelope. Pro uses that same
filter for its own submitted keys (`UserUpdateFormHandler::addWhiteListedFields`),
which is as close to a vendor endorsement of the approach as source gets.

---

## 1. Bindings settled by the source read

Everything in this table is now **VERIFIED against installed source** at the
stated file and line. The version axis is Fluent Forms 6.2.9 / Pro 6.2.7; nothing
here should be treated as verified for a different major version. Paths without a
`Pro:` prefix are in the free plugin.

| # | Binding | Answer | Source |
|---|---|---|---|
| 1 | Live submission handler | `SubmissionHandler::submit()` → `SubmissionHandlerService::handleSubmission()`. **`FormHandler::onSubmit()` is commented out** and is dead code — do not read bindings from it. | `app/Hooks/Ajax.php:17-24` |
| 2 | `$formData` at `validation_errors` | Filtered to registered fields + `getWhiteListedFields()`. Unregistered keys are dropped. | `SubmissionHandlerService.php:125-127` |
| 3 | Whitelist extension point | `apply_filters('fluentform/white_listed_fields', $fields, $formId)` | `Helper.php:1443` |
| 4 | `fluentform/validation_errors` | `($errors, $formData, $form, $fields)`, fired **unconditionally** (not only when errors exist). Our 4-arg / priority-20 registration is correct. | `FormValidationService.php:170` |
| 5 | Error delivery shape | `throw new ValidationException('', 423, null, ['errors' => $errors])` → `wp_send_json($e->errors(), 423)`. | `FormValidationService.php:212`, `SubmissionHandler.php:26` |
| 6 | **Account creates vs updates — the discriminator** | **Both** feed kinds live under **one** `meta_key`, `user_registration_feeds`. The discriminator is **`list_id`** inside the feed JSON, and the vendor's own test is `Arr::isTrue($feed,'enabled') && Arr::get($feed,'list_id') === 'user_update'`. Registration is the default branch: everything that is *not* `'user_update'` registers. | Pro: `UserRegistration/UserUpdateFormHandler.php:109-113`, `UserRegistrationApi.php:57-63`, `Getter.php:52-60` |
| 7 | Account feed row shape | `value` = `json_encode()` of a flat object; `enabled` is a **bool**; the status toggle writes `$metaValue['enabled'] = $status`; `conditionals` may gate a feed **at runtime**. | `FormIntegrationService.php:100-152`, `GlobalNotificationManager.php:262` |
| 7b | **`_has_user_registration` / `_has_user_update` are sticky** | Written by `handleValidate()` when a feed is **saved**, regardless of whether it is enabled, and **never deleted**. A form that once had a registration feed reports `_has_user_registration = 'yes'` forever. Usable as a fallback, not as current state. | Pro: `UserRegistration/Bootstrap.php:284-289` |
| 7c | Core's own gate on those flags | Registration errors fire only when `!get_current_user_id()`; update errors only when `get_current_user_id()`. A form may legitimately carry both. | `FormValidationService.php:178,193` |
| 8 | reCAPTCHA option | `_fluentform_reCaptcha_details`, stored as a **PHP array**, keys `siteKey`, `secretKey`, `api_version`. | `GlobalSettingsHelper.php:41-48` |
| 9 | reCAPTCHA version key/values | `api_version` ∈ `'v2_visible'` \| `'v3_invisible'`. | `GlobalSettingsHelper.php:36`, `filters.php:415-420` |
| 10 | hCaptcha option | `_fluentform_hCaptcha_details`, array, `siteKey`/`secretKey`, **no version key**. | `GlobalSettingsHelper.php:112` |
| 11 | Turnstile option | `_fluentform_turnstile_details`, array, `siteKey`/`secretKey`/`invisible`/`appearance`/`theme`. | `GlobalSettingsHelper.php:218-224` |
| 12 | Keys-valid flags | `_fluentform_reCaptcha_keys_status`, `_fluentform_hCaptcha_keys_status`, `_fluentform_turnstile_keys_status` — boolean, set only after the vendor validated the key pair. | `GlobalSettingsHelper.php:50,113,236` |
| 13 | Captcha field elements | `recaptcha`, `hcaptcha`, `turnstile` — matched with `FormFieldsParser::hasElement($form, '<name>')`. Our map is correct. | `FormValidationService.php:568,613,653` |
| 14 | **Captcha is per-form, plus a global override** | FF validates a captcha iff the form has the field **OR** `apply_filters('fluentform/has_recaptcha'\|`has_hcaptcha`\|`has_turnstile`, false)` returns true. | `FormValidationService.php:568` etc. |
| 15 | Host captcha can be suppressed by filter | `apply_filters('fluentform/disable_captcha', false, $form, 'recaptcha'\|'hcaptcha'\|'turnstile')` | `FormValidationService.php:567` |
| 16 | Payment field elements | `payment_method`, `custom_payment_component`, `multi_payment_component`, `subscription_payment_component`, `item_quantity_component`, `payment_summary_component`, **`stripe_inline`**, **`square_inline`**, **`payment_coupon`**. | component constructors under `app/Modules/Payments/Components/`; Pro: `Square/Components/SquareInline.php:22`, `Stripe/Components/StripeInline.php:22`, `Payments/Components/Coupon.php:17` |
| 17 | Password element | `input_password` — named in the core sanitiser. | `boot/globals.php:98` |
| 18 | Address sub-keys | Element `address`, submitted **nested under the field's own name**: `$formData['address_1']['address_line_1'\|'address_line_2'\|'city'\|'state'\|'zip'\|'country']`. | `DefaultElements.php:376-620` |
| 19 | Name sub-keys | `first_name`, `middle_name`, `last_name`, nested the same way. | `PredefinedForms.php` (blank-form JSON) |
| 20 | Currency at validation time | `PaymentHelper::getFormCurrency($formId)` → form meta `_payment_settings.currency`, falling back to `__fluentform_payment_module_settings.currency`, default `'USD'`. Available before any transaction row exists. | `PaymentHelper.php:17-20, 96-115, 146-170` |
| 21 | `fluentform/submission_inserted` | `($insertId, $formData, $form)`. Our registration is correct. | `SubmissionHandlerService.php:239-241` |
| 22 | `Helper::setSubmissionMeta` | `($submissionId, $metaKey, $value, $formId = false)` | `Helper.php` |
| 23 | `Helper::getSubmissionMeta` | `($submissionId, $metaKey, $default = false)` | `Helper.php` |
| 24 | **`fluentform/after_payment_status_change`** | **`($newStatus, $submission)` — two args, status FIRST.** | `BaseProcessor.php:157` |
| 25 | Payment status strings | `'paid'`, `'failed'`, plus gateway-supplied values passed straight through. `'refunded'` is not emitted by the free core. | `BaseProcessor.php:250,738` |
| 26 | Render paths | Gutenberg block, Elementor widget **and the Pro form modal** all emit `do_shortcode('[fluentform …]')`. **All route through `FormBuilder::render()`**, so all fire `form_element_start` / `before_form_render` / `after_form_render`. This closes the last render-path unknown in the handoff's §5.9. | `GutenbergBlock.php:69`, `FluentFormWidget.php:2540`; Pro: `classes/FormModal.php:43` |
| 27 | **Conversational forms do not** | Marked by form meta `is_conversion_form == 'yes'`; rendered by `FluentConversational\Classes\Form::renderFormHtml()` into a Vue view — reached both from core and from Pro's share-page. Fires **none** of the three render actions and emits **no** `.ff-errors-in-stack` container. | `Form.php:197+`, `app/Views/public/conversational-form.php`; Pro: `classes/SharePage/SharePage.php:219` |
| 28 | Buffer balance | `FormBuilder::render()` is itself wrapped in `ob_start()` … `ob_get_clean()`, with `before_form_render` and `after_form_render` both **inside** it and always paired. The buffered backstop nests safely. | `FormBuilder.php:152,219,221` |
| 29 | Error stack container | `<div id="fluentform_{id}_errors" class="ff-errors-in-stack …"></div>`, emitted immediately after `</form>` on every `FormBuilder::render()` path. | `FormBuilder.php:206` |
| 30 | Default error placement | **`'inline'`**, not `stackToBottom`. | `app/Models/Form.php:198` |
| 31 | **Charge timing — the server side, all gateways** | Every gateway without exception charges from `fluentform/process_payment_{method}`, dispatched by `PaymentHandler::maybeHandlePayment()` on `fluentform/before_insert_payment_form` — which runs **after** `handleValidation()`. There is no server-side charge path that precedes our filter. | `PaymentHandler.php:77`, `SubmissionHandlerService.php:44-50`; Pro: every `*Processor.php::init()` |
| 31b | **Charge timing — the client side, all gateways** | **No gateway authorises a card before the submission reaches us.** Stripe Inline: `createPaymentMethod` — tokenisation. Square Inline: `card.tokenize()` then `verifyBuyer(…, {intent:'CHARGE'})` — a 3-D Secure *challenge* producing a verification token; no payment, no hold. Authorize.Net: `Accept.dispatchData` → opaque nonce, and it runs in a **post-submission modal** (its config carries `submission_id` and `transaction_hash`). PayPal Inline: the button's `onClick` **submits our form first** and returns a promise; `createOrder` cannot run until the server answers, and a validation failure **rejects** that promise so no PayPal order is ever created. Mollie, Paddle, Paystack, RazorPay, Square-hosted, Stripe-hosted, Offline: server-side redirect or post-submission modal. | `assets/js/payment_handler.js`; Pro: `public/js/payment_handler_pro.js`, `public/js/ff_paypal_inline.js`, `public/js/authorizenet_accept_handler.js` |
| 32 | **Fluent Forms itself uses a non-field errors key** | Pro's user-registration guard returns `$errors['restricted'][] = …`, and core's rate limiter throws `['errors' => ['restricted' => [...]]]`. `restricted` is not a form field. The vendor relies on the same unresolvable-key → error-stack path D4 proposes. | `FormValidationService.php:147-152`; Pro: `UserRegistration/Getter.php:42-50` |

---

## 2. Defects to correct

Ranked by what they cost. Each names the file, the current behaviour, the
corrected behaviour, and how it is proved.

### D1 — Transport 1 is dead; the docblock says it is verified

**File:** `includes/class-gswp-provider-fluent-forms.php`, `submitted_token()` (~1365) and its docblock (~1330-1364).

**Now:** transport 1 reads `$form_data[TOKEN_FIELD]`, which is always absent
(§0.1). Transport 2 re-parses `$_POST['data']` by hand and carries every
submission. The docblock records transport 1 as VERIFIED working.

**Correct to:** register the token on Fluent Forms' own allow-list, which makes
transport 1 genuinely true, and demote transport 2 to what it actually is — a
backstop for a request shape we have not seen.

```php
// in register_hooks()
add_filter( 'fluentform/white_listed_fields', array( $this, 'whitelist_token_field' ), 10, 2 );

public function whitelist_token_field( $fields, $form_id ) {
    if ( is_array( $fields ) && $this->form_is_eligible( $form_id ) ) {
        $fields[] = self::TOKEN_FIELD;
    }
    return is_array( $fields ) ? $fields : array( self::TOKEN_FIELD );
}
```

Why this and not "delete transport 1":

- It is the host's documented extension point, used by Fluent Forms itself for
  `g-recaptcha-response`, `h-captcha-response` and `cf-turnstile-response`. We
  are asking for the same treatment as the three captchas we are replacing.
- It is a **read-path filter, not a settings write.** Nothing is persisted into
  Fluent Forms' options or tables, so the Phase 43/44 rule is untouched.
- It removes our dependence on the private shape of `$_POST['data']`. That shape
  is not API; `SubmissionHandler::submit()` `parse_str()`s it and any future
  transport change (REST, a different serialiser) breaks transport 2 silently
  while transport 1 keeps working.

**Cost, stated rather than discovered later:** a whitelisted key is included in
`$this->formData`, which `prepareInsertData()` JSON-encodes into
`fluentform_submissions.response`. So the spent token is stored on the entry. It
is not displayed — `SubmissionService::getSubmission()` strips whitelisted fields
with `Arr::except($data, Helper::getWhiteListedFields($formId))`
(`SubmissionService.php:712`) — and a v3 token is single-use and expires in 120
seconds, so it is inert data. This is a deliberate trade for determinism, and it
must be written into the docblock so the next reader does not "fix" it.

**Proof:** chunk 22 re-run with the provider ON, printing which transport
returned the token. Transport 1 must be the one that fires.

### D2 — Every User Update form is classified as an account-creation form

**File:** `account_feed_type()` (~567), `feed_is_update()` (~615).

**Severity: this is Phase 48, in shipped code, reachable by any site that turns
the provider on and has a profile-edit form.**

**Now:** the provider scans every `fluentform_form_meta` row whose `meta_key`
*contains* `user_registration` or `user_update`, decodes the value as JSON, and
decides create-vs-update from four candidate keys — `feedType`, `feed_type`,
`userRegistrationType`, `type`.

**What Pro actually stores.** Both feed kinds are written under **one**
`meta_key`, `user_registration_feeds` (`FormIntegrationService.php:143`,
`$metaKey = $integrationName . '_feeds'`; confirmed by Pro's own query in
`Getter.php:52-60`). The discriminator is **`list_id`**, and the vendor's test is
a single line (`UserUpdateFormHandler.php:109-113`):

```php
protected function isValidFeed($feed) {
    return Arr::isTrue($feed, 'enabled') && Arr::get($feed, 'list_id') === 'user_update';
}
```

**None of the four candidate keys exists.** `feed_is_update()` therefore returns
false for every real feed row, and the `strpos($key, 'user_update')` test never
matches a feed row either, because update feeds are stored under a key containing
`user_registration`.

**Trace it on a pure User Update form.** Two meta rows exist. Pro writes
`_has_user_update` first — `handleValidate()` runs on the
`fluentform/save_integration_value_*` filter, which fires *inside*
`FormIntegrationService::update()` **before** the feed row is written
(`Bootstrap.php:284-289`, `FormIntegrationService.php:130-152`) — so it is the
lower id and comes back first from an unordered `SELECT`.

1. Row `_has_user_update` = `'yes'`. `strpos($key,'user_update')` matches →
   `feed_is_update()` true → `$type = 'update'` → `continue`.
2. Row `user_registration_feeds`. `strpos($key,'user_registration')` matches.
   `json_decode` succeeds. `enabled` is `true`, so it is not skipped.
   `feed_is_update()` looks for four keys that are not there → false →
   **`return 'create'`**, immediately, discarding the `'update'` already found.

`form_is_strict()` → true. A signed-in customer submitting her profile-edit form
without a token — a stale single-use token, a cached page, a slow bootstrap — is
**rejected** and told the submission could not be verified.

Revision 1 of this document described this as a hazard for forms carrying both
feed kinds. That was too narrow, and it was too narrow for an instructive reason:
it was reasoned from the *core* flags, which are the thing core reads, without
checking what Pro writes alongside them. **The flags are not the feed.** One more
step of the same mistake this document opens by retracting — a binding checked on
the axis that was convenient rather than the axis that decides.

**Correct to** — feed rows primary, flags as fallback:

```php
private function account_feed_type( $form_id ) {
    // … memo (see note on the memo key below) …

    $creates = false;
    $updates = false;
    $saw_feed = false;

    foreach ( $this->form_meta_rows( $form_id ) as $row ) {
        if ( 'user_registration_feeds' !== (string) $row['meta_key'] ) {
            continue;
        }

        $feed = json_decode( (string) $row['value'], true );
        if ( ! is_array( $feed ) ) {
            // A feed row we cannot read is a feed we must assume creates.
            $saw_feed = true;
            $creates  = true;
            continue;
        }

        $saw_feed = true;

        // 'enabled' is a real bool here, written by the status toggle.
        // Absent is treated as enabled: the stricter reading.
        if ( array_key_exists( 'enabled', $feed ) && ! $feed['enabled'] ) {
            continue;
        }

        // VERIFIED against FluentFormPro\Integrations\UserRegistration\
        // UserUpdateFormHandler::isValidFeed(). 'user_update' is the only
        // special value; everything else registers. Matching the vendor's
        // direction matters: an unrecognised future value must fall to
        // 'creates', which is the stricter answer, not to 'updates'.
        //
        // Feed 'conditionals' are deliberately NOT evaluated. They are
        // resolved against submitted data, and the enforcement decision may
        // not be read from the request (the 2.17.0 rule). A conditional feed
        // counts as active.
        if ( 'user_update' === ( isset( $feed['list_id'] ) ? $feed['list_id'] : '' ) ) {
            $updates = true;
        } else {
            $creates = true;
        }
    }

    if ( ! $saw_feed ) {
        // No readable feed rows. Fall back to the flags core itself reads.
        // They are STICKY — written when a feed is saved and never deleted
        // (Pro Bootstrap.php:284-289) — so they over-report, which is the
        // safe direction for a fallback and the wrong direction for a
        // primary. That is why they are down here.
        $creates = 'yes' === $this->form_meta_value( $form_id, '_has_user_registration' );
        $updates = 'yes' === $this->form_meta_value( $form_id, '_has_user_update' );
    }

    if ( $creates && $updates ) {
        // Mirror Fluent Forms' own gate (FormValidationService.php:178,193):
        // registration only fires for a logged-out visitor, update only for a
        // logged-in one. A form carrying both is a supported configuration.
        //
        // is_user_logged_in() is not request data in the 2.17.0 sense. It is
        // WordPress's authenticated identity from a verified auth cookie, not
        // a value the submitter can assert. Diverging from the host's own rule
        // is what produces the false rejection.
        $type = is_user_logged_in() ? 'update' : 'create';
    } elseif ( $creates ) {
        $type = 'create';
    } elseif ( $updates ) {
        $type = 'update';
    } else {
        $type = '';
    }

    return $this->memo_set( … , $this->filter_account_type( $type, $form_id ) );
}
```

`feed_is_update()` is deleted. Its four candidate keys were a guess, the guess was
wrong, and keeping them as "tolerance" would only make a future wrong value look
handled.

**The memo key must include the login state.** `account_feed_type()` is memoised
per form id. On a persistent object cache the same key would otherwise serve a
logged-out answer to a logged-in request. The memo is per-request today, but the
tie-break makes the value login-dependent and the key must say so.

**Proof:** chunk 24, extended to dump every `user_registration_feeds` row
verbatim — `list_id`, `enabled`, and whether `conditionals.status` is set — plus
both `_has_*` flags. Fixtures needed: a User Registration form, a User Update
form, one carrying both feeds, and one whose update feed is **disabled**. Assert:
the pure update form is `update` (this is the regression that matters); the
both-feeds form is `create` logged out and `update` logged in; the disabled-feed
form ignores it.
### D3 — `after_payment_status_change` is bound backwards, so Transaction Defense never annotates

**File:** `register_hooks()` (~1136), `on_payment_status_change()` (~2048).

**Now:**

```php
add_action( 'fluentform/after_payment_status_change', array( $this, 'on_payment_status_change' ), 10, 5 );
public function on_payment_status_change( $submission, $transaction = null, $form_id = 0, $old_status = '', $new_status = '' )
```

**Actual signature** (`BaseProcessor.php:157`):

```php
do_action('fluentform/after_payment_status_change', $newStatus, $this->getSubmission());
```

Two arguments, status first. So today `$submission` receives the string `'paid'`,
`$transaction` receives the submission object, and `$new_status` is `''`.
`strtolower('')` matches neither branch, so **`annotate()` is never called.**

It does not crash — `annotate()`'s `is_numeric('paid')` check is false and it
returns 0 — which is why nothing surfaced. Transaction Defense annotation on
Fluent Forms has never worked and would not have announced itself. The handoff
recorded "`after_payment_status_change` has no listeners on the site, which is
normal for an action nobody subscribes to" — it is normal, and it is also not
what was being tested; the provider was the listener, and it was listening on the
wrong shape.

**Correct to:**

```php
add_action( 'fluentform/after_payment_status_change', array( $this, 'on_payment_status_change' ), 10, 2 );

/**
 * @param string       $new_status New payment status.
 * @param object|array $submission Submission row.
 */
public function on_payment_status_change( $new_status = '', $submission = null ) {
    $status = strtolower( (string) $new_status );
    if ( 'paid' === $status ) {
        $this->annotate( $submission, 'LEGITIMATE', 'PAYMENT' );
        return;
    }
    if ( in_array( $status, array( 'refunded', 'partially-refunded', 'partially_refunded' ), true ) ) {
        $this->annotate( $submission, 'FRAUDULENT', 'REFUND' );
    }
}
```

Keep the refund strings as a set even though free core only emits `'paid'` and
`'failed'` — refunds are issued by the Pro gateways and by `StripeListener`, and
an unrecognised status annotates nothing, which is the correct default.

**Proof:** chunk 25, extended to fire the action directly with the real argument
order and assert `annotate()` is entered; then one real Stripe payment.

### D4 — The rejection message can be delivered and never shown

**File:** `reject()` (~1637), `error_field_for()` (~1668).

**Now:** the message is attached to the **first named field on the form**, and if
no field can be resolved the submission is admitted instead.

**What the source says.** `assets/js/form-submission.js` renders errors two ways,
chosen by `settings.layout.errorMessagePlacement`, whose default is **`'inline'`**
(`app/Models/Form.php:198`) — not `stackToBottom` as the shipped code's fallback
reasoning assumed.

- `stackToBottom` → every key is rendered into `.ff-errors-in-stack` regardless of
  whether it resolves to a DOM node.
- `inline` → `S(key, msg)`. It resolves the key with
  `O(k) = $("[data-name='k']") || $("[name='k']") || $("[name='k[]']")`, scoped to
  the form, and then:
  - **resolves to nothing → `j([msg])`, which renders into `.ff-errors-in-stack`.**
    Safe, visible, and verified not to throw: `O(k).attr('name')` on an empty set
    yields `undefined`, the follow-on `[name='undefined']` selector is empty, and
    the scroll-into-view is guarded by `k(r[0])`.
  - resolves to a normal field → inline message under the field. Safe.
  - **resolves to something that is not a normal field → the message is appended
    into that element and may be invisible.** For a hidden `<input>` the code
    takes `i.append(div)` on a void element: nothing renders, and the visitor
    watches a stopped spinner.

So Fluent Forms **does** have a global error channel — any key that matches
nothing — and it works under both placements. That is strictly better than
borrowing a real field, for three reasons: it does not put a spam accusation
under an unrelated label ("Email: We could not verify this submission"), it
cannot land on a field hidden by conditional logic or on a later step, and it
removes the branch where `reject()` gives up and admits.

**Correct to:**

```php
/**
 * The errors key a rejection is delivered under.
 *
 * Deliberately a name that matches NO element in the form. Fluent Forms'
 * inline renderer falls back to the .ff-errors-in-stack container for any
 * key it cannot resolve (form-submission.js, S() -> j()), and the stack
 * renderer displays every key unconditionally — so an unresolvable key is
 * the one delivery that is visible under both placement settings.
 *
 * It must NOT be TOKEN_FIELD. That name DOES resolve, to our own hidden
 * input, which sends the message down the branch that appends a <div> into
 * an <input> — rendering nothing and leaving the visitor with a stopped
 * spinner. The invisible-rejection failure this method exists to prevent is
 * reachable only by naming our own field.
 */
const ERROR_KEY = 'gswp_verification';
```

`reject()` becomes unconditional:

```php
private function reject( $errors, $message, $form_id ) {
    $key = (string) apply_filters( 'gswp_ff_error_field', self::ERROR_KEY, (int) $form_id );
    if ( '' === $key || self::TOKEN_FIELD === $key ) {
        $key = self::ERROR_KEY;
    }
    $errors[ $key ] = array( $message );
    return $errors;
}
```

`error_field_for()` is deleted. `gswp_ff_error_field` is kept — a site that
*wants* the message on a named field can still say so — but it now defaults to
the global channel and refuses `TOKEN_FIELD` outright.

**Fluent Forms does this itself, which is the strongest evidence available short
of watching it render.** Core's rate limiter throws
`['errors' => ['restricted' => […]]]` (`FormValidationService.php:147`) and Pro's
user-registration guard appends to the same `restricted` key
(`UserRegistration/Getter.php:42-50`). `restricted` is not a field on any form.
The vendor is relying on precisely the unresolvable-key → error-stack path
proposed here, for its own form-level messages, on both sides of the paywall.

**One live check is still required, and it is not optional.** The stack container
is emitted by `FormBuilder::render()` (`:206`) on every path we cover, so it is
present. But a theme or a page builder that reorders the wrapper could move it
out of `t.parent()`. Chunk 22 must be extended to submit an eligible strict form
with the token stripped and confirm the message is **on screen**, under both
`errorMessagePlacement` settings. Until that is observed, this is a source-backed
prediction, not a verified binding.

**One gateway renders it differently.** On a PayPal-inline form the message the
buyer sees comes from the handler's own failure branch, which takes
`responseJSON.message || responseJSON.errors` and then `Object.values(e)[0]` —
the *first value* of the errors object, key ignored, written into
`.ff_paypal_card-errors` (`Pro: public/js/ff_paypal_inline.js`). Our key is
irrelevant there, but our value must survive `Object.values(…)[0]` and land in
`.text()`. `array( $message )` renders as the bare string for a one-element
array, so it works — and it works by accident, so the chunk-22 assertion must
cover a PayPal-inline form rather than assuming the stack path is the only one.

### D5 — Global v2 keys make every form ineligible, silently

**File:** `native_captcha_state()` (~849), `form_is_eligible()` (~439).

**Now:** when a form has no captcha field but the site has *any* stored reCAPTCHA
configuration, the state is derived from the global `api_version`. A site with v2
keys saved — extremely common; they are saved once and left — reports `'v2'` for
**every form**, and `form_is_eligible()` excludes `'v2'`. The provider is switched
on and does nothing at all, on every form, with no message explaining why.

**What the source says.** Fluent Forms validates a captcha **iff** the form
carries the field or the global auto-include filter is on
(`FormValidationService.php:568`):

```php
if (!$disableReCaptcha && (FormFieldsParser::hasElement($this->form, 'recaptcha') || $autoInclude)) { … }
```

So for a form with no captcha field and no auto-include, `'off'` is **provable**,
not assumed. The pessimistic rule says do not report `off` without proof; we now
have proof, from the host's own gate.

**Correct `native_captcha_state()` to:**

1. Field on the form → `'other'` for `hcaptcha`/`turnstile`; for `recaptcha`,
   `'v3'` if `api_version` contains `v3`, else `'v2'`. *(unchanged, and correct)*
2. No field, but an auto-include filter is on:
   `apply_filters('fluentform/has_recaptcha', false)` — and the hCaptcha and
   Turnstile equivalents — → treat as though the field were present. Reading
   another plugin's filter is a read; it does not register anything and cannot
   change host behaviour.
3. No field and no auto-include → **`'off'`**.
4. Unable to read the form definition at all → `'unknown'`. *(unchanged)*

Global configuration stops feeding eligibility and becomes what it always should
have been: a reporting fact for the coverage table ("site has reCAPTCHA v2 keys
stored; no form uses them").

Fold in the `_fluentform_*_keys_status` flags (§1 row 12) as the "configured and
validated" signal for that report — they are set only after Fluent Forms
round-tripped the key pair with the vendor, which is a stronger claim than
"a `siteKey` string is non-empty".

### D6 — Conversational forms are eligible and can never be covered

**File:** `form_is_eligible()` (~439).

Conversational forms (`fluentform_form_meta.is_conversion_form == 'yes'`) render
through `FluentConversational\Classes\Form::renderFormHtml()` into a Vue view.
They fire **none** of `form_element_start`, `before_form_render`,
`after_form_render`, and they emit **no** `.ff-errors-in-stack` container.

Consequences today: the form is eligible, is never injected into, and every
submission takes the never-injected branch — admitted unscored, with a COVERAGE
GAP logged **on every submission, forever**. The fail-open is correct and nobody
is blocked. The permanent log noise is not, and it trains the operator to ignore
the one message that is supposed to mean something.

**Correct to:** report conversational forms ineligible, with a distinct reason
string in the coverage table ("Conversational form — not supported"), so the
operator sees an answer rather than an alarm. Detection is one form-meta read.

If conversational support is wanted later it is a separate piece of work with its
own render and error-display bindings; it is not a variant of this one.

### D7 — Three payment elements are missing from the fallback scan

**File:** `$payment_elements` (~137).

Missing: **`stripe_inline`** (Pro: `Stripe/Components/StripeInline.php:22`),
**`square_inline`** (Pro: `Square/Components/SquareInline.php:22`) and
**`payment_coupon`** (Pro: `Payments/Components/Coupon.php:17`). Add all three.

Low severity — `has_payment` is the authoritative signal and the field scan is
the fallback for it being unreadable — but the fallback exists precisely for the
case where the column is wrong, and coupon-plus-inline-card is an ordinary
configuration.

While here, correct the docblock: the element names are no longer "documented,
not confirmed". They are read from the component constructors in both plugins.

### D8 — Payment blocking is disabled for a risk that does not exist

**File:** `may_block_payment()` (~1606). **This is the one conclusion that
inverts on the Pro source.**

`may_block_payment()` returns false because it was unknown whether Fluent Forms
authorises the card in the browser before the submission reaches us. If it did, a
server-side rejection would stop the order and leave a hold standing on a real
customer's card. That question has been open since 2.16.0 and is the reason the
whole Transaction Defense path on this provider is inert.

**It is now answered, for every gateway Fluent Forms ships, and the answer is
no.** §1 rows 31 and 31b give the citations. In summary:

- **Server side** — every gateway charges from `fluentform/process_payment_{method}`,
  dispatched on `fluentform/before_insert_payment_form`, which runs *after*
  `handleValidation()`. There is no charge path that precedes our filter.
- **Client side, pre-submit** — Stripe Inline tokenises (`createPaymentMethod`).
  Square Inline tokenises and then runs a 3-D Secure *challenge*
  (`verifyBuyer`), which yields a verification token and creates no payment and
  no hold. Neither authorises.
- **Client side, post-submit** — Authorize.Net's card modal carries a
  `submission_id` and a `transaction_hash` in its config, so it cannot open until
  the submission has already been accepted. Paddle, Paystack and RazorPay use the
  same post-submission modal shape; Mollie, PayPal-standard, Square-hosted and
  Stripe-hosted redirect from the server.
- **PayPal Inline** is the interesting one, and it is the best-behaved of the
  set. The button's `onClick` calls `this.$form.trigger("submit")` and returns a
  promise; the PayPal SDK will not call `createOrder` until that promise
  resolves, and the handler binds `fluentform_validation_failed` and
  `fluentform_submission_failed` to **reject** it. A validation rejection
  therefore means no PayPal order is ever created — the gateway is explicitly
  built to let server-side validation veto the order.

**Correct to:** `may_block_payment()` returns **true** by default.
`gswp_ff_txn_block_allowed` is kept and inverted in role — it becomes the escape
hatch for turning blocking back off, not the switch for turning it on.

Leaving it false would now be the worse error, and not only because it is
over-cautious. `gswp_txn_block` is an option the operator sets deliberately, on a
site that also has Enterprise keys and Transaction Defense on. A hidden filter
that silently vetoes that switch and writes "was NOT blocked" to a log nobody
reads is the plugin doing less than the operator asked while reporting that it
did — the exact failure the 2.23.0 notes criticise elsewhere. Once the harm it
was guarding against is proven not to exist, the guard is just a lie about our
own behaviour.

Two residuals, both to be written into the docblock rather than left implicit:

- On **Square Inline** the buyer may complete a 3-D Secure challenge before we
  reject. That is an annoyance, not a charge: the verification token expires
  unused. Worth naming so nobody reads "no hold" as "no visible effect".
- A gateway added by a **third-party add-on** is outside everything read here.
  `gswp_ff_txn_block_allowed` is what such a site turns off.

---

## 3. Corrections to documentation only

No behaviour change; these are docblocks and status markers that currently
overstate what is known. They matter because the 2.23.1 root cause was a
"VERIFIED" label outliving the axis it was earned on.

1. `submitted_token()` — rewrite the transport commentary per §0.1 and D1.
2. `native_recaptcha_settings()` — `_fluentform_reCaptcha_details` is now verified
   for **name and type and key set**, at 6.2.9. Say the version.
3. `native_any_captcha_configured()` — `_fluentform_hCaptcha_details` and
   `_fluentform_turnstile_details` are no longer inferred by symmetry; they are
   verified. Drop the lowercase-variant guesses or keep them explicitly as
   older-version tolerance, but say which.
4. `native_recaptcha_version()` — `api_version` is verified, and its two literal
   values are known. The "unreadable version degrades to v2" branch stays as
   tolerance for a future value, but is no longer the expected path.
5. `submitted_address()` / the name sub-keys — verified, and the nesting is
   confirmed: components arrive under the field's own name, not at top level.
6. `form_currency()` — replace the candidate-key scan with the verified path
   (`_payment_settings.currency` → `__fluentform_payment_module_settings.currency`
   → `'USD'`), keeping the scan as fallback. Delete the note that chunk 23 never
   printed the internal key names; they are in `PaymentHelper.php:153-166`.
7. `store_submission_meta()` — `fluentform/submission_inserted` and the two
   `Helper` signatures are verified. Downgrade PARTIAL to VERIFIED.
8. `register_hooks()` — the `form_element_start` comment should record that
   Gutenberg, Elementor **and Pro's form modal** all reach it through
   `do_shortcode()`, and that conversational forms do not reach it at all (D6).
9. `close_backstop_buffer()` — record that `FormBuilder::render()` is itself
   buffered and that the two render actions are always paired inside it, which is
   *why* the nesting-level guard has held. It is still the right guard; it is now
   guarding a known shape rather than an unknown one.
10. **Add a source-provenance block at the top of the class** naming Fluent Forms
    6.2.9 and Pro 6.2.7 as the versions every binding was read against, and
    stating that `FormHandler::onSubmit()` is dead code so nobody re-derives a
    binding from it.
11. `account_feed_type()` — the surviving feed-row reader is now VERIFIED against
    Pro, not a guess. Say so, and say that `_has_user_*` is a **sticky** fallback
    rather than current state, or the next reader will promote it back.

---

## 4. An opportunity, recorded but not scheduled

`apply_filters('fluentform/disable_captcha', false, $form, $type)`
(`FormValidationService.php:567,613,653`) is a first-class, host-provided way to
switch off Fluent Forms' own captcha **validation** on a per-form basis without
touching a single stored setting.

That is the operation the Gravity Forms incident made unavailable to us: there,
the only route was filtering stored options, and GF's settings screen read the
filtered blanks and saved them back over the real keys. Fluent Forms offers the
same outcome through a read-path filter, with nothing persisted and nothing to
corrupt.

It is worth having, and it is **not** part of 2.23.2. Two reasons:

- It only disables server-side validation. The captcha field still renders and
  still challenges the visitor, so on its own it produces a widget that asks for
  a click and then ignores the answer — worse than either end state. Doing it
  properly also means suppressing the render, via
  `fluentform/rendering_field_data_recaptcha` or by excluding the element, which
  is a second binding.
- Every form it applies to is a form we currently declare **ineligible** and
  leave alone. Changing that is a change in what the plugin covers, not a
  correction to how it covers what it already claims.

Schedule it as its own phase, with its own opt-in, after 2.23.2 has been observed
on a live install.

---

## 5. Order of work

Revision 1 put D2 last, on the grounds that it needed fixtures the test site does
not have. That was right when the binding was a guess and wrong now that it is
read from the vendor's own `isValidFeed()`: the implementation no longer depends
on the fixtures, only the confirmation does, and it is the defect that rejects
real customers. It goes first.

1. **D2** (account classification) — the reason for the release. It can be
   written and unit-guarded against synthetic meta rows today; the live fixtures
   confirm it, they do not gate it.
2. **D3** (payment hook signature) — isolated, two lines.
3. **D7** (payment elements) — isolated, one array.
4. **D6** (conversational ineligible) — isolated, narrows the covered set.
5. **D5** (captcha state / eligibility) — widens the covered set. Must land after
   D6 so the two changes to eligibility can be read apart in the coverage table.
6. **D1** (whitelist the token) — changes the submission path. Land alone.
7. **D4** (error key) — changes the rejection path. Land alone, immediately
   before the live rejection test, because it is the change whose proof is
   "a human saw the message on screen".
8. **D8** (payment blocking default) — land **last, and only after D4 is
   confirmed visible**. It is the only change here that can stop a real
   transaction, and a block the customer cannot see is worse than no block.
9. §3 documentation corrections — with the change each describes, not batched.

Version: **2.23.2**. `migrates_by_default()` keeps `fluent-forms` in the holdback
list. Nothing here is grounds for auto-enabling — eight defects in a provider
nobody has run in anger is an argument for more field evidence, not less. D8
notwithstanding: it makes an operator-chosen switch honest, it does not make the
provider switch itself on.

---

## 6. Verification suite changes

The suite found the 2.23.1 defect and is the reason this review had a live
install to argue with. It needs the changes below, all of them because a chunk
asserted something weaker than it appeared to.

| Chunk | Change |
|---|---|
| 21 `ff-render-coverage` | Add a conversational form to the fixtures and assert it is reported **ineligible with a reason**, not "eligible, never injected". |
| 22 `ff-submission-shape` | Print **which transport** returned the token, not just whether one did. The current output cannot distinguish "transport 1 works" from "transport 2 rescued it" — which is precisely how the false claim in §0.1 survived. Add the token-stripped submission and record whether the rejection message was **visible**, under both `errorMessagePlacement` values. |
| 23 `ff-native-captcha` | Print `api_version` verbatim, the three `_keys_status` flags, and the return of the three `fluentform/has_*` auto-include filters. Assert `native_captcha_state()` returns `off` for a form with no captcha field on a site that has global keys stored — the D5 case. |
| 24 `ff-classification` | Dump every `user_registration_feeds` row verbatim — `list_id`, `enabled`, whether `conditionals.status` is set — alongside both `_has_user_*` flags. Four fixtures: a registration form, **a User Update form**, one carrying both feeds, and one whose update feed is disabled. The assertion that matters is the **pure update form classifying as `update`** — that is the shipped regression. Then: both-feeds form is `create` logged out and `update` logged in; disabled feed is ignored. |
| 25 `ff-payment-lifecycle` | Fire `fluentform/after_payment_status_change` with the **real** argument order and assert `annotate()` is entered. Do this before any gateway is configured — it is the defect D3 that a listener-count check could never have found. |
| 26 `ff-enforcement` | Add a regression guard: `reject()` must never emit `TOKEN_FIELD` as an errors key, under any filter value. That is the one key that produces an invisible rejection (D4), and it is the key a well-meaning future edit would reach for first. |
| 22 `ff-submission-shape` (2) | Separately assert the rejection is visible on a **PayPal-inline** form, whose handler renders `Object.values(errors)[0]` into its own error node and ignores the key entirely. The stack path and this path are different code; passing one says nothing about the other. |
| 27 `ff-payment-authorisation` (**new**) | The D8 evidence is a source read, and D8 is the change that can stop a customer's transaction. One chunk per configured gateway: submit a form that our verifier is forced to reject, then check the gateway dashboard for **any** authorisation, hold, or pending payment against that attempt. Expected: none. This is the chunk that has to exist before an operator is told blocking is safe. |

Add to `README-ff-replacement.md`: **a chunk that can be run correctly and read
as a pass is as defective as one that can be read as a failure.** Chunk 22 was
already fixed once for the second failure mode; §0.1 is the first.

---

## 7. What remains unsettled after this

Stated plainly, so the next reader does not mistake this document for closure.

- **D8 is a source read, not an observation.** No card has been put through a
  rejected Fluent Forms submission. Chunk 27 exists because "the code says no
  authorisation happens" and "no authorisation happened" are different claims,
  and this project has already shipped one release on the first kind.
- **The D4 fix is source-backed, not observed.** A message rendering in
  `.ff-errors-in-stack` under a real theme is a thing a person has to look at —
  and on PayPal-inline it renders somewhere else entirely.
- **Third-party payment add-ons** are outside everything read here. Only the
  gateways shipped in Fluent Forms and Fluent Forms Pro were examined.
- **Feed `conditionals` are deliberately not evaluated** (D2). A form whose
  registration feed only fires on some conditions is treated as always
  registering, which is stricter than the host. That is a choice, not an
  oversight, and a site that finds it too strict has `gswp_ff_account_feed_type`.
- **Object-cache behaviour of the D2 memo** — the login-state key is reasoned,
  not tested.
- **Conversational forms** are now honestly reported as unsupported rather than
  alarming on every submission (D6). They are still unsupported.
- **Fluent Forms 6.3+ / Pro 6.3+** — every binding in §1 is verified at 6.2.9 and
  6.2.7 and nowhere else. The version is part of the claim, and 2.23.1 is the
  release that proves what happens when that qualifier gets dropped.
