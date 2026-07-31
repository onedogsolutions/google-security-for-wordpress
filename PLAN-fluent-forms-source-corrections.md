# Implementation Plan — correcting the Fluent Forms bindings against installed source

**Target release:** 2.23.2
**Predecessor:** `PLAN-fluent-forms-provider.md` (2.23.0), Phase 50 addendum in `STATE.md` (2.23.1)
**Evidence base:** Fluent Forms **6.2.9** free plugin source, read in full for every
binding below. Fluent Forms **Pro 6.2.7** was NOT available and its absence is
marked explicitly wherever it matters.
**Status: PLANNED. No code changed yet.**

---

## 0. What this document is, and what changed

The Phase 50 addendum listed nine open bindings (§5 of the handoff) that could
not be settled from documentation or from the live install. The Fluent Forms
plugin source has now been read. **Eight of the nine are settled.** The ninth
(charge timing for non-Stripe gateways) is settled for Stripe and cannot be
settled for the Pro-only gateways from this artefact.

The review also found **six defects in the shipped provider**, three of which are
in a request path and two of which are the exact failure shapes this project has
already been burned by. It also found **one claim recorded as settled that is
false**, which matters more than any single defect because it is the mechanism by
which the others get missed.

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

The fix (§2.1) makes transport 1 true rather than deleting it, because the
mechanism Fluent Forms provides for exactly this is a filter, and using it is
cheaper and more durable than re-parsing a request envelope.

---

## 1. Bindings settled by the source read

Everything in this table is now **VERIFIED against installed source** at the
stated file and line. The version axis is Fluent Forms 6.2.9 free; nothing here
should be treated as verified for a different major version.

| # | Binding | Answer | Source |
|---|---|---|---|
| 1 | Live submission handler | `SubmissionHandler::submit()` → `SubmissionHandlerService::handleSubmission()`. **`FormHandler::onSubmit()` is commented out** and is dead code — do not read bindings from it. | `app/Hooks/Ajax.php:17-24` |
| 2 | `$formData` at `validation_errors` | Filtered to registered fields + `getWhiteListedFields()`. Unregistered keys are dropped. | `SubmissionHandlerService.php:125-127` |
| 3 | Whitelist extension point | `apply_filters('fluentform/white_listed_fields', $fields, $formId)` | `Helper.php:1443` |
| 4 | `fluentform/validation_errors` | `($errors, $formData, $form, $fields)`, fired **unconditionally** (not only when errors exist). Our 4-arg / priority-20 registration is correct. | `FormValidationService.php:170` |
| 5 | Error delivery shape | `throw new ValidationException('', 423, null, ['errors' => $errors])` → `wp_send_json($e->errors(), 423)`. | `FormValidationService.php:212`, `SubmissionHandler.php:26` |
| 6 | **Account creates vs updates** | Core reads form meta **`_has_user_registration` == 'yes'** and **`_has_user_update` == 'yes'**, and gates them on login state: registration only when `!get_current_user_id()`, update only when `get_current_user_id()`. | `FormValidationService.php:178,193` |
| 7 | Account feed rows | `fluentform_form_meta.meta_key = 'user_registration_feeds'`; value is JSON; enabled flag is `enabled`, read with `ArrayHelper::isTrue()`. | `GlobalNotificationManager.php:262-272` |
| 8 | reCAPTCHA option | `_fluentform_reCaptcha_details`, stored as a **PHP array**, keys `siteKey`, `secretKey`, `api_version`. | `GlobalSettingsHelper.php:41-48` |
| 9 | reCAPTCHA version key/values | `api_version` ∈ `'v2_visible'` \| `'v3_invisible'`. | `GlobalSettingsHelper.php:36`, `filters.php:415-420` |
| 10 | hCaptcha option | `_fluentform_hCaptcha_details`, array, `siteKey`/`secretKey`, **no version key**. | `GlobalSettingsHelper.php:112` |
| 11 | Turnstile option | `_fluentform_turnstile_details`, array, `siteKey`/`secretKey`/`invisible`/`appearance`/`theme`. | `GlobalSettingsHelper.php:218-224` |
| 12 | Keys-valid flags | `_fluentform_reCaptcha_keys_status`, `_fluentform_hCaptcha_keys_status`, `_fluentform_turnstile_keys_status` — boolean, set only after the vendor validated the key pair. | `GlobalSettingsHelper.php:50,113,236` |
| 13 | Captcha field elements | `recaptcha`, `hcaptcha`, `turnstile` — matched with `FormFieldsParser::hasElement($form, '<name>')`. Our map is correct. | `FormValidationService.php:568,613,653` |
| 14 | **Captcha is per-form, plus a global override** | FF validates a captcha iff the form has the field **OR** `apply_filters('fluentform/has_recaptcha'\|`has_hcaptcha`\|`has_turnstile`, false)` returns true. | `FormValidationService.php:568` etc. |
| 15 | Host captcha can be suppressed by filter | `apply_filters('fluentform/disable_captcha', false, $form, 'recaptcha'\|'hcaptcha'\|'turnstile')` | `FormValidationService.php:567` |
| 16 | Payment field elements | `payment_method`, `custom_payment_component`, `multi_payment_component`, `subscription_payment_component`, `item_quantity_component`, `payment_summary_component`, **`stripe_inline`**, and (Pro-registered, free-declared) **`payment_coupon`**. | component constructors under `app/Modules/Payments/Components/`, `Stripe/Components/StripeInline.php:22`, `PaymentHandler.php:62` |
| 17 | Password element | `input_password` — named in the core sanitiser. | `boot/globals.php:98` |
| 18 | Address sub-keys | Element `address`, submitted **nested under the field's own name**: `$formData['address_1']['address_line_1'\|'address_line_2'\|'city'\|'state'\|'zip'\|'country']`. | `DefaultElements.php:376-620` |
| 19 | Name sub-keys | `first_name`, `middle_name`, `last_name`, nested the same way. | `PredefinedForms.php` (blank-form JSON) |
| 20 | Currency at validation time | `PaymentHelper::getFormCurrency($formId)` → form meta `_payment_settings.currency`, falling back to `__fluentform_payment_module_settings.currency`, default `'USD'`. Available before any transaction row exists. | `PaymentHelper.php:17-20, 96-115, 146-170` |
| 21 | `fluentform/submission_inserted` | `($insertId, $formData, $form)`. Our registration is correct. | `SubmissionHandlerService.php:239-241` |
| 22 | `Helper::setSubmissionMeta` | `($submissionId, $metaKey, $value, $formId = false)` | `Helper.php` |
| 23 | `Helper::getSubmissionMeta` | `($submissionId, $metaKey, $default = false)` | `Helper.php` |
| 24 | **`fluentform/after_payment_status_change`** | **`($newStatus, $submission)` — two args, status FIRST.** | `BaseProcessor.php:157` |
| 25 | Payment status strings | `'paid'`, `'failed'`, plus gateway-supplied values passed straight through. `'refunded'` is not emitted by the free core. | `BaseProcessor.php:250,738` |
| 26 | Render paths | Gutenberg block → `do_shortcode('[fluentform …]')`; Elementor widget → `do_shortcode('[fluentform …]')`. **Both route through `FormBuilder::render()`**, so both fire `form_element_start` / `before_form_render` / `after_form_render`. | `GutenbergBlock.php:69`, `FluentFormWidget.php:2540` |
| 27 | **Conversational forms do not** | Marked by form meta `is_conversion_form == 'yes'`; rendered by `FluentConversational\Classes\Form::renderFormHtml()` into a Vue view. Fires **none** of the three render actions and emits **no** `.ff-errors-in-stack` container. | `Form.php:197+`, `app/Views/public/conversational-form.php` |
| 28 | Buffer balance | `FormBuilder::render()` is itself wrapped in `ob_start()` … `ob_get_clean()`, with `before_form_render` and `after_form_render` both **inside** it and always paired. The buffered backstop nests safely. | `FormBuilder.php:152,219,221` |
| 29 | Error stack container | `<div id="fluentform_{id}_errors" class="ff-errors-in-stack …"></div>`, emitted immediately after `</form>` on every `FormBuilder::render()` path. | `FormBuilder.php:206` |
| 30 | Default error placement | **`'inline'`**, not `stackToBottom`. | `app/Models/Form.php:198` |
| 31 | **Stripe charge timing** | Client-side, pre-submit: `stripe.createPaymentMethod('card', …)` — **tokenisation only, no charge, no authorisation, no hold.** The PaymentIntent is created server-side on `fluentform/before_insert_payment_form`, which runs **after** `handleValidation()`. 3-D Secure (`handleCardAction` / `confirmCardPayment`) runs only after that server response. | `assets/js/payment_handler.js`, `SubmissionHandlerService.php:44-50`, `PaymentHandler.php:77` |

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

### D2 — Account create/update is misbound, and it is the Phase 48 shape

**File:** `account_feed_type()` (~567), `feed_is_update()` (~615).

**Now:** scans every `fluentform_form_meta` row for a `meta_key` *containing*
`user_registration` or `user_update`, decodes the value as JSON, and guesses the
create/update distinction from four candidate keys. A row it cannot classify
returns `'create'` **immediately**, before any later row can claim `'update'`.

**What the source says:** Fluent Forms core does not guess. It reads two form
meta flags and gates each on login state
(`FormValidationService.php:178,193`):

```php
if ('yes' == Helper::getFormMeta($this->form->id, '_has_user_registration') && !get_current_user_id()) { … }
if ('yes' == Helper::getFormMeta($this->form->id, '_has_user_update')       &&  get_current_user_id()) { … }
```

Two consequences, and the second is the dangerous one:

1. The authoritative flags are `_has_user_registration` and `_has_user_update`.
   They are maintained by Pro but consumed by core, so they are stable and cheap
   and we do not have to parse a Pro feed we cannot see.
2. **A form may carry both, and which one fires depends on whether the visitor is
   logged in.** A single form that registers anonymous visitors and updates
   signed-in ones is a normal, supported Fluent Forms configuration.

Under the current code that form resolves to `'create'` → `form_is_strict()` true
→ a signed-in customer editing her profile with a missing token is **rejected**
and told the submission could not be verified. That is Phase 48 reproduced
exactly: a real customer, already authenticated by WordPress, refused from her
own account page on a classification error.

**Correct to:**

```php
private function account_feed_type( $form_id ) {
    // … memo …
    $creates = 'yes' === $this->form_meta_value( $form_id, '_has_user_registration' );
    $updates = 'yes' === $this->form_meta_value( $form_id, '_has_user_update' );

    // Mirror Fluent Forms' own gate. This is not request data in the 2.17.0
    // sense: it is WordPress's authenticated identity from a verified auth
    // cookie, not a value the submitter can set. Diverging from the host's
    // rule here is what produces a false rejection.
    if ( $creates && $updates ) {
        $type = is_user_logged_in() ? 'update' : 'create';
    } elseif ( $creates ) {
        $type = 'create';
    } elseif ( $updates ) {
        $type = 'update';
    } else {
        $type = $this->account_type_from_feed_rows( $form_id ); // legacy scan, unchanged
    }

    return $this->memo_set( … , $this->filter_account_type( $type, $form_id ) );
}
```

Notes on the shape:

- The existing feed-row scan is **kept**, demoted to a fallback for an install
  where the `_has_*` flags are absent (an older Pro, or a form built before Pro
  started writing them). It keeps its fail-to-`create` behaviour, which is right
  when nothing better is known.
- `is_user_logged_in()` is consulted **only** to break the both-flags tie, never
  to weaken a form that only registers. A logged-out visitor on a both-flags form
  still gets `'create'` and still gets STRICT.
- The memo key must include the login state, or a persistent object cache across
  a logged-out and a logged-in request would serve the wrong answer.
- `gswp_ff_account_feed_type` still wraps every return path. Its docblock should
  now say the binding is verified for the flags and unverified for the feed-row
  fallback, rather than unverified across the board.

**Proof:** chunk 24, extended to print `_has_user_registration` /
`_has_user_update` per form, run against a real User Registration form and a real
User Update form, and against one form carrying both, submitted once logged out
and once logged in.

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

**One live check is still required, and it is not optional.** The stack container
is emitted by `FormBuilder::render()` (`:206`) on every path we cover, so it is
present. But a theme or a page builder that reorders the wrapper could move it
out of `t.parent()`. Chunk 22 must be extended to submit an eligible strict form
with the token stripped and confirm the message is **on screen**, under both
`errorMessagePlacement` settings. Until that is observed, this is a source-backed
prediction, not a verified binding.

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

### D7 — Two payment elements are missing from the fallback scan

**File:** `$payment_elements` (~137).

Missing: **`stripe_inline`** (`Stripe/Components/StripeInline.php:22`) and
**`payment_coupon`** (`PaymentHandler.php:62`). Add both.

Low severity — `has_payment` is the authoritative signal and the field scan is
the fallback for it being unreadable — but the fallback exists precisely for the
case where the column is wrong, and a coupon-plus-inline-Stripe form is a real
configuration.

While here, correct the docblock: the element names are no longer "documented,
not confirmed". They are read from the component constructors.

### D8 — Payment blocking is disabled for a risk that does not exist on Stripe

**File:** `may_block_payment()` (~1606).

`may_block_payment()` returns false because it was unknown whether Fluent Forms
authorises the card in the browser before submission. For **Stripe it does not**
(§1 row 31): the pre-submit call is `stripe.createPaymentMethod`, which
tokenises and nothing more. The PaymentIntent is created server-side on
`fluentform/before_insert_payment_form`, which runs after `handleValidation()`.
A rejection at `fluentform/validation_errors` therefore happens **before any
authorisation exists**, and leaves no hold on a real customer's card.

This cannot be extended to PayPal, Square, Mollie, Razorpay or Paystack — they
live in Fluent Forms Pro, which was not available for this review.

**Correct to:** keep `may_block_payment()` false as the shipped default, and
change only the log message, which currently states the risk as unresolved for
all gateways. It should now say: blocking is safe for Stripe on the evidence of
the 6.2.9 source; unresolved for the Pro gateways; enable per site with
`gswp_ff_txn_block_allowed` once you have confirmed your own gateway.

Deliberately **not** auto-enabling for Stripe-only forms. Detecting "this form
can only ever be paid by Stripe" means reading the `payment_method` field's
enabled-methods settings — a Pro-shaped binding, unverified, on the one path
where being wrong costs a customer money. A filter the operator sets after
looking at their own gateway dashboard is a better instrument than an inference
we cannot check.

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
   Gutenberg and Elementor both reach it through `do_shortcode()`, and that
   conversational forms do not reach it at all (D6).
9. `close_backstop_buffer()` — record that `FormBuilder::render()` is itself
   buffered and that the two render actions are always paired inside it, which is
   *why* the nesting-level guard has held. It is still the right guard; it is now
   guarding a known shape rather than an unknown one.
10. **Add a source-provenance block at the top of the class** naming Fluent Forms
    6.2.9 free as the version every binding was read against, and stating that
    `FormHandler::onSubmit()` is dead code so nobody re-derives a binding from it.

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

The order is chosen so that each step's proof does not depend on a later step.

1. **D3** (payment hook signature) — isolated, two lines, no interaction with
   anything else.
2. **D7** (payment elements) — isolated, one array.
3. **D6** (conversational ineligible) — isolated, narrows the covered set.
4. **D5** (captcha state / eligibility) — widens the covered set. Must land after
   D6 so the two changes to eligibility can be read apart in the coverage table.
5. **D1** (whitelist the token) — changes the submission path. Land alone.
6. **D4** (error key) — changes the rejection path. Land alone, immediately
   before the live rejection test, because it is the change whose proof is
   "a human saw the message on screen".
7. **D2** (account classification) — land last. It is the highest-consequence
   change and it needs a purpose-built form on the test site that does not exist
   yet, so it should not block the other six.
8. §3 documentation corrections — with the change each describes, not batched.

Version: **2.23.2**. `migrates_by_default()` keeps `fluent-forms` in the holdback
list. Nothing here is grounds for auto-enabling: six defects in a provider nobody
has run in anger is an argument for more field evidence, not less.

---

## 6. Verification suite changes

The suite found the 2.23.1 defect and is the reason this review had a live
install to argue with. It needs six changes, all of them because a chunk asserted
something weaker than it appeared to.

| Chunk | Change |
|---|---|
| 21 `ff-render-coverage` | Add a conversational form to the fixtures and assert it is reported **ineligible with a reason**, not "eligible, never injected". |
| 22 `ff-submission-shape` | Print **which transport** returned the token, not just whether one did. The current output cannot distinguish "transport 1 works" from "transport 2 rescued it" — which is precisely how the false claim in §0.1 survived. Add the token-stripped submission and record whether the rejection message was **visible**, under both `errorMessagePlacement` values. |
| 23 `ff-native-captcha` | Print `api_version` verbatim, the three `_keys_status` flags, and the return of the three `fluentform/has_*` auto-include filters. Assert `native_captcha_state()` returns `off` for a form with no captcha field on a site that has global keys stored — the D5 case. |
| 24 `ff-classification` | Print `_has_user_registration` and `_has_user_update` per form. Requires three new fixtures: a registration form, an update form, and one carrying both. Assert the both-flags form classifies `create` logged out and `update` logged in. |
| 25 `ff-payment-lifecycle` | Fire `fluentform/after_payment_status_change` with the **real** argument order and assert `annotate()` is entered. Do this before any gateway is configured — it is the defect D3 that a listener-count check could never have found. |
| 26 `ff-enforcement` | Add a regression guard: `reject()` must never emit `TOKEN_FIELD` as an errors key, under any filter value. That is the one key that produces an invisible rejection (D4), and it is the key a well-meaning future edit would reach for first. |

Add to `README-ff-replacement.md`: **a chunk that can be run correctly and read
as a pass is as defective as one that can be read as a failure.** Chunk 22 was
already fixed once for the second failure mode; §0.1 is the first.

---

## 7. What remains unsettled after this

Stated plainly, so the next reader does not mistake this document for closure.

- **Fluent Forms Pro 6.2.7 has not been read.** User Registration and User Update
  feeds, and every gateway except Stripe, live there. D2 is bound to flags that
  core consumes, which is why it is safe without Pro — but the feed-row fallback
  is still unverified, and D8 stays disabled for the Pro gateways.
- **Charge timing for PayPal, Square, Mollie, Razorpay, Paystack** — unknown.
- **The D4 fix is source-backed, not observed.** A message rendering in
  `.ff-errors-in-stack` under a real theme is a thing a person has to look at.
- **Multi-site / object-cache behaviour of the D2 memo** — the login-state key is
  reasoned, not tested.
- **Fluent Forms 6.3+** — every binding in §1 is verified at 6.2.9 and nowhere
  else. The version is part of the claim.
