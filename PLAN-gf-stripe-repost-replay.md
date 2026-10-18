# Plan: replay a failed GF Stripe pre-check on the native re-post (v2.31.1)

**Status: implemented in v2.31.1 (Phase 62).** Live checks in §5.4 are still outstanding.

Builds on v2.31.0 (`claude/youthful-maxwell-uds025`, not yet on `main`). Closes the
"Residual edge, deliberately left" in STATE.md Phase 61.

## 1. The edge, precisely

GF Stripe 6.0.3 Payment Element, one Pay click:

1. Our capture-phase `click` listener (`class-gswp-recaptcha-loader.php`, `replaceAfterSubmit()`)
   schedules a re-mint of the token field. It is async: the field holds **T1** until
   `grecaptcha.execute()` resolves with **T2**, typically a few hundred ms later.
2. GF Stripe posts `FormData(form)` (carrying T1) to `gfstripe_validate_form`. We score T1 and
   store the verdict under `hash(T1)` (`remember_precheck_verdict()`).
3. The pre-check **fails** (e.g. a low score on a strict payment form). GF Stripe's JS calls a
   native `event.target.submit()` so GF renders the error server-side.
4. That re-post carries whatever the field holds at that moment:
   - **T1** (re-mint not landed yet): `redeem_precheck_verdict()` finds the failed verdict and
     replays its message with no Google call. Correct, already covered by `tests/manual/34` §7.
   - **T2** (re-mint landed first): no verdict under `hash(T2)`, so T2 is **scored from scratch**.
     That is the open edge.

Why it matters:

- **Inconsistent outcome.** The visitor can see a different message from the one the pre-check
  reached, or a pass on a request that GF Stripe only sent to render an error.
- **A second roll of the dice.** A refused carding attempt gets a fresh score for free on every
  attempt. Only a fail-closed verdict is involved here, so this widens what an attacker gets from
  one click.
- **Cost and noise.** An extra assessment per failed payment, and a second `record_rejection()`.

## 2. Why the obvious fix was rejected, and still is

"Don't re-mint until the pre-check outcome is known" (holding T1 in the field) breaks the
commoner path: the pre-check **passes**, then the card is **declined** client-side by
`confirmPayment()`. There is no re-post, no page reload, and the visitor clicks Pay again. That
second pre-check must carry a fresh token. Pre-checks never redeem, so T1 would be re-scored and
come back DUPE ("expired"). The field must keep moving to T2 promptly. This plan leaves the
client's re-mint timing exactly as it is.

## 3. The fix: post the spent token alongside the fresh one

The problem is that the server cannot link T2 to T1. Give it the link: when the click handler
re-mints, it **synchronously** records the value it is about to replace in a companion hidden
field. The re-post then carries both:

```
gswp_gf_token = T2   (fresh, may or may not have landed)
gswp_gf_spent = T1   (what the click just sent to the pre-check)
```

On a **non-pre-check** request, `validate_submission()` already redeems by `gswp_gf_token`. Add
a second lookup: if that finds nothing, look up `gswp_gf_spent`, and if it holds a **failed**
pre-check verdict for this form, replay the failure without calling Google.

### Why this is safe

| Concern | Answer |
|---|---|
| Can a client use `gswp_gf_spent` to get in? | No. It can only ever **replay a failure**. A passing verdict under the spent key is ignored, never redeemed. Omitting or forging the field just falls through to normal scoring, which is today's behaviour. |
| Retry after a declined card | The next Pay click is a **pre-check**. Pre-checks ignore `gswp_gf_spent` entirely and score T2 as today. No change. |
| Successful payment completion | The draft's `$_POST` is captured at the pre-check, so the token field holds T1 and the existing redeem path admits it first. The spent lookup only runs when the token lookup found nothing. |
| Can a stale failure lock a visitor out? | The replay applies only to non-pre-check requests, and only on a hash match with a token this browser itself spent. A visitor's *next attempt* is always a pre-check, so it is always scored fresh. The failed verdict still expires at `PRECHECK_TTL` (15 min). |
| Other forms / providers | Only GF renders the companion field, and only Stripe pre-checks store verdicts. Every other path sees no change. |
| Privacy | The field carries a token the browser already holds. Server-side we keep only its hash, as today. |

## 4. Changes

### 4.1 `includes/class-gswp-provider-gravity-forms.php`

- `const SPENT_FIELD = 'gswp_gf_spent';` next to `TOKEN_FIELD`. The docblock explains it is
  **only** a back-reference for replaying a failed pre-check.
- `token_field()`: emit the companion after the token input:
  `<input type="hidden" name="gswp_gf_spent" value="" />`, and add
  `data-gswp-spent-field="gswp_gf_spent"` to the token input so the shared bootstrap can find it
  without knowing about GF.
- `validate_submission()`, inside `if ( ! $precheck )`, after the existing redeem returns `null`:

  ```php
  $spent = isset( $_POST[ self::SPENT_FIELD ] ) ? sanitize_text_field( wp_unslash( $_POST[ self::SPENT_FIELD ] ) ) : '';
  if ( '' !== $spent && $spent !== $token ) {
      $replayed = $this->replay_failed_precheck( $form_id, $spent );
      if ( null !== $replayed ) {
          return $this->reject( $validation_result, $replayed, $form_id );
      }
  }
  ```

- New `replay_failed_precheck( $form_id, $spent )`: reads `precheck_key( $spent )`. It returns the
  stored message **only** when the verdict is form-bound to `$form_id` and `ok === false`;
  otherwise it returns `null`. It never deletes, mirroring how failures are kept today. It logs one line under
  verbose logging ("re-post replayed the pre-check's refusal; fresh token not assessed") so the
  path is observable in the field.
- No `record_rejection()` on replay: the pre-check already recorded it. This also fixes the
  double count.

### 4.2 `includes/class-gswp-recaptcha-loader.php` (shared bootstrap)

In `replaceAfterSubmit( input )`, **before** the `setTimeout`:

```js
var spentName = input.getAttribute('data-gswp-spent-field');
if (spentName && input.form && input.value) {
    var spent = input.form.querySelector('input[name="' + spentName + '"]');
    if (spent) { spent.value = input.value; }
}
```

- It is synchronous on purpose. The value must be recorded before anything can replace it, and
  the click handler runs in the capture phase before GF Stripe builds its `FormData`.
- The token field is untouched, so the never-empty INVARIANT and the re-mint timing are
  unchanged.
- It is inert on every field without the attribute, which covers every non-GF form.
- The `submit` listener also calls `replaceAfterSubmit()`. That is harmless: it records the same T1.

### 4.3 Version and docs

- Bump to 2.31.1 (plugin header, constant, `readme.txt` stable tag and changelog, `package.json`).
- STATE.md Phase 61: replace "Residual edge, deliberately left" with a pointer to the fix. Add a
  Phase 62 entry recording the evidence.

## 5. Verification

### 5.1 `tests/manual/34`, new §7b (real verifier, real GF pipeline, Google stubbed)

1. Pre-check with `tok-s-low`, score 0.2 → refused, **1** call (as §7).
2. Re-post with `gswp_gf_token=tok-s-fresh`, `gswp_gf_spent=tok-s-low` → refused with **the
   pre-check's message**, **0** calls. This is the edge itself.
3. The same re-post with `gswp_gf_spent=tok-bogus` → **1** call (falls through to scoring).
4. **A spent pass never admits:** pre-check `tok-s-ok2` passes, then a non-pre-check with
   `gswp_gf_token=tok-s-x` and `gswp_gf_spent=tok-s-ok2` → `tok-s-x` is scored (1 call), and
   `tok-s-ok2`'s verdict is still present (not consumed).
5. **Retry after decline:** a pre-check with `gswp_gf_token=tok-s-retry` and
   `gswp_gf_spent=tok-s-low` → scored (1 call), not replayed.
6. Cross-form: a spent verdict from the Stripe form does not replay on the volunteer form.

Add `tok-s-fresh`, `tok-s-ok2` and `tok-s-retry` to the cleanup loop.

### 5.2 Bootstrap, DOM stub (same harness style as Phase 54)

- A click on a submit control in a form whose token field carries `data-gswp-spent-field` → the
  companion holds T1 **synchronously**, before the mint resolves. The token field still reads T1
  until the mint resolves, then T2, and is never empty.
- A field without the attribute → no write anywhere.
- An empty token field → the companion is not overwritten with `''`.

### 5.3 Fast checks

`php -l` on both files, `npm run build`, and `node --check` on the extracted bootstrap.

### 5.4 Live (test.onedog.solutions, GF Stripe test mode). This is what actually settles it.

1. Force a refused pre-check: temporarily raise the checkout threshold to 1.0. Throttle the
   network in DevTools so the re-mint lands before the re-post. Confirm the re-post's request body
   carries `gswp_gf_spent` = the pre-check's token, and that the reCAPTCHA console shows
   **one** assessment for the attempt.
2. A declined card (`4000 0000 0000 0002`), then a 4242 retry, with no reload → the second
   attempt succeeds with no "expired" message, and there are **two** assessments total (one per
   pre-check).
3. A 3-D Secure card (`4000 0027 6000 3184`) → the entry carries the pre-check's assessment name,
   as in v2.31.0.

## 6. Out of scope and residual risk

- If GF Stripe ever re-posts after a **second** click (the visitor double-clicks during the
  pre-check), the companion holds the second click's token. The outcome degrades to today's
  behaviour (scored once more), never to a wrong admit.
- The client ordering (our capture-phase click before GF Stripe's `FormData`) is source-read,
  not observed. Live check 5.4.1 is what proves it.
- Alternative considered: key the failed verdict on GF's `gform_unique_id` instead of a new field.
  That needs no JS change, but it depends on that field being populated and stable across the
  pre-check and the re-post in GF 3.1.3, which is unverified. It also ties a refusal to a form
  render rather than to the token that earned it. Revisit only if 5.4.1 shows the companion
  field failing to reach the re-post.
