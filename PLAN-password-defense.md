# PLAN — Password Defense (leaked-credential detection) — Phase 28 target, v2.13.0

## 1. Where this comes from

The Account Defender checkup (Phase 27 follow-up) confirmed the Account Defender feature itself is
now complete: identifiers on all login/registration/account-modification assessments, label
screening at registration, the step-up seam, and both halves of the annotation feedback loop
(login outcomes since 2.2.0, registration outcomes since 2.12.0). The remaining recommendation on
the Google Cloud **Fraud Defense** dashboard for `one-dog-solutions` is a different, sibling
feature the plugin does not implement at all:

> **Detect leaked passwords — Protect against credential stuffing with Password defense.**
> "Your users may have accessed password-related pages more than 1 times in the past 30 days."

Clicking **Configure Password defense** opens a panel asking for the *development environment*:
**Java**, **Node.js**, or **Other**. Google ships client helper libraries only for Java
(`GoogleCloudPlatform/java-recaptcha-password-check-helpers`) and TypeScript/Node
(`recaptcha-password-check-helpers` on npm). PHP is **Other**: Google's docs point you at the
protocol spec and expect you to implement the client-side cryptography yourself
(<https://docs.cloud.google.com/recaptcha/docs/check-passwords#cryptographic-function>).

That is the recommended update path this plan specifies: **implement Password Defense natively in
PHP as a new plugin feature**, using Google's documented protocol, with the official TypeScript
helper used as a black-box test oracle (not as ported code — see licensing, §9).

### What the feature does (docs: `#issue-assessment`, `#interpret-verdict`, `#use-verdict`)

On a credential event (login, signup, password change/reset) the site checks the user's
username+password pair against Google's database of billions of breached credentials **without
ever revealing the credentials to Google**. The check is a privacy-preserving two-party protocol:

1. The site sends a 26-bit bucket prefix of a salted hash of the username, plus the scrypt hash of
   the username+password pair **blinded with a per-request EC key only the site holds**.
2. Google re-encrypts the blinded hash with its own key and returns it, along with the (Google-key
   encrypted) breach-database entries in that username bucket.
3. The site strips its own blinding layer locally (commutative encryption makes the order not
   matter) and checks for a match locally. Google never learns the credentials or the verdict; the
   site never learns anything about non-matching database entries.

A positive match = the user's exact username+password pair is in a known breach → the account is
one credential-stuffing attempt away from takeover, even though the password is "correct".

## 2. Checkup conclusion / current state (what already exists)

- `GSWP_Verifier::assess_enterprise_token()` (class-gswp-verifier.php:305) builds Enterprise
  assessments but the body is only `{ "event": … }`. The leak-check fields live at the **top
  level** of the assessment resource, as a sibling of `event`, so nothing currently in the
  verifier can carry them.
- All credential surfaces are already hooked for other purposes and give us the plaintext password
  in-request: core login (`authenticate`, GSWP_Login at 30 / Account Defender capture at 40 / 2FA
  at 100), password reset (`validate_password_reset`, `after_password_reset`), own-profile and
  WooCommerce account-details saves (Account Defender events, Phase 19), and the four registration
  validators (Phase 26/27).
- The alerts pipeline (Phase 20/27) takes a new event type cheaply: an action hook, a sub-toggle,
  a dedupe key, and format/digest extensions.
- Nothing else in the plugin performs password-derived crypto; this is a genuinely new subsystem.

## 3. Update path — options considered

| Option | Verdict |
|---|---|
| **A. Native PHP implementation of the documented protocol** | **Recommended.** Self-contained (matches the plugin's zero-dependency, works-on-shared-hosting philosophy), covers every WP surface, and is the path Google's own console offers for "Other" environments. |
| B. Node.js sidecar using the official npm helper | Rejected: WordPress plugins cannot assume a Node runtime or a resident process; unshippable to agency shared hosting. |
| C. Have I Been Pwned k-anonymity API instead | Rejected: solves a related problem but is a different service — the Fraud Defense console recommendation would never clear, there is no username+password *pair* matching (HIBP checks passwords alone), and it adds a second external dependency. |
| D. Document as "not implementable in PHP" (like the console-side Account defense click) | Rejected: unlike that case, this *is* implementable — Google documents the client crypto precisely for this purpose. |

(See the rest of the investigation and implementation notes in the Phase 28 STATE.md entry; the
full protocol constants, verification harness, and per-surface behaviour design are captured there
alongside what actually shipped.)
