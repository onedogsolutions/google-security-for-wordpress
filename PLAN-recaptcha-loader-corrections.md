# Implementation plan — reCAPTCHA loader ownership and conflict corrections

Completes the corrections identified in
`PLAN-gravity-forms-stripe-and-integration-architecture.md` (items A2–A7).
A1 shipped in v2.17.0.

**Target release: 2.18.0** (single release — see §2 for why this cannot be
safely split the way the earlier draft proposed).
**Follow-up release: 2.18.1** for the Gravity Forms proactive warning, which is
gated on source discovery.

**Out of scope:** FluentCart, tracked separately as its own feature. Option B
(integration registry / cart adapters) remains future work; this plan deliberately
builds the loader owner in a way that Option B can absorb rather than replace.

---

## 1. Objective

Three outcomes, in priority order:

1. **Exactly one reCAPTCHA loader per page**, whoever asked for it. This is the
   defect behind the Gravity Forms / Stripe failure.
2. **Never silently disable our own protection.** Delete deferral. A page that
   renders one of our token fields always gets a working loader and bootstrap.
3. **Warn when another plugin loads reCAPTCHA with a different site key.** The
   operator has confirmed Gravity Forms currently shares our key, but that is a
   configuration that can change at any time in GF's settings, in a second
   environment, or on another site running this plugin. A silent divergence must
   become a visible one.

---

## 2. Why this ships as one release

The previous draft recommended splitting A4 (the "don't print a field we can't
fill" gate) and A5 into a quick 2.17.1. Designing A4 properly shows that split is
unsound, and this supersedes that recommendation.

A4 requires the print decision and the enforce decision to agree. They happen in
**two different requests**: the field is printed on a GET, the token is validated
on the POST. Any design where the POST body tells the server whether to enforce is
broken by construction — an attacker simply omits the marker, which is S1 in a new
costume. Signing the marker does not help; omission is the attack, not forgery.

So enforcement must be decided from stable server-side state, which means the
print predicate must depend only on stored options — not on page state. Today it
depends on `should_defer()`, which is page state. **A4 is therefore only sound once
A3 has deleted deferral**, and A3 depends on A2 replacing it. The three are one
change.

The inverse fix — "always register the loader when we print a field" — is sound in
isolation but would reintroduce a second loader tag on Gravity Forms pages, which
is the original bug. That is only safe once A2.1 deduplicates. Same conclusion.

**A5 alone is genuinely separable** and safe to ship early if something is wanted
today: deleting the DOM kill switches restores token generation on pages where our
loader does register, and changes nothing on pages where it does not. It is folded
into 2.18.0 below, but can be pulled forward as 2.17.1 on request.

---

## 3. Design

### 3.1 `GSWP_Recaptcha_Loader` — single owner (new file)

`includes/class-gswp-recaptcha-loader.php`. Static, no instantiation, matching the
existing utility-class convention.

The handle `google-recaptcha-v3` is currently registered in **three** places with
independently duplicated logic — `class-gswp-assets.php:66`,
`class-gswp-frontend.php:60`, `class-gswp-blocks-integration.php:52`. All three
collapse into this class.

```php
class GSWP_Recaptcha_Loader {
    const HANDLE = 'google-recaptcha-v3';

    public static function site_key();          // gswp_site_key
    public static function is_enterprise();     // gswp_key_type === 'enterprise'
    public static function loader_src();        // enterprise.js|api.js + ?render=key

    // Idempotent. Registers our loader unless a foreign loader already
    // provides our key, in which case registers an alias (see 3.3).
    public static function ensure_registered();

    // Generic scan of wp_scripts() for third-party reCAPTCHA loaders.
    public static function foreign_loaders();   // [ ['handle','src','key'], … ]
    public static function key_from_src( $src );// parse ?render= / &render=
    public static function conflicts();         // foreign loaders where key !== ours

    // A4: single predicate shared by field printing and token enforcement.
    // Depends only on stored options, never on page state.
    public static function will_load();
}
```

`will_load()` reduces to `'' !== site_key()` once deferral is deleted. That is the
whole point: both requests can evaluate it identically, so print and enforce can
never disagree again.

### 3.2 Detection is generic, not Gravity Forms specific

`foreign_loaders()` walks `wp_scripts()->registered`, matches `src` against the
existing needles (`google.com/recaptcha`, `recaptcha.net/recaptcha`,
`gstatic.com/recaptcha`), and parses the `render=` parameter for the site key.

This requires **no knowledge of any other plugin's option keys or handles**, which
is what unblocks the whole release: the GF source discovery (A2.4) is needed only
for the *proactive* admin-time warning in 2.18.1, not for runtime dedup or the
runtime warning. It also means WPForms, Elementor, CF7, Fluent Forms and anything
else are covered on day one, for free.

### 3.3 Dedup, and the WooCommerce Blocks trap

When a foreign loader already provides **our** key:

- Do not emit a second `<script>` tag.
- Still `wp_register_script( HANDLE, false, array(), GSWP_VERSION, true )` — a
  **src-less alias**.

The alias matters: `GSWP_Blocks_Integration` lists `google-recaptcha-v3` in its
block script's dependency array. WordPress silently refuses to enqueue a script
whose dependency is unregistered, so simply skipping registration would break the
Store API checkout token — a fresh outage of exactly the kind this plan exists to
end. The src-less alias satisfies the dependency graph while emitting nothing.

### 3.4 Bootstrap sequencing (A2.2)

The bootstrap currently rides `wp_add_inline_script()` on our handle. When we reuse
a foreign loader there is no tag of ours to attach to, and `wp_add_inline_script()`
returning false is one of the failure modes behind S2.

Move it to `wp_print_footer_scripts` (priority 20), printed directly, guarded on
`typeof grecaptcha !== 'undefined'` with a short bounded poll (e.g. 100 ms
interval, 10 s ceiling) for loaders that arrive late. Print once per request via a
static flag. This decouples us from any other plugin's handle lifecycle.

### 3.5 Key mismatch warning (A2.3 — now a first-class requirement)

Two Enterprise keys cannot both be pre-rendered via `?render=`, so on mismatch the
page is in a state we cannot make fully correct without operator action. Picking a
winner *silently* is precisely what produced this incident; picking one *loudly* is
the operator's chosen policy (§3.7). Our loader is always registered either way —
dropping it would silently disable our own protection, which is the failure mode
this whole plan exists to end.

**Two severities**, because the two states carry very different risk:

| State | Severity | Meaning |
|---|---|---|
| Divergent key detected, **not** being suppressed (mode `off`, or our loader absent from that page) | **Warning** | Both loaders present. One of them will likely fail to execute. Dismissible. |
| Divergent key detected **and** being suppressed (`active` on our pages, or `site`) | **Critical** | We are actively removing another plugin's reCAPTCHA. Its forms — including payment forms — may fail. Not dismissible while the condition persists. |

The Critical state is the one that broke Stripe. It must be impossible to miss.

**Recording.** `foreign_loaders()` runs on the front end; the admin screen cannot
see it directly. Persist observations to a transient:

```
gswp_foreign_recaptcha = [ [ 'key_masked', 'handle', 'src', 'first_seen' ], … ]
TTL 7 days
```

Write **only when the observed set differs** from what is stored (compare a hash),
so the common case is one `get_transient()` per request and no write.

**Surfaces (five):**

1. **Admin notice, site-wide** on any `manage_options` screen — not confined to our
   settings pages. An operator who never opens our settings is exactly the one who
   needs to see this.
   - *Warning* severity: `notice-warning`, dismissible per user via user meta
     (`gswp_loader_conflict_dismissed`) keyed by the **conflict hash**, so a new or
     changed conflict re-arms rather than staying dismissed forever.
   - *Critical* severity: `notice-error`, **not dismissible** while suppression is
     actually occurring. Names the suppressed handle, the owning plugin where
     resolvable, both masked keys, and the one-click path to the Compatibility tab.
2. **Compatibility tab panel** — live state inline with the mode selector, styled
   red in the Critical state, listing each detected loader: masked key, handle,
   owning plugin, matches-ours, and suppressed-or-not. Replaces the current static
   "we automatically defer to Gravity Forms" note, which will no longer be true.
3. **Plugins-screen row notice** on our own plugin row in the Critical state — the
   surface an operator hits during an incident when they are looking for what to
   deactivate.
4. **Log** — `error` level (not `warning`) in the Critical state via the existing
   `wc_get_logger()` path, once per detection change, not per request.
5. **REST diagnostic** — new `loader_conflicts` section in
   `POST /gswp/v1/diagnose`, reusing the Phase 32 structure in
   `class-gswp-rest-api.php:135`. Gives support a single call that reports what
   else is loading reCAPTCHA and whether we are suppressing it.

**Email alert (proposed).** `GSWP_Alerts` already turns `gswp_checkout_blocked` and
`gswp_suspicious_registration` into throttled operator emails. Firing a
`gswp_loader_conflict` action in the Critical state would reuse that pipeline
end-to-end for perhaps 20 lines. Recommended: entering the Critical state means
another plugin's payment forms may be failing right now, and nobody is watching a
WooCommerce log. Flagged rather than assumed — see §8 Q4.

**Explicitly out of scope:** the `grecaptcha.enterprise.render()` multi-key path
that would make two distinct keys genuinely coexist. Documented as the escalation
if warnings prove insufficient; not built on speculation.

### 3.6 Deletions

- `GSWP_Gravity_Forms::should_defer()`, `is_form_rendered()`, `is_gf_handle()`,
  `$gf_handles` — no callers remain after A2. The class reduces to `is_active()`,
  retained for 2.18.1.
- The `document.querySelector('.gform_wrapper, .gf-form, [id^="gform_"]')` bail-out
  in `class-gswp-frontend.php:152` and `class-gswp-assets.php:123` (A5).
- `GSWP_Conflict_Guard`'s blanket `is_active()` escape at
  `class-gswp-conflict-guard.php:97`.

### 3.7 Conflict Guard (A6) — `active` stays Recommended

**Operator decision (2026-07-26): `active` remains the Recommended mode; the
warning does the work instead of a default change.** This section is written to
that decision and supersedes the earlier draft, which moved "Recommended" to `off`.

Dedup changes what each mode means, and it is worth being precise, because
otherwise `active` would quietly become a synonym for `off`:

| Mode | Matching key | Divergent key |
|---|---|---|
| `off` | reused (dedup is unconditional) | both load, warn |
| `active` *(Recommended)* | **reused, never suppressed** | suppressed on pages where our reCAPTCHA loads — **warn loudly** |
| `site` | reused, never suppressed | suppressed on every front-end page — **warn loudly** |

**Dedup is unconditional and mode-independent.** A loader carrying our key is
always reused and never suppressed, in every mode. That single rule is what fixes
the original failure, and it is why `active` is now safe to keep recommending: the
configuration that broke Stripe (same key, `active` mode) becomes a no-op.

**`active` retains a real, narrow job:** on a page where our reCAPTCHA is running
and another plugin wants a *different* key, two Enterprise keys cannot both be
pre-rendered. `active` resolves that in our favour — which is what the setting has
always claimed to do — and the warning states the cost.

**Residual risk, stated plainly.** In `active` or `site` mode with divergent keys,
we will still suppress another plugin's loader and its forms may fail — including a
Gravity Forms Stripe payment, exactly as in the original incident. Suppression is
no longer *silent*, but it is still *destructive*. The warning is what makes this
survivable, not the suppression logic. If that trade is unacceptable, the change is
one line (never suppress, warn only) and can be made at implementation time — see
§8 Q1.

Migration: sites on `active` stay on `active`; its behaviour becomes correct for
matching keys and loud for divergent ones. No option rewrite, no migration routine.

---

## 4. Work breakdown

| # | Item | Files | Est. |
|---|---|---|---|
| 1 | `GSWP_Recaptcha_Loader` + generic detection | new file | 0.5 d |
| 2 | Collapse 3 registration sites onto it; alias for Blocks | `assets`, `frontend`, `blocks-integration` | 0.5 d |
| 3 | Bootstrap → footer printer with grecaptcha poll | `assets`, `frontend` | 0.5 d |
| 4 | `will_load()` gate wired into field printing + enforcement | `frontend`, `login`, `powerpack`, `verifier` | 0.5 d |
| 5 | Delete deferral + DOM kill switches | `gravity-forms`, `frontend`, `assets` | 0.25 d |
| 6 | Mismatch recording; two-severity notices (site-wide + plugins row); log | `recaptcha-loader`, `admin` | 0.75 d |
| 7 | Compatibility tab rebuild + REST diagnostic | `Compatibility.jsx`, `rest-api` | 0.5 d |
| 8 | Manual test script + staging verification | `tests/manual/09-*` | 0.75 d |
| 9 | *(optional, pending Q4)* `gswp_loader_conflict` → `GSWP_Alerts` email | `alerts`, `recaptcha-loader` | 0.25 d |

**Total ≈ 4.25 days** (4.5 with the optional email alert), up from the 2–3 in the
analysis doc. The increase is items 2, 3 and 7 — the Blocks dependency alias, the
bootstrap relocation, and the UI work were all folded into "A2" previously and are
each real — plus the extra warning surfaces item 6 gained from the `active`-stays-
Recommended decision.

Webpack rebuild required (item 7 touches `src/`).

---

## 5. Test plan

`tests/manual/09-recaptcha-coexistence.php`, plus staging verification against the
real Gravity Forms + Stripe page.

| # | Scenario | Expect |
|---|---|---|
| 1 | GF + Woo checkout on one page, **same key** | exactly one `enterprise.js` tag; both tokens populated; GF Stripe element mounts; Woo checkout completes |
| 2 | Same, conflict mode `active` | identical to 1 — no suppression of a matching key |
| 3 | Same, conflict mode `site` | GF loader suppressed (operator's explicit choice), warning surfaced |
| 4a | Different key, mode `off` | both tags present, neither suppressed; **Warning** notice, dismissible; Compatibility panel + log + diagnostic all report it |
| 4b | Different key, mode `active`, our reCAPTCHA on the page | theirs suppressed; **Critical** notice, **not dismissible**; plugins-row notice present; log at `error`; diagnostic reports suppression |
| 4c | Dismiss the Warning notice, then change the foreign key | notice re-arms (dismissal is keyed to the conflict hash, not permanent) |
| 5 | Woo login/registration on a page with a GF form | our tokens populated (regression test for S2/S4) |
| 6 | Page with GF form, no Woo | one loader, GF unaffected, no notice |
| 7 | WooCommerce **Blocks** checkout with a foreign loader present | block script still enqueues (alias resolves the dependency); Store API token present |
| 8 | No site key configured | no field printed, no enforcement, no fatal |
| 9 | Site key configured, GF absent entirely | unchanged from 2.17.0 behaviour |

Scenario 7 is the one most likely to be skipped and most likely to break; it is
listed explicitly for that reason. Scenario 4 must be run by temporarily pointing
GF at a second key on staging — it is the acceptance test for the operator's
requirement.

---

## 6. Rollback

Each item is independently revertable, but items 1–5 are a unit and should be
reverted together — reverting dedup while keeping the deletion of deferral would
restore the duplicate loader on GF pages with no mitigation.

The 2.17.0 tag is the rollback target. No database migration and no option schema
change is introduced, so a downgrade is a plugin-file swap; the only persistent
artefacts are a transient and a user meta key, both inert if the code is absent.

---

## 7. Release 2.18.1 — Gravity Forms proactive warning

Gated on the discovery pass (A2.4), which cannot be completed from this repository:

- Which option key GF's **Enterprise** integration stores its site key under. The
  current `gravityformsaddon_recaptcha_settings` / `site_key` / `public_key`
  handling was inferred, never verified, and GF's Enterprise integration may not
  share storage with the classic add-on.
- Where GF stores its own project ID and API key, so the shared-project assumption
  can be confirmed programmatically instead of trusted.
- GF's actual loader handle, `src` shape, and enqueue hook/priority.

Deliverable: `GSWP_Gravity_Forms::site_key()` plus an admin-time comparison, so a
divergence is reported **from the settings screen without waiting for someone to
visit a front-end page**. The runtime warning from 2.18.0 already covers the
reactive case; this makes it proactive.

Est. 0.5 d after discovery. Discovery itself is 0.5–1 d on staging.

---

## 8. Open questions for the operator

1. ~~**Conflict mode default.**~~ **Answered 2026-07-26: `active` stays
   Recommended, with loud warnings instead of a default change.** Implemented as
   §3.7. One sub-decision remains open and is cheap to flip at implementation
   time: in `active`/`site` mode with divergent keys, do we actually suppress
   (honouring the setting, accepting that the other plugin's forms may break), or
   warn only? §3.7 currently specifies **suppress + warn loudly**, on the reading
   that a mode which never suppresses anything is indistinguishable from `off`.
   Say so if the safer reading was intended.
2. ~~**Notice audience.**~~ Resolved by the same decision — if warnings carry the
   weight instead of the default, they must be **site-wide** on any
   `manage_options` screen. Specified in §3.5.
3. **Staging access for scenario 4** — a second Enterprise site key to point GF at
   temporarily, to prove the warning fires.
4. **Email alert on Critical.** Reuse the existing `GSWP_Alerts` pipeline for a
   throttled operator email when we enter the suppressing-a-divergent-key state?
   Recommended (§3.5). ~20 lines, no new infrastructure.
