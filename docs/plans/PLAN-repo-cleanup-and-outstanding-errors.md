# Implementation plan — repository cleanup and the outstanding errors on `main`

**Written:** 2026-08-01. **`main` is at `52160f1` (v2.26.0).** **Branch for this
work:** `claude/state-cleanup-plan-qf4v09`.

Scope: retire the stale branches left behind by finished work, and close the
defects and unverified claims `STATE.md` records as still open. Nothing here
changes a protection surface's behaviour except items **E2** and **E3**, both of
which are explicitly bounded below.

Every claim in §1 and §2 was checked against the repository or the working tree
at the commit above, not read out of `STATE.md`. Where `STATE.md` is the only
source for something, it says so.

---

## 0. The finding that reframes "cleanup old PRs"

**This repository has no pull requests. Not stale ones — none at all.**
`list_pull_requests` returns an empty array for `state=open` and for
`state=closed`. Fifty-three phases and twenty-six releases were merged by
pushing to `main` directly.

So there is nothing to close, and the thing that actually needs cleaning is what
stands in for the PRs: **seven remote branches, six of which are fully contained
in `main`.** They read exactly like open work — a `git branch -a` shows six
`claude/*` branches with plausible names — and none of them is.

A second finding falls out of the same look:

**There are no git tags. Zero.** Twenty-six shipped releases, `readme.txt`
claiming `Stable tag: 2.26.0`, and no `v2.26.0` in the repository. Every prior
release is reachable only by knowing its commit hash, and the hashes live
nowhere but `STATE.md` prose. This matters here specifically because §1 deletes
branches, and deleting a branch is only safe when the history it points at is
anchored by something else.

---

## 1. Branch cleanup

### 1.1 Inventory, with the containment check that justifies each disposition

Counts are `git rev-list --left-right --count origin/main...origin/<branch>` —
left is commits on `main` the branch lacks, right is commits the branch has that
`main` lacks. **A right-hand `0` means the branch is fully merged and deleting
it loses nothing.**

| Branch | Head | main-ahead / branch-ahead | Disposition |
| --- | --- | --- | --- |
| `claude/issue-to-solve-kbuo47` | `52160f1` | 0 / 0 | Delete — identical to `main` |
| `claude/fluent-forms-integration-plan-ykmij4` | `a90eafa` | 8 / 0 | Delete — merged |
| `claude/fluentforms-gravity-parity-5oi6xm` | `7655407` | 19 / 0 | Delete — merged |
| `claude/2fa-suspicious-login-check-byzsfv` | `9625ad3` | 25 / 0 | Delete — merged |
| `claude/gravity-form-dashboard-issues-djk2m4` | `1412c71` | 30 / 0 | Delete — merged |
| `claude/stripe-gravity-forms-review-mokafg` | `dd5641f` | 41 / 0 | Delete — merged |
| `backup/v2.26.0-local` | `41f74dd` | 5 / 2 | **Tag, then delete** — see 1.2 |

### 1.2 `backup/v2.26.0-local` is the only one that needs an argument

It carries two commits `main` does not (`4ca5a8a`, `41f74dd`), so the
containment check alone does not clear it. It is nonetheless superseded, and
here is the evidence rather than the assertion:

- Its two commits have the same subjects as `main`'s `84dcfff` and `032dd16` —
  it is a parallel authoring of the Phase 53 work, not different work.
- It branched before `main`'s `323547c`, so it predates the chunk 24 paste fix
  and does not contain `tests/manual/28-ff-account-binding.php` at all
  (`git diff --stat` reports that file as −136 lines going `main` → backup).
- `git diff --stat origin/main origin/backup/v2.26.0-local` is 57 insertions
  against 390 deletions, and `includes/class-gswp-comments.php` is −197. The
  backup holds the **pre-fix** draft of the comment surface — the one before
  `52160f1` closed the `comment_form_defaults` and `pre_comment_approved`
  breakages. Its 57 insertions are the superseded text of chunks 22–27, not new
  material.

So it contains nothing that is not either in `main` or deliberately replaced by
it. It is still the one branch a human made on purpose, which is why it gets a
tag rather than a plain delete.

### 1.3 Order of work

1. **Tag the releases first.** At minimum `v2.26.0` on `52160f1`. Ideally walk
   `readme.txt`'s changelog and tag each release commit it names; if that is too
   much archaeology for now, tag `v2.26.0` and stop — the point is that the
   current release stops depending on a branch name for its existence.
   ```
   git tag -a v2.26.0 52160f1 -m "v2.26.0"
   git push origin v2.26.0
   ```
2. **Archive the backup branch as a tag**, so the pre-fix Phase 53 draft stays
   recoverable without occupying a branch name:
   ```
   git tag -a archive/v2.26.0-local-draft 41f74dd \
     -m "Pre-fix Phase 53 draft; superseded by 52160f1"
   git push origin archive/v2.26.0-local-draft
   ```
3. **Re-run the containment check immediately before deleting**, not from this
   document. `STATE.md`'s own §Release state records the failure this guards
   against: a stale `origin/*` ref reads exactly like a real branch, and a claim
   about repository state is only as current as the last fetch. `git fetch
   --prune` first, then re-run the `rev-list` counts, then delete only the
   branches still reporting `0` on the right.
4. **Delete the six merged branches, then the tagged backup.**
5. **Enable "automatically delete head branches"** in the repository settings so
   this does not re-accumulate — and note that it will not help until work
   actually goes through PRs, which §1.4 is about.

### 1.4 The process change this is really asking for

Deleting seven branches is ten minutes. Not regrowing them is the deliverable.
Two options, and the recommendation is the first:

- **Recommended: keep merging to `main` directly, and delete the working branch
  as part of the release commit.** This project's actual workflow is a single
  operator with an agent; a PR that nobody reviews is ceremony, and `STATE.md`
  already does the job a PR description would. The rule is just: a branch whose
  work is on `main` gets deleted the same day.
- If PRs are wanted for the review trail, then the release step becomes
  open-PR → merge → auto-delete, and `STATE.md` phase entries should carry the
  PR number so the two records point at each other.

### 1.5 While in the tree: the plan-file sprawl

Ten `PLAN-*.md` files sit at the repository root, all for completed phases
(37–50), totalling ~4,000 lines. This one makes eleven. They are genuinely
valuable — several are the only record of why a binding is what it is — so
**do not delete them.** Move them to `docs/plans/`, leaving the root to
`STATE.md`, `readme.txt`, the plugin bootstrap and the build config.

One consequence worth checking while doing it: there is **no `.distignore` and
no packaging script** in this repository. If the distribution ZIP is built by
zipping the working tree, then `STATE.md`, every `PLAN-*.md` and all of
`tests/manual/` — including chunks that write options and attach render hooks —
are shipping to customer sites. Confirm how the ZIP is actually produced before
assuming this is fine; if it is a naive zip, add a `.distignore` or a build
script in the same pass.

---

## 2. Outstanding errors

Ordered by whether the fix is mechanical, behavioural, or a test that has to be
run by someone with a live site. **E1–E4 are code changes verifiable here.
E5–E9 cannot be closed from this environment at all**, and the plan for them is
to state precisely what would close them rather than to pretend otherwise.

### E1 — the ESLint error (mechanical, zero risk)

**Verified, not inherited from `STATE.md`'s claim.** `npm ci` then
`npx wp-scripts lint-js src` reports exactly one problem:

```
src/components/FormProtection.jsx
  137:15  error  Replace `⏎↹↹` with `·`  prettier/prettier
✖ 1 problem (1 error, 0 warnings)
```

It is a line break in the `settings.form_providers || adminData.formProviders ||
{...}` fallback added by the Phase 50 addendum 4 toggle fix. Auto-fixable, no
runtime effect. `npm run build` compiles successfully with it present, which is
why three releases shipped over the top of it.

**Fix:** `npx wp-scripts lint-js --fix src/components/FormProtection.jsx`, as its
own commit touching one file.

**Also fix the evidence claim it invalidates.** The v2.24.0 and v2.25.0 entries
in `STATE.md` both say "ESLint 0 errors". That was untrue when written. Phase 53
already caught this and said so; the two earlier entries should be corrected in
place so a future reader does not trust an "ESLint clean" line that was never
true, and so the *next* real lint regression is not lost in a baseline of one
known error.

### E2 — the compatibility shim that was due for removal three releases ago

`GSWP_Provider_Gravity_Forms::accepted_actions()`
(`includes/class-gswp-provider-gravity-forms.php:600-608`) still returns
`array( $action, 'submit' )` for `register` / `account_update` /
`password_reset`. `STATE.md`'s Phase 48 entry says of it, in bold:
**"Remove in 2.23.0."** `main` is at 2.26.0.

The Fluent Forms provider never had it — `accepted_actions()` there is a
one-liner returning `array( $this->action_for( $form_id ) )`
(`class-gswp-provider-fluent-forms.php:899-901`) — so this is a GF-only carry.

It existed so pages cached under 2.21.1 would not keep rejecting customers until
every cache expired. Those caches expired in July 2026.

**Fix:** delete the special case; return `array( $action )` unconditionally, and
delete the paragraph of docblock that explains the allowance.

**Risk, stated rather than waved off.** A page cached under 2.21.1 and submitted
after the change renders `submit` where the server now expects `register`. On a
non-strict form that is already downgraded to score-only by the
`recaptcha_action_mismatch` branch at `:1118`, so the visitor is scored, not
blocked. On a **strict** form it is a rejection — but strict account-creating
forms have been pairing correctly since 2.22.0, so the only page that could
still carry the old label is one cached for over a year. Ship it, and keep the
`gswp_gf_account_feed_type` escape hatch in mind if a site reports otherwise.

### E3 — the payment threshold dial no operator can reach

**Verified in both files.** `context_for()` returns `checkout` for any payment
form in both providers (`class-gswp-provider-gravity-forms.php:625`,
`class-gswp-provider-fluent-forms.php:869` and `:916`), so a payment form is
scored against `gswp_threshold_checkout`. That dial is defined inside the
WooCommerce checkpoint array (`src/components/PageToggles.jsx:267`) and rendered
only under `{ woocommerceActive && (` at `:294`.

On a site with a Gravity Form or Fluent Form that takes payment and **no
WooCommerce**, the threshold governing the highest-stakes form on the site sits
at its `0.5` default and cannot be changed from the admin screen at all. Worse
than merely absent: the Form Protection panel simultaneously shows four
per-provider dials (ordinary / creates account / updates account / changes
password), **none of which apply to that form.** An operator tuning them would
reasonably believe they had.

Pre-existing, shared by both providers, not a regression — and first observed
during the Phase 50 live run on a WooCommerce-free site.

**Fix (the minimal one `STATE.md` already identifies):** surface the checkout
threshold inside the Form Protection panel whenever a provider's audit reports at
least one payment form. Additive; it changes no scoring and no context
resolution — it renders a control for an option that already exists and is
already read.

Implementation notes:
- The audit already carries what is needed. `FormProtection.jsx` reads
  `settings.form_providers` (per the `:130-141` comment — read `settings` first,
  `adminData` only as fallback, or this control will revert on save exactly as
  the toggles did).
- Label it for what it is. "WooCommerce Checkout Process" is the wrong name when
  the form is Fluent Form #4; the option is shared, so the copy must say so —
  something like "Payment forms (shared with WooCommerce checkout)".
- `threshold_checkout` is already in the REST update whitelist and sanitizer, so
  no server-side change is required. Confirm before writing the component.

### E4 — the plugin's own rejection log has no reader

**Verified:** `GSWP_Log::tail()` (`includes/class-gswp-log.php:133`) has no
caller anywhere in the codebase. The only other occurrences are
`append_tail()`'s definition and its call site inside the same class. Nothing in
`class-gswp-rest-api.php` and nothing in `src/` reads it.

Consequence, and this is not hypothetical — it is what made the Phase 49 support
ticket expensive: on a site without WooCommerce (no WC log viewer to mask it),
the record of what this plugin rejected and why is reachable only by WP-CLI or a
direct database read. The per-form `gswp_gf_last_rejection` surface on the Form
Protection tab covers form-provider rejections only; the verifier's own log —
which is where `timeout-or-duplicate`, `BROWSER_ERROR` and `SITE_MISMATCH` land
for wp-login, WooCommerce, PowerPack, Beaver Builder and now comments — has no
surface at all.

`STATE.md` calls surfacing it "the obvious next phase". It is also the cheapest
item on this list that a real operator would notice.

**Fix:** a read-only REST route (`GET .../diagnostics/log`, same permission
callback as the existing settings routes — administrator only) returning
`GSWP_Log::tail( 50 )`, and a panel on the Diagnostics tab that renders it. Two
things to get right:

- **Escape the entries on render.** Log lines contain Google's `invalidReason`
  and observed action names, which originate in a request. React escapes by
  default; do not reach for `dangerouslySetInnerHTML` for formatting.
- **Do not add a clear-log button in this pass.** A destructive control on a
  diagnostics tab is a separate decision with its own confirmation design.

### E5 — the entire Phase 53 comment surface is unexercised

v2.26.0's evidence is `php -l`, `node --check` on the generated snippet, and a
completed build. No browser, no comment submission, no page cache, no REST
client. The two breakages `52160f1` closed were both found by reading WordPress
source, and both were *silent* — which is the argument for running the checks
rather than reasoning once more.

Checks that settle it, in priority order:

1. **The REST regression, as a subscriber.** `POST /wp/v2/comments`
   authenticated as a subscriber, toggle on. Expect the comment to be created —
   **not** an HTTP 500. This is the one that was reasoned from source and never
   observed, and an administrator testing it would never see the failure, because
   `moderate_comments` users are exempt (`class-gswp-comments.php:171`).
2. **A comment from a logged-out visitor** on a default theme: field present in
   the DOM inside `</form>`, populated, comment accepted.
3. **A comment on a theme that customises `submit_field`**, confirming the
   `comment_form` action still fires and the field is still injected — the
   failure mode `comment_form_defaults` would have had.
4. **A trackback/pingback and an XML-RPC comment**, confirming both pass through
   unscored.
5. **A cached page served while the reCAPTCHA script is still loading**, which is
   the only thing that exercises the submit-hold snippet at all.

**One thing to watch for in check 5, reasoned from the code and worth stating
because nobody will otherwise look for it.** The snippet
(`class-gswp-comments.php:229-263`) calls `e.preventDefault()` **and**
`e.stopPropagation()` in the capture phase, then completes the submit with
`nativeSubmit.call(form)`. On a theme that posts comments over AJAX by listening
for `submit`, that combination cancels the theme's handler and converts the first
comment of the page-load into a **full page navigation** instead of an AJAX post.
For the core comment form this is correct and invisible. On an AJAX comment
theme it is a visible behaviour change, and the hold only fires when the field is
empty, so it will present as "the first comment reloads the page, later ones do
not" — which is exactly the shape of bug that gets misattributed to caching. If
check 5 is run on an AJAX theme, watch for it specifically. This is reasoned from
source, not observed.

### E6 — D2, the Fluent Forms account create/update binding

Still the highest-consequence unobserved item in the project, and it has been
carried across three releases. Its Gravity Forms equivalent is the Phase 48
incident — a named customer told she was spam while editing her own profile.

The state is precise and worth not blurring: the fix is source-verified against
`UserUpdateFormHandler::isValidFeed()`, exercised through six synthetic cases in
chunk 26 §F, and confirmed in *shape* on a real registration feed by chunk 28.
**None of that discriminates the fix from the bug**, because the broken
2.23.0/2.23.1 code also returns `create` on a registration feed — same answer,
wrong reason, indistinguishable output.

**The one check that closes it:** a Fluent Form carrying **only** a User Update
feed (`list_id = user_update`, enabled), run through
`tests/manual/24-ff-classification.php`. Expect `account=update`, action
`account_update`, **non-strict**. Under the 2.23.0 code the same form returns
`create` / `register` / STRICT.

Requires operator action on `test.onedog.solutions` — a User Update form does not
exist there yet. Nothing in this repository can close it.

### E7 — the v2.22.1 bootstrap staging checks

Per `STATE.md`, the largest untested surface on `main`: inline JS in
`get_bootstrap_js()` that touches token refresh on **every** form the bootstrap
fills, including WooCommerce checkout and PowerPack. Evidence is a hand-rolled
DOM stub, no browser. The checks are enumerated in
`PLAN-suspicious-login-2fa-and-stale-token.md` and are still outstanding.

The WooCommerce checkout regression case **cannot** be signed off from the
reporting site, which has no WooCommerce. Closing that one needs a different
site. Say so in the next release notes rather than letting "staging checks
outstanding" imply a single blocked task.

### E8 — Transaction Defense annotation on failed payments

Observed on the live run: submission 8 (payment declined at Stripe) has no
`gswp_assessment_name`, while the two successful submissions do. The likely cause
is that the request short-circuits inside the payment handler before
`fluentform/submission_inserted` fires, so `store_submission_meta()` never runs.

Bounded — a payment that never succeeded has little worth annotating — and
recorded as not chased. **Keep it that way**; it is listed here so it stays a
known gap rather than becoming a surprise. Revisit only if Google's Fraud
Prevention reporting turns out to want the declined attempts.

### E9 — `migrates_by_default()` still holds `fluent-forms` back

**Not an error, and it should not be "fixed" as part of a cleanup pass.** It is
deliberate, it is the reason none of the Fluent Forms work can hurt a site that
did not ask for it, and E6 is unclosed. Flipping it is a one-line change in a
release that has field evidence to justify it. This entry exists so a future
reader does not mistake it for an oversight and tidy it away.

---

## 3. Sequencing

**Pass 1 — no behaviour change, land together.**
E1 (lint fix, one file), §1.5 (move plans to `docs/plans/`, plus the packaging
question), and the `STATE.md` correction to the v2.24.0/v2.25.0 ESLint claims.

**Pass 2 — branch and tag hygiene.** §1.3 in order: tag `v2.26.0`, tag the
backup draft, `git fetch --prune`, **re-run the containment counts**, delete the
six merged branches, delete the tagged backup, turn on auto-delete.

**Pass 3 — the two bounded behaviour changes, as v2.26.1.**
E2 (remove the GF compat shim) and E3 (surface the checkout dial). Independent of
each other and separately revertable. Evidence available here is `php -l`,
ESLint — which will be genuinely clean once E1 lands — and a build. Not a
signed-off release; say so in `STATE.md` in the same words the last four
releases used.

**Pass 4 — E4, the diagnostics log surface, as v2.27.0.** Additive, its own
phase, and the item most likely to pay for itself the next time a support ticket
arrives.

**Operator track, in parallel and not blocking any of the above.** E6 (build the
User Update form, run chunk 24) then E5 check 1 (the REST comment as a
subscriber), then E7. These are the only items that convert "source-verified"
into "observed", and no amount of work in this repository substitutes for them.

---

## 4. What this plan deliberately does not do

- **It does not revert anything.** `main` carries several releases whose evidence
  is `php -l` and a build. That is a reason to run the checks in E5–E7, not a
  reason to unship working code, and `STATE.md` already records that reverting
  2.22.1 restores the stale-token defect rather than a known-good state.
- **It does not touch `migrates_by_default()`** — see E9.
- **It does not rewrite `STATE.md`'s history.** The file is long because it
  records retractions and wrong turns in place, and that is its most useful
  property. The only edit proposed is correcting two evidence claims that were
  false when written (E1), which is the same thing the file already does to
  itself.
