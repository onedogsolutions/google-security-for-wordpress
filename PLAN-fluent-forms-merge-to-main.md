# Implementation Plan — integrating the Fluent Forms provider with `main`

**Branch:** `claude/fluentforms-gravity-parity-5oi6xm` (commit `ae5c5c2`)
**Target:** `origin/main` at `9625ad3` (v2.22.1)
**Merge base:** `1412c71`

`main` moved while this branch was being written. It gained four commits and a
release. Two of them matter, and one of them takes something this branch had
already claimed.

---

## 1. The blocking finding: Phase 49 is already taken

`main` now carries **Phase 49 = v2.22.1, "a spent token is not a spam signal"** —
the stale-token rework in `GSWP_Recaptcha_Loader::get_bootstrap_js()`. This
branch's `STATE.md` also calls itself Phase 49.

This is not a text conflict to resolve by picking a side. Both phases are real,
both are on their way to `main`, and the numbering is the project's only index
into its own history: STATE.md's phase numbers are referenced from code comments
(`class-gswp-provider-gravity-forms.php` cites "Phases 43–45, 47"), from
`readme.txt`, and from the plan documents. Two Phase 49s would make every one of
those references ambiguous.

**Resolution: this branch becomes Phase 50.** `main`'s Phase 49 was released and
recorded first; renumbering the unreleased branch is the cheap direction.

## 2. The non-conflict that matters more: v2.22.1 helps this work

`main`'s loader change touches `class-gswp-recaptcha-loader.php`, which this
branch does not modify — so git reports no conflict. That silence is misleading
in the useful direction: **v2.22.1 materially improves the Fluent Forms case, and
one of its additions was written for exactly this shape of form plugin.**

Before 2.22.1 the bootstrap refreshed tokens on load, on a 100-second interval,
on tab refocus, and on DOM insertion — but nothing was tied to a *submission*,
which is the only thing that spends a token. A form that stays in the DOM
resubmitted the spent value, Google returned DUPE, and the visitor was told
verification had expired.

Fluent Forms is precisely that shape: it submits over AJAX and the form never
leaves the page. Without 2.22.1, a visitor whose first Fluent Forms submission
was rejected for any reason would have been rejected again on every retry for up
to 100 seconds. This branch would have shipped that defect on day one and it
would have read as a Fluent Forms integration bug.

Three of 2.22.1's additions land on this path:

- the universal post-submit token replacement;
- **the `click` backstop**, added for "modules that submit from a click handler
  that calls `preventDefault()`, so no submit event ever fires at all" — a
  description of Fluent Forms' own submit path;
- the `pageshow` bfcache refresh.

There is no ordering hazard between that and this branch. `replaceAfterSubmit()`
defers a tick, so Fluent Forms' serialisation captures the current value first;
and `fetchToken()` assigns only on resolve, so the field is never observably
empty. A fail-closed Fluent Form therefore cannot be rejected for a blank token
mid-refresh.

**Two follow-on edits are needed, and neither is optional:**

1. **The loader's INVARIANT docblock names only the Gravity Forms provider** as
   the reason a token field is never blanked. There are now two providers that
   fail closed on a missing token. Left as written, a future editor reading
   "the constraint comes from Gravity Forms" could reasonably conclude the
   invariant is negotiable on a site without Gravity Forms. It is not.

2. **`PLAN-fluent-forms-provider.md` §2 describes the pre-2.22.1 bootstrap**
   ("refreshes on `visibilitychange` and on `submit`"). It now does more than
   that, and the plan is the document someone will read to understand why the
   provider needs no JavaScript of its own.

## 3. Everything else is mechanical

Four files conflict, all on version strings or adjacent insertions:

| File | Conflict | Resolution |
|---|---|---|
| `google-security-for-wordpress.php` | `2.22.1` vs `2.23.0`, twice | **`2.23.0`** — correct next feature release after 2.22.1 |
| `readme.txt` | `Stable tag`, and a `= 2.22.1 =` entry inserted where `= 2.23.0 =` went | Keep **both** changelog entries, 2.23.0 above 2.22.1 |
| `package.json` | version | `2.23.0` |
| `STATE.md` | `main` rewrote the release-state paragraph and the Phase 49 heading | Rewrite: new release state, Phase 50 section, demote `main`'s Phase 49 to Historical |

One file needs attention *because* git merged it silently:

- **`package-lock.json`** — `main` bumped it to 2.22.1; this branch never touched
  it. It merges clean and is then wrong: `package.json` at 2.23.0 against a lock
  at 2.22.1. `npm` will not fail on it, which is why it is worth naming rather
  than discovering later.

Nothing in `includes/` conflicts. The provider, registry, interface, REST API and
`FormProtection.jsx` changes apply unchanged.

## 4. Sequence

1. Rebase onto `origin/main`. Rebase rather than a merge commit: the project's
   convention is a fast-forward from the feature branch ("fast-forwarded from
   the Phase 48 branch", "…from `claude/2fa-suspicious-login-check-byzsfv`"), and
   a fast-forward needs linear history.
2. Resolve the four conflicts per the table above.
3. Renumber this work Phase 49 → **Phase 50** throughout, and demote `main`'s
   Phase 49 heading to `Historical Phase`.
4. Sync `package-lock.json` to 2.23.0.
5. Widen the loader's INVARIANT docblock to name both providers (§2.1).
6. Correct `PLAN-fluent-forms-provider.md` §2 for the 2.22.1 bootstrap (§2.2),
   and record in §11 that 2.22.1 turned out to be a prerequisite.
7. Re-verify: `php -l` on every touched PHP file, interface-conformance and
   provider-parity check by reflection.
8. `npm ci && npm run build`. **This is a gate, not a nicety.** `build/` is
   gitignored and absent, and the settings screen is the React app in it — a zip
   without a built bundle has no Form Protection panel at all, which is the
   entire surface being tested.
9. Push the branch, fast-forward `main`, push `main`.
10. Update `STATE.md`'s release state to reflect the merge, keeping the honest
    limit attached: **the Fluent Forms bindings have not met a live install, and
    `tests/manual/20-26` have not been run.** Follows the precedent `main`'s own
    Phase 49 entry set for a released-but-unproven change.
11. Build the testing zip from a clean export plus `build/`, excluding
    development files.

## 5. What does not change

- The provider still ships **off**. `migrates_by_default()` still holds
  `fluent-forms` back, so merging this to `main` does not switch it on for any
  site on upgrade. Merging is therefore a much smaller act than it would be for
  the Gravity Forms provider, and that was the point of §7 of the provider plan.
- No discovery chunk has been run. Merging does not change that and must not be
  reported as if it had.
