# Implementation Plan — Tabbed Settings Screen + 2FA Button Text Fix

**Target version:** 2.8.1 (Phase 22)
**Feature:** Two admin-UI items, no behaviour/settings changes:

1. **Tabbed configuration screen.** The Google Security settings page now stacks seven full-width panels (API Credentials, Form Protection, Transaction Defense, Account Defender, Email Alerts, Conflict Handling, Two-Factor Authentication) — roughly 1,900 lines of JSX rendered as one very long scroll. Convert it to a tabbed layout so each functional area fits within the fold.
2. **2FA button text colour.** The "Set up Two-Factor Authentication" button on the settings screen renders its label in WP-admin link blue instead of white, despite carrying Tailwind's `text-white` *and* a dedicated override added in Phase 8. Root cause identified below; the fix is two lines of CSS moved, not added.

---

## 1. What we already have (reused, not rebuilt)

| Plumbing | Where | Reused for |
| --- | --- | --- |
| All settings state lifted into `App.jsx` (`useState( initialData.settings )`, single `handleSettingChange`, single REST POST on save) | `src/components/App.jsx:56-127` | Tab switching is pure presentation — unsaved edits survive tab changes for free because no state lives in the panels. |
| Seven self-contained panel components, each already a rounded card with its own heading | `src/components/{SettingsPanel,PageToggles,TransactionDefense,AccountDefender,AlertSettings,Compatibility,TwoFactorNotice}.jsx` | Each panel drops into a tab unchanged; only `App.jsx`'s layout wrapper changes. |
| Existing white-text override for the 2FA button link | `src/styles/index.css:51-58` (`.gswp-admin-isolated a.gswp-2fa-btn` + `:hover/:focus/:active`) | The rule is correct — it is just in the wrong cascade layer (§2.6). Moving it fixes the bug. |
| Scoped admin wrapper class | `#gswp-admin-root.gswp-admin-isolated` (`includes/class-gswp-admin.php:43`) | Keeps the fixed rule scoped to our screen. |
| Tailwind v4 build via `@wordpress/scripts` | `npm run build` → `build/index.css` / `build/index.js` (enqueued in `class-gswp-admin.php:73-88`) | No enqueue or PHP changes needed for either item. |

**No PHP, REST, or option changes anywhere in this phase.** The single `POST /gswp/v1/settings` payload is untouched.

## 2. Design decisions

1. **Hand-rolled tabs, not `@wordpress/components` `TabPanel`.** The screen is styled entirely with scoped Tailwind; pulling in `wp-components` would drag its stylesheet into our isolated wrapper and fight the existing aesthetic. A tablist is ~40 lines of JSX following the WAI-ARIA tabs pattern (`role="tablist"` / `role="tab"` / `role="tabpanel"`, `aria-selected`, `aria-controls`, arrow-key navigation, roving `tabindex`).
2. **Five tabs, grouped by what an operator is doing, not one tab per component:**

   | Tab (id) | Panels | Rationale |
   | --- | --- | --- |
   | **API Credentials** (`credentials`) | `SettingsPanel` | First-run setup; natural default tab. |
   | **Form Protection** (`forms`) | `PageToggles` | The per-form toggles + thresholds (WooCommerce and WP core sections already live in this one component). |
   | **Enterprise Defense** (`defense`) | `TransactionDefense` (WooCommerce only, existing gate), `AccountDefender` | Both are Enterprise-key features with the same "requires Enterprise" notice pattern; together they fit one screen. |
   | **Two-Factor Auth** (`two-factor`) | `TwoFactorNotice` | The longest single panel (400 lines) — the main driver of this change — gets its own tab. |
   | **Alerts & Compatibility** (`advanced`) | `AlertSettings`, `Compatibility` | Operational concerns that are set once and rarely revisited. |

   When WooCommerce is inactive the **Enterprise Defense** tab still renders (Account Defender applies to core login/registration); only the `TransactionDefense` card inside it is conditional — exactly the gate `App.jsx` applies today.
3. **All panels stay mounted; inactive tabpanels get the HTML `hidden` attribute.** Not conditional rendering. Reasons: the single `<form onSubmit={handleSave}>` keeps wrapping *all* fields so Save (and Enter-to-submit) always submits the complete settings object from any tab; no re-triggering of the `animate-fadeIn` reveals on every tab switch; and Tailwind v4's preflight already ships `[hidden] { display: none !important }` so no CSS is needed. Cost is negligible — the full form is what renders today.
4. **Active tab in the URL hash** (`#tab=two-factor`), read on mount, written with `history.replaceState` on change (no scroll jump, no history spam). Gives refresh-persistence and lets docs/support deep-link straight to a tab. Unknown/absent hash → first tab. No new dependency (no router).
5. **Save bar stays global and visible on every tab**, outside the tabpanels but inside the `<form>`, exactly where it is now. One Save button saving everything matches the single REST route and avoids per-tab dirty-state bookkeeping. The toast already renders `fixed`, so save feedback is visible regardless of tab.
6. **The button-colour bug is a cascade-layer problem, and the fix is to un-layer the rule.** Diagnosis: the Phase 8 override (`src/styles/index.css:51-58`) lives inside `@layer base`. Tailwind v4 emits genuine CSS cascade layers (`@layer theme, base, components, utilities`), and *all* our styles — the `text-white` utility and the override alike — are therefore layered. WordPress admin's own stylesheets (`common.css` et al., with `a { color: #2271b1 }`, `a:hover { color: #135e96 }`) are **unlayered**, and per the cascade spec unlayered author styles beat layered ones regardless of specificity. So WP's plain `a` rule wins over both, and the button label renders admin-link blue. (This worked when Phase 8 shipped and regressed with the Tailwind v4 layer migration.) Fix: move the four `a.gswp-2fa-btn` selectors **out of the `@layer base` block** into plain top-level CSS in `src/styles/index.css`. Unlayered vs unlayered, our `.gswp-admin-isolated a.gswp-2fa-btn:hover` (specificity 0-2-1) beats WP's `a:hover` (0-1-1) in every state. No `!important` needed; add `:visited` to the selector list while there for completeness.

## 3. Changes by file

### 3.1 New `src/components/SettingsTabs.jsx`

Small presentational component owning the ARIA tabs pattern:

- Props: `tabs` (array of `{ id, label }`), `active`, `onChange`, `children` keyed by tab id (or render-prop; simplest: App passes panel groups as named children).
- Tablist styling to match the existing card aesthetic: horizontal `border-b border-gray-200` bar under the page header; each tab a button with `border-b-2` — `border-indigo-600 text-indigo-600 font-semibold` when active, `border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300` otherwise; `overflow-x-auto` + `whitespace-nowrap` on the list so five tabs degrade to a horizontal scroll on narrow screens.
- Keyboard handling per WAI-ARIA: `ArrowLeft`/`ArrowRight` (+ `Home`/`End`) move focus and activate; inactive tabs `tabIndex={-1}`.
- Tabs are `type="button"` so they never submit the surrounding form.

### 3.2 `src/components/App.jsx`

- New state `activeTab`, initialised from `window.location.hash` (`#tab=<id>`, validated against the tab list, fallback `'credentials'`); `useEffect` mirrors changes into the hash via `history.replaceState`.
- Replace the current `grid grid-cols-1 … md:grid-cols-2` panel container with `<SettingsTabs>`: five `role="tabpanel"` wrappers (each `id="gswp-tab-<id>"`, `aria-labelledby`, `hidden` unless active), containing the same seven panel instances with unchanged props, including the existing `!! initialData.woocommerceActive` gate around `TransactionDefense`.
- Panels currently all declare `md:col-span-2`; the class becomes inert inside the new wrapper (harmless), but strip it from the seven components' root divs anyway so the markup doesn't lie. Multi-panel tabs (`defense`, `advanced`) stack their cards with `space-y-8`.
- Header (title + `StatusBadge`) and the save bar stay outside the tab region, unchanged.

### 3.3 `src/styles/index.css`

- Move the `.gswp-admin-isolated a.gswp-2fa-btn { … }` block (lines 51-58) out of `@layer base` to the top level of the file (after the `@theme` block), adding `:visited`, with a comment explaining *why* it must stay unlayered (WP admin CSS is unlayered and outranks anything inside `@layer`). Everything else in `@layer base` stays put — the font/colour defaults and range-slider styling are not fighting WP rules that matter, and moving them would broaden the blast radius for no benefit.

### 3.4 Docs & version bump

- `readme.txt`: stable tag + changelog entry ("Settings screen reorganised into tabs; fixed 2FA setup button text colour").
- Main file header + `GSWP_VERSION`, `package.json` + `package-lock.json` root → **2.8.1** (UI-only, no new options — patch bump per the Phase 11 precedent).
- Append Phase 22 section to `STATE.md`.
- `npm run build` to rebuild `build/index.{js,css}` (the version bump busts the enqueue cache).

## 4. Edge cases & failure modes

- **Unsaved edits across tabs:** state lives in `App.jsx`, panels stay mounted — switching tabs cannot drop edits. Verify explicitly (edit on tab 1, switch, save from tab 4, confirm tab-1 value persisted).
- **Enter-to-submit from a text input** submits the whole form from any tab (all fields mounted). Tab buttons must be `type="button"` or Enter/Space on a tab would submit instead of switch.
- **Hash vs WP admin URL:** the settings URL is `options-general.php?page=…`; a fragment coexists fine. Navigating via the admin menu yields no hash → default tab, which is correct.
- **`hidden` reliability:** Tailwind v4 preflight's `[hidden] { display:none !important }` is itself layered — but there is no unlayered WP rule forcing `display` on arbitrary `div`s inside our wrapper, so the attribute holds. Sanity-check on a real wp-admin anyway (part of §6).
- **Admin colour schemes:** WP's alternate admin schemes recolour `a` via their own unlayered stylesheets; the un-layered override (§2.6) outranks them by specificity in every scheme, unlike an `@layer` rule which would lose to all of them.
- **Focus loss on hidden panels:** hiding a panel containing `document.activeElement` drops focus to `<body>`; on tab switch, move focus to the newly active tab button (standard for the ARIA pattern) so keyboard users aren't stranded.
- **Screen readers:** each tabpanel gets `aria-labelledby` its tab; panels keep their existing `<h2>`s so in-panel structure is unchanged.

## 5. Out of scope (noted for the roadmap)

- Per-tab or dirty-state save buttons / "unsaved changes" warning on navigation away from the page (pre-existing behaviour, unchanged by tabs).
- Persisting the last-visited tab in user meta across sessions (hash covers refresh/deep-link; more adds server round-trips for little gain).
- Restyling the grace-notice "Set up now" button rendered by PHP `admin_notices` (`GSWP_Two_Factor::render_grace_notice()`) — it uses core button classes on core admin pages and is unaffected by this bug.
- Auditing the rest of `@layer base` for other WP-admin cascade losses (nothing else is currently reported broken).

## 6. Verification checklist

1. `npm run build` + `wp-scripts lint-js` clean; `npm run lint:css` clean.
2. **Button colour:** on the settings screen, the "Set up Two-Factor Authentication" label computes to `#fff` in default, hover, focus, active, and visited states (DevTools computed-style check), in the default admin scheme and at least one alternate colour scheme. Confirm the winning rule is the unlayered one from `build/index.css`.
3. **Tabs:** five tabs render; each panel appears on exactly one tab; `TransactionDefense` card present only with WooCommerce active, and the Enterprise Defense tab still renders without it.
4. **State survival:** change a value on one tab, switch tabs and back (value intact), save from a different tab, reload → all edited values persisted via the REST round-trip.
5. **Deep link:** `…&page=<slug>#tab=two-factor` opens on the 2FA tab; unknown hash falls back to API Credentials; switching tabs updates the hash without adding history entries.
6. **Keyboard/a11y:** arrow keys cycle tabs, Home/End jump, Enter in a text field saves (doesn't switch tabs), focus lands on the active tab after a switch; quick pass with a screen reader announcing "tab, x of 5, selected".
7. **Within the fold:** each tab's content fits a 1080p viewport without scrolling for typical states (the 2FA tab with everything enabled may still scroll slightly — acceptable; it's one feature's worth, not seven).
8. Toast still appears bottom-right on save success/failure from any tab.
