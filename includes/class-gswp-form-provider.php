<?php
/**
 * Form Provider Contract
 *
 * A provider makes this plugin the reCAPTCHA implementation for a third-party
 * form plugin, so the operator can then retire that plugin's own reCAPTCHA.
 *
 * A provider never switches the host plugin's reCAPTCHA off itself. 2.20.x did,
 * by filtering the host's stored settings at read time, and the host's own
 * settings screen saved the filtered value back and destroyed its keys. There
 * is no version of that idea that is safe: any screen which reads an option to
 * populate its fields will write back whatever it was shown. Providers may read
 * the host's configuration to report on it — see native_captcha_state() — and
 * may add their own markup and validation, but must never filter or write
 * another plugin's settings. GSWP_Foreign_Recaptcha turns what is found into a
 * notice, and the operator decides.
 *
 * Written as an interface with the first implementation rather than after the
 * third: Fluent Forms and FluentCart are already committed, and this codebase
 * already carries three hand-rolled integrations (Xootix, PowerPack, Blocks)
 * whose divergence is a maintenance cost. A second provider that needs changes
 * to this contract is a signal the first one over-fitted.
 *
 * Every method that reaches into the host plugin's API must fail safe. A method
 * that cannot answer returns the pessimistic value — 'unknown' for captcha
 * state, false for eligibility — never a guess. An unverifiable answer must
 * degrade to "we do not cover this form", which loses no protection because the
 * host plugin's own reCAPTCHA is still running until the operator retires it.
 *
 * @package Google_Security_For_WordPress
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

interface GSWP_Form_Provider {

	/**
	 * Stable identifier, used in option names and the REST payload.
	 *
	 * @return string e.g. 'gravity-forms'.
	 */
	public function id();

	/**
	 * Human-readable name for the settings UI.
	 *
	 * @return string e.g. 'Gravity Forms'.
	 */
	public function label();

	/**
	 * Whether the host plugin is installed and active.
	 *
	 * @return bool
	 */
	public function is_active();

	/**
	 * Every form the host plugin knows about.
	 *
	 * @return array<int|string,string> Map of form ID => title.
	 */
	public function forms();

	/**
	 * Whether this plugin can provide equivalent protection for a form.
	 *
	 * False for forms we deliberately do not replace — notably ones using a
	 * visible v2 checkbox challenge, which our score-only implementation has no
	 * equivalent for. Ineligible forms keep the host plugin's reCAPTCHA.
	 *
	 * @param int|string $form_id Form identifier.
	 * @return bool
	 */
	public function form_is_eligible( $form_id );

	/**
	 * Whether a form takes payment.
	 *
	 * Drives the enforcement policy: payment forms fail closed on a missing
	 * token, everything else fails open. Must be derived from the stored form
	 * definition, never from the request — request-derived enforcement is the
	 * bypass class removed in 2.17.0.
	 *
	 * @param int|string $form_id Form identifier.
	 * @return bool
	 */
	public function form_has_payment( $form_id );

	/**
	 * Whether a form warrants fail-closed enforcement.
	 *
	 * Broader than form_has_payment(): a form that creates a WordPress account
	 * is a security surface too, and admitting an unverified submission to it is
	 * how spam registrations get in. Both money and account creation are
	 * outcomes worth refusing rather than admitting unverified; a contact form
	 * entry is not.
	 *
	 * Like form_has_payment(), must derive from the stored form definition and
	 * never from the request.
	 *
	 * @param int|string $form_id Form identifier.
	 * @return bool
	 */
	public function form_is_strict( $form_id );

	/**
	 * State of the host plugin's own captcha for a form.
	 *
	 * @param int|string $form_id Form identifier.
	 * @return string One of 'off', 'v3', 'v2', 'unknown'.
	 */
	public function native_captcha_state( $form_id );

	/**
	 * Register the runtime hooks: field injection and submission validation.
	 *
	 * Called only when the provider is on and the kill switch is not engaged.
	 *
	 * @param GSWP_Verifier $verifier Shared verifier.
	 */
	public function register_hooks( GSWP_Verifier $verifier );

	/**
	 * When a token field was last observed being injected into a form.
	 *
	 * Feeds both the coverage report and the server-side coverage assertion: a
	 * submission with no token on a form we have never successfully injected
	 * into is our bug, not an attack, and must not be punished.
	 *
	 * @param int|string $form_id Form identifier.
	 * @return int Unix timestamp, or 0 when never observed.
	 */
	public function last_injection( $form_id );
}
