<?php
/**
 * Form Provider Registry
 *
 * Holds the providers, owns the staged-takeover state machine, the coverage
 * audit, and the kill switch.
 *
 * Takeover stages, per provider, stored in "gswp_provider_{id}_mode":
 *
 *  - 'off'    : (default) nothing is hooked. The host plugin's own reCAPTCHA is
 *               the only protection, exactly as before this feature existed.
 *  - 'shadow' : we inject tokens and create assessments, and NEVER block. The
 *               host plugin's reCAPTCHA is still the real protection. Purpose:
 *               prove coverage and calibrate thresholds against live traffic at
 *               zero customer risk.
 *  - 'active' : we block per the enforcement policy. The host plugin's
 *               reCAPTCHA is expected to still be on — a transitional state.
 *  - 'sole'   : the host plugin's reCAPTCHA has been switched off and we are
 *               the only layer. Cannot be selected for a provider whose
 *               coverage audit is not clean.
 *
 * The staging exists because replacement removes a backstop. Until 'sole',
 * a bug in this plugin cannot leave a form unprotected — the host plugin is
 * still scoring. That property is what makes the transfer safe, and it is the
 * reason 'off' is the default and nothing advances automatically.
 *
 * @package Google_Security_For_WordPress
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class GSWP_Form_Provider_Registry {

	/**
	 * Master switch. Setting this option to '0', or defining
	 * GSWP_DISABLE_FORM_PROVIDERS, stops all provider interception immediately
	 * without deactivating the plugin — 2FA, WooCommerce protection, Account
	 * Defender and Password Defense keep running.
	 *
	 * Required infrastructure for a plugin that owns form submission. The
	 * constant exists so recovery is possible from wp-config.php when wp-admin
	 * is unreachable.
	 */
	const ENABLED_OPTION = 'gswp_form_providers_enabled';

	/**
	 * Registered providers, keyed by id.
	 *
	 * @var GSWP_Form_Provider[]
	 */
	private static $providers = array();

	/**
	 * Valid takeover stages, in order of increasing responsibility.
	 *
	 * @var string[]
	 */
	private static $modes = array( 'off', 'shadow', 'active', 'sole' );

	/**
	 * Register the built-in providers and wire their hooks.
	 *
	 * @param GSWP_Verifier $verifier Shared verifier.
	 */
	public static function init( GSWP_Verifier $verifier ) {
		self::register( new GSWP_Provider_Gravity_Forms() );

		if ( ! self::enabled() ) {
			return;
		}

		foreach ( self::$providers as $provider ) {
			if ( ! $provider->is_active() ) {
				continue;
			}
			if ( 'off' === self::mode( $provider->id() ) ) {
				continue;
			}

			$provider->register_hooks( $verifier );
		}
	}

	/**
	 * Add a provider to the registry.
	 *
	 * @param GSWP_Form_Provider $provider Provider instance.
	 */
	public static function register( GSWP_Form_Provider $provider ) {
		self::$providers[ $provider->id() ] = $provider;
	}

	/**
	 * All registered providers.
	 *
	 * @return GSWP_Form_Provider[]
	 */
	public static function all() {
		return self::$providers;
	}

	/**
	 * A provider by id.
	 *
	 * @param string $id Provider id.
	 * @return GSWP_Form_Provider|null
	 */
	public static function get( $id ) {
		return isset( self::$providers[ $id ] ) ? self::$providers[ $id ] : null;
	}

	/**
	 * Whether provider interception is enabled at all.
	 *
	 * @return bool
	 */
	public static function enabled() {
		if ( defined( 'GSWP_DISABLE_FORM_PROVIDERS' ) && GSWP_DISABLE_FORM_PROVIDERS ) {
			return false;
		}

		return '1' === get_option( self::ENABLED_OPTION, '1' );
	}

	/**
	 * Option name holding a provider's takeover stage.
	 *
	 * @param string $id Provider id.
	 * @return string
	 */
	public static function mode_option( $id ) {
		return 'gswp_provider_' . str_replace( '-', '_', $id ) . '_mode';
	}

	/**
	 * A provider's current takeover stage.
	 *
	 * Returns 'off' when the kill switch is engaged, so every caller — runtime
	 * and UI alike — sees one consistent answer.
	 *
	 * @param string $id Provider id.
	 * @return string One of 'off', 'shadow', 'active', 'sole'.
	 */
	public static function mode( $id ) {
		if ( ! self::enabled() ) {
			return 'off';
		}

		$mode = get_option( self::mode_option( $id ), 'off' );

		return in_array( $mode, self::$modes, true ) ? $mode : 'off';
	}

	/**
	 * Whether a stage may be selected for a provider.
	 *
	 * 'sole' is gated on a clean coverage audit: the operator must not be able
	 * to switch off the host plugin's reCAPTCHA while any eligible form is
	 * uncovered. Enforced here rather than in the UI so the REST route and any
	 * future WP-CLI path inherit the same guard.
	 *
	 * @param string $id   Provider id.
	 * @param string $mode Requested stage.
	 * @return true|WP_Error True when allowed, WP_Error explaining why not.
	 */
	public static function can_set_mode( $id, $mode ) {
		if ( ! in_array( $mode, self::$modes, true ) ) {
			return new WP_Error( 'gswp_invalid_mode', __( 'Unknown takeover stage.', 'google-security-for-wordpress' ) );
		}

		$provider = self::get( $id );
		if ( null === $provider ) {
			return new WP_Error( 'gswp_unknown_provider', __( 'Unknown form provider.', 'google-security-for-wordpress' ) );
		}

		if ( 'sole' !== $mode ) {
			return true;
		}

		$audit = self::audit( $id );
		if ( ! empty( $audit['uncovered'] ) ) {
			return new WP_Error(
				'gswp_coverage_incomplete',
				sprintf(
					/* translators: %d: number of forms that would lose protection. */
					_n(
						'%d eligible form is not yet covered. Switching off the form plugin’s own reCAPTCHA now would leave it unprotected.',
						'%d eligible forms are not yet covered. Switching off the form plugin’s own reCAPTCHA now would leave them unprotected.',
						count( $audit['uncovered'] ),
						'google-security-for-wordpress'
					),
					count( $audit['uncovered'] )
				)
			);
		}

		return true;
	}

	/**
	 * Coverage audit for a provider.
	 *
	 * The guard against silent gaps. The host plugin's own reCAPTCHA covers
	 * every one of its forms automatically; we cover only what we hook, so a
	 * render path we miss means a form quietly loses protection once the host's
	 * implementation is retired. This enumerates every form and reports, per
	 * form, whether we would actually protect it.
	 *
	 * @param string $id Provider id.
	 * @return array {
	 *     @type bool   $available  Whether the provider could be inspected at all.
	 *     @type string $mode       Current takeover stage.
	 *     @type array  $forms      Per-form rows.
	 *     @type array  $uncovered  Ids of eligible-but-uncovered forms.
	 *     @type array  $ineligible Ids of forms we deliberately do not replace.
	 * }
	 */
	public static function audit( $id ) {
		$provider = self::get( $id );

		$result = array(
			'available'  => false,
			'mode'       => self::mode( $id ),
			'forms'      => array(),
			'uncovered'  => array(),
			'ineligible' => array(),
		);

		if ( null === $provider || ! $provider->is_active() ) {
			return $result;
		}

		$forms = $provider->forms();
		if ( ! is_array( $forms ) ) {
			return $result;
		}

		$result['available'] = true;

		foreach ( $forms as $form_id => $title ) {
			$eligible = $provider->form_is_eligible( $form_id );
			$payment  = $provider->form_has_payment( $form_id );
			$native   = $provider->native_captcha_state( $form_id );

			// We cover a form when it is eligible and the provider is running.
			$covered = $eligible && 'off' !== $result['mode'];

			$result['forms'][] = array(
				'id'          => $form_id,
				'title'       => (string) $title,
				'eligible'    => $eligible,
				'covered'     => $covered,
				'payment'     => $payment,
				'native'      => $native,
				'enforcement' => $payment ? 'reject' : 'allow',
			);

			if ( ! $eligible ) {
				$result['ineligible'][] = $form_id;
			} elseif ( ! $covered ) {
				$result['uncovered'][] = $form_id;
			}
		}

		return $result;
	}

	/**
	 * Audit every registered, active provider.
	 *
	 * @return array Map of provider id => audit result, plus label and state.
	 */
	public static function audit_all() {
		$out = array(
			'enabled'   => self::enabled(),
			'providers' => array(),
		);

		foreach ( self::$providers as $id => $provider ) {
			if ( ! $provider->is_active() ) {
				continue;
			}

			$audit          = self::audit( $id );
			$audit['id']    = $id;
			$audit['label'] = $provider->label();

			$out['providers'][ $id ] = $audit;
		}

		return $out;
	}
}
