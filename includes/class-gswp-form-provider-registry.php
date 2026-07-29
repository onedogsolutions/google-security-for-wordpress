<?php
/**
 * Form Provider Registry
 *
 * Holds the providers, owns the on/off state, the coverage report, and the
 * kill switch.
 *
 * Since 2.20.0 a provider is simply on or off. The Shadow → Active → Sole
 * ladder shipped in 2.19.0 is gone: it was a mechanism for gradually
 * approaching replacement, defaulted to off, which replaced nothing. When a
 * provider is on, this plugin scores that form plugin's submissions and that
 * plugin's own reCAPTCHA is switched off.
 *
 * What replaces the staging as the safety property is reversibility. Disabling
 * a provider — or throwing the kill switch — restores the form plugin's own
 * implementation on the very next request, because nothing we do writes to its
 * stored configuration. There is no migration to undo and no form to re-edit.
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
	 * Defender and Password Defense keep running, and every form plugin's own
	 * reCAPTCHA comes back on the next request.
	 *
	 * The constant exists so recovery is possible from wp-config.php when
	 * wp-admin is unreachable.
	 */
	const ENABLED_OPTION = 'gswp_form_providers_enabled';

	/**
	 * Option recording that the 2.20.0 upgrade has run.
	 */
	const MIGRATED_OPTION = 'gswp_form_providers_migrated';

	/**
	 * Registered providers, keyed by id.
	 *
	 * @var GSWP_Form_Provider[]
	 */
	private static $providers = array();

	/**
	 * Register the built-in providers and wire their hooks.
	 *
	 * @param GSWP_Verifier $verifier Shared verifier.
	 */
	public static function init( GSWP_Verifier $verifier ) {
		self::register( new GSWP_Provider_Gravity_Forms() );
		self::register( new GSWP_Provider_Fluent_Forms() );

		self::maybe_migrate();

		if ( ! self::enabled() ) {
			return;
		}

		foreach ( self::$providers as $provider ) {
			if ( ! $provider->is_active() || ! self::is_on( $provider->id() ) ) {
				continue;
			}

			// The host plugin's own reCAPTCHA is left alone. Retiring it is the
			// operator's call, prompted by GSWP_Foreign_Recaptcha; this plugin
			// touches nothing outside its own options.
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
	 * Option name holding a provider's on/off state.
	 *
	 * @param string $id Provider id.
	 * @return string
	 */
	public static function option( $id ) {
		return 'gswp_provider_' . str_replace( '-', '_', $id ) . '_enabled';
	}

	/**
	 * Whether a provider is replacing its form plugin's reCAPTCHA.
	 *
	 * Returns false when the kill switch is engaged, so runtime and UI can
	 * never disagree about whether interception is live.
	 *
	 * @param string $id Provider id.
	 * @return bool
	 */
	public static function is_on( $id ) {
		if ( ! self::enabled() ) {
			return false;
		}

		return '1' === get_option( self::option( $id ), '0' );
	}

	/**
	 * Set a provider's on/off state.
	 *
	 * @param string $id Provider id.
	 * @param bool   $on Whether to enable it.
	 */
	public static function set( $id, $on ) {
		update_option( self::option( $id ), $on ? '1' : '0' );
	}

	/**
	 * Enable replacement on upgrade, once.
	 *
	 * 2.20.0 turns replacement on for any site where it can work: Gravity Forms
	 * active and a reCAPTCHA site key configured. This is a deliberate
	 * behaviour change on upgrade — the alternative is another release that
	 * ships a switch and replaces nothing.
	 *
	 * It is defensible because it is reversible: one click restores the form
	 * plugin's own reCAPTCHA, with nothing left behind in its settings. An
	 * admin notice states what changed and links to both the coverage report
	 * and the off switch.
	 */
	private static function maybe_migrate() {
		if ( get_option( self::MIGRATED_OPTION, '0' ) === GSWP_VERSION ) {
			return;
		}

		update_option( self::MIGRATED_OPTION, GSWP_VERSION, false );

		if ( '' === GSWP_Recaptcha_Loader::site_key() ) {
			return;
		}

		$activated = array();

		foreach ( self::$providers as $id => $provider ) {
			if ( ! $provider->is_active() ) {
				continue;
			}

			// Only ever enable a provider the operator has expressed no opinion
			// about. This guard is the whole point of the method since 2.22.0.
			//
			// MIGRATED_OPTION holds the version that last ran this, so it fires
			// again on EVERY upgrade — and the old skip condition was "already
			// on", which meant an explicit '0' was treated as merely not-yet-on
			// and switched back to '1'. An operator who turned form protection
			// off, for any reason including a defect we told them to work around,
			// silently had it turned back on by the next update. A stored '0' is
			// a decision, and an upgrade is not a licence to overrule it.
			//
			// get_option() with a null default returns null only when the row
			// does not exist, which is exactly "never chosen".
			if ( null !== get_option( self::option( $id ), null ) ) {
				continue;
			}

			// A provider in its first release is not switched on for anybody.
			//
			// This method is what delivered the 2.22.0 action-pairing defect to
			// sites that never opted into form replacement, and it did so for a
			// provider whose host-plugin bindings had already been wrong four
			// times. A new provider's bindings are necessarily less verified
			// than that, and the failure mode of getting one wrong is every
			// payment and account form on the site failing closed. Saving the
			// operator one click is not worth it.
			if ( ! self::migrates_by_default( $id ) ) {
				continue;
			}

			self::set( $id, true );
			$activated[] = $provider->label();
		}

		if ( ! empty( $activated ) ) {
			update_option( 'gswp_form_providers_activated_notice', $activated, false );
		}
	}

	/**
	 * Whether a provider may be switched on automatically at upgrade.
	 *
	 * A list rather than a hard-coded id test so the answer is a property of
	 * the provider's maturity, not of its name, and so flipping one is a
	 * one-line change in the release that has field reports to justify it.
	 *
	 * Removing an id from this list is a deliberate act with a deliberate
	 * trigger: clean coverage reports from real installs. It is not something
	 * to do because the code looks finished.
	 *
	 * @param string $id Provider id.
	 * @return bool
	 */
	public static function migrates_by_default( $id ) {
		$holdback = array(
			// 2.23.0. Its bindings were written from vendor documentation that
			// could not be opened directly, and the manual discovery suite
			// (tests/manual chunks 20-26) has not been run against a live
			// install. Flip this once it has.
			'fluent-forms',
		);

		/**
		 * Filter whether a provider is auto-enabled on upgrade.
		 *
		 * @param bool   $allowed Whether the provider may be auto-enabled.
		 * @param string $id      Provider id.
		 */
		return (bool) apply_filters( 'gswp_provider_migrates_by_default', ! in_array( $id, $holdback, true ), $id );
	}

	/**
	 * Coverage report for a provider.
	 *
	 * Reporting, not a gate. In 2.19.0 this blocked the final takeover stage;
	 * with the staging gone it exists to tell the operator what is actually
	 * happening — including, per form, whether a token field was observed being
	 * injected on a real front-end render (see GSWP_Provider_Gravity_Forms).
	 *
	 * @param string $id Provider id.
	 * @return array
	 */
	public static function audit( $id ) {
		$provider = self::get( $id );

		$result = array(
			'available'  => false,
			'on'         => self::is_on( $id ),
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
			$strict   = $provider->form_is_strict( $form_id );

			$row = array(
				'id'          => $form_id,
				'title'       => (string) $title,
				'eligible'    => $eligible,
				'covered'     => $eligible && $result['on'],
				'payment'     => $payment,
				// Derived, and lossy: a payment form could never also report that
				// it creates an account. Kept for providers that offer nothing
				// better; where form_policy() exists, 'account_feed' below is
				// authoritative and independent of whether the form takes money.
				'account'     => $strict && ! $payment,
				'native'      => $provider->native_captcha_state( $form_id ),
				'enforcement' => $strict ? 'reject' : 'allow',
				'injected'    => $provider->last_injection( $form_id ),
			);

			// Optional reporting, not part of the provider contract: the action
			// and threshold a form actually resolves to, and why it last
			// rejected someone. A provider that does not offer these simply
			// reports less. Guarded rather than added to the interface so a
			// second provider is not forced to implement diagnostics it has no
			// equivalent for.
			if ( method_exists( $provider, 'form_policy' ) ) {
				$policy               = $provider->form_policy( $form_id );
				$row['action']        = isset( $policy['action'] ) ? $policy['action'] : '';
				$row['context']       = isset( $policy['context'] ) ? $policy['context'] : '';
				$row['account_feed']  = isset( $policy['account'] ) ? $policy['account'] : '';
				$row['password']      = ! empty( $policy['password'] );
			}

			if ( method_exists( $provider, 'last_rejection' ) ) {
				$row['last_rejection'] = $provider->last_rejection( $form_id );
			}

			// An internal form is ineligible for a different reason than a v2
			// challenge is, and the distinction matters: one is a deliberate
			// exclusion, the other is a form we decline to cover. Reporting both
			// as "not eligible" would leave the operator chasing the wrong thing.
			if ( method_exists( $provider, 'form_is_internal' ) ) {
				$row['internal'] = $provider->form_is_internal( $form_id );
			}

			$result['forms'][] = $row;

			if ( ! $eligible ) {
				$result['ineligible'][] = $form_id;
			} elseif ( ! $result['on'] ) {
				$result['uncovered'][] = $form_id;
			}
		}

		return $result;
	}

	/**
	 * Coverage report for every registered, active provider.
	 *
	 * @return array
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
