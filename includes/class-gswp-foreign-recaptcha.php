<?php
/**
 * Foreign reCAPTCHA Discovery and Notice
 *
 * Finds reCAPTCHA site keys configured in OTHER plugins and tells the operator
 * to retire them, rather than reaching in and switching them off.
 *
 * This replaces the settings-takeover mechanism removed in 2.21.0. That
 * mechanism filtered a host plugin's stored settings so its reCAPTCHA would
 * stand down, on the stated grounds that a read filter is safe because it is
 * reversible and writes nothing. It is not. A settings screen reads its option
 * to populate its fields and saves back what it read, so the filtered value
 * round-trips to disk the first time anyone opens that screen — which is
 * exactly what happened to Gravity Forms' reCAPTCHA add-on in 2.20.4, emptying
 * its stored keys. The mechanism also had to guess each host plugin's option
 * names, key names and class names; on one plugin, across one version, those
 * guesses were wrong three times.
 *
 * So detection stays and enforcement goes. What is lost is only automation: on
 * a site whose operator ignores the notice, two reCAPTCHAs run. That costs a
 * duplicate assessment per submission and leaves the other plugin's threshold
 * as a second, invisible policy — a real cost, but a bounded one, and the
 * notice names it. Nothing breaks, because the loader owner already
 * deduplicates a shared script and keeps both families when they differ.
 *
 * The scan itself does not guess. It reads every option whose name suggests
 * captcha configuration and looks for values shaped like a Google site key,
 * reporting whatever it finds under the option name it found it in. Known
 * option names get a friendly plugin label; unknown ones are reported verbatim
 * rather than being quietly skipped.
 *
 * @package Google_Security_For_WordPress
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class GSWP_Foreign_Recaptcha {

	/**
	 * Cached scan result.
	 */
	const SCAN_TRANSIENT = 'gswp_foreign_recaptcha_scan';

	/**
	 * How long a scan is cached. The options table does not change often, and
	 * an admin page load should not pay for a LIKE scan every time.
	 */
	const SCAN_TTL = 12 * HOUR_IN_SECONDS;

	/**
	 * User meta storing the findings hash a user has dismissed.
	 */
	const DISMISS_META = 'gswp_foreign_recaptcha_dismissed';

	/**
	 * Query arg used to dismiss the notice.
	 */
	const DISMISS_ARG = 'gswp_dismiss_foreign_recaptcha';

	/**
	 * Constructor.
	 */
	public function __construct() {
		add_action( 'admin_notices', array( $this, 'render_notice' ) );
		add_action( 'admin_init', array( $this, 'handle_dismiss' ) );

		// A key change makes any cached comparison stale.
		add_action( 'update_option_gswp_site_key', array( __CLASS__, 'flush' ) );
		add_action( 'update_option_gswp_key_type', array( __CLASS__, 'flush' ) );
		add_action( 'activated_plugin', array( __CLASS__, 'flush' ) );
		add_action( 'deactivated_plugin', array( __CLASS__, 'flush' ) );
	}

	/**
	 * Discard the cached scan.
	 */
	public static function flush() {
		delete_transient( self::SCAN_TRANSIENT );
	}

	/**
	 * Friendly labels for option names we have verified against a live install.
	 *
	 * Anything not listed is reported under its raw option name. Reporting an
	 * unrecognised finding honestly is the point — the alternative is the
	 * silent skip that made the old detection report "unknown" for a plugin
	 * that was configured the whole time.
	 *
	 * @return array<string,string> Option name prefix => plugin label.
	 */
	private static function labels() {
		return (array) apply_filters(
			'gswp_foreign_recaptcha_labels',
			array(
				'gravityformsaddon_gravityformsrecaptcha_settings' => 'Gravity Forms reCAPTCHA Add-On',
				'gravityformsaddon_recaptcha_settings' => 'Gravity Forms reCAPTCHA Add-On',
				'bb_powerpack_'                        => 'PowerPack for Beaver Builder',
				'fluentform_'                          => 'Fluent Forms',
				'_fluentform_'                         => 'Fluent Forms',
				'wpforms_'                             => 'WPForms',
				'frm_'                                 => 'Formidable Forms',
				'wpcf7'                                => 'Contact Form 7',
				'elementor_'                           => 'Elementor',
			)
		);
	}

	/**
	 * Label for an option name.
	 *
	 * @param string $option Option name.
	 * @return string
	 */
	private static function label_for( $option ) {
		foreach ( self::labels() as $needle => $label ) {
			if ( 0 === strpos( $option, $needle ) ) {
				return $label;
			}
		}

		return $option;
	}

	/**
	 * Whether the plugin owning an option is known to be switched off.
	 *
	 * Deactivating a WordPress plugin does not delete its options, so a stored
	 * site key proves only that a plugin was configured once — never that it is
	 * running now. Reporting one of those as a live conflict sends the operator
	 * to switch off something already off.
	 *
	 * This can only be answered where the owning plugin exposes its own state,
	 * so it is deliberately narrow rather than a guess: Gravity Forms publishes
	 * its registered add-ons, and nothing else here does. Everything else is
	 * still reported, and the notice says plainly that findings come from stored
	 * settings.
	 *
	 * @param string $option Option name.
	 * @return bool True only when the owner is known to be inactive.
	 */
	private static function owner_is_inactive( $option ) {
		if ( 0 !== strpos( $option, 'gravityformsaddon' ) ) {
			return false;
		}

		if ( ! class_exists( 'GFAddOn' ) || ! method_exists( 'GFAddOn', 'get_registered_addons' ) ) {
			return false;
		}

		foreach ( (array) GFAddOn::get_registered_addons() as $class ) {
			if ( false !== stripos( (string) $class, 'recaptcha' ) ) {
				return false;
			}
		}

		return true;
	}

	/**
	 * Whether a scalar looks like a Google reCAPTCHA site key.
	 *
	 * Classic and Enterprise site keys share the same shape, so this cannot
	 * distinguish them — and does not need to. A key configured elsewhere is
	 * worth reporting either way.
	 *
	 * @param mixed $value Candidate value.
	 * @return bool
	 */
	private static function looks_like_site_key( $value ) {
		return is_string( $value ) && (bool) preg_match( '/^6L[A-Za-z0-9_-]{20,}$/', $value );
	}

	/**
	 * Every reCAPTCHA site key configured by a plugin other than this one.
	 *
	 * @param bool $force Skip the cache.
	 * @return array<int,array> Records: plugin, option, setting, key, matches_ours.
	 */
	public static function discover( $force = false ) {
		if ( ! $force ) {
			$cached = get_transient( self::SCAN_TRANSIENT );
			if ( is_array( $cached ) ) {
				return $cached;
			}
		}

		global $wpdb;

		$ours = class_exists( 'GSWP_Recaptcha_Loader' ) ? GSWP_Recaptcha_Loader::site_key() : '';

		// Same query shape as the discovery chunk that found the Gravity Forms
		// option, which is why it is used verbatim rather than narrowed.
		$rows = $wpdb->get_results(
			"SELECT option_name, option_value FROM {$wpdb->options}
			  WHERE option_name LIKE '%recaptcha%'
			     OR option_name LIKE '%captcha%'
			     OR option_name LIKE 'gravityformsaddon%'",
			ARRAY_A
		); // phpcs:ignore WordPress.DB.DirectDatabaseQuery

		$found = array();

		foreach ( (array) $rows as $row ) {
			$option = $row['option_name'];

			// Never report ourselves.
			if ( 0 === strpos( $option, 'gswp_' ) ) {
				continue;
			}

			if ( self::owner_is_inactive( $option ) ) {
				continue;
			}

			$value = maybe_unserialize( $row['option_value'] );

			if ( self::looks_like_site_key( $value ) ) {
				$found[] = array(
					'plugin'  => self::label_for( $option ),
					'option'  => $option,
					'setting' => '',
					'key'     => $value,
				);
				continue;
			}

			if ( ! is_array( $value ) ) {
				continue;
			}

			foreach ( $value as $setting => $inner ) {
				if ( ! self::looks_like_site_key( $inner ) ) {
					continue;
				}

				// A secret key never reaches a browser, so reporting one would
				// be noise; only site keys indicate a live front-end loader.
				if ( false !== stripos( (string) $setting, 'secret' ) || false !== stripos( (string) $setting, 'private' ) ) {
					continue;
				}

				$found[] = array(
					'plugin'  => self::label_for( $option ),
					'option'  => $option,
					'setting' => (string) $setting,
					'key'     => $inner,
				);
			}
		}

		// Collapse duplicates: one plugin storing the same key under several
		// setting names is one finding, not three.
		$unique = array();
		foreach ( $found as $record ) {
			$slot = $record['plugin'] . '|' . $record['key'];
			if ( isset( $unique[ $slot ] ) ) {
				continue;
			}
			$record['matches_ours'] = ( '' !== $ours && $record['key'] === $ours );
			$unique[ $slot ]        = $record;
		}

		$records = array_values( $unique );

		set_transient( self::SCAN_TRANSIENT, $records, self::SCAN_TTL );

		return $records;
	}

	/**
	 * Stable hash of the current findings, used to key dismissals.
	 *
	 * A dismissal applies to what was dismissed. A newly configured plugin, or
	 * a key that changes to one that no longer matches ours, re-arms the notice
	 * rather than staying hidden behind an old dismissal.
	 *
	 * @param array $records Findings.
	 * @return string
	 */
	public static function hash( array $records ) {
		$parts = array();
		foreach ( $records as $record ) {
			$parts[] = $record['plugin'] . '|' . $record['key'] . '|' . ( empty( $record['matches_ours'] ) ? '0' : '1' );
		}
		sort( $parts );

		return md5( implode( ',', $parts ) );
	}

	/**
	 * Persist a dismissal.
	 */
	public function handle_dismiss() {
		if ( ! isset( $_GET[ self::DISMISS_ARG ] ) ) {
			return;
		}
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}

		$nonce = isset( $_GET['_wpnonce'] ) ? sanitize_text_field( wp_unslash( $_GET['_wpnonce'] ) ) : '';
		if ( ! wp_verify_nonce( $nonce, self::DISMISS_ARG ) ) {
			return;
		}

		update_user_meta( get_current_user_id(), self::DISMISS_META, self::hash( self::discover() ) );
	}

	/**
	 * Render the notice.
	 */
	public function render_notice() {
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}

		// Nothing to say until this plugin is itself configured — telling an
		// operator to consolidate on us before we work would be wrong.
		if ( ! class_exists( 'GSWP_Recaptcha_Loader' ) || '' === GSWP_Recaptcha_Loader::site_key() ) {
			return;
		}

		$records = self::discover();
		if ( empty( $records ) ) {
			return;
		}

		$dismissed = get_user_meta( get_current_user_id(), self::DISMISS_META, true );
		if ( is_string( $dismissed ) && $dismissed === self::hash( $records ) ) {
			return;
		}

		$divergent = false;
		foreach ( $records as $record ) {
			if ( empty( $record['matches_ours'] ) ) {
				$divergent = true;
			}
		}

		echo '<div class="notice ' . ( $divergent ? 'notice-warning' : 'notice-info' ) . '">';

		echo '<p><strong>' . esc_html(
			$divergent
				? __( 'Google Security: another plugin is configured with a different reCAPTCHA site key', 'google-security-for-wordpress' )
				: __( 'Google Security: reCAPTCHA is also configured in another plugin', 'google-security-for-wordpress' )
		) . '</strong></p>';

		echo '<ul style="list-style:disc;margin-left:20px;">';
		foreach ( $records as $record ) {
			printf(
				'<li><strong>%s</strong> — %s <code>%s</code>%s</li>',
				esc_html( $record['plugin'] ),
				esc_html__( 'site key', 'google-security-for-wordpress' ),
				esc_html( $record['key'] ),
				empty( $record['matches_ours'] )
					? ' <em>' . esc_html__( '(different from this plugin’s key)', 'google-security-for-wordpress' ) . '</em>'
					: ''
			);
		}
		echo '</ul>';

		if ( $divergent ) {
			echo '<p>' . esc_html__( 'Only one site key can be pre-rendered per page, so where two keys appear on the same page one of them will fail to execute. This is what breaks payment forms: the field never receives a token and the submission is rejected.', 'google-security-for-wordpress' ) . '</p>';
		} else {
			echo '<p>' . esc_html__( 'The keys match, so both implementations share one script and coexist safely. The cost is that every submission is assessed twice, and the other plugin applies its own score threshold — so it can reject a submission for reasons that will not appear in this plugin’s logs.', 'google-security-for-wordpress' ) . '</p>';
		}

		echo '<p>' . esc_html__( 'Recommended: turn reCAPTCHA off in the plugin listed above and configure it only here. This plugin deliberately does not switch it off for you — writing to another plugin’s settings is how its stored keys get destroyed.', 'google-security-for-wordpress' ) . '</p>';

		echo '<p><em>' . esc_html__( 'These are stored settings. A plugin that has been deactivated keeps its settings, so if one listed above is switched off it is not loading anything and can be ignored.', 'google-security-for-wordpress' ) . '</em></p>';

		$dismiss = wp_nonce_url( add_query_arg( self::DISMISS_ARG, '1' ), self::DISMISS_ARG );

		echo '<p><a class="button button-primary" href="' . esc_url( admin_url( 'options-general.php?page=gswp-admin' ) ) . '">'
			. esc_html__( 'Open Google Security settings', 'google-security-for-wordpress' )
			. '</a> <a class="button" href="' . esc_url( $dismiss ) . '">'
			. esc_html__( 'Dismiss', 'google-security-for-wordpress' )
			. '</a></p></div>';
	}
}
