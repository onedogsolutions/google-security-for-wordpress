<?php
/**
 * Password Defense Class
 *
 * Implements Google's "Password Check" / Fraud Defense "Password defense"
 * protocol natively in PHP: on a credential event, the site checks the
 * submitted username+password pair against Google's database of breached
 * credentials without ever revealing the credentials to Google. A per-request
 * EC key blinds the credentials hash; Google re-encrypts it with its own key
 * and returns candidate breach-entry prefixes; the site strips its own
 * blinding locally and compares — Google never learns the credentials or the
 * verdict, and the site never learns anything about non-matching entries.
 *
 * See PLAN-password-defense.md for the full protocol write-up and the
 * verification harness used to confirm this implementation's constants and
 * arithmetic against Google's official (Apache-2.0) TypeScript helper — used
 * only as an external test oracle, never as source for this file (§9 of the
 * plan; this project is GPLv2-or-later).
 *
 * @package Google_Security_For_WordPress
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class GSWP_Password_Defense {

	/** Constant salt appended to the canonicalized username before hashing. */
	const USERNAME_SALT_HEX = 'C494A395F8C0E23EA92304787022C7218565499B3E921186C211A01223C454AFA';

	/** Constant salt appended to the raw username before scrypt-hashing the pair. */
	const PASSWORD_SALT_HEX = '30762AD23F7BA19BF8E342FCA1A78D06E66BE4DBB84F8153C503C8DBBDDEA520';

	/** Bits of the username hash sent to Google as the lookup bucket prefix. */
	const PREFIX_BITS = 26;

	/** User meta: cadence bookkeeping for the deferred login check. */
	const META_LAST_CHECK = 'gswp_pd_last_check';

	/** User meta: a login-time leak verdict awaiting a password change. */
	const META_LEAKED = 'gswp_pd_leaked';

	/**
	 * Login credentials stashed for the deferred (shutdown) check.
	 *
	 * @var array{user:WP_User,username:string,password:string}|null
	 */
	private static $pending_login_check = null;

	/**
	 * Constructor. Hooks the credential surfaces when the feature is active.
	 */
	public function __construct() {
		if ( ! self::is_active() ) {
			return;
		}

		if ( '1' === get_option( 'gswp_pd_login', '1' ) ) {
			// Priority 45: after the core password check (20) and the Account
			// Defender capture (40), before 2FA enforcement (100).
			add_filter( 'authenticate', array( $this, 'on_authenticate' ), 45, 3 );
			add_action( 'admin_notices', array( $this, 'maybe_show_leaked_notice' ) );
		}

		// Choice-time surfaces: a leak here can block the change outright.
		add_action( 'validate_password_reset', array( $this, 'check_password_reset' ), 20, 2 );
		add_action( 'after_password_reset', array( $this, 'clear_leak_meta_after_reset' ), 10, 2 );
		add_action( 'user_profile_update_errors', array( $this, 'check_profile_update' ), 20, 3 );
		add_action( 'woocommerce_save_account_details_errors', array( $this, 'check_account_details' ), 20, 2 );
	}

	/* ---------------------------------------------------------------------
	 * Capability / settings
	 * ------------------------------------------------------------------- */

	/**
	 * Whether the server has a bignum backend the EC math needs.
	 *
	 * @return bool
	 */
	public static function supported() {
		return GSWP_EC_Cipher::supported();
	}

	/**
	 * Whether Password Defense is enabled and usable: Enterprise key, master
	 * toggle, and a supported server.
	 *
	 * @return bool
	 */
	public static function is_active() {
		return self::supported()
			&& 'enterprise' === get_option( 'gswp_key_type', 'classic' )
			&& '1' === get_option( 'gswp_password_defense', '0' );
	}

	/**
	 * Whether a newly chosen password should be rejected on a leak.
	 *
	 * @return bool
	 */
	private static function block_choice() {
		return '1' === get_option( 'gswp_pd_block_choice', '1' );
	}

	/**
	 * Whether a leaked login should be refused outright until reset.
	 *
	 * @return bool
	 */
	private static function force_reset() {
		return '1' === get_option( 'gswp_pd_force_reset', '0' );
	}

	/**
	 * Whether verbose (per-check) logging is enabled.
	 *
	 * @return bool
	 */
	private static function verbose() {
		return '1' === get_option( 'gswp_verbose_logging', '0' );
	}

	/* ---------------------------------------------------------------------
	 * Login path: deferred, at most weekly per user, never blocks in-flight
	 * ------------------------------------------------------------------- */

	/**
	 * On a successful password check, decide whether this login is due for a
	 * leak check (deferred to shutdown) and enforce any already-known leak
	 * from a previous login.
	 *
	 * @param null|WP_User|WP_Error $user     Auth result so far.
	 * @param string                $username Submitted login/username.
	 * @param string                $password Submitted password.
	 * @return null|WP_User|WP_Error
	 */
	public function on_authenticate( $user, $username, $password ) {
		if ( ! $user instanceof WP_User || '' === $password ) {
			return $user;
		}

		$leaked = get_user_meta( $user->ID, self::META_LEAKED, true );
		if ( is_array( $leaked ) && isset( $leaked['fp'] ) ) {
			if ( $leaked['fp'] === self::password_fingerprint( $user ) ) {
				if ( self::force_reset() ) {
					return new WP_Error(
						'gswp_password_leaked',
						sprintf(
							/* translators: %s: lost password URL. */
							__( '<strong>Error:</strong> This password appeared in a data breach. <a href="%s">Reset your password</a> to sign in.', 'google-security-for-wordpress' ),
							esc_url( wp_lostpassword_url() )
						)
					);
				}
				// Not force-blocking: an admin notice nags the user; login proceeds.
				return $user;
			}
			// The stored fingerprint no longer matches the current password
			// hash, i.e. it has already been changed — clear the stale flag.
			delete_user_meta( $user->ID, self::META_LEAKED );
		}

		if ( self::due_for_check( $user ) ) {
			self::$pending_login_check = array(
				'user'     => $user,
				'username' => $username,
				'password' => $password,
			);
			add_action( 'shutdown', array( $this, 'run_deferred_login_check' ) );
		}

		return $user;
	}

	/**
	 * Whether this user's last check is missing, stale, or the stored
	 * password's fingerprint has changed since.
	 *
	 * @param WP_User $user
	 * @return bool
	 */
	private static function due_for_check( $user ) {
		$last = get_user_meta( $user->ID, self::META_LAST_CHECK, true );
		if ( ! is_array( $last ) || empty( $last['time'] ) || empty( $last['fp'] ) ) {
			return true;
		}
		if ( $last['fp'] !== self::password_fingerprint( $user ) ) {
			return true;
		}
		$interval = (int) apply_filters( 'gswp_pd_recheck_interval', WEEK_IN_SECONDS );
		return ( time() - (int) $last['time'] ) >= $interval;
	}

	/**
	 * A keyed hash of the already-hashed stored password, used only to
	 * detect that it has changed since the last check — no new secret
	 * material is persisted.
	 *
	 * @param WP_User $user
	 * @return string
	 */
	private static function password_fingerprint( $user ) {
		return wp_hash( $user->user_pass );
	}

	/**
	 * Run the deferred leak check after the response has been sent, so the
	 * scrypt hash and API round trip never delay the login.
	 */
	public function run_deferred_login_check() {
		if ( null === self::$pending_login_check ) {
			return;
		}

		$check                      = self::$pending_login_check;
		self::$pending_login_check = null;

		$user     = $check['user'];
		$username = '' !== $check['username'] ? $check['username'] : $user->user_login;

		$result = self::check_credentials( $username, $check['password'] );

		update_user_meta(
			$user->ID,
			self::META_LAST_CHECK,
			array(
				'time' => time(),
				'fp'   => self::password_fingerprint( $user ),
			)
		);

		if ( true !== $result ) {
			return; // Not leaked, or the check failed (fail-open).
		}

		update_user_meta(
			$user->ID,
			self::META_LEAKED,
			array(
				'time' => time(),
				'fp'   => self::password_fingerprint( $user ),
			)
		);

		self::log( 'Leaked credentials detected for user #' . $user->ID . ' (' . $user->user_login . ') at login.' );

		/**
		 * Fires when Password Defense detects a leaked username+password pair.
		 *
		 * @param WP_User $user    The affected account.
		 * @param string  $context 'login', 'registration', 'password_reset',
		 *                         'profile_update', or 'account_details'.
		 * @param array   $meta    Extra context, e.g. { blocked: bool }.
		 */
		do_action( 'gswp_leaked_credentials', $user, 'login', array( 'blocked' => self::force_reset() ) );
	}

	/**
	 * Persistent nag for a user whose most recent login was flagged, when
	 * force-reset is off. Shown only to the affected user.
	 */
	public function maybe_show_leaked_notice() {
		if ( self::force_reset() ) {
			return;
		}

		$user_id = get_current_user_id();
		if ( ! $user_id ) {
			return;
		}

		$leaked = get_user_meta( $user_id, self::META_LEAKED, true );
		if ( ! is_array( $leaked ) || empty( $leaked['fp'] ) ) {
			return;
		}

		$user = get_userdata( $user_id );
		if ( ! $user || $leaked['fp'] !== self::password_fingerprint( $user ) ) {
			return;
		}

		printf(
			'<div class="notice notice-warning"><p>%s <a href="%s">%s</a></p></div>',
			esc_html__( 'Your password appeared in a known data breach.', 'google-security-for-wordpress' ),
			esc_url( admin_url( 'profile.php#password' ) ),
			esc_html__( 'Change your password now.', 'google-security-for-wordpress' )
		);
	}

	/* ---------------------------------------------------------------------
	 * Choice-time surfaces: checked inline, may block the change
	 * ------------------------------------------------------------------- */

	/**
	 * Password-reset form submission.
	 *
	 * @param WP_Error         $errors Reset errors object, mutated in place.
	 * @param WP_User|WP_Error $user   The user resetting their password.
	 */
	public function check_password_reset( $errors, $user = null ) {
		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- core validates the reset key before this hook.
		if ( ! isset( $_POST['pass1'] ) || '' === $_POST['pass1'] ) {
			return;
		}
		if ( ! $user instanceof WP_User ) {
			return;
		}

		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- see above; sanitized as a password, not output.
		$password = wp_unslash( $_POST['pass1'] );
		$this->maybe_block_choice( $errors, $user->user_login, $password, 'password_reset', $user );
	}

	/**
	 * Clear a stale leak flag once the flagged password has actually changed.
	 *
	 * @param WP_User $user     The user whose password was reset.
	 * @param string  $new_pass Unused.
	 */
	public function clear_leak_meta_after_reset( $user, $new_pass = '' ) {
		if ( $user instanceof WP_User ) {
			delete_user_meta( $user->ID, self::META_LEAKED );
		}
	}

	/**
	 * Own-profile / admin-set password change.
	 *
	 * @param WP_Error $errors Errors object, mutated in place.
	 * @param bool     $update Whether this is an existing-user update.
	 * @param stdClass $user   The user object being saved.
	 */
	public function check_profile_update( $errors, $update, $user ) {
		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- core's own profile-update nonce guards this screen.
		if ( ! isset( $_POST['pass1'] ) || '' === $_POST['pass1'] ) {
			return;
		}
		if ( ! $update || empty( $user->ID ) ) {
			return;
		}

		$login = isset( $user->user_login ) ? $user->user_login : '';
		if ( '' === $login ) {
			$existing = get_userdata( (int) $user->ID );
			$login    = $existing ? $existing->user_login : '';
		}
		if ( '' === $login ) {
			return;
		}

		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- see above; sanitized as a password, not output.
		$password = wp_unslash( $_POST['pass1'] );
		$this->maybe_block_choice( $errors, $login, $password, 'profile_update', (int) $user->ID );

		if ( ! is_wp_error( $errors ) || ! $errors->get_error_codes() ) {
			delete_user_meta( (int) $user->ID, self::META_LEAKED );
		}
	}

	/**
	 * WooCommerce "Account details" password change.
	 *
	 * @param WP_Error $errors  Errors object, mutated in place.
	 * @param WP_User  $user    The account being saved.
	 */
	public function check_account_details( $errors, $user = null ) {
		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- WooCommerce's own account-details nonce guards this form.
		if ( ! isset( $_POST['password_1'] ) || '' === $_POST['password_1'] ) {
			return;
		}
		if ( ! $user instanceof WP_User ) {
			return;
		}

		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- see above; sanitized as a password, not output.
		$password = wp_unslash( $_POST['password_1'] );
		$this->maybe_block_choice( $errors, $user->user_login, $password, 'account_details', $user );

		if ( ! $errors->get_error_codes() ) {
			delete_user_meta( $user->ID, self::META_LEAKED );
		}
	}

	/**
	 * Shared choice-time check: runs synchronously (these POSTs are rare),
	 * adds a blocking error when the password is leaked and blocking is on,
	 * otherwise only logs and fires the action.
	 *
	 * @param WP_Error        $errors   Errors object, mutated in place when blocking.
	 * @param string          $username Username/login for the pair hash.
	 * @param string          $password Submitted new password.
	 * @param string          $context  Event context passed to the action hook.
	 * @param WP_User|int|null $user    Affected user (object, ID, or null).
	 */
	private function maybe_block_choice( $errors, $username, $password, $context, $user ) {
		$result = self::check_credentials( $username, $password );
		if ( true !== $result ) {
			return;
		}

		self::log( 'Leaked credentials detected for "' . $username . '" at ' . $context . '.' );

		$user_object = $user instanceof WP_User ? $user : ( is_numeric( $user ) ? get_userdata( $user ) : null );

		do_action(
			'gswp_leaked_credentials',
			$user_object,
			$context,
			array( 'blocked' => self::block_choice() )
		);

		if ( self::block_choice() && is_wp_error( $errors ) ) {
			$errors->add(
				'gswp_password_leaked',
				__( '<strong>Error:</strong> This password appeared in a data breach. Please choose a different password.', 'google-security-for-wordpress' )
			);
		}
	}

	/* ---------------------------------------------------------------------
	 * Protocol
	 * ------------------------------------------------------------------- */

	/**
	 * Run the full Password Check protocol for a username+password pair.
	 *
	 * @param string $username Submitted username (login field as typed, or
	 *                         the account's user_login as a fallback).
	 * @param string $password Submitted password.
	 * @return bool|null True when leaked, false when not, null on failure
	 *                    (fail-open — never treat null as "not leaked" for
	 *                    blocking decisions beyond simply not blocking).
	 */
	public static function check_credentials( $username, $password ) {
		if ( '' === $username || '' === $password ) {
			return null;
		}

		try {
			$cipher = new GSWP_EC_Cipher();

			$canonical = self::canonicalize_username( $username );
			$prefix    = self::lookup_hash_prefix( $canonical );

			$pair_hash = GSWP_Scrypt::hash(
				$username . $password,
				$username . hex2bin( self::PASSWORD_SALT_HEX ),
				4096,
				8,
				1,
				32
			);

			$key_bytes = GSWP_EC_Cipher::random_scalar_bytes();
			$k         = $cipher->scalar_from_bytes( $key_bytes );
			$point     = $cipher->hash_to_curve( $pair_hash );
			$encrypted = $cipher->compress( $cipher->scalar_mult( $k, $point ) );
		} catch ( Exception $e ) {
			self::log( 'Local crypto failed, skipping check: ' . $e->getMessage() );
			return null;
		}

		$response = self::issue_assessment( $prefix, $encrypted );
		if ( null === $response ) {
			return null;
		}

		$verification = isset( $response['privatePasswordLeakVerification'] ) && is_array( $response['privatePasswordLeakVerification'] )
			? $response['privatePasswordLeakVerification']
			: array();

		if ( empty( $verification['reencryptedUserCredentialsHash'] ) ) {
			return null;
		}

		try {
			$reencrypted = base64_decode( $verification['reencryptedUserCredentialsHash'], true );
			if ( false === $reencrypted || 33 !== strlen( $reencrypted ) ) {
				return null;
			}

			$kinv        = $cipher->invert_scalar( $k );
			$server_hash = $cipher->scalar_mult( $kinv, $cipher->decompress( $reencrypted ) );
			$digest      = hash( 'sha256', $cipher->compress( $server_hash ), true );
		} catch ( Exception $e ) {
			self::log( 'Local verdict computation failed: ' . $e->getMessage() );
			return null;
		}

		$leak_prefixes = isset( $verification['encryptedLeakMatchPrefixes'] ) && is_array( $verification['encryptedLeakMatchPrefixes'] )
			? $verification['encryptedLeakMatchPrefixes']
			: array();

		foreach ( $leak_prefixes as $encoded_prefix ) {
			$leak_prefix = base64_decode( (string) $encoded_prefix, true );
			if ( false === $leak_prefix || '' === $leak_prefix ) {
				continue;
			}
			if ( substr( $digest, 0, strlen( $leak_prefix ) ) === $leak_prefix ) {
				return true;
			}
		}

		return false;
	}

	/**
	 * Canonicalize a username: strip a trailing mail host, lowercase, and
	 * strip the first dot only — matching Google's official helper library
	 * byte-for-byte (its `.replace('.', '')` removes just the first
	 * occurrence, not all dots, despite the docs saying "stripping dots").
	 * Matching this exactly matters: canonicalizing differently changes
	 * which 26-bit bucket is queried, causing silent false negatives rather
	 * than errors.
	 *
	 * @param string $username Raw submitted username.
	 * @return string
	 */
	private static function canonicalize_username( $username ) {
		$at = strrpos( $username, '@' );
		if ( false !== $at ) {
			$username = substr( $username, 0, $at );
		}
		$username = strtolower( $username );

		$dot = strpos( $username, '.' );
		if ( false !== $dot ) {
			$username = substr_replace( $username, '', $dot, 1 );
		}

		return $username;
	}

	/**
	 * The 26-bit (4-byte, last byte masked) lookup hash prefix for a
	 * canonicalized username.
	 *
	 * @param string $canonical Canonicalized username.
	 * @return string 4 raw bytes.
	 */
	private static function lookup_hash_prefix( $canonical ) {
		$hash   = hash( 'sha256', $canonical . hex2bin( self::USERNAME_SALT_HEX ), true );
		$prefix = substr( $hash, 0, 4 );
		// 26 bits = 3 full bytes + the top 2 bits of the 4th byte.
		$prefix[3] = chr( ord( $prefix[3] ) & 0xC0 );
		return $prefix;
	}

	/**
	 * Issue a standalone Enterprise assessment carrying only the
	 * privatePasswordLeakVerification fields (no token/event required).
	 *
	 * @param string $prefix    4 raw lookup-hash-prefix bytes.
	 * @param string $encrypted 33 raw compressed-point bytes.
	 * @return array|null Decoded response body, or null on failure (fail-open).
	 */
	private static function issue_assessment( $prefix, $encrypted ) {
		$project_id = get_option( 'gswp_gcp_project_id', '' );
		$api_key    = get_option( 'gswp_gcp_api_key', '' );

		if ( '' === $project_id || '' === $api_key ) {
			return null;
		}

		$api_url = sprintf(
			'https://recaptchaenterprise.googleapis.com/v1/projects/%s/assessments?key=%s',
			rawurlencode( $project_id ),
			rawurlencode( $api_key )
		);

		$response = wp_remote_post(
			$api_url,
			array(
				'timeout' => 15,
				'headers' => array( 'Content-Type' => 'application/json' ),
				'body'    => wp_json_encode(
					array(
						'privatePasswordLeakVerification' => array(
							'lookupHashPrefix'               => base64_encode( $prefix ),
							'encryptedUserCredentialsHash'   => base64_encode( $encrypted ),
						),
					)
				),
			)
		);

		if ( is_wp_error( $response ) ) {
			self::log( 'Password Defense assessment request failed: ' . $response->get_error_message() );
			return null;
		}

		$status = wp_remote_retrieve_response_code( $response );
		$data   = json_decode( wp_remote_retrieve_body( $response ), true );

		if ( 200 !== $status || ! is_array( $data ) ) {
			$detail = is_array( $data ) && isset( $data['error']['message'] ) ? $data['error']['message'] : 'no detail';
			self::log( 'Password Defense assessment request failed with HTTP ' . $status . ' (' . $detail . '). Verification was skipped.' );
			return null;
		}

		return $data;
	}

	/**
	 * Log a message when verbose logging is on, or always under WP_DEBUG.
	 *
	 * @param string $message
	 */
	private static function log( $message ) {
		if ( ! self::verbose() && ! ( defined( 'WP_DEBUG' ) && WP_DEBUG ) ) {
			return;
		}
		GSWP_Log::info( 'Password defense: ' . $message );
	}
}
