<?php
/**
 * Two-Factor Authentication
 *
 * Adds TOTP (Google Authenticator) two-factor authentication to WordPress
 * logins. Users enrol from their profile screen by scanning a QR code (or
 * entering the setup key manually) and confirming a code. Once enrolled, a
 * second-factor challenge is interposed after the password check on every
 * interactive login. Backup codes provide recovery when the authenticator app
 * is unavailable.
 *
 * The challenge flow mirrors the approach used by the WordPress "Two-Factor"
 * feature plugin: on a successful primary login (`wp_login`) the freshly issued
 * auth cookie is cleared and an interstitial is shown; the cookie is only
 * (re)issued once the second factor is verified.
 *
 * @package Google_Security_For_WordPress
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class GSWP_Two_Factor {

	const META_ENABLED     = 'gswp_2fa_enabled';
	const META_SECRET      = 'gswp_2fa_secret';
	const META_PENDING     = 'gswp_2fa_pending_secret';
	const META_BACKUP      = 'gswp_2fa_backup_codes';
	const META_LAST_TS     = 'gswp_2fa_last_timestep';
	const META_LOGIN_NONCE = 'gswp_2fa_login_nonce';

	/** Cookie carrying the single-use token for an in-progress challenge. */
	const COOKIE_PENDING = 'gswp_2fa_pending';

	/** Transient key prefix storing the pending login behind that token. */
	const PENDING_PREFIX = 'gswp_2fa_pending_';

	/** How long an unfinished challenge stays valid. */
	const PENDING_TTL = 300; // 5 * MINUTE_IN_SECONDS.

	/**
	 * Constructor. Registers hooks only when the feature is enabled.
	 */
	public function __construct() {
		if ( ! self::is_feature_enabled() ) {
			return;
		}

		// Login challenge.
		add_action( 'wp_login', array( $this, 'maybe_start_challenge' ), 10, 2 );
		add_action( 'login_form_gswp_2fa', array( $this, 'handle_challenge' ) );
		// Resume an interrupted challenge. A login that began over AJAX (e.g.
		// the PowerPack login module) or that redirected elsewhere can't be
		// sent to the interstitial from inside wp_signon(); these guards catch
		// the half-finished login on the next page load and force the prompt.
		add_action( 'login_init', array( $this, 'maybe_resume_challenge' ) );
		add_action( 'template_redirect', array( $this, 'maybe_resume_challenge' ) );
		// Close the XML-RPC bypass: programmatic logins cannot satisfy an
		// interactive challenge, so block them for enrolled users.
		add_filter( 'authenticate', array( $this, 'block_non_interactive' ), 99, 3 );

		// Profile enrolment UI.
		add_action( 'show_user_profile', array( $this, 'render_profile_section' ) );
		add_action( 'edit_user_profile', array( $this, 'render_profile_section' ) );
		add_action( 'personal_options_update', array( $this, 'save_profile' ) );
		add_action( 'edit_user_profile_update', array( $this, 'save_profile' ) );
		add_action( 'admin_enqueue_scripts', array( $this, 'enqueue_profile_assets' ) );

		// Role-based enforcement.
		add_action( 'admin_init', array( $this, 'maybe_enforce_setup' ) );
	}

	/**
	 * Whether a user's role requires two-factor authentication.
	 *
	 * @param int $user_id User ID.
	 * @return bool
	 */
	public static function role_is_enforced( $user_id ) {
		$enforced = get_option( 'gswp_2fa_enforced_roles', array() );
		if ( empty( $enforced ) || ! is_array( $enforced ) ) {
			return false;
		}

		$user = get_userdata( $user_id );
		if ( ! $user ) {
			return false;
		}

		return (bool) array_intersect( (array) $user->roles, $enforced );
	}

	/**
	 * Force users in an enforced role to set up 2FA before using the admin.
	 *
	 * Only the profile screen (where enrolment happens) remains reachable until
	 * the user has enrolled. Default settings enforce no roles, so this is inert
	 * unless an administrator opts a role in.
	 */
	public function maybe_enforce_setup() {
		if ( wp_doing_ajax() || ( defined( 'DOING_CRON' ) && DOING_CRON ) ) {
			return;
		}

		$user_id = get_current_user_id();
		if ( ! $user_id || self::user_has_2fa( $user_id ) || ! self::role_is_enforced( $user_id ) ) {
			return;
		}

		// Let the enrolment screen itself load.
		global $pagenow;
		if ( in_array( $pagenow, array( 'profile.php' ), true ) ) {
			return;
		}

		wp_safe_redirect( add_query_arg( 'gswp_2fa_required', '1', admin_url( 'profile.php' ) ) . '#gswp-2fa' );
		exit;
	}

	/**
	 * Whether the two-factor feature is enabled site-wide.
	 *
	 * @return bool
	 */
	public static function is_feature_enabled() {
		return '1' === get_option( 'gswp_2fa_enabled', '1' );
	}

	/**
	 * Whether a user has an active second factor.
	 *
	 * @param int $user_id User ID.
	 * @return bool
	 */
	public static function user_has_2fa( $user_id ) {
		if ( ! self::is_feature_enabled() ) {
			return false;
		}

		return '1' === get_user_meta( $user_id, self::META_ENABLED, true )
			&& '' !== (string) get_user_meta( $user_id, self::META_SECRET, true );
	}

	/* ---------------------------------------------------------------------
	 * Login challenge
	 * ------------------------------------------------------------------- */

	/**
	 * After a successful password login, interpose the second-factor challenge.
	 *
	 * The interstitial itself is rendered on wp-login.php (where login_header()
	 * exists), so here we only discard the freshly issued auth cookie, stash the
	 * in-progress login behind a single-use cookie token, and send the browser
	 * to the prompt. Doing the redirect — rather than echoing the form inline —
	 * is what lets this work from every login entry point: wp-login.php, the
	 * WooCommerce "My Account" form (a front-end POST where login_header() is
	 * undefined and would fatal), and AJAX forms such as the PowerPack login
	 * module (where echoing a form is impossible).
	 *
	 * @param string  $user_login Username.
	 * @param WP_User $user       Authenticated user.
	 */
	public function maybe_start_challenge( $user_login, $user ) {
		if ( ! ( $user instanceof WP_User ) || ! self::user_has_2fa( $user->ID ) ) {
			return;
		}

		// Programmatic logins (cron, REST, XML-RPC) can never satisfy an
		// interactive challenge. XML-RPC is already blocked in authenticate;
		// for the rest, leave the login untouched so it fails closed elsewhere
		// rather than stranding a half-finished challenge.
		if ( wp_doing_cron()
			|| ( defined( 'REST_REQUEST' ) && REST_REQUEST )
			|| ( defined( 'XMLRPC_REQUEST' ) && XMLRPC_REQUEST ) ) {
			return;
		}

		// wp-login.php uses `redirect_to`; the WooCommerce My Account form uses
		// `redirect`. Honour either so the post-2FA landing page is correct.
		if ( isset( $_REQUEST['redirect_to'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended
			$redirect_to = wp_unslash( $_REQUEST['redirect_to'] ); // phpcs:ignore WordPress.Security.NonceVerification.Recommended
		} elseif ( isset( $_REQUEST['redirect'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended
			$redirect_to = wp_unslash( $_REQUEST['redirect'] ); // phpcs:ignore WordPress.Security.NonceVerification.Recommended
		} else {
			$redirect_to = admin_url();
		}
		$rememberme = ! empty( $_REQUEST['rememberme'] ); // phpcs:ignore WordPress.Security.NonceVerification.Recommended

		// Discard the auth cookie WordPress just set; it is re-issued only once
		// the second factor is verified. This is the line that prevents a 2FA
		// bypass when the login was initiated over AJAX or a front-end form
		// instead of wp-login.php.
		wp_clear_auth_cookie();

		// Stash the in-progress login so the interstitial can resume it.
		$this->store_pending_login( $user->ID, $redirect_to, $rememberme );

		// AJAX logins control their own response and cannot be redirected from
		// here; the auth cookie is cleared and the pending cookie set, so
		// maybe_resume_challenge() forces the prompt on the next page load.
		if ( wp_doing_ajax() ) {
			return;
		}

		wp_safe_redirect( $this->challenge_url() );
		exit;
	}

	/**
	 * Render the prompt, or verify a submitted code (login_form_gswp_2fa).
	 *
	 * Runs only on wp-login.php, so login_header()/login_footer() are available.
	 */
	public function handle_challenge() {
		$pending = $this->get_pending_login();
		$user    = $pending ? get_user_by( 'id', $pending['user_id'] ) : false;

		// No valid pending challenge (expired, consumed, or forged): start over.
		if ( ! $user || ! self::user_has_2fa( $user->ID ) ) {
			$this->clear_pending_login();
			wp_safe_redirect( wp_login_url() );
			exit;
		}

		// A GET (or any request without a submitted code) shows the prompt.
		if ( ! isset( $_POST['gswp_2fa_code'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Missing
			$this->show_challenge( $user );
			exit;
		}

		$code = sanitize_text_field( wp_unslash( $_POST['gswp_2fa_code'] ) ); // phpcs:ignore WordPress.Security.NonceVerification.Missing
		if ( ! $this->verify_user_code( $user->ID, $code ) ) {
			$this->show_challenge( $user, __( 'Invalid verification code. Please try again.', 'google-security-for-wordpress' ) );
			exit;
		}

		// Second factor verified: consume the pending login and complete it.
		$redirect_to = wp_validate_redirect( $pending['redirect_to'], admin_url() );
		$rememberme  = ! empty( $pending['rememberme'] );
		$this->clear_pending_login();
		wp_set_auth_cookie( $user->ID, $rememberme );

		wp_safe_redirect( $redirect_to );
		exit;
	}

	/**
	 * Force the prompt for a login that began but never reached wp-login.php.
	 *
	 * Hooked to both login_init and template_redirect: when a user is not
	 * logged in yet carries a valid pending-challenge cookie, redirect them to
	 * the interstitial. This is what closes the AJAX bypass — after a PowerPack
	 * (or similar) AJAX login the auth cookie is already cleared, so the user
	 * lands here logged-out with the pending cookie and is sent to the prompt.
	 */
	public function maybe_resume_challenge() {
		if ( is_user_logged_in() ) {
			return;
		}

		// On wp-login.php only the plain sign-in screen should resume the
		// challenge; leave the challenge action itself, logout, lost password,
		// registration, etc. untouched.
		if ( did_action( 'login_init' ) ) {
			$action = isset( $_GET['action'] ) ? sanitize_key( wp_unslash( $_GET['action'] ) ) : 'login'; // phpcs:ignore WordPress.Security.NonceVerification.Recommended
			if ( 'login' !== $action ) {
				return;
			}
		}

		if ( empty( $_COOKIE[ self::COOKIE_PENDING ] ) || ! $this->get_pending_login() ) {
			return;
		}

		wp_safe_redirect( $this->challenge_url() );
		exit;
	}

	/**
	 * Block programmatic (XML-RPC) logins for enrolled users.
	 *
	 * @param null|WP_User|WP_Error $user     Auth result so far.
	 * @param string                $username Username.
	 * @param string                $password Password.
	 * @return null|WP_User|WP_Error
	 */
	public function block_non_interactive( $user, $username, $password ) {
		if ( ! ( $user instanceof WP_User ) ) {
			return $user;
		}

		if ( defined( 'XMLRPC_REQUEST' ) && XMLRPC_REQUEST && self::user_has_2fa( $user->ID ) ) {
			return new WP_Error(
				'gswp_2fa_required',
				__( 'Two-factor authentication is required for this account. XML-RPC login is disabled.', 'google-security-for-wordpress' )
			);
		}

		return $user;
	}

	/**
	 * Render the interstitial challenge screen and exit.
	 *
	 * The pending login (user, redirect target, "remember me") is carried by the
	 * single-use cookie token, so the form needs no identifying hidden fields.
	 *
	 * @param WP_User $user  User being challenged (for context only).
	 * @param string  $error Optional error message to display.
	 */
	private function show_challenge( $user, $error = '' ) {
		// login_header()/login_footer() are defined by wp-login.php, which is the
		// only context this method runs in.
		login_header( __( 'Two-Factor Authentication', 'google-security-for-wordpress' ) );

		if ( $error ) {
			echo '<div id="login_error">' . wp_kses_post( $error ) . '</div>';
		}
		?>
		<form name="gswp_2fa_form" id="loginform" action="<?php echo esc_url( site_url( 'wp-login.php?action=gswp_2fa', 'login_post' ) ); ?>" method="post">
			<p><?php esc_html_e( 'Enter the 6-digit code from your authenticator app. You can also enter a backup code.', 'google-security-for-wordpress' ); ?></p>
			<p>
				<label for="gswp_2fa_code"><?php esc_html_e( 'Authentication code', 'google-security-for-wordpress' ); ?></label>
				<input type="text" name="gswp_2fa_code" id="gswp_2fa_code" class="input" inputmode="numeric" autocomplete="one-time-code" autofocus="autofocus" />
			</p>
			<p class="submit">
				<input type="submit" name="wp-submit" id="wp-submit" class="button button-primary button-large" value="<?php esc_attr_e( 'Verify', 'google-security-for-wordpress' ); ?>" />
			</p>
		</form>
		<?php
		login_footer( 'gswp_2fa_code' );
	}

	/**
	 * Verify a submitted code against the user's TOTP secret or backup codes.
	 *
	 * @param int    $user_id User ID.
	 * @param string $code    Submitted code.
	 * @return bool
	 */
	private function verify_user_code( $user_id, $code ) {
		$secret = (string) get_user_meta( $user_id, self::META_SECRET, true );
		if ( '' === $secret ) {
			return false;
		}

		$last_ts = (int) get_user_meta( $user_id, self::META_LAST_TS, true );
		$matched = GSWP_TOTP::verify( $secret, $code, 1, $last_ts > 0 ? $last_ts : null );

		if ( false !== $matched ) {
			// Record the matched step so the same code cannot be replayed.
			update_user_meta( $user_id, self::META_LAST_TS, $matched );
			return true;
		}

		return $this->consume_backup_code( $user_id, $code );
	}

	/* ---------------------------------------------------------------------
	 * Pending login (ties a challenge to a successful password check)
	 * ------------------------------------------------------------------- */

	/**
	 * The wp-login.php URL that renders the challenge.
	 *
	 * @return string
	 */
	private function challenge_url() {
		return site_url( 'wp-login.php?action=gswp_2fa', 'login' );
	}

	/**
	 * The cookie path used for the pending-challenge token.
	 *
	 * Broad enough to be sent on both wp-login.php and front-end forms.
	 *
	 * @return string
	 */
	private function cookie_path() {
		return ( defined( 'COOKIEPATH' ) && COOKIEPATH ) ? COOKIEPATH : '/';
	}

	/**
	 * Persist an in-progress login behind a single-use cookie token.
	 *
	 * The token is unguessable and the cookie is HTTP-only, so it can only be
	 * issued by a successful password login; an attacker cannot forge their way
	 * to a victim's challenge (and the code itself is still required).
	 *
	 * @param int    $user_id     User ID.
	 * @param string $redirect_to Post-login redirect target.
	 * @param bool   $rememberme  Whether "remember me" was set.
	 */
	private function store_pending_login( $user_id, $redirect_to, $rememberme ) {
		$token = wp_generate_password( 32, false );

		set_transient(
			self::PENDING_PREFIX . $token,
			array(
				'user_id'     => (int) $user_id,
				'redirect_to' => (string) $redirect_to,
				'rememberme'  => (bool) $rememberme,
			),
			self::PENDING_TTL
		);

		if ( ! headers_sent() ) {
			setcookie( self::COOKIE_PENDING, $token, time() + self::PENDING_TTL, $this->cookie_path(), COOKIE_DOMAIN, is_ssl(), true );
		}

		// Make the token readable within the same request (e.g. AJAX logins).
		$_COOKIE[ self::COOKIE_PENDING ] = $token;
	}

	/**
	 * Read the pending login for the current request's cookie token.
	 *
	 * @return array|false Pending login data, or false when absent/expired.
	 */
	private function get_pending_login() {
		$token = isset( $_COOKIE[ self::COOKIE_PENDING ] ) ? sanitize_text_field( wp_unslash( $_COOKIE[ self::COOKIE_PENDING ] ) ) : '';
		if ( '' === $token ) {
			return false;
		}

		$data = get_transient( self::PENDING_PREFIX . $token );
		if ( ! is_array( $data ) || empty( $data['user_id'] ) ) {
			return false;
		}

		return $data;
	}

	/**
	 * Consume the pending login: delete its transient and expire the cookie.
	 */
	private function clear_pending_login() {
		$token = isset( $_COOKIE[ self::COOKIE_PENDING ] ) ? sanitize_text_field( wp_unslash( $_COOKIE[ self::COOKIE_PENDING ] ) ) : '';
		if ( '' !== $token ) {
			delete_transient( self::PENDING_PREFIX . $token );
		}

		if ( ! headers_sent() ) {
			setcookie( self::COOKIE_PENDING, ' ', time() - YEAR_IN_SECONDS, $this->cookie_path(), COOKIE_DOMAIN, is_ssl(), true );
		}

		unset( $_COOKIE[ self::COOKIE_PENDING ] );
	}

	/* ---------------------------------------------------------------------
	 * Backup codes
	 * ------------------------------------------------------------------- */

	/**
	 * Generate, store (hashed), and return a fresh set of backup codes.
	 *
	 * @param int $user_id User ID.
	 * @param int $count   Number of codes.
	 * @return string[] Plaintext codes (shown to the user once).
	 */
	public function generate_backup_codes( $user_id, $count = 10 ) {
		$plain  = array();
		$hashes = array();

		for ( $i = 0; $i < $count; $i++ ) {
			$code     = bin2hex( random_bytes( 5 ) ); // 10 hex chars.
			$plain[]  = $code;
			$hashes[] = password_hash( $code, PASSWORD_DEFAULT );
		}

		update_user_meta( $user_id, self::META_BACKUP, $hashes );

		return $plain;
	}

	/**
	 * Verify and consume a backup code.
	 *
	 * @param int    $user_id User ID.
	 * @param string $code    Submitted code.
	 * @return bool True when a matching code was found and removed.
	 */
	private function consume_backup_code( $user_id, $code ) {
		$code   = strtolower( preg_replace( '/[^A-Za-z0-9]/', '', $code ) );
		$hashes = get_user_meta( $user_id, self::META_BACKUP, true );

		if ( '' === $code || ! is_array( $hashes ) ) {
			return false;
		}

		foreach ( $hashes as $index => $hash ) {
			if ( password_verify( $code, $hash ) ) {
				unset( $hashes[ $index ] );
				update_user_meta( $user_id, self::META_BACKUP, array_values( $hashes ) );
				return true;
			}
		}

		return false;
	}

	/**
	 * Count a user's remaining backup codes.
	 *
	 * @param int $user_id User ID.
	 * @return int
	 */
	public static function backup_codes_remaining( $user_id ) {
		$hashes = get_user_meta( $user_id, self::META_BACKUP, true );

		return is_array( $hashes ) ? count( $hashes ) : 0;
	}

	/**
	 * Remove all two-factor data for a user (disable).
	 *
	 * @param int $user_id User ID.
	 */
	public function disable_for_user( $user_id ) {
		delete_user_meta( $user_id, self::META_ENABLED );
		delete_user_meta( $user_id, self::META_SECRET );
		delete_user_meta( $user_id, self::META_PENDING );
		delete_user_meta( $user_id, self::META_BACKUP );
		delete_user_meta( $user_id, self::META_LAST_TS );
		delete_user_meta( $user_id, self::META_LOGIN_NONCE );
	}

	/* ---------------------------------------------------------------------
	 * Profile enrolment UI
	 * ------------------------------------------------------------------- */

	/**
	 * Enqueue the QR-code renderer on the profile and user-edit screens.
	 *
	 * @param string $hook Current admin page.
	 */
	public function enqueue_profile_assets( $hook ) {
		if ( 'profile.php' !== $hook && 'user-edit.php' !== $hook ) {
			return;
		}

		/**
		 * Filter the QR-code library URL. The library runs entirely in the
		 * browser, so the TOTP secret never leaves the page. Point this at a
		 * locally bundled copy to remove the third-party dependency.
		 *
		 * @param string $url Script URL.
		 */
		$qr_url = apply_filters(
			'gswp_2fa_qr_script_url',
			'https://cdn.jsdelivr.net/npm/qrcode-generator@1.4.4/qrcode.min.js'
		);

		wp_enqueue_script( 'gswp-qrcode', $qr_url, array(), '1.4.4', true );
		wp_add_inline_script( 'gswp-qrcode', $this->get_qr_inline_js() );
	}

	/**
	 * Inline script that renders the otpauth QR code into its container.
	 *
	 * @return string
	 */
	private function get_qr_inline_js() {
		return <<<'JS'
( function() {
	function draw() {
		var el = document.getElementById( 'gswp-2fa-qr' );
		if ( ! el || typeof qrcode === 'undefined' ) {
			return;
		}
		var data = el.getAttribute( 'data-otpauth' );
		if ( ! data ) {
			return;
		}
		try {
			var qr = qrcode( 0, 'M' );
			qr.addData( data );
			qr.make();
			el.innerHTML = qr.createSvgTag( { cellSize: 4, margin: 4, scalable: true } );
		} catch ( e ) {
			el.textContent = '';
		}
	}
	if ( 'loading' === document.readyState ) {
		document.addEventListener( 'DOMContentLoaded', draw );
	} else {
		draw();
	}
} )();
JS;
	}

	/**
	 * Render the two-factor section on a profile screen.
	 *
	 * @param WP_User $user The user being edited.
	 */
	public function render_profile_section( $user ) {
		if ( ! self::is_feature_enabled() ) {
			return;
		}

		$is_self  = ( get_current_user_id() === $user->ID );
		$enabled  = self::user_has_2fa( $user->ID );

		echo '<h2 id="gswp-2fa">' . esc_html__( 'Two-Factor Authentication (Google Authenticator)', 'google-security-for-wordpress' ) . '</h2>';

		// Surface any one-time notices (new backup codes, setup errors).
		$this->maybe_render_notices( $user->ID );

		wp_nonce_field( 'gswp_2fa_save_' . $user->ID, 'gswp_2fa_nonce' );

		echo '<table class="form-table" role="presentation"><tbody>';

		if ( ! $is_self ) {
			// Administrators can see status and reset another user's 2FA, but
			// never see their secret.
			$this->render_admin_row( $user, $enabled );
		} elseif ( $enabled ) {
			$this->render_manage_rows( $user );
		} else {
			$this->render_setup_rows( $user );
		}

		echo '</tbody></table>';
	}

	/**
	 * Row shown to administrators editing another user.
	 *
	 * @param WP_User $user    Target user.
	 * @param bool    $enabled Whether 2FA is active.
	 */
	private function render_admin_row( $user, $enabled ) {
		?>
		<tr>
			<th scope="row"><?php esc_html_e( 'Status', 'google-security-for-wordpress' ); ?></th>
			<td>
				<?php if ( $enabled ) : ?>
					<p><span class="dashicons dashicons-yes" style="color:#46b450"></span> <?php esc_html_e( 'Two-factor authentication is enabled for this user.', 'google-security-for-wordpress' ); ?></p>
					<?php if ( current_user_can( 'edit_user', $user->ID ) ) : ?>
						<label><input type="checkbox" name="gswp_2fa_admin_disable" value="1" /> <?php esc_html_e( 'Disable two-factor authentication for this user', 'google-security-for-wordpress' ); ?></label>
						<p class="description"><?php esc_html_e( 'Use this to recover access for a user who has lost their authenticator and backup codes.', 'google-security-for-wordpress' ); ?></p>
					<?php endif; ?>
				<?php else : ?>
					<p><?php esc_html_e( 'Two-factor authentication is not enabled for this user.', 'google-security-for-wordpress' ); ?></p>
				<?php endif; ?>
			</td>
		</tr>
		<?php
	}

	/**
	 * Rows shown to a user who already has 2FA enabled.
	 *
	 * @param WP_User $user Current user.
	 */
	private function render_manage_rows( $user ) {
		$remaining = self::backup_codes_remaining( $user->ID );
		?>
		<tr>
			<th scope="row"><?php esc_html_e( 'Status', 'google-security-for-wordpress' ); ?></th>
			<td>
				<p><span class="dashicons dashicons-yes" style="color:#46b450"></span> <?php esc_html_e( 'Two-factor authentication is active on your account.', 'google-security-for-wordpress' ); ?></p>
				<p class="description">
					<?php
					/* translators: %d: number of remaining backup codes. */
					echo esc_html( sprintf( _n( '%d backup code remaining.', '%d backup codes remaining.', $remaining, 'google-security-for-wordpress' ), $remaining ) );
					?>
				</p>
				<p><label><input type="checkbox" name="gswp_2fa_regen" value="1" /> <?php esc_html_e( 'Generate a new set of backup codes', 'google-security-for-wordpress' ); ?></label></p>
				<p><label><input type="checkbox" name="gswp_2fa_disable" value="1" /> <?php esc_html_e( 'Disable two-factor authentication', 'google-security-for-wordpress' ); ?></label></p>
			</td>
		</tr>
		<?php
	}

	/**
	 * Rows shown to a user setting up 2FA for the first time.
	 *
	 * @param WP_User $user Current user.
	 */
	private function render_setup_rows( $user ) {
		// Persist a pending secret across the render/submit round-trip.
		$secret = (string) get_user_meta( $user->ID, self::META_PENDING, true );
		if ( '' === $secret ) {
			$secret = GSWP_TOTP::generate_secret();
			update_user_meta( $user->ID, self::META_PENDING, $secret );
		}

		$issuer = wp_specialchars_decode( get_bloginfo( 'name' ), ENT_QUOTES );
		$uri    = GSWP_TOTP::provisioning_uri( $secret, $user->user_login, $issuer );
		?>
		<tr>
			<th scope="row"><?php esc_html_e( 'Set up an authenticator', 'google-security-for-wordpress' ); ?></th>
			<td>
				<p><?php esc_html_e( 'Scan this QR code with Google Authenticator (or any compatible app), then enter the 6-digit code it shows to finish.', 'google-security-for-wordpress' ); ?></p>
				<div id="gswp-2fa-qr" data-otpauth="<?php echo esc_attr( $uri ); ?>" style="width:160px;height:160px;background:#fff;padding:8px;border:1px solid #dcdcde;"></div>
				<p style="margin-top:12px;">
					<?php esc_html_e( "Can't scan it? Enter this setup key manually:", 'google-security-for-wordpress' ); ?><br />
					<code style="font-size:14px;letter-spacing:1px;"><?php echo esc_html( $this->format_secret( $secret ) ); ?></code>
				</p>
			</td>
		</tr>
		<tr>
			<th scope="row"><label for="gswp_2fa_setup_code"><?php esc_html_e( 'Verification code', 'google-security-for-wordpress' ); ?></label></th>
			<td>
				<input type="text" name="gswp_2fa_setup_code" id="gswp_2fa_setup_code" class="regular-text" inputmode="numeric" autocomplete="off" />
				<p class="description"><?php esc_html_e( 'Enter the current 6-digit code and save your profile to enable two-factor authentication.', 'google-security-for-wordpress' ); ?></p>
			</td>
		</tr>
		<?php
	}

	/**
	 * Group a Base32 secret into readable blocks of four.
	 *
	 * @param string $secret Base32 secret.
	 * @return string
	 */
	private function format_secret( $secret ) {
		return trim( chunk_split( $secret, 4, ' ' ) );
	}

	/**
	 * Render one-time notices (new backup codes or a setup error).
	 *
	 * @param int $user_id User ID.
	 */
	private function maybe_render_notices( $user_id ) {
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		if ( isset( $_GET['gswp_2fa_required'] ) && get_current_user_id() === $user_id ) {
			echo '<div class="notice notice-error inline"><p>' . esc_html__( 'Your account requires two-factor authentication. Set it up below to continue.', 'google-security-for-wordpress' ) . '</p></div>';
		}

		$error = get_transient( 'gswp_2fa_error_' . $user_id );
		if ( $error ) {
			delete_transient( 'gswp_2fa_error_' . $user_id );
			echo '<div class="notice notice-error inline"><p>' . esc_html( $error ) . '</p></div>';
		}

		$codes = get_transient( 'gswp_2fa_codes_' . $user_id );
		if ( is_array( $codes ) && $codes ) {
			delete_transient( 'gswp_2fa_codes_' . $user_id );
			echo '<div class="notice notice-warning inline"><p><strong>' . esc_html__( 'Save your backup codes', 'google-security-for-wordpress' ) . '</strong> — ' . esc_html__( 'each can be used once if you lose access to your authenticator. They will not be shown again.', 'google-security-for-wordpress' ) . '</p><p style="font-family:monospace;font-size:14px;line-height:1.8;">';
			echo esc_html( implode( '   ', $codes ) );
			echo '</p></div>';
		}
	}

	/**
	 * Persist profile changes to two-factor settings.
	 *
	 * @param int $user_id User being saved.
	 */
	public function save_profile( $user_id ) {
		if ( ! self::is_feature_enabled() || ! current_user_can( 'edit_user', $user_id ) ) {
			return;
		}

		if ( ! isset( $_POST['gswp_2fa_nonce'] )
			|| ! wp_verify_nonce( sanitize_text_field( wp_unslash( $_POST['gswp_2fa_nonce'] ) ), 'gswp_2fa_save_' . $user_id ) ) {
			return;
		}

		$is_self = ( get_current_user_id() === $user_id );

		// Administrator resetting another user's 2FA.
		if ( ! $is_self ) {
			if ( ! empty( $_POST['gswp_2fa_admin_disable'] ) ) {
				$this->disable_for_user( $user_id );
			}
			return;
		}

		// Disable own 2FA.
		if ( ! empty( $_POST['gswp_2fa_disable'] ) ) {
			$this->disable_for_user( $user_id );
			return;
		}

		// Regenerate backup codes.
		if ( ! empty( $_POST['gswp_2fa_regen'] ) && self::user_has_2fa( $user_id ) ) {
			$codes = $this->generate_backup_codes( $user_id );
			set_transient( 'gswp_2fa_codes_' . $user_id, $codes, 2 * MINUTE_IN_SECONDS );
			return;
		}

		// First-time enrolment: confirm a code against the pending secret.
		if ( ! self::user_has_2fa( $user_id ) && ! empty( $_POST['gswp_2fa_setup_code'] ) ) {
			$pending = (string) get_user_meta( $user_id, self::META_PENDING, true );
			$code    = sanitize_text_field( wp_unslash( $_POST['gswp_2fa_setup_code'] ) );

			$matched = '' !== $pending ? GSWP_TOTP::verify( $pending, $code, 1 ) : false;

			if ( false !== $matched ) {
				update_user_meta( $user_id, self::META_SECRET, $pending );
				update_user_meta( $user_id, self::META_ENABLED, '1' );
				update_user_meta( $user_id, self::META_LAST_TS, $matched );
				delete_user_meta( $user_id, self::META_PENDING );

				$codes = $this->generate_backup_codes( $user_id );
				set_transient( 'gswp_2fa_codes_' . $user_id, $codes, 2 * MINUTE_IN_SECONDS );
			} else {
				set_transient(
					'gswp_2fa_error_' . $user_id,
					__( 'That verification code was incorrect. Scan the code again and retry — make sure your device clock is accurate.', 'google-security-for-wordpress' ),
					MINUTE_IN_SECONDS
				);
			}
		}
	}
}
