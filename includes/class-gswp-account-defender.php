<?php
/**
 * Account Defender Class
 *
 * Integrates reCAPTCHA Enterprise Account Defender: reads the per-login
 * accountDefenderAssessment labels captured by the verifier, logs them,
 * optionally forces a 2FA step-up on suspicious logins, and annotates login
 * and two-factor outcomes so Google's site-specific model keeps learning.
 *
 * @package Google_Security_For_WordPress
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class GSWP_Account_Defender {

	/**
	 * Shared verifier whose last assessment this layer interprets.
	 *
	 * @var GSWP_Verifier
	 */
	private $verifier;

	/**
	 * Assessment name captured for the current request's login attempt.
	 *
	 * @var string
	 */
	private static $assessment_name = '';

	/**
	 * Whether a 2FA step-up was requested for this request's login.
	 *
	 * @var bool
	 */
	private static $force_2fa = false;

	/**
	 * Whether the login outcome has already been annotated this request.
	 *
	 * @var bool
	 */
	private static $annotated = false;

	/**
	 * Assessment name captured for the current request's account-modification
	 * event (profile save or WooCommerce account-details save). Empty when none.
	 *
	 * @var string
	 */
	private static $modification_name = '';

	/**
	 * Which sensitive changes were detected for the current modification event
	 * (any of 'email', 'password', '2fa').
	 *
	 * @var string[]
	 */
	private static $modification_changes = array();

	/**
	 * A 2FA change made through the profile form this request: 'enabled',
	 * 'disabled', or '' when none. Set by GSWP_Two_Factor::save_profile().
	 *
	 * @var string
	 */
	private static $twofa_change = '';

	/**
	 * Whether the current request's modification assessment has been annotated.
	 *
	 * @var bool
	 */
	private static $modification_annotated = false;

	/** Transient key prefix for a deferred (pending) account-modification. */
	const PENDING_PREFIX = 'gswp_ad_pending_';

	/** User meta holding a registration assessment awaiting its outcome. */
	const META_REGISTRATION = 'gswp_registration_assessment';

	/**
	 * User ID created by a registration in the current request, so an auto-login
	 * riding the same request never annotates its own signup as legitimate.
	 *
	 * @var int
	 */
	private static $registered_user_id = 0;

	/**
	 * Constructor. Hooks the login lifecycle when the feature is active.
	 *
	 * @param GSWP_Verifier $verifier Shared verifier instance.
	 */
	public function __construct( GSWP_Verifier $verifier ) {
		$this->verifier = $verifier;

		if ( ! self::is_active() ) {
			return;
		}

		// Runs after the verifier's login scoring (priority 30) and before the
		// 2FA enforcement (priority 100), so the labels are available to decide a
		// step-up and to seed the annotation hooks.
		add_filter( 'authenticate', array( $this, 'capture_login_assessment' ), 40, 3 );

		// Terminal login outcomes (every entry point funnels through these).
		add_action( 'wp_login', array( $this, 'on_login_success' ), 10, 2 );
		add_action( 'wp_login_failed', array( $this, 'on_login_failed' ), 10, 2 );

		// Registration outcome feedback loop: remember each scored signup's
		// assessment, then annotate it once its real outcome is known — the
		// account's first genuine login (legitimate) or its deletion before any
		// login (fraudulent, i.e. an operator sweeping spam accounts). This is
		// the supervised signal Account Defender's fake-signup model learns from.
		add_action( 'user_register', array( $this, 'on_registered' ), 10, 1 );
		add_action( 'delete_user', array( $this, 'on_user_deleted' ), 10, 1 );
		add_action( 'wpmu_delete_user', array( $this, 'on_user_deleted' ), 10, 1 );

		// Account-modification events (password/email/2FA changes). Assessed
		// where a token can be attached, annotated at the terminal outcome, and
		// never blocking. The password-reset lifecycle lives in GSWP_Login since
		// it owns the wp-login.php forms; here we cover the self-service profile
		// and WooCommerce "Account details" screens.
		if ( ! self::events_active() ) {
			return;
		}

		// Own-profile screen: inject the token field into the profile form and
		// load the reCAPTCHA script there (profile.php only — never user-edit.php,
		// so an admin editing another user is never attributed to that account).
		add_action( 'show_user_profile', array( $this, 'inject_profile_field' ), 1 );
		add_action( 'admin_enqueue_scripts', array( $this, 'enqueue_profile_assets' ) );
		add_action( 'user_profile_update_errors', array( $this, 'assess_profile_update' ), 10, 3 );
		add_action( 'profile_update', array( $this, 'annotate_profile_update' ), 10, 2 );

		// WooCommerce "Account details" screen (email/password change, immediate).
		add_action( 'woocommerce_edit_account_form', array( $this, 'inject_account_field' ) );
		add_action( 'woocommerce_save_account_details_errors', array( $this, 'assess_account_details' ), 10, 2 );
		add_action( 'woocommerce_save_account_details', array( $this, 'annotate_account_details' ), 10, 1 );
	}

	/**
	 * Whether Account Defender and its account-modification events are both on.
	 *
	 * Gated on top of is_active() (Enterprise key + Account Defender) by the
	 * gswp_ad_events toggle (default on), so a site can keep login coverage but
	 * switch off the reCAPTCHA script on the profile/account screens.
	 *
	 * @return bool
	 */
	public static function events_active() {
		return self::is_active() && '1' === get_option( 'gswp_ad_events', '1' );
	}

	/**
	 * Whether Account Defender is enabled and using an Enterprise key.
	 *
	 * @return bool
	 */
	public static function is_active() {
		return 'enterprise' === get_option( 'gswp_key_type', 'classic' )
			&& '1' === get_option( 'gswp_account_defender', '0' );
	}

	/**
	 * Whether verbose (per-event) logging is enabled.
	 *
	 * @return bool
	 */
	public static function verbose() {
		return '1' === get_option( 'gswp_verbose_logging', '0' );
	}

	/**
	 * Capture the assessment labels for the current login and decide step-up.
	 *
	 * @param null|WP_User|WP_Error $user     Auth result so far.
	 * @param string                $username Submitted username (unused).
	 * @param string                $password Submitted password (unused).
	 * @return null|WP_User|WP_Error The unchanged $user.
	 */
	public function capture_login_assessment( $user, $username, $password ) {
		$name = $this->verifier->get_last_assessment_name();
		if ( '' === $name ) {
			return $user;
		}

		// Only capture an assessment a *login* form created. A registration flow
		// that auto-logs the new user in fires `authenticate` in the same request
		// while the verifier still holds the registration assessment; capturing
		// it here would let wp_login annotate a fresh signup (spam included) as
		// LEGITIMATE + CORRECT_PASSWORD.
		if ( ! in_array( $this->verifier->get_last_context(), array( 'login', 'wp_login' ), true ) ) {
			return $user;
		}

		self::$assessment_name = $name;

		$labels = $this->verifier->get_last_account_labels();
		if ( ! empty( $labels ) ) {
			// PROFILE_MATCH is returned on ordinary, legitimate logins, so logging
			// every label would write a line per sign-in. Record only genuine risk
			// labels by default; the full set is logged when verbose logging is on.
			$risk_labels = array_intersect(
				$labels,
				array( 'SUSPICIOUS_LOGIN_ACTIVITY', 'SUSPICIOUS_ACCOUNT_CREATION', 'RELATED_ACCOUNTS_NUMBER_HIGH' )
			);

			if ( ! empty( $risk_labels ) || self::verbose() ) {
				$this->log( 'Account Defender labels for login: ' . implode( ', ', $labels ) . '.' );
			}
		}

		// Optional step-up: a suspicious login forces the 2FA challenge. This
		// guarantees the challenge for enrolled users (manage_options accounts are
		// enrolled by policy); users without 2FA are logged only, never blocked.
		if ( '1' === get_option( 'gswp_ad_step_up', '0' ) && in_array( 'SUSPICIOUS_LOGIN_ACTIVITY', $labels, true ) ) {
			self::$force_2fa = true;
			$this->log( 'Account Defender flagged SUSPICIOUS_LOGIN_ACTIVITY; 2FA step-up requested.' );
		}

		// Fire the admin-alert action for a suspicious login on an admin-capable
		// account. Independent of the step-up setting: whether a step-up ran is
		// reported in the alert, not a precondition for it. GSWP_Alerts is the
		// only shipped subscriber (and only when alerts are enabled); the action
		// also gives third parties a seam for Slack/webhook forwarding.
		if ( in_array( 'SUSPICIOUS_LOGIN_ACTIVITY', $labels, true ) ) {
			$this->maybe_alert_suspicious_login( $user, $username, $labels, $name );
		}

		return $user;
	}

	/**
	 * Resolve the flagged account and fire the admin-alert action when it is
	 * administrator-capable.
	 *
	 * On a wrong-password attempt (exactly the credential-stuffing case worth
	 * alerting on) the $user arg is a WP_Error, so the target is resolved from
	 * the submitted username/email. An unresolvable username is not an admin
	 * account, so no alert fires.
	 *
	 * @param null|WP_User|WP_Error $user     Auth result so far.
	 * @param string                $username Submitted username or email.
	 * @param string[]              $labels   Account Defender labels.
	 * @param string                $name     Assessment resource name.
	 */
	private function maybe_alert_suspicious_login( $user, $username, $labels, $name ) {
		$target = $user instanceof WP_User ? $user : self::resolve_user( $username );
		if ( ! $target instanceof WP_User ) {
			return;
		}

		$capability = apply_filters( 'gswp_alert_login_capability', 'manage_options' );
		if ( ! user_can( $target, $capability ) ) {
			return;
		}

		do_action(
			'gswp_suspicious_admin_login',
			$target,
			$labels,
			array(
				'correct_password' => $user instanceof WP_User,
				'step_up'          => self::$force_2fa,
				'assessment'       => $name,
			)
		);
	}

	/**
	 * Look up a user by login name, then by email.
	 *
	 * @param string $username Submitted identifier.
	 * @return WP_User|null
	 */
	private static function resolve_user( $username ) {
		if ( ! is_string( $username ) || '' === $username ) {
			return null;
		}
		$user = get_user_by( 'login', $username );
		if ( ! $user ) {
			$user = get_user_by( 'email', $username );
		}
		return $user ? $user : null;
	}

	/**
	 * Annotate a successful (non-2FA) login as legitimate.
	 *
	 * Held 2FA logins never reach wp_login (the challenge completes via the AJAX
	 * verifier with wp_set_auth_cookie), so this only fires for logins that
	 * finished on the password alone.
	 *
	 * @param string  $user_login Username.
	 * @param WP_User $user       Logged-in user.
	 */
	public function on_login_success( $user_login, $user = null ) {
		// A first genuine login settles any pending registration assessment,
		// independent of whether this login itself was assessed.
		$this->maybe_annotate_registration_outcome( $user );

		if ( self::$annotated || '' === self::$assessment_name ) {
			return;
		}
		self::$annotated = true;

		self::annotate( self::$assessment_name, 'LEGITIMATE', array( 'CORRECT_PASSWORD' ) );
	}

	/* ---------------------------------------------------------------------
	 * Registration outcome feedback loop
	 * ------------------------------------------------------------------- */

	/**
	 * Remember the assessment behind a just-created account.
	 *
	 * Fires on user_register, which runs inside wp_insert_user() for every
	 * covered registration surface (core, WooCommerce, Xootix, PowerPack). Only
	 * a registration-context assessment is stored — an admin creating a user in
	 * wp-admin, or any other creation path, has none in flight.
	 *
	 * @param int $user_id Newly created user ID.
	 */
	public function on_registered( $user_id ) {
		if ( ! in_array( $this->verifier->get_last_context(), array( 'registration', 'wp_register' ), true ) ) {
			return;
		}

		$name = $this->verifier->get_last_assessment_name();
		if ( '' === $name ) {
			return;
		}

		update_user_meta(
			$user_id,
			self::META_REGISTRATION,
			array(
				'name' => $name,
				'time' => time(),
			)
		);
		self::$registered_user_id = (int) $user_id;

		if ( self::verbose() ) {
			$this->log( 'Account Defender stored registration assessment for user ' . (int) $user_id . ' pending its outcome.' );
		}
	}

	/**
	 * Annotate a deleted account's stored registration assessment as fraudulent.
	 *
	 * The meta is only still present when the account never completed a real
	 * login (a first login consumes it), so deleting a long-standing legitimate
	 * user never mis-annotates — this catches exactly the operator sweeping
	 * spam signups.
	 *
	 * @param int $user_id User being deleted.
	 */
	public function on_user_deleted( $user_id ) {
		$stored = get_user_meta( $user_id, self::META_REGISTRATION, true );
		if ( empty( $stored['name'] ) ) {
			return;
		}

		delete_user_meta( $user_id, self::META_REGISTRATION );
		self::annotate( $stored['name'], 'FRAUDULENT' );

		if ( self::verbose() ) {
			$this->log( 'Account Defender annotated deleted user ' . (int) $user_id . "'s registration as FRAUDULENT." );
		}
	}

	/**
	 * Annotate a pending registration assessment LEGITIMATE on first real login.
	 *
	 * Skipped when the login rides the same request as the registration (an
	 * auto-login is no evidence of legitimacy); the genuinely-next login — a
	 * fresh visit that passed the login scoring — is what settles the signup.
	 *
	 * @param WP_User|null $user The user who just logged in.
	 */
	private function maybe_annotate_registration_outcome( $user ) {
		if ( ! $user instanceof WP_User ) {
			return;
		}
		if ( self::$registered_user_id === (int) $user->ID ) {
			return;
		}

		$stored = get_user_meta( $user->ID, self::META_REGISTRATION, true );
		if ( empty( $stored['name'] ) ) {
			return;
		}

		delete_user_meta( $user->ID, self::META_REGISTRATION );
		self::annotate( $stored['name'], 'LEGITIMATE' );

		if ( self::verbose() ) {
			$this->log( 'Account Defender annotated user ' . (int) $user->ID . "'s registration as LEGITIMATE after first login." );
		}
	}

	/**
	 * Screen a just-scored registration against Account Defender's labels.
	 *
	 * Called by each registration validator after the reCAPTCHA score passed.
	 * Logs any labels, fires the gswp_suspicious_registration alert action when
	 * SUSPICIOUS_ACCOUNT_CREATION is present, and — only when the opt-in
	 * gswp_ad_block_signup toggle is on — returns a WP_Error for the caller to
	 * surface exactly like a low score, so no account is created.
	 *
	 * @param GSWP_Verifier $verifier Verifier holding the fresh assessment.
	 * @param string        $email    Submitted registration email.
	 * @param string        $source   Registration surface ('woocommerce', 'wp-login', 'xootix', 'powerpack').
	 * @return WP_Error|null WP_Error to block the signup, null to allow.
	 */
	public static function screen_registration( $verifier, $email, $source ) {
		if ( ! self::is_active() || ! $verifier instanceof GSWP_Verifier ) {
			return null;
		}

		$labels = $verifier->get_last_account_labels();
		if ( empty( $labels ) ) {
			return null;
		}

		$suspicious = in_array( 'SUSPICIOUS_ACCOUNT_CREATION', $labels, true );
		$blocking   = $suspicious && '1' === get_option( 'gswp_ad_block_signup', '0' );

		if ( $suspicious || self::verbose() ) {
			self::static_log( 'Account Defender labels for registration (' . $source . '): ' . implode( ', ', $labels ) . '.' );
		}

		if ( $suspicious ) {
			/**
			 * A registration was flagged as a suspicious account creation.
			 * Fires whether or not the signup is blocked; GSWP_Alerts is the
			 * shipped subscriber, and the action doubles as a seam for
			 * third-party (Slack/webhook) forwarding.
			 */
			do_action(
				'gswp_suspicious_registration',
				$email,
				$labels,
				array(
					'source'     => $source,
					'blocked'    => $blocking,
					'assessment' => $verifier->get_last_assessment_name(),
				)
			);
		}

		if ( $blocking ) {
			return new WP_Error(
				'recaptcha_suspicious_signup',
				__( '<strong>Error:</strong> This sign-up was flagged as suspicious and cannot be completed. Please contact us if you believe this is a mistake.', 'google-security-for-wordpress' )
			);
		}

		return null;
	}

	/**
	 * Screen registration field content for obviously bot-generated data.
	 *
	 * A local, Google-independent heuristic layer: analyses the submitted
	 * name/website fields for random-character patterns that no human would
	 * type (gibberish consonant clusters, random case alternation, extremely
	 * low vowel ratios). Blocks when 2 or more fields are flagged, gated by
	 * the same gswp_ad_block_signup toggle as the label-based screening.
	 *
	 * Does NOT require an Enterprise key or Account Defender to be active —
	 * the patterns are unambiguous regardless of key type.
	 *
	 * @param array  $fields Associative array with optional keys 'first_name',
	 *                       'last_name', 'user_url'.
	 * @param string $email  Submitted registration email (for the alert action).
	 * @param string $source Registration surface identifier.
	 * @return WP_Error|null WP_Error to block the signup, null to allow.
	 */
	public static function screen_registration_content( $fields, $email = '', $source = 'unknown' ) {
		if ( '1' !== get_option( 'gswp_ad_block_signup', '0' ) ) {
			return null;
		}

		$flagged = array();
		$check   = array( 'first_name', 'last_name', 'user_url' );

		foreach ( $check as $key ) {
			$value = isset( $fields[ $key ] ) ? trim( (string) $fields[ $key ] ) : '';
			if ( '' === $value ) {
				continue;
			}
			if ( self::is_gibberish_field( $value ) ) {
				$flagged[] = $key;
			}
		}

		// Require 2+ flagged fields to avoid false positives on a single
		// unusual-but-legitimate value.
		if ( count( $flagged ) < 2 ) {
			return null;
		}

		self::static_log(
			'Content heuristic flagged registration fields (' . implode( ', ', $flagged ) . ') from source: ' . $source . '.'
		);

		/**
		 * Fires when a registration is flagged by local content heuristics.
		 * Reuses the same action as the label-based screening so the alert
		 * pipeline handles both uniformly.
		 */
		do_action(
			'gswp_suspicious_registration',
			$email,
			array( 'CONTENT_HEURISTIC' ),
			array(
				'source'     => $source,
				'blocked'    => true,
				'assessment' => '',
				'fields'     => $flagged,
			)
		);

		return new WP_Error(
			'recaptcha_suspicious_signup',
			__( '<strong>Error:</strong> This sign-up was flagged as suspicious and cannot be completed. Please contact us if you believe this is a mistake.', 'google-security-for-wordpress' )
		);
	}

	/**
	 * Whether a single field value looks like random bot-generated text.
	 *
	 * Triggers when at least one of the following unambiguous signals fires:
	 *  1. Low vowel ratio: 10+ alpha chars with fewer than 20% vowels.
	 *  2. Long consonant cluster: 8+ consecutive consonants.
	 *  3. Random case alternation: 12+ alpha chars, no spaces, 5+ case
	 *     transitions (real names and URLs do not alternate case randomly).
	 *
	 * @param string $value Trimmed field value.
	 * @return bool True when the value appears machine-generated.
	 */
	private static function is_gibberish_field( $value ) {
		// Strip non-alpha for ratio/cluster analysis; keep original for case.
		$alpha = preg_replace( '/[^a-zA-Z]/', '', $value );
		$len   = strlen( $alpha );

		// Signal 1: extremely low vowel ratio in a long-enough string.
		if ( $len >= 10 ) {
			$vowels = preg_match_all( '/[aeiouyAEIOUY]/', $alpha );
			if ( $vowels / $len < 0.20 ) {
				return true;
			}
		}

		// Signal 2: 8+ consecutive consonants (case-insensitive).
		if ( $len >= 8 && preg_match( '/[^aeiouyAEIOUY]{8,}/', $alpha ) ) {
			return true;
		}

		// Signal 3: random case alternation in a long, spaceless string.
		if ( $len >= 12 && false === strpos( $value, ' ' ) ) {
			$transitions = 0;
			$prev_upper  = ctype_upper( $alpha[0] );
			for ( $i = 1; $i < $len; $i++ ) {
				$cur_upper = ctype_upper( $alpha[ $i ] );
				if ( $cur_upper !== $prev_upper ) {
					$transitions++;
				}
				$prev_upper = $cur_upper;
			}
			if ( $transitions >= 5 ) {
				return true;
			}
		}

		return false;
	}

	/**
	 * Annotate a failed login (wrong password) for the assessed attempt.
	 *
	 * @param string        $username Submitted username.
	 * @param WP_Error|null $error    Failure reason.
	 */
	public function on_login_failed( $username, $error = null ) {
		// Our own 2FA hold surfaces as a login failure; that is not a bad
		// password, so leave it for the two-factor outcome to annotate.
		if ( $error instanceof WP_Error && 'gswp_2fa_required' === $error->get_error_code() ) {
			return;
		}

		if ( self::$annotated || '' === self::$assessment_name ) {
			return;
		}
		self::$annotated = true;

		self::annotate( self::$assessment_name, '', array( 'INCORRECT_PASSWORD' ) );
	}

	/* ---------------------------------------------------------------------
	 * Helpers used by the two-factor flow
	 * ------------------------------------------------------------------- */

	/**
	 * The assessment name captured for the current request's login.
	 *
	 * @return string
	 */
	public static function current_assessment_name() {
		return self::$assessment_name;
	}

	/**
	 * Whether a 2FA step-up was requested for the current login.
	 *
	 * @return bool
	 */
	public static function should_force_2fa() {
		return self::$force_2fa;
	}

	/* ---------------------------------------------------------------------
	 * Account-modification events (password / email / 2FA changes)
	 * ------------------------------------------------------------------- */

	/**
	 * Print the hidden reCAPTCHA field, carrying a reCAPTCHA action, into a form.
	 *
	 * @param string $action reCAPTCHA action name for the token.
	 */
	private function render_field( $action ) {
		if ( '' === GSWP_Assets::site_key() ) {
			return;
		}

		printf(
			'<input type="hidden" name="g-recaptcha-response" class="g-recaptcha-response" data-recaptcha-action="%s" value="" />',
			esc_attr( $action )
		);
	}

	/**
	 * Inject the token field into the user's own profile form.
	 *
	 * @param WP_User $user The profile being shown (always the current user here).
	 */
	public function inject_profile_field( $user ) {
		$this->render_field( 'account_update' );
	}

	/**
	 * Load the reCAPTCHA API script and token bootstrap on the profile screen.
	 *
	 * Restricted to profile.php: on user-edit.php an administrator edits another
	 * account, and that change must not be assessed under the target's identity.
	 *
	 * @param string $hook Current admin page hook.
	 */
	public function enqueue_profile_assets( $hook ) {
		if ( 'profile.php' !== $hook ) {
			return;
		}

		if ( GSWP_Assets::enqueue_api_script() ) {
			GSWP_Assets::add_refresh_bootstrap();
		}
	}

	/**
	 * Assess a self-service profile update when it carries a sensitive change.
	 *
	 * Runs on user_profile_update_errors. Never adds an error (account changes
	 * are recorded, not blocked); it only creates the assessment whose outcome
	 * is annotated later by annotate_profile_update() / the two-factor flow.
	 *
	 * @param WP_Error $errors Validation errors (left untouched).
	 * @param bool     $update Whether this is an update (unused).
	 * @param stdClass $user   Incoming user data (new values).
	 */
	public function assess_profile_update( $errors, $update, $user ) {
		if ( ! isset( $user->ID ) || (int) $user->ID !== get_current_user_id() ) {
			return; // Self-service only.
		}

		$changes = $this->detect_profile_changes( $user );
		if ( empty( $changes ) ) {
			return;
		}

		$this->verifier->verify_token( 'account_update', 'account_update', array(), (int) $user->ID );

		$name = $this->verifier->get_last_assessment_name();
		if ( '' === $name ) {
			return; // No token / classic key / connection skipped: nothing to annotate.
		}

		self::$modification_name    = $name;
		self::$modification_changes = $changes;

		// A profile email change is deferred by core (a confirmation link updates
		// user_email in a later request), so remember the assessment to annotate
		// when that confirmation lands.
		if ( in_array( 'email', $changes, true ) ) {
			self::store_pending( 'email_' . (int) $user->ID, $name, WEEK_IN_SECONDS );
		}

		if ( self::verbose() ) {
			$this->log( 'Account Defender assessed profile change (' . implode( ', ', $changes ) . ').' );
		}
	}

	/**
	 * Annotate a committed profile update as legitimate.
	 *
	 * Handles two cases: a deferred email change completing in a later request
	 * (consume the pending assessment), and an immediate change (password or 2FA)
	 * assessed earlier this request.
	 *
	 * @param int     $user_id       Updated user ID.
	 * @param WP_User $old_user_data User object before the update.
	 */
	public function annotate_profile_update( $user_id, $old_user_data = null ) {
		if ( (int) $user_id !== get_current_user_id() ) {
			return; // Self-service only.
		}

		$email_changed_now = $this->email_changed( $user_id, $old_user_data );

		// No assessment this request: this is the email-confirmation link landing,
		// so annotate the assessment stored when the change was requested.
		if ( '' === self::$modification_name ) {
			if ( $email_changed_now ) {
				$name = self::take_pending( 'email_' . (int) $user_id );
				if ( '' !== $name ) {
					self::annotate( $name, 'LEGITIMATE' );
				}
			}
			return;
		}

		// An assessment was made this request. Annotate now for changes that take
		// effect immediately (password, 2FA); a profile email change is deferred,
		// so leave it for the confirmation link unless it also changed something
		// immediate.
		$has_immediate = $email_changed_now
			|| in_array( 'password', self::$modification_changes, true )
			|| '' !== self::$twofa_change;

		if ( $has_immediate ) {
			$this->finalize_modification();
		}
	}

	/**
	 * Inject the token field into the WooCommerce "Account details" form.
	 */
	public function inject_account_field() {
		if ( GSWP_Assets::enqueue_api_script() ) {
			GSWP_Assets::add_refresh_bootstrap();
		}
		$this->render_field( 'account_update' );
	}

	/**
	 * Assess a WooCommerce account-details save carrying a sensitive change.
	 *
	 * @param WP_Error $errors Validation errors (left untouched).
	 * @param stdClass $user   Incoming user data (unused; current user is used).
	 */
	public function assess_account_details( $errors, $user = null ) {
		$user_id = get_current_user_id();
		if ( ! $user_id ) {
			return;
		}

		$changes = $this->detect_account_changes( $user_id );
		if ( empty( $changes ) ) {
			return;
		}

		$this->verifier->verify_token( 'account_update', 'account_update', array(), $user_id );

		$name = $this->verifier->get_last_assessment_name();
		if ( '' === $name ) {
			return;
		}

		self::$modification_name    = $name;
		self::$modification_changes = $changes;

		if ( self::verbose() ) {
			$this->log( 'Account Defender assessed WooCommerce account change (' . implode( ', ', $changes ) . ').' );
		}
	}

	/**
	 * Annotate a committed WooCommerce account-details save as legitimate.
	 *
	 * WooCommerce applies email and password changes immediately (no confirmation
	 * step), so the change is real by the time this fires. Idempotent: the shared
	 * guard means the profile_update annotation (fired inside wp_update_user) and
	 * this call never double-annotate the same assessment.
	 *
	 * @param int $user_id Updated user ID.
	 */
	public function annotate_account_details( $user_id ) {
		$this->finalize_modification();
	}

	/**
	 * Detect sensitive changes in an incoming profile save.
	 *
	 * @param stdClass $user Incoming user data (new values).
	 * @return string[] Subset of { 'email', 'password', '2fa' }.
	 */
	private function detect_profile_changes( $user ) {
		$changes = array();

		$current = get_userdata( (int) $user->ID );
		if ( $current instanceof WP_User && isset( $user->user_email )
			&& strtolower( $user->user_email ) !== strtolower( $current->user_email ) ) {
			$changes[] = 'email';
		}

		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- core verifies the profile nonce before this hook.
		if ( ! empty( $_POST['pass1'] ) ) {
			$changes[] = 'password';
		}

		// A 2FA enrol posts the setup code; a disable posts the disable checkbox.
		// phpcs:ignore WordPress.Security.NonceVerification.Missing
		if ( ! empty( $_POST['gswp_2fa_setup_code'] ) || ! empty( $_POST['gswp_2fa_disable'] ) ) {
			$changes[] = '2fa';
		}

		return $changes;
	}

	/**
	 * Detect sensitive changes in an incoming WooCommerce account save.
	 *
	 * @param int $user_id Current user ID.
	 * @return string[] Subset of { 'email', 'password' }.
	 */
	private function detect_account_changes( $user_id ) {
		$changes = array();

		$current = get_userdata( $user_id );
		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- WooCommerce verifies its own nonce before this hook.
		$new_email = isset( $_POST['account_email'] ) ? sanitize_email( wp_unslash( $_POST['account_email'] ) ) : '';
		if ( $current instanceof WP_User && '' !== $new_email
			&& strtolower( $new_email ) !== strtolower( $current->user_email ) ) {
			$changes[] = 'email';
		}

		// phpcs:ignore WordPress.Security.NonceVerification.Missing
		if ( ! empty( $_POST['password_1'] ) ) {
			$changes[] = 'password';
		}

		return $changes;
	}

	/**
	 * Whether a user's email actually differs from its pre-update value.
	 *
	 * @param int          $user_id       Updated user ID.
	 * @param WP_User|null $old_user_data User object before the update.
	 * @return bool
	 */
	private function email_changed( $user_id, $old_user_data ) {
		if ( ! $old_user_data instanceof WP_User ) {
			return false;
		}
		$current = get_userdata( $user_id );
		return $current instanceof WP_User
			&& strtolower( $current->user_email ) !== strtolower( $old_user_data->user_email );
	}

	/**
	 * Annotate this request's modification assessment LEGITIMATE, exactly once.
	 *
	 * Adds the PASSED_TWO_FACTOR reason when the change enabled 2FA (a code was
	 * verified). The guard makes the two terminal hooks (profile_update and
	 * woocommerce_save_account_details) safe to both fire for one save.
	 */
	private function finalize_modification() {
		if ( self::$modification_annotated || '' === self::$modification_name ) {
			return;
		}
		self::$modification_annotated = true;

		$reasons = ( 'enabled' === self::$twofa_change ) ? array( 'PASSED_TWO_FACTOR' ) : array();

		self::annotate( self::$modification_name, 'LEGITIMATE', $reasons );
	}

	/**
	 * The account-modification assessment captured for this request, if any.
	 *
	 * @return string
	 */
	public static function current_modification_assessment() {
		return self::$modification_name;
	}

	/**
	 * Record a 2FA change made through the profile form this request.
	 *
	 * Called by GSWP_Two_Factor::save_profile() on a successful enable/disable.
	 * The profile assessment is created after that hook runs (edit_user fires
	 * user_profile_update_errors later), so the outcome is annotated at
	 * profile_update using this flag rather than annotated inline.
	 *
	 * @param string $type 'enabled' or 'disabled'.
	 */
	public static function note_2fa_change( $type ) {
		self::$twofa_change = ( 'enabled' === $type ) ? 'enabled' : 'disabled';
	}

	/* ---------------------------------------------------------------------
	 * Pending (deferred) assessment store
	 * ------------------------------------------------------------------- */

	/**
	 * Stash an assessment name to annotate when a deferred flow completes.
	 *
	 * @param string $key  Short key (e.g. "email_42").
	 * @param string $name Assessment resource name.
	 * @param int    $ttl  Lifetime in seconds.
	 */
	public static function store_pending( $key, $name, $ttl ) {
		if ( '' === $name ) {
			return;
		}
		set_transient( self::PENDING_PREFIX . $key, $name, $ttl );
	}

	/**
	 * Consume a stored pending assessment name.
	 *
	 * @param string $key Short key used with store_pending().
	 * @return string Assessment name, or '' when none is stored.
	 */
	public static function take_pending( $key ) {
		$name = get_transient( self::PENDING_PREFIX . $key );
		if ( false === $name || '' === $name ) {
			return '';
		}
		delete_transient( self::PENDING_PREFIX . $key );
		return (string) $name;
	}

	/**
	 * Send an annotation for an assessment to the reCAPTCHA Enterprise API.
	 *
	 * Fails open: any error is logged and ignored so the login flow is never
	 * blocked by the feedback call.
	 *
	 * @param string   $name       Assessment resource name.
	 * @param string   $annotation Annotation enum (LEGITIMATE/FRAUDULENT) or '' to omit.
	 * @param string[] $reasons    Reason enum values to include.
	 */
	public static function annotate( $name, $annotation, $reasons = array() ) {
		if ( '' === $name || ! self::is_active() ) {
			return;
		}

		$api_key = get_option( 'gswp_gcp_api_key', '' );
		if ( '' === $api_key ) {
			return;
		}

		$body = array();
		if ( '' !== $annotation ) {
			$body['annotation'] = $annotation;
		}
		if ( ! empty( $reasons ) ) {
			$body['reasons'] = array_values( $reasons );
		}
		if ( empty( $body ) ) {
			return;
		}

		$api_url = sprintf(
			'https://recaptchaenterprise.googleapis.com/v1/%s:annotate?key=%s',
			$name,
			rawurlencode( $api_key )
		);

		$response = wp_remote_post(
			$api_url,
			array(
				'timeout' => 10,
				'headers' => array( 'Content-Type' => 'application/json' ),
				'body'    => wp_json_encode( $body ),
			)
		);

		if ( is_wp_error( $response ) ) {
			self::static_log( 'Account Defender annotation failed to connect: ' . $response->get_error_message() );
			return;
		}

		$status = wp_remote_retrieve_response_code( $response );
		if ( 200 !== $status ) {
			self::static_log( 'Account Defender annotation returned HTTP ' . $status . ' (' . wp_remote_retrieve_body( $response ) . ').' );
		}
	}

	/**
	 * Log a warning to the WooCommerce logger, or the error log under WP_DEBUG.
	 *
	 * @param string $message Log message.
	 */
	private function log( $message ) {
		self::static_log( $message );
	}

	/**
	 * Static log helper shared with the annotation methods.
	 *
	 * @param string $message Log message.
	 */
	private static function static_log( $message ) {
		if ( function_exists( 'wc_get_logger' ) ) {
			wc_get_logger()->warning( $message, array( 'source' => 'gswp' ) );
		} elseif ( defined( 'WP_DEBUG' ) && WP_DEBUG ) {
			error_log( 'GSWP Account Defender: ' . $message ); // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log
		}
	}
}
