<?php
/**
 * Verifier Class
 *
 * Intercepts WooCommerce login, registration, and checkout actions to verify reCAPTCHA tokens.
 *
 * @package Google_Security_For_WordPress
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class GSWP_Verifier {

	/**
	 * Resource name of the most recent Enterprise assessment, e.g.
	 * "projects/123/assessments/abc". Captured so a checkout can be tied to
	 * its assessment and annotated later. Empty when none was created.
	 *
	 * @var string
	 */
	private $last_assessment_name = '';

	/**
	 * The fraudPreventionAssessment block from the most recent Enterprise
	 * assessment response, or null when Transaction defense returned nothing.
	 *
	 * @var array|null
	 */
	private $last_fraud_assessment = null;

	/**
	 * The accountDefenderAssessment block from the most recent Enterprise
	 * assessment response, or null when Account Defender returned nothing.
	 *
	 * @var array|null
	 */
	private $last_account_assessment = null;

	/**
	 * Constructor.
	 */
	public function __construct() {
		// Hook into login validation.
		add_filter( 'woocommerce_process_login_errors', array( $this, 'validate_login' ), 10, 3 );

		// Hook into registration validation.
		add_filter( 'woocommerce_process_registration_errors', array( $this, 'validate_registration' ), 10, 3 );

		// Hook into checkout validation.
		add_action( 'woocommerce_after_checkout_validation', array( $this, 'validate_checkout' ), 10, 2 );
	}

	/**
	 * Validate login request.
	 *
	 * @param WP_Error $validation_error Current validation errors.
	 * @param string   $username         Submitted username.
	 * @param string   $password         Submitted password.
	 * @return WP_Error Filtered validation errors.
	 */
	public function validate_login( $validation_error, $username, $password ) {
		if ( '1' !== get_option( 'gswp_enable_login', '0' ) ) {
			return $validation_error;
		}

		$result = $this->verify_token( 'login', 'login', array(), $username );
		if ( is_wp_error( $result ) ) {
			if ( ! is_wp_error( $validation_error ) ) {
				$validation_error = new WP_Error();
			}
			$validation_error->add( 'recaptcha_error', $result->get_error_message() );
		}

		return $validation_error;
	}

	/**
	 * Validate registration request.
	 *
	 * @param WP_Error $validation_errors Current validation errors.
	 * @param string   $username          Submitted username.
	 * @param string   $email             Submitted email.
	 * @return WP_Error Filtered validation errors.
	 */
	public function validate_registration( $validation_errors, $username, $email ) {
		if ( '1' !== get_option( 'gswp_enable_registration', '0' ) ) {
			return $validation_errors;
		}

		$result = $this->verify_token( 'registration', 'register', array(), $email );
		if ( is_wp_error( $result ) ) {
			if ( ! is_wp_error( $validation_errors ) ) {
				$validation_errors = new WP_Error();
			}
			$validation_errors->add( 'recaptcha_error', $result->get_error_message() );
		}

		return $validation_errors;
	}

	/**
	 * Validate checkout request.
	 *
	 * @param array    $data   Post data.
	 * @param WP_Error $errors Validation errors object.
	 */
	public function validate_checkout( $data, $errors ) {
		if ( '1' !== get_option( 'gswp_enable_checkout', '0' ) ) {
			return;
		}

		// Attach payment transaction data so reCAPTCHA Enterprise Transaction
		// defense can return a fraudPreventionAssessment. Empty for classic
		// keys, when the feature is off, or when the minimum fields are absent.
		$event_extra = $this->build_checkout_event_extra();

		$result = $this->verify_token( 'checkout', 'checkout', $event_extra );
		if ( is_wp_error( $result ) ) {
			$errors->add( 'recaptcha_error', $result->get_error_message() );
		}

		// Interpret the Transaction defense verdict: record the risk, stash the
		// assessment name for annotation, and optionally block high-risk orders.
		$this->process_fraud_prevention( $errors );
	}

	/**
	 * Verify the submitted reCAPTCHA token for the given context.
	 *
	 * Routes verification through the classic siteverify endpoint or the
	 * reCAPTCHA Enterprise assessments API depending on the configured key type.
	 *
	 * @param string $context         Threshold context. The configured threshold
	 *                                is read from "gswp_threshold_{$context}".
	 * @param string $expected_action reCAPTCHA action name the frontend executed
	 *                                with, validated for Enterprise assessments.
	 * @param array  $event_extra     Extra fields merged into the Enterprise
	 *                                assessment "event" (e.g. transactionData).
	 *                                Ignored for classic verification.
	 * @param mixed  $account_identifier Optional WP_User, user ID, login, or email
	 *                                identifying the account, used to attach
	 *                                Account Defender userInfo on login/register
	 *                                assessments.
	 * @return true|WP_Error Returns true on success, WP_Error object on failure.
	 */
	public function verify_token( $context, $expected_action, $event_extra = array(), $account_identifier = null ) {
		// Reset any verdict captured by a previous call on this request.
		$this->last_assessment_name   = '';
		$this->last_fraud_assessment  = null;
		$this->last_account_assessment = null;

		// Attach Account Defender account identifiers on login/registration
		// assessments so Google can build its site-specific behavioural model.
		$user_info = $this->build_account_user_info( $context, $account_identifier );
		if ( ! empty( $user_info ) ) {
			$event_extra = array_merge( is_array( $event_extra ) ? $event_extra : array(), $user_info );
		}

		$key_type = get_option( 'gswp_key_type', 'classic' );

		// Skip verification if credentials are not configured to avoid blocking users.
		if ( 'enterprise' === $key_type ) {
			$configured = '' !== get_option( 'gswp_gcp_project_id', '' )
				&& '' !== get_option( 'gswp_gcp_api_key', '' )
				&& '' !== get_option( 'gswp_site_key', '' );
		} else {
			$configured = '' !== get_option( 'gswp_secret_key', '' );
		}

		if ( ! $configured ) {
			return true;
		}

		$token = isset( $_POST['g-recaptcha-response'] ) ? sanitize_text_field( wp_unslash( $_POST['g-recaptcha-response'] ) ) : '';

		if ( empty( $token ) ) {
			return new WP_Error(
				'recaptcha_missing',
				__( '<strong>Error:</strong> Anti-spam verification token is missing. Please refresh the page and try again.', 'google-security-for-wordpress' )
			);
		}

		$result = 'enterprise' === $key_type
			? $this->assess_enterprise_token( $token, $expected_action, $event_extra )
			: $this->verify_classic_token( $token );

		if ( true !== $result && ! is_wp_error( $result ) ) {
			// Score returned: check it against the configured threshold.
			$threshold = floatval( get_option( 'gswp_threshold_' . $context, '0.5' ) );

			if ( floatval( $result ) < $threshold ) {
				return new WP_Error(
					'recaptcha_low_score',
					__( '<strong>Error:</strong> Verification score too low. Submission rejected as potential spam.', 'google-security-for-wordpress' )
				);
			}

			return true;
		}

		return $result;
	}

	/**
	 * Perform a classic reCAPTCHA v3 siteverify call.
	 *
	 * @param string $token Submitted reCAPTCHA token.
	 * @return float|true|WP_Error Score on success, true to skip scoring, WP_Error on failure.
	 */
	private function verify_classic_token( $token ) {
		$secret_key = get_option( 'gswp_secret_key', '' );

		$response = wp_remote_post(
			'https://www.google.com/recaptcha/api/siteverify',
			array(
				'timeout' => 10,
				'body'    => array(
					'secret'   => $secret_key,
					'response' => $token,
					'remoteip' => $this->get_remote_ip(),
				),
			)
		);

		if ( is_wp_error( $response ) ) {
			return new WP_Error(
				'recaptcha_api_failed',
				__( '<strong>Error:</strong> Failed to connect to Google reCAPTCHA service. Please try again.', 'google-security-for-wordpress' )
			);
		}

		$body = wp_remote_retrieve_body( $response );
		$data = json_decode( $body, true );

		if ( ! is_array( $data ) || ! isset( $data['success'] ) ) {
			return new WP_Error(
				'recaptcha_invalid_response',
				__( '<strong>Error:</strong> Invalid verification response. Please try again.', 'google-security-for-wordpress' )
			);
		}

		if ( ! $data['success'] ) {
			$error_codes = isset( $data['error-codes'] ) && is_array( $data['error-codes'] ) ? $data['error-codes'] : array();

			// Credential misconfiguration is a site problem, not a visitor
			// problem: log it and let the submission through rather than
			// blocking every customer.
			$config_errors = array_intersect( $error_codes, array( 'invalid-input-secret', 'missing-input-secret', 'invalid-keys' ) );
			if ( ! empty( $config_errors ) ) {
				$this->log( 'siteverify rejected the configured secret key (' . implode( ', ', $config_errors ) . '). Check the secret key in WooCommerce > reCAPTCHA v3. Verification was skipped.' );
				return true;
			}

			return new WP_Error(
				'recaptcha_failed',
				__( '<strong>Error:</strong> Verification failed. You have been flagged as potential spam. Please try again.', 'google-security-for-wordpress' )
			);
		}

		return isset( $data['score'] ) ? floatval( $data['score'] ) : 0.0;
	}

	/**
	 * Create a reCAPTCHA Enterprise assessment for the token.
	 *
	 * @param string $token           Submitted reCAPTCHA token.
	 * @param string $expected_action reCAPTCHA action name the frontend executed with.
	 * @param array  $event_extra     Extra fields merged into the "event" object,
	 *                                such as transactionData and fraudPrevention.
	 * @return float|true|WP_Error Score on success, true to skip scoring, WP_Error on failure.
	 */
	private function assess_enterprise_token( $token, $expected_action, $event_extra = array() ) {
		$project_id = get_option( 'gswp_gcp_project_id', '' );
		$api_key    = get_option( 'gswp_gcp_api_key', '' );
		$site_key   = get_option( 'gswp_site_key', '' );

		$api_url = sprintf(
			'https://recaptchaenterprise.googleapis.com/v1/projects/%s/assessments?key=%s',
			rawurlencode( $project_id ),
			rawurlencode( $api_key )
		);

		$event = array_merge(
			array(
				'token'          => $token,
				'siteKey'        => $site_key,
				'expectedAction' => $expected_action,
				'userIpAddress'  => $this->get_remote_ip(),
			),
			is_array( $event_extra ) ? $event_extra : array()
		);

		$response = wp_remote_post(
			$api_url,
			array(
				'timeout' => 10,
				'headers' => array( 'Content-Type' => 'application/json' ),
				'body'    => wp_json_encode( array( 'event' => $event ) ),
			)
		);

		if ( is_wp_error( $response ) ) {
			return new WP_Error(
				'recaptcha_api_failed',
				__( '<strong>Error:</strong> Failed to connect to Google reCAPTCHA service. Please try again.', 'google-security-for-wordpress' )
			);
		}

		$status = wp_remote_retrieve_response_code( $response );
		$data   = json_decode( wp_remote_retrieve_body( $response ), true );

		if ( 200 !== $status || ! is_array( $data ) ) {
			// Non-200 responses indicate a configuration problem (bad API
			// key, wrong project ID, API not enabled): log it and let the
			// submission through rather than blocking every customer.
			$detail = is_array( $data ) && isset( $data['error']['message'] ) ? $data['error']['message'] : 'no detail';
			$this->log( 'Enterprise assessment request failed with HTTP ' . $status . ' (' . $detail . '). Check the GCP project ID and API key in WooCommerce > reCAPTCHA v3. Verification was skipped.' );
			return true;
		}

		// Capture the assessment name (for later annotation) and the Transaction
		// defense verdict, when the integration is complete enough to return one.
		if ( isset( $data['name'] ) ) {
			$this->last_assessment_name = sanitize_text_field( $data['name'] );
		}
		if ( isset( $data['fraudPreventionAssessment'] ) && is_array( $data['fraudPreventionAssessment'] ) ) {
			$this->last_fraud_assessment = $data['fraudPreventionAssessment'];
		}
		if ( isset( $data['accountDefenderAssessment'] ) && is_array( $data['accountDefenderAssessment'] ) ) {
			$this->last_account_assessment = $data['accountDefenderAssessment'];
		}

		$token_properties = isset( $data['tokenProperties'] ) && is_array( $data['tokenProperties'] ) ? $data['tokenProperties'] : array();

		if ( empty( $token_properties['valid'] ) ) {
			$reason = isset( $token_properties['invalidReason'] ) ? $token_properties['invalidReason'] : 'UNKNOWN';

			// Expired or already-used tokens just need a fresh attempt.
			if ( in_array( $reason, array( 'EXPIRED', 'DUPE' ), true ) ) {
				return new WP_Error(
					'recaptcha_expired',
					__( '<strong>Error:</strong> Anti-spam verification expired. Please try again.', 'google-security-for-wordpress' )
				);
			}

			return new WP_Error(
				'recaptcha_failed',
				__( '<strong>Error:</strong> Verification failed. You have been flagged as potential spam. Please try again.', 'google-security-for-wordpress' )
			);
		}

		if ( isset( $token_properties['action'] ) && $token_properties['action'] !== $expected_action ) {
			return new WP_Error(
				'recaptcha_failed',
				__( '<strong>Error:</strong> Verification failed. You have been flagged as potential spam. Please try again.', 'google-security-for-wordpress' )
			);
		}

		return isset( $data['riskAnalysis']['score'] ) ? floatval( $data['riskAnalysis']['score'] ) : 0.0;
	}

	/**
	 * Build the extra Enterprise event fields for a checkout assessment.
	 *
	 * Assembles reCAPTCHA Enterprise transactionData from the posted checkout
	 * fields and the WooCommerce cart so Transaction defense can score the
	 * payment. Returns an empty array (no transaction data) unless every
	 * precondition holds: an Enterprise key, the feature enabled, an available
	 * cart, and the minimum fields Google requires (billing region + postal
	 * code + payment method). Without that minimum the assessment API rejects
	 * the request with HTTP 400, which would also skip the reCAPTCHA score.
	 *
	 * @return array Event fields to merge (transactionData, fraudPrevention), or empty.
	 */
	private function build_checkout_event_extra() {
		if ( 'enterprise' !== get_option( 'gswp_key_type', 'classic' ) ) {
			return array();
		}
		if ( '1' !== get_option( 'gswp_txn_defense', '0' ) ) {
			return array();
		}
		if ( ! function_exists( 'WC' ) || ! WC()->cart ) {
			return array();
		}

		$billing  = $this->build_address( 'billing' );
		$shipping = $this->build_address( 'shipping' );

		// WooCommerce reuses the billing address when "ship to a different
		// address" is unchecked, in which case the shipping_* fields are blank.
		if ( empty( $shipping['regionCode'] ) && empty( $shipping['postalCode'] ) ) {
			$shipping = $billing;
		}

		$payment_method = $this->posted_field( 'payment_method' );

		// Enforce Google's documented minimum; otherwise omit transaction data
		// entirely and let the assessment run as a plain reCAPTCHA score.
		if ( empty( $billing['regionCode'] ) || empty( $billing['postalCode'] ) || '' === $payment_method ) {
			return array();
		}

		$transaction_data = array(
			'paymentMethod'  => $payment_method,
			'currencyCode'   => function_exists( 'get_woocommerce_currency' ) ? get_woocommerce_currency() : '',
			'value'          => (float) WC()->cart->get_total( 'edit' ),
			'shippingValue'  => (float) WC()->cart->get_shipping_total(),
			'billingAddress' => $billing,
		);

		if ( ! empty( $shipping['regionCode'] ) || ! empty( $shipping['postalCode'] ) ) {
			$transaction_data['shippingAddress'] = $shipping;
		}

		$user = $this->build_transaction_user();
		if ( ! empty( $user ) ) {
			$transaction_data['user'] = $user;
		}

		$items = $this->build_transaction_items();
		if ( ! empty( $items ) ) {
			$transaction_data['items'] = $items;
		}

		return array(
			'transactionData' => $transaction_data,
			// Force the fraud assessment regardless of the console toggle state.
			'fraudPrevention' => 'ENABLED',
		);
	}

	/**
	 * Read a posted checkout field, unslashed and sanitized.
	 *
	 * @param string $key Field name in $_POST.
	 * @return string Sanitized value, or '' when absent.
	 */
	private function posted_field( $key ) {
		// Nonce verification is handled by WooCommerce checkout before this
		// validation hook fires; we only read fields it has already accepted.
		// phpcs:ignore WordPress.Security.NonceVerification.Missing
		return isset( $_POST[ $key ] ) ? sanitize_text_field( wp_unslash( $_POST[ $key ] ) ) : '';
	}

	/**
	 * Build a reCAPTCHA Enterprise Address from posted billing/shipping fields.
	 *
	 * @param string $prefix Either "billing" or "shipping".
	 * @return array Address fields keyed for the assessment API.
	 */
	private function build_address( $prefix ) {
		$first = $this->posted_field( $prefix . '_first_name' );
		$last  = $this->posted_field( $prefix . '_last_name' );

		$lines = array_values(
			array_filter(
				array(
					$this->posted_field( $prefix . '_address_1' ),
					$this->posted_field( $prefix . '_address_2' ),
				)
			)
		);

		$address = array(
			'recipient'          => trim( $first . ' ' . $last ),
			'locality'           => $this->posted_field( $prefix . '_city' ),
			'administrativeArea' => $this->posted_field( $prefix . '_state' ),
			'regionCode'         => $this->posted_field( $prefix . '_country' ),
			'postalCode'         => $this->posted_field( $prefix . '_postcode' ),
		);

		if ( ! empty( $lines ) ) {
			$address['address'] = $lines;
		}

		// Drop empties so the payload only carries what we actually have.
		return array_filter(
			$address,
			static function ( $value ) {
				return '' !== $value && array() !== $value;
			}
		);
	}

	/**
	 * Build the transactionData.user block for the payer.
	 *
	 * @return array User fields keyed for the assessment API, or empty.
	 */
	private function build_transaction_user() {
		$user  = array();
		$email = $this->posted_field( 'billing_email' );

		if ( '' !== $email ) {
			$user['email'] = $email;
		}

		if ( is_user_logged_in() ) {
			$current = wp_get_current_user();
			$user['accountId']     = (string) $current->ID;
			$user['emailVerified'] = true;

			$registered = strtotime( $current->user_registered );
			if ( $registered ) {
				$user['creationMs'] = (string) ( $registered * 1000 );
			}
		}

		return $user;
	}

	/**
	 * Build the transactionData.items list from the WooCommerce cart.
	 *
	 * @return array List of item arrays keyed for the assessment API.
	 */
	private function build_transaction_items() {
		$items = array();

		foreach ( WC()->cart->get_cart() as $cart_item ) {
			$product  = isset( $cart_item['data'] ) ? $cart_item['data'] : null;
			$quantity = isset( $cart_item['quantity'] ) ? (int) $cart_item['quantity'] : 0;

			if ( ! $product || $quantity < 1 ) {
				continue;
			}

			// Per-item price after line discounts.
			$line_total = isset( $cart_item['line_total'] ) ? (float) $cart_item['line_total'] : 0.0;

			$items[] = array(
				'name'     => $product->get_name(),
				'value'    => $quantity > 0 ? round( $line_total / $quantity, 2 ) : 0.0,
				'quantity' => (string) $quantity,
			);
		}

		return $items;
	}

	/**
	 * Act on the Transaction defense verdict captured during the assessment.
	 *
	 * Logs the transaction risk, hands the assessment name to the annotation
	 * layer via the WooCommerce session (the order does not exist yet), and,
	 * when enabled, blocks orders whose risk meets the configured threshold.
	 *
	 * @param WP_Error $errors WooCommerce checkout validation errors object.
	 */
	private function process_fraud_prevention( $errors ) {
		if ( null === $this->last_fraud_assessment ) {
			return;
		}

		$risk = isset( $this->last_fraud_assessment['transactionRisk'] )
			? floatval( $this->last_fraud_assessment['transactionRisk'] )
			: null;

		// Carry the assessment name and risk to the order via the session so the
		// annotation layer can label the outcome once the order is created.
		if ( '' !== $this->last_assessment_name && function_exists( 'WC' ) && WC()->session ) {
			WC()->session->set( 'gswp_assessment_name', $this->last_assessment_name );
			if ( null !== $risk ) {
				WC()->session->set( 'gswp_transaction_risk', $risk );
			}
		}

		if ( null === $risk ) {
			return;
		}

		// The per-order risk is already recorded as an order note, so the routine
		// case stays out of the log. Only blocked checkouts are logged below;
		// every assessment is logged when verbose logging is enabled.
		if ( '1' === get_option( 'gswp_verbose_logging', '0' ) ) {
			$this->log( sprintf( 'Transaction defense risk %.2f for assessment %s.', $risk, $this->last_assessment_name ) );
		}

		// Optional, opt-in blocking. transactionRisk is a fraud probability:
		// closer to 1.0 is riskier, so block when it meets the threshold.
		if ( '1' === get_option( 'gswp_txn_block', '0' ) ) {
			$threshold = floatval( get_option( 'gswp_threshold_txn', '0.8' ) );
			if ( $risk >= $threshold ) {
				$this->log( sprintf( 'Transaction defense blocked checkout: risk %.2f >= threshold %.2f (assessment %s).', $risk, $threshold, $this->last_assessment_name ) );
				$errors->add(
					'recaptcha_transaction_risk',
					__( '<strong>Error:</strong> This transaction was flagged as high risk and cannot be completed. Please contact us if you believe this is a mistake.', 'google-security-for-wordpress' )
				);
			}
		}
	}

	/**
	 * Resource name of the most recent Enterprise assessment.
	 *
	 * @return string Assessment name, or '' when none was created this request.
	 */
	public function get_last_assessment_name() {
		return $this->last_assessment_name;
	}

	/**
	 * Account Defender labels from the most recent Enterprise assessment.
	 *
	 * @return string[] Label strings (e.g. SUSPICIOUS_LOGIN_ACTIVITY), or empty.
	 */
	public function get_last_account_labels() {
		if ( null === $this->last_account_assessment || empty( $this->last_account_assessment['labels'] ) ) {
			return array();
		}

		return array_values( (array) $this->last_account_assessment['labels'] );
	}

	/**
	 * Build the Account Defender userInfo block for a login/registration event.
	 *
	 * Returns an empty array unless Account Defender is enabled, an Enterprise
	 * key is configured, the context is a login or registration assessment, and
	 * an identifier was supplied. Only an opaque, salted account hash is sent —
	 * never the raw email, username, or phone number.
	 *
	 * @param string $context            Assessment context.
	 * @param mixed  $account_identifier WP_User, user ID, login, or email.
	 * @return array { userInfo: array } or empty array.
	 */
	private function build_account_user_info( $context, $account_identifier ) {
		if ( null === $account_identifier ) {
			return array();
		}
		if ( 'enterprise' !== get_option( 'gswp_key_type', 'classic' ) ) {
			return array();
		}
		if ( '1' !== get_option( 'gswp_account_defender', '0' ) ) {
			return array();
		}

		// Account Defender applies to account access events, not checkout.
		$account_contexts = array( 'login', 'registration', 'wp_login', 'wp_register' );
		if ( ! in_array( $context, $account_contexts, true ) ) {
			return array();
		}

		list( $account_id, $created ) = $this->resolve_account_id( $account_identifier );
		if ( '' === $account_id ) {
			return array();
		}

		$user_info = array( 'accountId' => $account_id );

		// createAccountTime is a strong signal for account-takeover and
		// fake-signup detection when the account already exists.
		if ( $created > 0 ) {
			$user_info['createAccountTime'] = gmdate( 'Y-m-d\TH:i:s\Z', $created );
		}

		return array( 'userInfo' => $user_info );
	}

	/**
	 * Resolve an identifier to a stable, opaque account hash.
	 *
	 * Existing users are keyed by their immutable user ID so the same account
	 * maps to the same hash across logins regardless of whether they signed in
	 * with a username or email. A not-yet-created account (registration) is
	 * keyed by its normalised email.
	 *
	 * @param mixed $identifier WP_User, user ID, login, or email.
	 * @return array{0:string,1:int} [ account hash, account creation epoch seconds ].
	 */
	private function resolve_account_id( $identifier ) {
		$user = null;

		if ( $identifier instanceof WP_User ) {
			$user = $identifier;
		} elseif ( is_numeric( $identifier ) ) {
			$user = get_user_by( 'id', (int) $identifier );
		} elseif ( is_string( $identifier ) && '' !== $identifier ) {
			$user = get_user_by( 'login', $identifier );
			if ( ! $user && is_email( $identifier ) ) {
				$user = get_user_by( 'email', $identifier );
			}
		}

		if ( $user instanceof WP_User ) {
			$created = strtotime( $user->user_registered . ' UTC' );
			return array( $this->hash_account( 'id:' . $user->ID ), $created ? (int) $created : 0 );
		}

		// No existing account: key registrations by their normalised email.
		if ( is_string( $identifier ) && is_email( $identifier ) ) {
			return array( $this->hash_account( 'email:' . strtolower( $identifier ) ), 0 );
		}

		if ( is_string( $identifier ) && '' !== $identifier ) {
			return array( $this->hash_account( 'login:' . strtolower( $identifier ) ), 0 );
		}

		return array( '', 0 );
	}

	/**
	 * Hash an identifier with a stable site-specific salt.
	 *
	 * The salt is generated once and stored, so the same account always yields
	 * the same opaque hash without exposing any personal data to Google.
	 *
	 * @param string $value Pre-namespaced identifier (e.g. "id:42").
	 * @return string 64-char hex hash.
	 */
	private function hash_account( $value ) {
		$salt = get_option( 'gswp_account_salt', '' );
		if ( '' === $salt ) {
			$salt = wp_generate_password( 64, true, true );
			update_option( 'gswp_account_salt', $salt, false );
		}

		return hash( 'sha256', $salt . '|' . $value );
	}

	/**
	 * Get the visitor IP for the verification request.
	 *
	 * @return string Remote IP address.
	 */
	private function get_remote_ip() {
		return isset( $_SERVER['REMOTE_ADDR'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ) ) : '';
	}

	/**
	 * Log a verification warning to the WooCommerce logger when available.
	 *
	 * @param string $message Log message.
	 */
	private function log( $message ) {
		if ( function_exists( 'wc_get_logger' ) ) {
			wc_get_logger()->warning( $message, array( 'source' => 'gswp' ) );
		}
	}
}
