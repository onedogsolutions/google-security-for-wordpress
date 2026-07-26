<?php
/**
 * Gravity Forms Provider
 *
 * Makes this plugin the reCAPTCHA implementation for Gravity Forms, so GF's own
 * reCAPTCHA can eventually be switched off.
 *
 * ---------------------------------------------------------------------------
 * VERIFICATION STATUS
 *
 * The Gravity Forms bindings below (hook names, feed meta keys, native-captcha
 * option names) were written WITHOUT the installed Gravity Forms source to hand
 * and are marked individually. Writing GF integration code from assumption is
 * the defect that produced the 2.16.0 Stripe outage, so every host-plugin call
 * here is guarded and fails to the pessimistic answer:
 *
 *   - an unrecognised captcha state returns 'unknown', never 'off';
 *   - a form we cannot inspect is ineligible, so we do not claim to cover it;
 *   - a form we cannot classify is treated as a PAYMENT form, so it fails
 *     closed rather than silently fails open on a real payment;
 *   - unreadable transaction mappings yield no transactionData, which
 *     GSWP_Verifier already degrades to a plain score rather than an API error.
 *
 * Combined with the registry's default stage of 'off' and the 'sole' gate on a
 * clean coverage audit, a wrong binding costs coverage — which the audit then
 * reports — and cannot break a form or silently drop protection while GF's own
 * reCAPTCHA is still running.
 *
 * Confirm against the installed source before advancing any form to 'sole'.
 * ---------------------------------------------------------------------------
 *
 * @package Google_Security_For_WordPress
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class GSWP_Provider_Gravity_Forms implements GSWP_Form_Provider {

	/**
	 * Name of the hidden token field injected into GF forms.
	 *
	 * Deliberately NOT 'g-recaptcha-response': that name is read by
	 * GSWP_Verifier for WooCommerce and may be read by GF for its own reCAPTCHA
	 * field. The class attribute is what matters — the shared footer bootstrap
	 * fills every .g-recaptcha-response on the page.
	 */
	const TOKEN_FIELD = 'gswp_gf_token';

	/**
	 * Entry meta key holding the assessment resource name.
	 */
	const META_ASSESSMENT = 'gswp_assessment_name';

	/**
	 * Entry meta key flagging an entry admitted without a verified token
	 * (fail-open on a non-payment form).
	 */
	const META_UNVERIFIED = 'gswp_unverified';

	/**
	 * Entry meta key guarding against double annotation.
	 */
	const META_ANNOTATED = 'gswp_annotated';

	/**
	 * Add-on slugs whose presence marks a form as taking payment.
	 *
	 * UNVERIFIED against installed source. Incompleteness is safe: an
	 * unrecognised feed falls through to the product-field check below, and a
	 * form we cannot classify is treated as a payment form.
	 *
	 * @var string[]
	 */
	private static $payment_addons = array(
		'gravityformsstripe',
		'gravityformspaypal',
		'gravityformspaypalcheckout',
		'gravityformssquare',
		'gravityformsauthorizenet',
		'gravityforms2checkout',
		'gravityformsmollie',
		'gravityformsrazorpay',
	);

	/**
	 * Shared verifier.
	 *
	 * @var GSWP_Verifier|null
	 */
	private $verifier = null;

	/**
	 * Error message to surface on a rejected submission, per form.
	 *
	 * @var array<int,string>
	 */
	private $errors = array();

	/**
	 * Assessment name captured during validation, awaiting an entry to store it
	 * on. Keyed by form id.
	 *
	 * @var array<int,string>
	 */
	private $pending_assessment = array();

	/**
	 * Forms admitted this request without a verified token.
	 *
	 * @var array<int,bool>
	 */
	private $pending_unverified = array();

	/**
	 * {@inheritDoc}
	 */
	public function id() {
		return 'gravity-forms';
	}

	/**
	 * {@inheritDoc}
	 */
	public function label() {
		return 'Gravity Forms';
	}

	/**
	 * {@inheritDoc}
	 */
	public function is_active() {
		return class_exists( 'GFAPI' ) && ( defined( 'GF_VERSION' ) || class_exists( 'GFCommon' ) );
	}

	/**
	 * {@inheritDoc}
	 */
	public function forms() {
		if ( ! $this->is_active() || ! method_exists( 'GFAPI', 'get_forms' ) ) {
			return array();
		}

		$forms = GFAPI::get_forms( true );
		if ( ! is_array( $forms ) ) {
			return array();
		}

		$out = array();
		foreach ( $forms as $form ) {
			if ( ! is_array( $form ) || ! isset( $form['id'] ) ) {
				continue;
			}
			$out[ (int) $form['id'] ] = isset( $form['title'] ) ? (string) $form['title'] : ( '#' . $form['id'] );
		}

		return $out;
	}

	/**
	 * {@inheritDoc}
	 *
	 * A form is ineligible when it uses a visible v2 checkbox challenge. Our
	 * implementation is score-only, so replacing that would change both the UX
	 * and the threat model. Those forms keep GF's own reCAPTCHA — partial
	 * takeover is a supported end state, not a failure.
	 */
	public function form_is_eligible( $form_id ) {
		$form = $this->form( $form_id );
		if ( null === $form ) {
			// Cannot inspect it, so do not claim to cover it.
			return false;
		}

		return 'v2' !== $this->native_captcha_state( $form_id );
	}

	/**
	 * {@inheritDoc}
	 *
	 * Deliberately biased toward "yes". A form wrongly classified as payment
	 * fails closed on a missing token, which is an inconvenience. A payment form
	 * wrongly classified as non-payment fails open, which is a hole. When in
	 * doubt, choose the inconvenience.
	 */
	public function form_has_payment( $form_id ) {
		$form = $this->form( $form_id );
		if ( null === $form ) {
			return true;
		}

		// An active feed from a known payment add-on.
		if ( method_exists( 'GFAPI', 'get_feeds' ) ) {
			$feeds = GFAPI::get_feeds( null, (int) $form_id );
			if ( is_array( $feeds ) ) {
				foreach ( $feeds as $feed ) {
					if ( empty( $feed['is_active'] ) ) {
						continue;
					}
					$slug = isset( $feed['addon_slug'] ) ? (string) $feed['addon_slug'] : '';
					if ( in_array( $slug, self::$payment_addons, true ) ) {
						return true;
					}
				}
			}
		}

		// Fallback: any pricing field means money is being quoted, which is
		// enough to warrant the stricter policy.
		if ( ! empty( $form['fields'] ) && is_array( $form['fields'] ) ) {
			foreach ( $form['fields'] as $field ) {
				$type = is_object( $field ) && isset( $field->type ) ? $field->type : '';
				if ( in_array( $type, array( 'product', 'total', 'shipping', 'option', 'creditcard' ), true ) ) {
					return true;
				}
			}
		}

		return false;
	}

	/**
	 * {@inheritDoc}
	 *
	 * UNVERIFIED: the reCAPTCHA add-on's option name is a candidate list rather
	 * than a confirmed key, so a v3 integration this does not recognise reports
	 * 'unknown'. That is the safe direction — 'unknown' never lets the settings
	 * UI claim GF's reCAPTCHA is already off.
	 */
	public function native_captcha_state( $form_id ) {
		$form = $this->form( $form_id );
		if ( null === $form ) {
			return 'unknown';
		}

		// A CAPTCHA field on the form is the visible-challenge case.
		if ( ! empty( $form['fields'] ) && is_array( $form['fields'] ) ) {
			foreach ( $form['fields'] as $field ) {
				$type = is_object( $field ) && isset( $field->type ) ? $field->type : '';
				if ( 'captcha' !== $type ) {
					continue;
				}

				$captcha_type = isset( $field->captchaType ) ? (string) $field->captchaType : 'recaptcha'; // phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- Gravity Forms property.

				// 'math' and 'simple_captcha' are GF's own non-reCAPTCHA
				// challenges; they do not load Google reCAPTCHA and do not
				// conflict, so they are not our concern.
				if ( in_array( $captcha_type, array( 'math', 'simple_captcha' ), true ) ) {
					continue;
				}

				return 'v2';
			}
		}

		// The reCAPTCHA add-on (v3 / Enterprise) is configured site-wide.
		foreach ( $this->native_v3_option_candidates() as $option ) {
			$settings = get_option( $option, null );
			if ( ! is_array( $settings ) ) {
				continue;
			}
			foreach ( array( 'site_key', 'public_key', 'siteKey' ) as $key ) {
				if ( ! empty( $settings[ $key ] ) ) {
					return 'v3';
				}
			}
		}

		return 'unknown';
	}

	/**
	 * Candidate option names for GF's v3 reCAPTCHA add-on settings.
	 *
	 * UNVERIFIED. Filterable so a site can correct it without a code change,
	 * which is also how the staging discovery pass can confirm the real key
	 * before it is hard-coded.
	 *
	 * @return string[]
	 */
	private function native_v3_option_candidates() {
		return (array) apply_filters(
			'gswp_gf_native_recaptcha_options',
			array(
				'gravityformsaddon_gravityformsrecaptcha_settings',
				'gravityformsaddon_recaptcha_settings',
			)
		);
	}

	/**
	 * Fetch a form definition, or null when unavailable.
	 *
	 * @param int|string $form_id Form identifier.
	 * @return array|null
	 */
	private function form( $form_id ) {
		if ( ! $this->is_active() || ! method_exists( 'GFAPI', 'get_form' ) ) {
			return null;
		}

		$form = GFAPI::get_form( (int) $form_id );

		return is_array( $form ) ? $form : null;
	}

	/**
	 * {@inheritDoc}
	 */
	public function register_hooks( GSWP_Verifier $verifier ) {
		$this->verifier = $verifier;

		// UNVERIFIED hook choice: gform_submit_button is the conventional
		// injection point inside the <form> element. Confirm it fires for every
		// render path (multi-page, AJAX, conditional logic) during staging —
		// scenario D of the test plan exists precisely to catch a miss here.
		add_filter( 'gform_submit_button', array( $this, 'inject_token_field' ), 10, 2 );

		// UNVERIFIED hook choice: gform_validation is GF's canonical validation
		// filter and runs before payment feeds process. The critical unknown is
		// whether the card is authorised client-side before submission in the
		// configured Stripe mode; if so, a rejection here stops the entry but
		// not the authorisation.
		add_filter( 'gform_validation', array( $this, 'validate_submission' ), 20 );
		add_filter( 'gform_validation_message', array( $this, 'validation_message' ), 10, 2 );

		// Persist the assessment name and any fail-open flag onto the entry.
		add_action( 'gform_entry_created', array( $this, 'store_entry_meta' ), 10, 2 );

		// Payment lifecycle → Transaction Defense annotation.
		add_action( 'gform_post_payment_completed', array( $this, 'on_payment_completed' ), 10, 2 );
		add_action( 'gform_post_payment_refunded', array( $this, 'on_payment_refunded' ), 10, 2 );
	}

	/**
	 * Inject the hidden token field immediately before the submit button.
	 *
	 * @param string $button Submit button markup.
	 * @param array  $form   Form definition.
	 * @return string Button markup with our field prepended.
	 */
	public function inject_token_field( $button, $form ) {
		if ( ! is_array( $form ) || empty( $form['id'] ) ) {
			return $button;
		}
		if ( ! GSWP_Recaptcha_Loader::will_load() ) {
			return $button;
		}
		if ( ! $this->form_is_eligible( $form['id'] ) ) {
			return $button;
		}

		// Shares the page's single loader (2.18.0) and the footer bootstrap,
		// which fills every .g-recaptcha-response and refreshes it before the
		// 120-second expiry. No provider-specific JavaScript.
		GSWP_Recaptcha_Loader::enqueue();

		$field = sprintf(
			'<input type="hidden" name="%s" class="g-recaptcha-response" data-recaptcha-action="%s" value="" />',
			esc_attr( self::TOKEN_FIELD ),
			esc_attr( $this->form_has_payment( $form['id'] ) ? 'checkout' : 'submit' )
		);

		return $field . $button;
	}

	/**
	 * Score a submission and, outside shadow mode, reject it when warranted.
	 *
	 * @param array $validation_result GF validation result.
	 * @return array Filtered validation result.
	 */
	public function validate_submission( $validation_result ) {
		if ( ! is_array( $validation_result ) || empty( $validation_result['form'] ) ) {
			return $validation_result;
		}

		$form = $validation_result['form'];
		if ( ! is_array( $form ) || empty( $form['id'] ) ) {
			return $validation_result;
		}

		$form_id = (int) $form['id'];

		// Never re-judge a submission GF has already rejected.
		if ( isset( $validation_result['is_valid'] ) && ! $validation_result['is_valid'] ) {
			return $validation_result;
		}
		if ( ! $this->form_is_eligible( $form_id ) ) {
			return $validation_result;
		}

		$mode    = GSWP_Form_Provider_Registry::mode( $this->id() );
		$shadow  = ( 'shadow' === $mode );
		$payment = $this->form_has_payment( $form_id );

		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- Gravity Forms validates its own nonce before this filter runs.
		$token = isset( $_POST[ self::TOKEN_FIELD ] ) ? sanitize_text_field( wp_unslash( $_POST[ self::TOKEN_FIELD ] ) ) : '';

		if ( '' === $token ) {
			// Asymmetric enforcement. The decision is read from the stored form
			// definition, never from the request — a request-derived predicate
			// would let a caller opt out by omitting the field, which is the
			// bypass class removed in 2.17.0.
			if ( $payment && ! $shadow ) {
				return $this->reject(
					$validation_result,
					__( 'We could not verify this submission. Please refresh the page and try again.', 'google-security-for-wordpress' ),
					$form_id
				);
			}

			$this->pending_unverified[ $form_id ] = true;
			$this->log(
				sprintf(
					'Gravity Forms #%d submitted with no reCAPTCHA token; admitted (%s). If this repeats, token generation is broken on that page.',
					$form_id,
					$shadow ? 'shadow mode' : 'non-payment form, fail-open'
				)
			);

			return $validation_result;
		}

		$context     = $payment ? 'checkout' : 'wp_register';
		$action      = $payment ? 'checkout' : 'submit';
		$event_extra = $payment ? $this->payment_context( $form, $form_id ) : array();

		$result = $this->verifier->verify_token( $context, $action, $event_extra, null, $token );

		$name = $this->verifier->get_last_assessment_name();
		if ( '' !== $name ) {
			$this->pending_assessment[ $form_id ] = $name;
		}

		if ( is_wp_error( $result ) ) {
			if ( $shadow ) {
				$this->log(
					sprintf(
						'SHADOW: Gravity Forms #%d would have been rejected (%s). Not blocked.',
						$form_id,
						$result->get_error_code()
					)
				);

				return $validation_result;
			}

			return $this->reject( $validation_result, wp_strip_all_tags( $result->get_error_message() ), $form_id );
		}

		// Transaction Defense verdict on payment forms.
		if ( $payment ) {
			$risk = $this->verifier->get_last_fraud_risk();
			if ( null !== $risk ) {
				if ( '1' === get_option( 'gswp_verbose_logging', '0' ) ) {
					$this->log( sprintf( 'Gravity Forms #%d transaction risk %.2f.', $form_id, $risk ) );
				}

				if ( '1' === get_option( 'gswp_txn_block', '0' ) ) {
					$threshold = floatval( get_option( 'gswp_threshold_txn', '0.8' ) );
					if ( $risk >= $threshold ) {
						$this->log( sprintf( 'Gravity Forms #%d %s: risk %.2f >= %.2f.', $form_id, $shadow ? 'would be blocked' : 'blocked', $risk, $threshold ) );

						do_action(
							'gswp_checkout_blocked',
							$risk,
							$threshold,
							array(
								'source'     => 'gravity-forms',
								'assessment' => $name,
								'form_id'    => $form_id,
							)
						);

						if ( ! $shadow ) {
							return $this->reject(
								$validation_result,
								__( 'This transaction was flagged as high risk and cannot be completed. Please contact us if you believe this is a mistake.', 'google-security-for-wordpress' ),
								$form_id
							);
						}
					}
				}
			}
		}

		if ( $shadow && '1' === get_option( 'gswp_verbose_logging', '0' ) ) {
			$this->log( sprintf( 'SHADOW: Gravity Forms #%d passed.', $form_id ) );
		}

		return $validation_result;
	}

	/**
	 * Mark a validation result as failed and record the message.
	 *
	 * @param array  $validation_result GF validation result.
	 * @param string $message           Customer-facing message.
	 * @param int    $form_id           Form id.
	 * @return array
	 */
	private function reject( $validation_result, $message, $form_id ) {
		$validation_result['is_valid'] = false;
		$this->errors[ $form_id ]      = $message;

		return $validation_result;
	}

	/**
	 * Replace GF's generic validation message with ours when we rejected.
	 *
	 * @param string $message Existing message markup.
	 * @param array  $form    Form definition.
	 * @return string
	 */
	public function validation_message( $message, $form ) {
		$form_id = is_array( $form ) && isset( $form['id'] ) ? (int) $form['id'] : 0;

		if ( ! isset( $this->errors[ $form_id ] ) ) {
			return $message;
		}

		return '<div class="validation_error gswp-validation-error">'
			. esc_html( $this->errors[ $form_id ] )
			. '</div>';
	}

	/**
	 * Build transactionData for a payment form from its payment feed mapping.
	 *
	 * UNVERIFIED: feed meta keys are inferred. Returning an empty array is
	 * safe — GSWP_Verifier enforces Google's documented minimum (billing region
	 * + postal code + payment method) and omits transaction data entirely when
	 * it is unmet, degrading to a plain score rather than an API error.
	 *
	 * @param array $form    Form definition.
	 * @param int   $form_id Form id.
	 * @return array Event extras, or empty.
	 */
	private function payment_context( $form, $form_id ) {
		if ( 'enterprise' !== get_option( 'gswp_key_type', 'classic' ) ) {
			return array();
		}
		if ( '1' !== get_option( 'gswp_txn_defense', '0' ) ) {
			return array();
		}
		if ( ! method_exists( 'GFAPI', 'get_feeds' ) ) {
			return array();
		}

		$feeds = GFAPI::get_feeds( null, $form_id );
		if ( ! is_array( $feeds ) ) {
			return array();
		}

		$feed = null;
		foreach ( $feeds as $candidate ) {
			if ( empty( $candidate['is_active'] ) || empty( $candidate['meta'] ) ) {
				continue;
			}
			$slug = isset( $candidate['addon_slug'] ) ? (string) $candidate['addon_slug'] : '';
			if ( in_array( $slug, self::$payment_addons, true ) ) {
				$feed = $candidate;
				break;
			}
		}

		if ( null === $feed ) {
			return array();
		}

		$meta = is_array( $feed['meta'] ) ? $feed['meta'] : array();

		// The operator has already mapped these fields so the gateway knows who
		// is paying. Reusing that mapping avoids a second, drift-prone mapping
		// UI of our own.
		$billing = array_filter(
			array(
				'recipient'          => trim( $this->mapped( $meta, 'billingInformation_first_name' ) . ' ' . $this->mapped( $meta, 'billingInformation_last_name' ) ),
				'locality'           => $this->mapped( $meta, 'billingInformation_city' ),
				'administrativeArea' => $this->mapped( $meta, 'billingInformation_state' ),
				'regionCode'         => $this->mapped( $meta, 'billingInformation_country' ),
				'postalCode'         => $this->mapped( $meta, 'billingInformation_zip' ),
			),
			static function ( $value ) {
				return '' !== $value;
			}
		);

		$line1 = $this->mapped( $meta, 'billingInformation_address' );
		if ( '' !== $line1 ) {
			$billing['address'] = array( $line1 );
		}

		if ( empty( $billing['regionCode'] ) || empty( $billing['postalCode'] ) ) {
			return array();
		}

		$total = $this->order_total( $form );
		if ( null === $total ) {
			return array();
		}

		$transaction = array(
			'paymentMethod'  => isset( $feed['addon_slug'] ) ? str_replace( 'gravityforms', '', (string) $feed['addon_slug'] ) : 'unknown',
			'currencyCode'   => class_exists( 'GFCommon' ) && method_exists( 'GFCommon', 'get_currency' ) ? GFCommon::get_currency() : '',
			'value'          => (float) $total,
			'billingAddress' => $billing,
		);

		$email = $this->mapped( $meta, 'billingInformation_email' );
		if ( '' !== $email ) {
			$transaction['user'] = array( 'email' => $email );
		}

		return array(
			'transactionData' => $transaction,
			'fraudPrevention' => 'ENABLED',
		);
	}

	/**
	 * Resolve a feed mapping to its submitted value.
	 *
	 * @param array  $meta Feed meta.
	 * @param string $key  Mapping key.
	 * @return string Submitted value, or ''.
	 */
	private function mapped( $meta, $key ) {
		if ( empty( $meta[ $key ] ) ) {
			return '';
		}

		$field_id = $meta[ $key ];

		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- Gravity Forms validates its own nonce before validation runs.
		$posted = isset( $_POST[ 'input_' . str_replace( '.', '_', (string) $field_id ) ] )
			// phpcs:ignore WordPress.Security.NonceVerification.Missing
			? sanitize_text_field( wp_unslash( $_POST[ 'input_' . str_replace( '.', '_', (string) $field_id ) ] ) )
			: '';

		return $posted;
	}

	/**
	 * Order total for the submission being validated.
	 *
	 * @param array $form Form definition.
	 * @return float|null Total, or null when it cannot be determined.
	 */
	private function order_total( $form ) {
		if ( ! class_exists( 'GFCommon' ) || ! method_exists( 'GFCommon', 'get_order_total' ) ) {
			return null;
		}

		// GFCommon::get_order_total() accepts the submitted values during
		// validation via GF's own field-value resolution.
		$total = GFCommon::get_order_total( $form, array() );

		return is_numeric( $total ) ? (float) $total : null;
	}

	/**
	 * Persist the assessment name and any fail-open flag onto the new entry.
	 *
	 * @param array $entry Entry.
	 * @param array $form  Form definition.
	 */
	public function store_entry_meta( $entry, $form ) {
		$form_id  = is_array( $form ) && isset( $form['id'] ) ? (int) $form['id'] : 0;
		$entry_id = is_array( $entry ) && isset( $entry['id'] ) ? (int) $entry['id'] : 0;

		if ( ! $entry_id || ! function_exists( 'gform_update_meta' ) ) {
			return;
		}

		if ( ! empty( $this->pending_assessment[ $form_id ] ) ) {
			gform_update_meta( $entry_id, self::META_ASSESSMENT, $this->pending_assessment[ $form_id ] );
		}

		if ( ! empty( $this->pending_unverified[ $form_id ] ) ) {
			// Flagged rather than silent: a real breakage in token generation
			// shows up as a burst of unverified entries instead of nothing.
			gform_update_meta( $entry_id, self::META_UNVERIFIED, '1' );
		}
	}

	/**
	 * Annotate the assessment as legitimate once payment completes.
	 *
	 * @param array $entry  Entry.
	 * @param array $action Payment action data.
	 */
	public function on_payment_completed( $entry, $action ) {
		$this->annotate( $entry, 'LEGITIMATE', 'PAYMENT' );
	}

	/**
	 * Annotate the assessment as fraudulent on refund or chargeback.
	 *
	 * @param array $entry  Entry.
	 * @param array $action Payment action data.
	 */
	public function on_payment_refunded( $entry, $action ) {
		$this->annotate( $entry, 'FRAUDULENT', 'REFUND' );
	}

	/**
	 * Send an annotation for an entry's stored assessment.
	 *
	 * @param array  $entry      Entry.
	 * @param string $annotation LEGITIMATE or FRAUDULENT.
	 * @param string $event_type transactionEvent eventType.
	 */
	private function annotate( $entry, $annotation, $event_type ) {
		$entry_id = is_array( $entry ) && isset( $entry['id'] ) ? (int) $entry['id'] : 0;

		if ( ! $entry_id || ! function_exists( 'gform_get_meta' ) || ! function_exists( 'gform_update_meta' ) ) {
			return;
		}
		if ( ! class_exists( 'GSWP_Transaction_Defense' ) ) {
			return;
		}
		if ( gform_get_meta( $entry_id, self::META_ANNOTATED ) ) {
			return;
		}

		$name = gform_get_meta( $entry_id, self::META_ASSESSMENT );
		if ( empty( $name ) ) {
			return;
		}

		$sent = GSWP_Transaction_Defense::annotate_assessment( (string) $name, $annotation, $event_type );
		if ( $sent ) {
			gform_update_meta( $entry_id, self::META_ANNOTATED, $annotation );
		}
	}

	/**
	 * Log to the WooCommerce logger when available.
	 *
	 * @param string $message Log message.
	 */
	private function log( $message ) {
		if ( function_exists( 'wc_get_logger' ) ) {
			wc_get_logger()->warning( $message, array( 'source' => 'gswp' ) );
		} elseif ( defined( 'WP_DEBUG' ) && WP_DEBUG ) {
			error_log( 'GSWP Gravity Forms: ' . $message ); // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log
		}
	}
}
