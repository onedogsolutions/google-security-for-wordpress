<?php
/**
 * Fluent Forms Provider
 *
 * Makes this plugin the reCAPTCHA implementation for Fluent Forms, to the same
 * specification as GSWP_Provider_Gravity_Forms.
 *
 * Like the Gravity Forms provider, it NEVER switches Fluent Forms' own captcha
 * off and never writes to a Fluent Forms option. Detection drives the coverage
 * report and the operator notice; retiring the host plugin's captcha is the
 * operator's action. Reads of Fluent Forms' settings go straight to the
 * database rather than through get_option(), so nothing this plugin does can
 * colour what it reports about another plugin.
 *
 * ---------------------------------------------------------------------------
 * VERIFICATION STATUS
 *
 * Written from vendor documentation reached only through search excerpts — the
 * documentation site is blocked from the authoring environment — plus one
 * option name this project confirmed against a live install during the Smart
 * Key Scavenger work. See PLAN-fluent-forms-provider.md §0 and §4.
 *
 * Every host-plugin binding below is therefore marked and every one fails to
 * the pessimistic answer:
 *
 *   - an unrecognised captcha state returns 'unknown', never 'off';
 *   - a form we cannot inspect is ineligible, so we do not claim to cover it;
 *   - a form we cannot classify is treated as a PAYMENT form, so it fails
 *     closed rather than silently fails open on a real payment;
 *   - a User Registration feed whose type cannot be read is treated as
 *     'create', the stricter reading;
 *   - unreadable billing mappings yield no transactionData, which
 *     GSWP_Verifier already degrades to a plain score rather than an API error.
 *
 * Three Fluent Forms specifics carry more weight than any hook name:
 *
 *   1. SUBMISSION TRANSPORT. Fluent Forms submits over AJAX and serialises the
 *      form into a single request parameter, so the token is very probably NOT
 *      at $_POST[ TOKEN_FIELD ]. submitted_token() tries three transports and
 *      is correct under any of them. Reading the token from the request is
 *      fine — it is request data. What is never request-derived is the
 *      ENFORCEMENT DECISION: form_is_strict() reads the stored form definition,
 *      so a caller cannot opt out by omitting a field (the bypass class removed
 *      in 2.17.0).
 *
 *   2. REJECTION VISIBILITY. Fluent Forms attaches validation errors to fields.
 *      Our token field is not one of its registered fields, so an error keyed
 *      to it may be delivered and then dropped for want of a DOM node to attach
 *      it to — the visitor sees the button spin and stop, with nothing on
 *      screen. This plugin must have no branch that hangs a submission, so
 *      error_field_for() resolves a real field to carry the message.
 *
 *   3. NO WHOLE-MARKUP FILTER. Fluent Forms has no equivalent of
 *      gform_get_form_filter, so the coverage backstop is a gated output
 *      buffer. It only opens for a form whose primary injection point has
 *      already been observed to miss, and it refuses to close a buffer it does
 *      not own.
 * ---------------------------------------------------------------------------
 *
 * @package Google_Security_For_WordPress
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class GSWP_Provider_Fluent_Forms implements GSWP_Form_Provider {

	/**
	 * Name of the hidden token field injected into Fluent Forms forms.
	 *
	 * Distinct from the Gravity Forms provider's field so the two never collide
	 * on a page carrying both. Deliberately NOT 'g-recaptcha-response': that
	 * name is read by GSWP_Verifier for WooCommerce and may be read by Fluent
	 * Forms for its own reCAPTCHA field. The class attribute is what matters —
	 * the shared footer bootstrap fills every .g-recaptcha-response on the page.
	 */
	const TOKEN_FIELD = 'gswp_ff_token';

	/**
	 * Submission meta key holding the assessment resource name.
	 */
	const META_ASSESSMENT = 'gswp_assessment_name';

	/**
	 * Submission meta key flagging a submission admitted without a verified
	 * token (fail-open on a non-strict form).
	 */
	const META_UNVERIFIED = 'gswp_unverified';

	/**
	 * Submission meta key guarding against double annotation.
	 */
	const META_ANNOTATED = 'gswp_annotated';

	/**
	 * Option recording, per form, when a token field was last successfully
	 * injected on a real front-end render.
	 *
	 * What turns a coverage gap from silent into loud: a submission with no
	 * token on a form we have never injected into is our bug, not an attack,
	 * and must not be punished.
	 */
	const INJECTION_OPTION = 'gswp_ff_injection_log';

	/**
	 * Option recording, per form, why the last submission was rejected.
	 */
	const REJECTION_OPTION = 'gswp_ff_last_rejection';

	/**
	 * Option listing form ids that are never submitted by a visitor.
	 *
	 * An operator declaration, never inferred from the request. It suppresses
	 * exactly one thing — the missing-token alarm (coverage gap, error log,
	 * operator email) — and nothing else. A submission carrying a token is
	 * scored whatever this says, so the declaration is inert on any form a
	 * human can actually reach.
	 *
	 * The Gravity Forms provider learned this the hard way: its first cut made
	 * an internal form ineligible, which silently stripped bot scoring from a
	 * password-change form reachable in a browser. A reporting preference must
	 * never be able to remove protection.
	 */
	const INTERNAL_OPTION = 'gswp_ff_internal_forms';

	/**
	 * Field elements that mean the form quotes or takes money.
	 *
	 * PARTIAL: element names follow Fluent Forms' documented payment field set.
	 * Incompleteness is safe — the authoritative signal is the `has_payment`
	 * column, this is the fallback, and a form we cannot classify at all is
	 * treated as a payment form.
	 *
	 * @var string[]
	 */
	private static $payment_elements = array(
		'payment_method',
		'custom_payment_component',
		'multi_payment_component',
		'subscription_payment_component',
		'item_quantity_component',
		'payment_summary_component',
	);

	/**
	 * Field elements that carry a password.
	 *
	 * @var string[]
	 */
	private static $password_elements = array( 'input_password' );

	/**
	 * Captcha field elements, mapped to the state they imply.
	 *
	 * Fluent Forms ships three challenge products. Only reCAPTCHA maps onto the
	 * states this plugin has an opinion about; hCaptcha and Turnstile are
	 * reported as 'other' — a captcha we neither provide nor recognise — which
	 * makes the form ineligible without misnaming the product to the operator.
	 *
	 * PARTIAL.
	 *
	 * @var array<string,string>
	 */
	private static $captcha_elements = array(
		'recaptcha' => 'recaptcha',
		'hcaptcha'  => 'other',
		'turnstile' => 'other',
	);

	/**
	 * Per-request cache of derived form data and classification.
	 *
	 * Classification runs on the render path as well as the validation path
	 * (the action a form's token is minted with depends on it) and each answer
	 * costs a query. A page with several forms would repeat those per render
	 * hook without this.
	 *
	 * @var array<string,array<int,mixed>>
	 */
	private $memo = array();

	/**
	 * Shared verifier.
	 *
	 * @var GSWP_Verifier|null
	 */
	private $verifier = null;

	/**
	 * Output-buffer nesting level recorded when a backstop buffer was opened,
	 * keyed by form id. Used to refuse to close a buffer we do not own.
	 *
	 * @var array<int,int>
	 */
	private $buffer_level = array();

	/**
	 * Assessment name captured during validation, awaiting a submission to
	 * store it on. Keyed by form id.
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
		return 'fluent-forms';
	}

	/**
	 * {@inheritDoc}
	 */
	public function label() {
		return 'Fluent Forms';
	}

	/**
	 * {@inheritDoc}
	 *
	 * Deliberately NOT a namespaced class_exists() alone. That is the Phase 45
	 * defect verbatim: an unqualified class_exists() against a namespaced class
	 * reported "not loaded" for an add-on that was active the whole time. A
	 * constant plus the presence of the forms table answers the question
	 * without needing to know Fluent Forms' internal namespace.
	 */
	public function is_active() {
		$cached = $this->memo_get( 'active', 0 );
		if ( null !== $cached ) {
			return $cached;
		}

		$loaded = defined( 'FLUENTFORM' )
			|| defined( 'FLUENTFORM_VERSION' )
			|| function_exists( 'wpFluentForm' )
			|| function_exists( 'fluentFormApi' );

		if ( ! $loaded ) {
			return $this->memo_set( 'active', 0, false );
		}

		return $this->memo_set( 'active', 0, '' !== $this->forms_table() );
	}

	/**
	 * Name of the Fluent Forms forms table, when it exists.
	 *
	 * @return string Table name, or '' when absent or unreadable.
	 */
	private function forms_table() {
		return $this->table( 'fluentform_forms' );
	}

	/**
	 * Resolve a Fluent Forms table name, confirming it exists.
	 *
	 * @param string $suffix Unprefixed table name.
	 * @return string Prefixed table name, or '' when absent.
	 */
	private function table( $suffix ) {
		global $wpdb;

		if ( ! $wpdb ) {
			return '';
		}

		$cached = $this->memo_get( 'table_' . $suffix, 0 );
		if ( null !== $cached ) {
			return (string) $cached;
		}

		$table = $wpdb->prefix . $suffix;
		$found = $wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', $table ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL

		return (string) $this->memo_set( 'table_' . $suffix, 0, $found === $table ? $table : '' );
	}

	/**
	 * {@inheritDoc}
	 */
	public function forms() {
		global $wpdb;

		$table = $this->is_active() ? $this->forms_table() : '';
		if ( '' === $table ) {
			return array();
		}

		$rows = $wpdb->get_results( "SELECT id, title FROM {$table} ORDER BY id ASC", ARRAY_A ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL

		if ( ! is_array( $rows ) ) {
			return array();
		}

		$out = array();
		foreach ( $rows as $row ) {
			if ( ! isset( $row['id'] ) ) {
				continue;
			}
			$id         = (int) $row['id'];
			$out[ $id ] = isset( $row['title'] ) && '' !== $row['title'] ? (string) $row['title'] : ( '#' . $id );
		}

		return $out;
	}

	/**
	 * Fetch a form row, or null when unavailable.
	 *
	 * @param int|string $form_id Form identifier.
	 * @return array|null Row with 'id', 'title', 'has_payment', 'fields'.
	 */
	private function form( $form_id ) {
		global $wpdb;

		$cached = $this->memo_get( 'form', $form_id );
		if ( null !== $cached ) {
			return false === $cached ? null : $cached;
		}

		$table = $this->is_active() ? $this->forms_table() : '';
		if ( '' === $table ) {
			$this->memo_set( 'form', $form_id, false );

			return null;
		}

		$row = $wpdb->get_row( $wpdb->prepare( "SELECT * FROM {$table} WHERE id = %d LIMIT 1", (int) $form_id ), ARRAY_A ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL

		if ( ! is_array( $row ) ) {
			$this->memo_set( 'form', $form_id, false );

			return null;
		}

		$row['fields'] = $this->decode_fields( isset( $row['form_fields'] ) ? $row['form_fields'] : '' );

		return $this->memo_set( 'form', $form_id, $row );
	}

	/**
	 * Flatten a form's field definition into a list of leaf fields.
	 *
	 * Fluent Forms nests fields inside container elements (columns), so a flat
	 * read of the top level misses everything inside a multi-column row — which
	 * on a real form is most of it, including the payment and password fields
	 * this class classifies on.
	 *
	 * PARTIAL: the JSON shape ({"fields": [ { "element": ..., "attributes": {
	 * "name": ... }, "columns": [ { "fields": [...] } ] } ]}) follows Fluent
	 * Forms' documented field structure. An undecodable definition yields an
	 * empty list, which routes every caller to its pessimistic branch.
	 *
	 * @param string $json Raw form_fields JSON.
	 * @return array<int,array{element:string,name:string}> Leaf fields, in order.
	 */
	private function decode_fields( $json ) {
		if ( ! is_string( $json ) || '' === $json ) {
			return array();
		}

		$decoded = json_decode( $json, true );
		if ( ! is_array( $decoded ) ) {
			return array();
		}

		$fields = isset( $decoded['fields'] ) && is_array( $decoded['fields'] ) ? $decoded['fields'] : array();

		$out = array();
		$this->walk_fields( $fields, $out );

		return $out;
	}

	/**
	 * Recursive body of decode_fields().
	 *
	 * @param array $fields Field nodes.
	 * @param array $out    Accumulator, by reference.
	 * @param int   $depth  Recursion depth guard.
	 */
	private function walk_fields( $fields, &$out, $depth = 0 ) {
		// A malformed or hostile definition must not recurse without bound.
		if ( $depth > 10 || ! is_array( $fields ) ) {
			return;
		}

		foreach ( $fields as $field ) {
			if ( ! is_array( $field ) ) {
				continue;
			}

			$element = isset( $field['element'] ) ? (string) $field['element'] : '';
			$name    = isset( $field['attributes']['name'] ) ? (string) $field['attributes']['name'] : '';

			if ( '' !== $element ) {
				$out[] = array(
					'element' => $element,
					'name'    => $name,
				);
			}

			// Container: {"columns": [ { "fields": [ ... ] } ]}.
			if ( isset( $field['columns'] ) && is_array( $field['columns'] ) ) {
				foreach ( $field['columns'] as $column ) {
					if ( isset( $column['fields'] ) ) {
						$this->walk_fields( $column['fields'], $out, $depth + 1 );
					}
				}
			}

			// Step / repeater: {"fields": [ ... ]}.
			if ( isset( $field['fields'] ) && is_array( $field['fields'] ) ) {
				$this->walk_fields( $field['fields'], $out, $depth + 1 );
			}
		}
	}

	/**
	 * {@inheritDoc}
	 *
	 * A form is ineligible when it carries a challenge we have no equivalent
	 * for: a visible v2 checkbox, or an hCaptcha / Turnstile widget. Our
	 * implementation is score-only, so replacing those would change both the UX
	 * and the threat model. Those forms keep Fluent Forms' own captcha —
	 * partial takeover is a supported end state, not a failure.
	 *
	 * An internal form is deliberately still eligible. See INTERNAL_OPTION.
	 */
	public function form_is_eligible( $form_id ) {
		if ( null === $this->form( $form_id ) ) {
			// Cannot inspect it, so do not claim to cover it.
			return false;
		}

		return ! in_array( $this->native_captcha_state( $form_id ), array( 'v2', 'other' ), true );
	}

	/**
	 * Whether a form is driven programmatically rather than submitted by a
	 * visitor.
	 *
	 * @param int|string $form_id Form identifier.
	 * @return bool
	 */
	public function form_is_internal( $form_id ) {
		$listed = get_option( self::INTERNAL_OPTION, array() );
		$listed = is_array( $listed ) ? array_map( 'intval', $listed ) : array();

		$internal = in_array( (int) $form_id, $listed, true );

		/**
		 * Filter whether a Fluent Form is internal (never publicly submitted).
		 *
		 * @param bool $internal Whether the form is internal.
		 * @param int  $form_id  Form identifier.
		 */
		return (bool) apply_filters( 'gswp_ff_form_is_internal', $internal, (int) $form_id );
	}

	/**
	 * {@inheritDoc}
	 *
	 * Deliberately biased toward "yes". A form wrongly classified as payment
	 * fails closed on a missing token, which is an inconvenience. A payment
	 * form wrongly classified as non-payment fails open, which is a hole.
	 *
	 * Fluent Forms is easier here than Gravity Forms: the forms table carries a
	 * has_payment column, which is a direct answer where GF has to sniff add-on
	 * slugs. The field scan is kept as a fallback for the column being absent
	 * on an older schema.
	 */
	public function form_has_payment( $form_id ) {
		$cached = $this->memo_get( 'payment', $form_id );
		if ( null !== $cached ) {
			return $cached;
		}

		return $this->memo_set( 'payment', $form_id, $this->compute_has_payment( $form_id ) );
	}

	/**
	 * Uncached body of form_has_payment().
	 *
	 * @param int|string $form_id Form identifier.
	 * @return bool
	 */
	private function compute_has_payment( $form_id ) {
		$form = $this->form( $form_id );
		if ( null === $form ) {
			return true;
		}

		// PARTIAL: `has_payment` is documented on the fluentform_forms schema.
		// Present and truthy is authoritative; present and falsy still falls
		// through to the field scan, because a column we have misread must not
		// be able to clear a form that plainly contains a payment field.
		if ( isset( $form['has_payment'] ) && (int) $form['has_payment'] > 0 ) {
			return true;
		}

		foreach ( $form['fields'] as $field ) {
			if ( in_array( $field['element'], self::$payment_elements, true ) ) {
				return true;
			}
		}

		// A form whose fields could not be read at all is unclassifiable, and
		// unclassifiable means payment. An empty definition on a form row that
		// does exist is the signal that decode_fields() failed.
		if ( empty( $form['fields'] ) ) {
			return true;
		}

		return false;
	}

	/**
	 * Whether a form's active feeds create a new WordPress account.
	 *
	 * @param int|string $form_id Form identifier.
	 * @return bool
	 */
	public function form_creates_account( $form_id ) {
		return 'create' === $this->account_feed_type( $form_id );
	}

	/**
	 * Whether a form's active feeds update an existing WordPress account.
	 *
	 * A profile-edit form. WordPress has already authenticated whoever is
	 * submitting it, so reCAPTCHA here is defence in depth, not the gate — see
	 * form_is_strict().
	 *
	 * @param int|string $form_id Form identifier.
	 * @return bool
	 */
	public function form_updates_account( $form_id ) {
		return 'update' === $this->account_feed_type( $form_id );
	}

	/**
	 * What a form's User Registration feeds do to an account.
	 *
	 * UNVERIFIED: Fluent Forms Pro stores integration feeds as rows in
	 * fluentform_form_meta, and neither the meta_key naming nor the key that
	 * distinguishes a registration feed from a profile-update feed is confirmed
	 * against installed source. Chunk 24 of the manual suite prints every meta
	 * row per form verbatim so this can be settled on a live install.
	 *
	 * Fails to the strict answer, per this class's standing rule: a feed we can
	 * see but cannot classify is treated as 'create'. A form carrying both
	 * kinds is 'create' — the stricter of the two.
	 *
	 * @param int|string $form_id Form identifier.
	 * @return string 'create', 'update', or '' when the form touches no account.
	 */
	private function account_feed_type( $form_id ) {
		$cached = $this->memo_get( 'account_feed_type', $form_id );
		if ( null !== $cached ) {
			return $cached;
		}

		$type = '';

		foreach ( $this->form_meta_rows( $form_id ) as $row ) {
			$key = isset( $row['meta_key'] ) ? strtolower( (string) $row['meta_key'] ) : '';

			if ( false === strpos( $key, 'user_registration' ) && false === strpos( $key, 'user_update' ) ) {
				continue;
			}

			$meta = json_decode( isset( $row['value'] ) ? (string) $row['value'] : '', true );
			$meta = is_array( $meta ) ? $meta : array();

			// A disabled feed does nothing. An unreadable enabled flag is
			// treated as enabled, which is the stricter reading.
			if ( isset( $meta['enabled'] ) && ! $meta['enabled'] ) {
				continue;
			}

			if ( $this->feed_is_update( $key, $meta ) ) {
				// Only downgrade to 'update' if nothing has claimed 'create'.
				$type = ( 'create' === $type ) ? 'create' : 'update';
				continue;
			}

			return $this->memo_set( 'account_feed_type', $form_id, $this->filter_account_type( 'create', $form_id ) );
		}

		return $this->memo_set( 'account_feed_type', $form_id, $this->filter_account_type( $type, $form_id ) );
	}

	/**
	 * Whether an account feed updates an existing user rather than creating one.
	 *
	 * UNVERIFIED. Two independent signals are consulted because neither is
	 * confirmed: the meta key naming, and a declared type inside the feed. A
	 * feed that says nothing recognisable is NOT an update — it falls through
	 * to 'create', the stricter reading.
	 *
	 * @param string $key  Lowercased meta key.
	 * @param array  $meta Decoded feed value.
	 * @return bool
	 */
	private function feed_is_update( $key, $meta ) {
		if ( false !== strpos( $key, 'user_update' ) ) {
			return true;
		}

		foreach ( array( 'feedType', 'feed_type', 'userRegistrationType', 'type' ) as $candidate ) {
			if ( ! isset( $meta[ $candidate ] ) || ! is_scalar( $meta[ $candidate ] ) ) {
				continue;
			}

			$declared = strtolower( trim( (string) $meta[ $candidate ] ) );
			if ( 'update' === $declared || 'update_user' === $declared ) {
				return true;
			}
		}

		return false;
	}

	/**
	 * Every fluentform_form_meta row for a form.
	 *
	 * @param int|string $form_id Form identifier.
	 * @return array<int,array<string,mixed>> Rows, or empty when unreadable.
	 */
	private function form_meta_rows( $form_id ) {
		global $wpdb;

		$cached = $this->memo_get( 'form_meta', $form_id );
		if ( null !== $cached ) {
			return $cached;
		}

		$table = $this->table( 'fluentform_form_meta' );
		if ( '' === $table ) {
			return $this->memo_set( 'form_meta', $form_id, array() );
		}

		$rows = $wpdb->get_results( $wpdb->prepare( "SELECT meta_key, value FROM {$table} WHERE form_id = %d", (int) $form_id ), ARRAY_A ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL

		return $this->memo_set( 'form_meta', $form_id, is_array( $rows ) ? $rows : array() );
	}

	/**
	 * Let a site correct a form's account classification.
	 *
	 * The feed binding is unverified and misreading it is not cosmetic: a
	 * profile-edit form mistaken for a signup is scored under the stricter
	 * threshold and rejected outright when its token is missing. A site that
	 * hits this should not have to wait for a release:
	 *
	 *     add_filter( 'gswp_ff_account_feed_type', function ( $type, $form_id ) {
	 *         return in_array( $form_id, array( 7, 9 ), true ) ? 'update' : $type;
	 *     }, 10, 2 );
	 *
	 * Returning anything other than 'create' or 'update' means "this form
	 * touches no account". Every return path in account_feed_type() routes
	 * through here, including the 'create' fallback — which is the one an
	 * affected site would actually need to override.
	 *
	 * @param string $type    Derived type: 'create', 'update', or ''.
	 * @param int    $form_id Form identifier.
	 * @return string Filtered type.
	 */
	private function filter_account_type( $type, $form_id ) {
		$filtered = apply_filters( 'gswp_ff_account_feed_type', $type, (int) $form_id );

		return in_array( $filtered, array( 'create', 'update' ), true ) ? $filtered : '';
	}

	/**
	 * {@inheritDoc}
	 *
	 * Fail closed on anything that moves money or creates an account. Neither a
	 * contact form entry nor a signed-in user editing her own profile warrants
	 * it — WordPress has already authenticated her, and locking her out of her
	 * own account details is worse than admitting one unscored edit.
	 */
	public function form_is_strict( $form_id ) {
		return $this->form_has_payment( $form_id ) || $this->form_creates_account( $form_id );
	}

	/**
	 * Whether a form sets or changes a password.
	 *
	 * Read from the stored form definition, never the request. A password field
	 * is the signal: whether the change lands via an integration feed or the
	 * site's own handler, the form is a credential-changing surface either way.
	 *
	 * @param int|string $form_id Form identifier.
	 * @return bool
	 */
	public function form_changes_password( $form_id ) {
		$cached = $this->memo_get( 'password', $form_id );
		if ( null !== $cached ) {
			return $cached;
		}

		$form = $this->form( $form_id );
		if ( null === $form ) {
			return $this->memo_set( 'password', $form_id, false );
		}

		foreach ( $form['fields'] as $field ) {
			if ( in_array( $field['element'], self::$password_elements, true ) ) {
				return $this->memo_set( 'password', $form_id, true );
			}
		}

		return $this->memo_set( 'password', $form_id, false );
	}

	/**
	 * The reCAPTCHA action a form's token is minted with and checked against.
	 *
	 * ONE resolver, called from both token_field() (which labels the token in
	 * the browser) and validate_submission() (which tells Google what to
	 * expect).
	 *
	 * This is not a stylistic preference. In 2.22.0 the Gravity Forms provider
	 * decided the action twice, in two separate ternaries, and they disagreed:
	 * a non-payment form with a User Registration feed rendered 'submit' but was
	 * validated as 'register'. Enterprise assessments reject on expectedAction
	 * mismatch before scoring, so every submission of every account form failed,
	 * for every visitor, with a message accusing them of being spam. The fix
	 * was not to correct one of the two expressions — it was to have only one.
	 *
	 * @param int|string $form_id Form identifier.
	 * @return string reCAPTCHA action name.
	 */
	private function action_for( $form_id ) {
		if ( $this->form_has_payment( $form_id ) ) {
			return 'checkout';
		}
		if ( $this->form_creates_account( $form_id ) ) {
			return 'register';
		}
		// Ranked above a plain account update: changing a password is the step
		// an account takeover performs to lock the real owner out, so it is
		// worth scoring and tuning on its own rather than averaging in with
		// profile edits.
		if ( $this->form_changes_password( $form_id ) ) {
			return 'password_reset';
		}
		if ( $this->form_updates_account( $form_id ) ) {
			return 'account_update';
		}

		return 'submit';
	}

	/**
	 * Action names accepted for a form's token.
	 *
	 * Exactly one, unlike the Gravity Forms provider. Its extra allowance
	 * exists only to tolerate pages cached under 2.21.1, which rendered a
	 * different action; this provider has no prior release and therefore no
	 * stale pages to forgive.
	 *
	 * @param int|string $form_id Form identifier.
	 * @return string[] Accepted actions.
	 */
	private function accepted_actions( $form_id ) {
		return array( $this->action_for( $form_id ) );
	}

	/**
	 * The threshold context for a form.
	 *
	 * Deliberately its own set of options rather than sharing the Gravity Forms
	 * ones. A site tuning its Gravity Forms registration threshold must not
	 * silently retune Fluent Forms — that is the same defect 2.22.0 fixed when
	 * GF forms stopped borrowing gswp_threshold_wp_register.
	 *
	 * @param int|string $form_id Form identifier.
	 * @return string Context, resolving to option "gswp_threshold_{context}".
	 */
	private function context_for( $form_id ) {
		if ( $this->form_has_payment( $form_id ) ) {
			return 'checkout';
		}
		if ( $this->form_creates_account( $form_id ) ) {
			return 'ff_register';
		}
		if ( $this->form_changes_password( $form_id ) ) {
			return 'ff_password';
		}
		if ( $this->form_updates_account( $form_id ) ) {
			return 'ff_account_update';
		}

		return 'ff_submit';
	}

	/**
	 * Read a memoized value.
	 *
	 * @param string     $bucket  Cache bucket.
	 * @param int|string $form_id Form identifier.
	 * @return mixed Cached value, or null on a miss.
	 */
	private function memo_get( $bucket, $form_id ) {
		return isset( $this->memo[ $bucket ][ (int) $form_id ] ) ? $this->memo[ $bucket ][ (int) $form_id ] : null;
	}

	/**
	 * Store a memoized value.
	 *
	 * @param string     $bucket  Cache bucket.
	 * @param int|string $form_id Form identifier.
	 * @param mixed      $value   Value to cache and return.
	 * @return mixed The value, so callers can `return $this->memo_set( ... )`.
	 */
	private function memo_set( $bucket, $form_id, $value ) {
		$this->memo[ $bucket ][ (int) $form_id ] = $value;

		return $value;
	}

	/**
	 * {@inheritDoc}
	 *
	 * Returns 'other' for a challenge that is neither ours nor Google's.
	 * Fluent Forms ships reCAPTCHA, hCaptcha and Turnstile, configured
	 * identically, and none of 'off' / 'v3' / 'v2' / 'unknown' can express the
	 * latter two: 'off' would be a lie, 'v2' misnames the product to an
	 * operator who then goes looking for reCAPTCHA settings that do not exist,
	 * and 'unknown' would leave the form eligible so we would take over a form
	 * that is also running Turnstile.
	 *
	 * The per-form field is checked before the global settings, because a
	 * captcha field on the form is a visible challenge whatever the global
	 * configuration says.
	 */
	public function native_captcha_state( $form_id ) {
		$form = $this->form( $form_id );
		if ( null === $form ) {
			return 'unknown';
		}

		$found_recaptcha_field = false;

		foreach ( $form['fields'] as $field ) {
			if ( ! isset( self::$captcha_elements[ $field['element'] ] ) ) {
				continue;
			}

			if ( 'other' === self::$captcha_elements[ $field['element'] ] ) {
				return 'other';
			}

			$found_recaptcha_field = true;
		}

		$settings = $this->native_recaptcha_settings();

		// A reCAPTCHA field on the form is a rendered widget. Whether it is a
		// visible challenge depends on the configured version, and an
		// unreadable version must not be assumed invisible.
		if ( $found_recaptcha_field ) {
			return 'v3' === $this->native_recaptcha_version( $settings ) ? 'v3' : 'v2';
		}

		// No captcha field on this form. A global configuration still tells the
		// operator what Fluent Forms has set up, which is what the coverage
		// table reports.
		if ( array() === $settings ) {
			// Nothing configured anywhere we recognise. 'unknown' rather than
			// 'off': we have not proved absence, only failed to find it.
			return $this->native_any_captcha_configured() ? 'other' : 'unknown';
		}

		$version = $this->native_recaptcha_version( $settings );

		if ( 'v3' === $version ) {
			return 'v3';
		}
		if ( 'v2' === $version ) {
			return 'v2';
		}

		return 'unknown';
	}

	/**
	 * Fluent Forms' stored reCAPTCHA settings.
	 *
	 * VERIFIED for `_fluentform_reCaptcha_details`: this project confirmed that
	 * option name against a live install during the Smart Key Scavenger work
	 * (see readme.txt, 2.13.x). The others are retained for other versions.
	 * Filterable so a site can correct it without a code change.
	 *
	 * @return array Settings array, or empty when none found.
	 */
	private function native_recaptcha_settings() {
		$cached = $this->memo_get( 'native_recaptcha', 0 );
		if ( null !== $cached ) {
			return $cached;
		}

		$candidates = (array) apply_filters(
			'gswp_ff_native_captcha_options',
			array(
				'_fluentform_reCaptcha_details',
				'_fluentform_recaptcha_details',
				'fluentform_reCaptcha_details',
			)
		);

		foreach ( $candidates as $option ) {
			$settings = $this->raw_option( $option );
			if ( is_array( $settings ) && array() !== $settings ) {
				return $this->memo_set( 'native_recaptcha', 0, $settings );
			}
		}

		return $this->memo_set( 'native_recaptcha', 0, array() );
	}

	/**
	 * Which reCAPTCHA version Fluent Forms has configured.
	 *
	 * UNVERIFIED: the key holding the version is inferred. An unrecognised
	 * value returns '', which callers treat as "not proven invisible" — the
	 * pessimistic direction, since a v2 checkbox makes the form ineligible and
	 * leaves Fluent Forms' own captcha in charge.
	 *
	 * @param array $settings Stored settings.
	 * @return string 'v2', 'v3', or ''.
	 */
	private function native_recaptcha_version( $settings ) {
		if ( ! is_array( $settings ) || array() === $settings ) {
			return '';
		}

		$has_key = false;
		foreach ( array( 'siteKey', 'site_key', 'secretKey', 'secret_key' ) as $key ) {
			if ( ! empty( $settings[ $key ] ) ) {
				$has_key = true;
				break;
			}
		}

		if ( ! $has_key ) {
			return '';
		}

		foreach ( array( 'api_version', 'apiVersion', 'version', 'type' ) as $key ) {
			if ( ! isset( $settings[ $key ] ) || ! is_scalar( $settings[ $key ] ) ) {
				continue;
			}

			$value = strtolower( (string) $settings[ $key ] );

			if ( false !== strpos( $value, 'v3' ) || false !== strpos( $value, 'invisible' ) ) {
				return 'v3';
			}
			if ( false !== strpos( $value, 'v2' ) || false !== strpos( $value, 'checkbox' ) ) {
				return 'v2';
			}
		}

		// Keys are configured but the version is unreadable. Report v2, the
		// answer that makes the form ineligible and leaves Fluent Forms' own
		// captcha running — an unverifiable answer must degrade to "we do not
		// cover this form", which loses no protection.
		return 'v2';
	}

	/**
	 * Whether Fluent Forms has an hCaptcha or Turnstile configuration stored.
	 *
	 * UNVERIFIED: option names inferred by symmetry with the confirmed
	 * reCAPTCHA one. A false negative here simply leaves the state 'unknown'.
	 *
	 * @return bool
	 */
	private function native_any_captcha_configured() {
		$candidates = (array) apply_filters(
			'gswp_ff_native_other_captcha_options',
			array(
				'_fluentform_hCaptcha_details',
				'_fluentform_hcaptcha_details',
				'_fluentform_turnstile_details',
			)
		);

		foreach ( $candidates as $option ) {
			$settings = $this->raw_option( $option );
			if ( ! is_array( $settings ) ) {
				continue;
			}

			foreach ( array( 'siteKey', 'site_key', 'secretKey', 'secret_key' ) as $key ) {
				if ( ! empty( $settings[ $key ] ) ) {
					return true;
				}
			}
		}

		return false;
	}

	/**
	 * Read one of Fluent Forms' settings options straight from the database.
	 *
	 * Bypasses get_option(), and therefore bypasses every filter, ours or
	 * anyone else's. Reporting on another plugin's settings must not pass
	 * through anything that could colour it.
	 *
	 * @param string $option Option name.
	 * @return array|null Settings array, or null when absent/unreadable.
	 */
	private function raw_option( $option ) {
		global $wpdb;

		if ( ! $wpdb ) {
			return null;
		}

		$value = $wpdb->get_var( $wpdb->prepare( "SELECT option_value FROM {$wpdb->options} WHERE option_name = %s LIMIT 1", $option ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery

		if ( null === $value ) {
			return null;
		}

		$value = maybe_unserialize( $value );

		// Fluent Forms stores some settings as JSON inside the option value.
		if ( is_string( $value ) ) {
			$decoded = json_decode( $value, true );
			$value   = is_array( $decoded ) ? $decoded : null;
		}

		return is_array( $value ) ? $value : null;
	}

	/**
	 * {@inheritDoc}
	 */
	public function last_injection( $form_id ) {
		$log = get_option( self::INJECTION_OPTION, array() );

		return is_array( $log ) && isset( $log[ (int) $form_id ] ) ? (int) $log[ (int) $form_id ] : 0;
	}

	/**
	 * Record that a token field reached the browser for this form.
	 *
	 * Written at most once per form per day so a busy site does not turn every
	 * page view into an option write.
	 *
	 * @param int $form_id Form id.
	 */
	private function record_injection( $form_id ) {
		$form_id = (int) $form_id;
		$log     = get_option( self::INJECTION_OPTION, array() );
		$log     = is_array( $log ) ? $log : array();

		if ( isset( $log[ $form_id ] ) && ( time() - (int) $log[ $form_id ] ) < DAY_IN_SECONDS ) {
			return;
		}

		$log[ $form_id ] = time();
		update_option( self::INJECTION_OPTION, $log, false );
	}

	/**
	 * {@inheritDoc}
	 */
	public function register_hooks( GSWP_Verifier $verifier ) {
		$this->verifier = $verifier;

		// PARTIAL hook choice: fluentform/form_element_start runs before the
		// form's input elements are rendered, so echoing here places our field
		// inside the <form>. Chunk 21 confirms it fires on every render path.
		add_action( 'fluentform/form_element_start', array( $this, 'inject_token_field' ), 10, 1 );

		// Coverage backstop. Fluent Forms has no equivalent of Gravity Forms'
		// gform_get_form_filter — no filter receives the finished form HTML —
		// so the backstop is an output buffer. It is deliberately narrow: see
		// open_backstop_buffer().
		add_action( 'fluentform/before_form_render', array( $this, 'open_backstop_buffer' ), 1, 1 );
		add_action( 'fluentform/after_form_render', array( $this, 'close_backstop_buffer' ), 999, 1 );

		// PARTIAL hook choice: fluentform/validation_errors is Fluent Forms'
		// canonical validation filter, documented as living in
		// FormValidationService::validateSubmission().
		add_filter( 'fluentform/validation_errors', array( $this, 'validate_submission' ), 20, 4 );

		// Persist the assessment name and any fail-open flag onto the entry.
		add_action( 'fluentform/submission_inserted', array( $this, 'store_submission_meta' ), 10, 3 );

		// Payment lifecycle -> Transaction Defense annotation. One hook covers
		// both directions, unlike Gravity Forms' pair.
		add_action( 'fluentform/after_payment_status_change', array( $this, 'on_payment_status_change' ), 10, 5 );
	}

	/**
	 * Echo the hidden token field inside the form element.
	 *
	 * @param object|array $form Fluent Forms form object.
	 */
	public function inject_token_field( $form ) {
		$form_id = $this->form_id_of( $form );

		if ( ! $form_id || ! GSWP_Recaptcha_Loader::will_load() || ! $this->form_is_eligible( $form_id ) ) {
			return;
		}

		// Shares the page's single loader (2.18.0) and the footer bootstrap,
		// which fills every .g-recaptcha-response and refreshes it before the
		// 120-second expiry. No provider-specific JavaScript.
		//
		// Two parts of that bootstrap are load-bearing for Fluent Forms in a way
		// they never were for Gravity Forms, and neither is obvious from here:
		//
		//  - the MutationObserver, which populates a form rendered into the DOM
		//    after page load — in a modal, or by a conditional;
		//  - the post-submit token replacement added in 2.22.1. v3 tokens are
		//    single-use and a Fluent Form never leaves the page, so without it a
		//    visitor whose first submission was rejected for ANY reason would be
		//    rejected again on every retry for up to 100 seconds while Google
		//    returned DUPE. That is not a nicety this provider benefits from; it
		//    is a prerequisite, and it would have surfaced as a defect here.
		//
		// Neither is safe to weaken on the grounds that "the form plugin handles
		// it" — nothing in Fluent Forms knows this field exists.
		GSWP_Recaptcha_Loader::enqueue();

		$this->record_injection( $form_id );

		echo $this->token_field( $form_id ); // phpcs:ignore WordPress.Security.EscapingOutput.OutputNotEscaped -- token_field() escapes every interpolated value.
	}

	/**
	 * Open an output buffer around a form render, as a coverage backstop.
	 *
	 * Only for a form whose primary injection point has already been observed
	 * to miss. Buffering a third-party render is more invasive than a filter
	 * and can be left unbalanced by a fatal inside the render, so it is not the
	 * default path — it is the recovery path for a render route we failed to
	 * hook, which without a staged rollout has to be caught here rather than in
	 * the logs six weeks from now.
	 *
	 * @param object|array $form Fluent Forms form object.
	 */
	public function open_backstop_buffer( $form ) {
		$form_id = $this->form_id_of( $form );

		if ( ! $form_id || ! GSWP_Recaptcha_Loader::will_load() || ! $this->form_is_eligible( $form_id ) ) {
			return;
		}

		// The primary hook has worked for this form before, so there is nothing
		// to recover and no reason to buffer.
		if ( $this->last_injection( $form_id ) > 0 ) {
			return;
		}

		if ( ! ob_start() ) {
			return;
		}

		$this->buffer_level[ $form_id ] = ob_get_level();
	}

	/**
	 * Close the backstop buffer, injecting the field if the render did not.
	 *
	 * Refuses to close a buffer it does not own. If the nesting level does not
	 * match what we opened, something else opened or closed a buffer inside the
	 * form render, and unwinding blindly would emit a partial page. Reporting a
	 * coverage gap is the honest outcome.
	 *
	 * @param object|array $form Fluent Forms form object.
	 */
	public function close_backstop_buffer( $form ) {
		$form_id = $this->form_id_of( $form );

		if ( ! $form_id || ! isset( $this->buffer_level[ $form_id ] ) ) {
			return;
		}

		$expected = $this->buffer_level[ $form_id ];
		unset( $this->buffer_level[ $form_id ] );

		$level = ob_get_level();

		if ( $level !== $expected ) {
			// Something inside the render opened or closed a buffer of its own.
			// We can no longer identify our own content, so we inject nothing —
			// but we must still leave the buffer stack as we found it. Simply
			// returning here would abandon our own open buffer and swallow the
			// rest of the page, which is a far worse outcome than the missing
			// token field this branch exists to report.
			while ( ob_get_level() >= $expected ) {
				if ( ! ob_end_flush() ) {
					break;
				}
			}

			$this->log_error(
				sprintf(
					'COVERAGE GAP: Fluent Forms #%d changed the output buffer nesting during render (expected level %d, found %d), so this plugin could not safely inject a reCAPTCHA token field. The form may be submitted unscored.',
					$form_id,
					$expected,
					$level
				)
			);
			do_action( 'gswp_form_coverage_gap', $this->id(), $form_id );

			return;
		}

		$markup = ob_get_clean();
		if ( ! is_string( $markup ) ) {
			return;
		}

		// The primary hook fired after all; nothing to do.
		if ( false !== strpos( $markup, 'name="' . self::TOKEN_FIELD . '"' ) ) {
			echo $markup; // phpcs:ignore WordPress.Security.EscapingOutput.OutputNotEscaped -- unmodified third-party markup, passed through.

			return;
		}

		$close = strripos( $markup, '</form>' );
		if ( false === $close ) {
			$this->log_error(
				sprintf(
					'COVERAGE GAP: Fluent Forms #%d rendered without a closing form tag, so no reCAPTCHA token field could be injected.',
					$form_id
				)
			);
			do_action( 'gswp_form_coverage_gap', $this->id(), $form_id );

			echo $markup; // phpcs:ignore WordPress.Security.EscapingOutput.OutputNotEscaped -- unmodified third-party markup, passed through.

			return;
		}

		GSWP_Recaptcha_Loader::enqueue();
		$this->record_injection( $form_id );

		echo substr( $markup, 0, $close ) // phpcs:ignore WordPress.Security.EscapingOutput.OutputNotEscaped -- unmodified third-party markup, passed through.
			. $this->token_field( $form_id ) // phpcs:ignore WordPress.Security.EscapingOutput.OutputNotEscaped -- token_field() escapes every interpolated value.
			. substr( $markup, $close ); // phpcs:ignore WordPress.Security.EscapingOutput.OutputNotEscaped -- unmodified third-party markup, passed through.
	}

	/**
	 * The hidden token field markup for a form.
	 *
	 * @param int $form_id Form id.
	 * @return string
	 */
	private function token_field( $form_id ) {
		return sprintf(
			'<input type="hidden" name="%s" class="g-recaptcha-response" data-recaptcha-action="%s" value="" />',
			esc_attr( self::TOKEN_FIELD ),
			// Same resolver validate_submission() uses. See action_for().
			esc_attr( $this->action_for( $form_id ) )
		);
	}

	/**
	 * Extract a form id from whatever Fluent Forms hands a hook.
	 *
	 * PARTIAL: Fluent Forms passes its form as an object with an `id` property
	 * on the render hooks. Accepting an array and a bare id as well costs
	 * nothing and means a shape change does not silently disable injection —
	 * which is the failure mode that would leave forms live and unscored.
	 *
	 * @param mixed $form Form object, array, or id.
	 * @return int Form id, or 0 when it cannot be determined.
	 */
	private function form_id_of( $form ) {
		if ( is_object( $form ) && isset( $form->id ) ) {
			return (int) $form->id;
		}
		if ( is_array( $form ) && isset( $form['id'] ) ) {
			return (int) $form['id'];
		}
		if ( is_scalar( $form ) && is_numeric( $form ) ) {
			return (int) $form;
		}

		return 0;
	}

	/**
	 * The submitted reCAPTCHA token, from whichever transport carried it.
	 *
	 * Fluent Forms submits over AJAX and serialises the form into a single
	 * request parameter, so $_POST[ TOKEN_FIELD ] is very probably empty. Three
	 * transports are tried because it is not settled which one is real, and a
	 * resolver that tries all three is correct under any of them — the same
	 * reasoning as the candidate lists used for option names.
	 *
	 * Returning '' routes the caller into the coverage-assertion branch, not
	 * into a rejection.
	 *
	 * @param array $form_data Parsed submission data handed to the validation filter.
	 * @return string Token, or ''.
	 */
	private function submitted_token( $form_data ) {
		// 1. The parsed data Fluent Forms itself assembled, if our key survived
		//    its mapping of submitted values against registered fields.
		if ( is_array( $form_data ) && ! empty( $form_data[ self::TOKEN_FIELD ] ) && is_scalar( $form_data[ self::TOKEN_FIELD ] ) ) {
			return sanitize_text_field( (string) $form_data[ self::TOKEN_FIELD ] );
		}

		// 2. The serialised envelope, parsed out by hand.
		foreach ( array( 'data', 'formData' ) as $envelope ) {
			// phpcs:ignore WordPress.Security.NonceVerification.Missing -- Fluent Forms validates its own nonce before this filter runs.
			if ( ! isset( $_POST[ $envelope ] ) || ! is_string( $_POST[ $envelope ] ) ) {
				continue;
			}

			// phpcs:ignore WordPress.Security.NonceVerification.Missing
			$raw = wp_unslash( $_POST[ $envelope ] );

			$parsed = array();
			parse_str( (string) $raw, $parsed );

			if ( ! empty( $parsed[ self::TOKEN_FIELD ] ) && is_scalar( $parsed[ self::TOKEN_FIELD ] ) ) {
				return sanitize_text_field( (string) $parsed[ self::TOKEN_FIELD ] );
			}
		}

		// 3. A plain POST, for any non-AJAX render path.
		// phpcs:ignore WordPress.Security.NonceVerification.Missing
		if ( isset( $_POST[ self::TOKEN_FIELD ] ) && is_scalar( $_POST[ self::TOKEN_FIELD ] ) ) {
			// phpcs:ignore WordPress.Security.NonceVerification.Missing
			return sanitize_text_field( wp_unslash( $_POST[ self::TOKEN_FIELD ] ) );
		}

		return '';
	}

	/**
	 * Score a submission and reject it when warranted.
	 *
	 * @param array        $errors    Validation errors so far.
	 * @param array        $form_data Submitted data.
	 * @param object|array $form      Form.
	 * @param array        $fields    Form fields.
	 * @return array Filtered errors.
	 */
	public function validate_submission( $errors, $form_data = array(), $form = null, $fields = array() ) {
		if ( ! is_array( $errors ) ) {
			return $errors;
		}

		$form_id = $this->form_id_of( $form );
		if ( ! $form_id ) {
			return $errors;
		}

		// Never re-judge a submission Fluent Forms has already rejected.
		if ( ! empty( $errors ) ) {
			return $errors;
		}
		if ( ! $this->form_is_eligible( $form_id ) ) {
			return $errors;
		}

		$payment = $this->form_has_payment( $form_id );
		$strict  = $this->form_is_strict( $form_id );

		$token = $this->submitted_token( $form_data );

		if ( '' === $token ) {
			// Declared programmatic: no browser, so no token, and neither a gap
			// nor an attack. Admit it without the alarm.
			//
			// This is the ONLY thing the declaration does. A submission that
			// DOES carry a token has already fallen past this branch and is
			// scored exactly like any other, so ticking "Not public" can never
			// silently unprotect a form somebody can actually reach.
			if ( $this->form_is_internal( $form_id ) ) {
				return $errors;
			}

			// Coverage assertion. A missing token means one of two very
			// different things, and they deserve opposite responses.
			if ( 0 === $this->last_injection( $form_id ) ) {
				// We have no record of ever getting a token field into this
				// form. That is our coverage bug, not an attack, and a visitor
				// must never be blocked for it. Fail open on every form type,
				// including payment forms, and make the gap loud.
				$this->pending_unverified[ $form_id ] = true;

				$this->log_error(
					sprintf(
						'COVERAGE GAP: Fluent Forms #%d was submitted with no reCAPTCHA token and this plugin has no record of ever injecting one into it. The submission was allowed through unscored. Check that the form renders our token field.',
						$form_id
					)
				);

				do_action( 'gswp_form_coverage_gap', $this->id(), $form_id );

				return $errors;
			}

			// We do inject into this form, so a submission without a token is
			// adversarial or broken client-side. Asymmetric enforcement: the
			// decision is read from the stored form definition, never from the
			// request — a request-derived predicate would let a caller opt out
			// by omitting the field, the bypass class removed in 2.17.0.
			if ( $strict ) {
				$this->record_rejection( $form_id, 'missing token' );

				return $this->reject(
					$errors,
					__( 'We could not verify this submission. Please refresh the page and try again.', 'google-security-for-wordpress' ),
					$form_id
				);
			}

			$this->pending_unverified[ $form_id ] = true;
			$this->log(
				sprintf(
					'Fluent Forms #%d submitted with no reCAPTCHA token; admitted (takes no payment and creates no account, fail-open). If this repeats, token generation is broken on that page.',
					$form_id
				)
			);

			return $errors;
		}

		$context     = $this->context_for( $form_id );
		$actions     = $this->accepted_actions( $form_id );
		$event_extra = $payment ? $this->payment_context( $form_id, $form_data ) : array();

		$result = $this->verifier->verify_token( $context, $actions, $event_extra, null, $token );

		$name = $this->verifier->get_last_assessment_name();
		if ( '' !== $name ) {
			$this->pending_assessment[ $form_id ] = $name;
		}

		if ( is_wp_error( $result ) ) {
			// An action mismatch means the token was valid for this site key but
			// carried a different action name. That is a fault in this plugin or
			// a stale cached page — never evidence about the visitor — so it does
			// not get to block one on a form where the stakes do not justify it.
			// Google's actual score is still available and is still applied.
			if ( 'recaptcha_action_mismatch' === $result->get_error_code() && ! $strict ) {
				$score     = $this->verifier->get_last_score();
				$threshold = floatval( get_option( 'gswp_threshold_' . $context, '0.5' ) );

				if ( null !== $score && $score < $threshold ) {
					$this->record_rejection( $form_id, 'low score' );

					return $this->reject(
						$errors,
						__( 'Verification score too low. Submission rejected as potential spam.', 'google-security-for-wordpress' ),
						$form_id
					);
				}

				$this->pending_unverified[ $form_id ] = true;

				$this->log_error(
					sprintf(
						'Fluent Forms #%d submitted a token whose action was "%s" but this form expects "%s". Admitted (takes no payment and creates no account) and flagged unverified. This is a plugin or caching fault, not a spam signal — if it persists, the form is rendering a stale action.',
						$form_id,
						$this->verifier->get_last_token_action(),
						implode( '" or "', $actions )
					)
				);

				return $errors;
			}

			$this->record_rejection( $form_id, $result->get_error_code() );

			return $this->reject( $errors, wp_strip_all_tags( $result->get_error_message() ), $form_id );
		}

		// Transaction Defense verdict on payment forms.
		if ( $payment ) {
			$risk = $this->verifier->get_last_fraud_risk();
			if ( null !== $risk ) {
				if ( '1' === get_option( 'gswp_verbose_logging', '0' ) ) {
					$this->log( sprintf( 'Fluent Forms #%d transaction risk %.2f.', $form_id, $risk ) );
				}

				if ( '1' === get_option( 'gswp_txn_block', '0' ) ) {
					$threshold = floatval( get_option( 'gswp_threshold_txn', '0.8' ) );

					if ( $risk >= $threshold && ! $this->may_block_payment() ) {
						// Scored, above threshold, and deliberately not blocked.
						// Whether Fluent Forms authorises the card in the browser
						// before submission is unsettled (chunk 25). If it does, a
						// rejection here stops the submission but not the hold on
						// the customer's card, and telling the operator we blocked
						// a payment we did not block is worse than not claiming it.
						$this->log_error(
							sprintf(
								'Fluent Forms #%d scored transaction risk %.2f (>= %.2f) but was NOT blocked. Blocking is disabled for Fluent Forms until the payment authorisation timing is confirmed on this install — a server-side block may not reverse a card authorisation already taken in the browser. Enable with the gswp_ff_txn_block_allowed filter once confirmed.',
								$form_id,
								$risk,
								$threshold
							)
						);
					} elseif ( $risk >= $threshold ) {
						$this->log( sprintf( 'Fluent Forms #%d blocked: risk %.2f >= %.2f.', $form_id, $risk, $threshold ) );

						do_action(
							'gswp_checkout_blocked',
							$risk,
							$threshold,
							array(
								'source'     => 'fluent-forms',
								'assessment' => $name,
								'form_id'    => $form_id,
							)
						);

						$this->record_rejection( $form_id, 'transaction risk' );

						return $this->reject(
							$errors,
							__( 'This transaction was flagged as high risk and cannot be completed. Please contact us if you believe this is a mistake.', 'google-security-for-wordpress' ),
							$form_id
						);
					}
				}
			}
		}

		return $errors;
	}

	/**
	 * Whether high-risk transaction blocking is permitted on Fluent Forms.
	 *
	 * Defaults to false, and deliberately so. The Gravity Forms provider
	 * carries the same unknown as an open question in its docblock; here it is
	 * closed by default until chunk 25 answers it on a real install, because
	 * the failure mode costs a customer money rather than an entry.
	 *
	 * @return bool
	 */
	private function may_block_payment() {
		/**
		 * Allow this plugin to block a high-risk Fluent Forms payment.
		 *
		 * Turn this on only once you have confirmed that a rejected submission
		 * leaves no authorisation on the customer's card.
		 *
		 * @param bool $allowed Whether blocking is permitted.
		 */
		return (bool) apply_filters( 'gswp_ff_txn_block_allowed', false );
	}

	/**
	 * Attach a rejection message to the errors array.
	 *
	 * Fluent Forms renders validation errors against fields. Our token field is
	 * not one of its registered fields, so an error keyed to it may be
	 * delivered to the browser and then dropped for want of a DOM node to
	 * attach it to — leaving the visitor watching the submit button spin and
	 * stop, with nothing on screen to explain it.
	 *
	 * This plugin must have no branch that hangs a submission, so the message
	 * is attached to a real field on the form. It reads oddly under the first
	 * field, which is why the target is filterable, but odd and visible beats
	 * correct and invisible.
	 *
	 * @param array  $errors  Errors so far.
	 * @param string $message Customer-facing message.
	 * @param int    $form_id Form id.
	 * @return array
	 */
	private function reject( $errors, $message, $form_id ) {
		$field = $this->error_field_for( $form_id );

		if ( '' === $field ) {
			// No field to hang it on. Rejecting anyway would produce exactly
			// the silent spinner described above, so admit the submission,
			// flag it, and make the reason loud in the log instead.
			$this->pending_unverified[ $form_id ] = true;

			$this->log_error(
				sprintf(
					'Fluent Forms #%d: this plugin wanted to reject a submission ("%s") but could not resolve a field to display the message on, so the submission was ADMITTED and flagged unverified. A rejection the visitor cannot see is indistinguishable from an outage. Set a target with the gswp_ff_error_field filter.',
					$form_id,
					$message
				)
			);

			return $errors;
		}

		$errors[ $field ] = array( $message );

		return $errors;
	}

	/**
	 * Which field a rejection message is displayed against.
	 *
	 * @param int $form_id Form id.
	 * @return string Field name, or '' when none can be resolved.
	 */
	private function error_field_for( $form_id ) {
		$form  = $this->form( $form_id );
		$field = '';

		if ( null !== $form ) {
			foreach ( $form['fields'] as $candidate ) {
				// Skip our own field and any captcha widget: neither is a place
				// a visitor would look for an error.
				if ( '' === $candidate['name'] || self::TOKEN_FIELD === $candidate['name'] ) {
					continue;
				}
				if ( isset( self::$captcha_elements[ $candidate['element'] ] ) ) {
					continue;
				}

				$field = $candidate['name'];
				break;
			}
		}

		/**
		 * Filter the field a Fluent Forms rejection message is shown against.
		 *
		 * @param string $field   Field name.
		 * @param int    $form_id Form identifier.
		 */
		return (string) apply_filters( 'gswp_ff_error_field', $field, (int) $form_id );
	}

	/**
	 * Record why a form's last submission was rejected.
	 *
	 * Surfaced per form in the coverage report so "why is this form rejecting?"
	 * has an answer in wp-admin. Only the cause and the time are kept — nothing
	 * about the person who submitted it.
	 *
	 * Throttled, like record_injection(). A payment form under a carding run
	 * rejects continuously, and one option write per rejected attempt would turn
	 * an attack into database load — the plugin amplifying the thing it exists
	 * to absorb. A CHANGE of reason always writes immediately: that is new
	 * information.
	 *
	 * @param int    $form_id Form id.
	 * @param string $reason  Error code, e.g. 'recaptcha_low_score'.
	 */
	private function record_rejection( $form_id, $reason ) {
		$form_id = (int) $form_id;
		$reason  = (string) $reason;

		$log = get_option( self::REJECTION_OPTION, array() );
		$log = is_array( $log ) ? $log : array();

		if ( isset( $log[ $form_id ] )
			&& isset( $log[ $form_id ]['reason'], $log[ $form_id ]['time'] )
			&& $log[ $form_id ]['reason'] === $reason
			&& ( time() - (int) $log[ $form_id ]['time'] ) < 5 * MINUTE_IN_SECONDS
		) {
			return;
		}

		$log[ $form_id ] = array(
			'reason' => $reason,
			'time'   => time(),
		);

		update_option( self::REJECTION_OPTION, $log, false );
	}

	/**
	 * Why a form's last submission was rejected, for the coverage report.
	 *
	 * @param int|string $form_id Form id.
	 * @return array{reason:string,time:int}|null Null when none recorded.
	 */
	public function last_rejection( $form_id ) {
		$log = get_option( self::REJECTION_OPTION, array() );

		if ( ! is_array( $log ) || ! isset( $log[ (int) $form_id ] ) ) {
			return null;
		}

		$entry = $log[ (int) $form_id ];

		return array(
			'reason' => isset( $entry['reason'] ) ? (string) $entry['reason'] : '',
			'time'   => isset( $entry['time'] ) ? (int) $entry['time'] : 0,
		);
	}

	/**
	 * The reCAPTCHA action and threshold context resolved for a form.
	 *
	 * Reporting surface for the coverage table. Not on the provider interface —
	 * callers must guard with method_exists().
	 *
	 * @param int|string $form_id Form identifier.
	 * @return array
	 */
	public function form_policy( $form_id ) {
		return array(
			'action'   => $this->action_for( $form_id ),
			'context'  => $this->context_for( $form_id ),
			'account'  => $this->account_feed_type( $form_id ),
			'password' => $this->form_changes_password( $form_id ),
			'internal' => $this->form_is_internal( $form_id ),
		);
	}

	/**
	 * Build transactionData for a payment form.
	 *
	 * UNVERIFIED: Fluent Forms' billing field mapping is inferred from its
	 * address field element. Returning an empty array is safe — GSWP_Verifier
	 * enforces Google's documented minimum (billing region + postal code +
	 * payment method) and omits transaction data entirely when it is unmet,
	 * degrading to a plain score rather than an API error.
	 *
	 * @param int   $form_id   Form id.
	 * @param array $form_data Submitted data.
	 * @return array Event extras, or empty.
	 */
	private function payment_context( $form_id, $form_data ) {
		if ( 'enterprise' !== get_option( 'gswp_key_type', 'classic' ) ) {
			return array();
		}
		if ( '1' !== get_option( 'gswp_txn_defense', '0' ) ) {
			return array();
		}
		if ( ! is_array( $form_data ) ) {
			return array();
		}

		$form = $this->form( $form_id );
		if ( null === $form ) {
			return array();
		}

		$address = $this->submitted_address( $form, $form_data );

		$billing = array_filter(
			array(
				'recipient'          => isset( $address['recipient'] ) ? $address['recipient'] : '',
				'locality'           => isset( $address['city'] ) ? $address['city'] : '',
				'administrativeArea' => isset( $address['state'] ) ? $address['state'] : '',
				'regionCode'         => isset( $address['country'] ) ? $address['country'] : '',
				'postalCode'         => isset( $address['zip'] ) ? $address['zip'] : '',
			),
			static function ( $value ) {
				return '' !== $value;
			}
		);

		if ( ! empty( $address['address_line_1'] ) ) {
			$billing['address'] = array( $address['address_line_1'] );
		}

		// Google's documented minimum. Below it, send nothing rather than a
		// partial object the API will reject.
		if ( empty( $billing['regionCode'] ) || empty( $billing['postalCode'] ) ) {
			return array();
		}

		$transaction = array(
			'paymentMethod'  => 'fluentforms',
			'currencyCode'   => $this->form_currency( $form ),
			'billingAddress' => $billing,
		);

		if ( ! empty( $address['email'] ) ) {
			$transaction['user'] = array( 'email' => $address['email'] );
		}

		return array(
			'transactionData' => $transaction,
			'fraudPrevention' => 'ENABLED',
		);
	}

	/**
	 * Pull billing details out of a submission using the form's field types.
	 *
	 * UNVERIFIED. Fluent Forms' address field submits a nested array keyed by
	 * component ('address_line_1', 'city', 'state', 'zip', 'country'). Anything
	 * that does not match yields no components, which routes payment_context()
	 * to its empty return.
	 *
	 * @param array $form      Form row.
	 * @param array $form_data Submitted data.
	 * @return array<string,string> Address components, empties dropped.
	 */
	private function submitted_address( $form, $form_data ) {
		$out = array();

		foreach ( $form['fields'] as $field ) {
			$name = $field['name'];
			if ( '' === $name || ! isset( $form_data[ $name ] ) ) {
				continue;
			}

			$value = $form_data[ $name ];

			if ( 'address' === $field['element'] && is_array( $value ) ) {
				foreach ( array( 'address_line_1', 'city', 'state', 'zip', 'country' ) as $part ) {
					if ( isset( $value[ $part ] ) && is_scalar( $value[ $part ] ) ) {
						$out[ $part ] = sanitize_text_field( (string) $value[ $part ] );
					}
				}
				continue;
			}

			if ( 'input_email' === $field['element'] && is_scalar( $value ) && empty( $out['email'] ) ) {
				$out['email'] = sanitize_email( (string) $value );
				continue;
			}

			if ( 'input_name' === $field['element'] && empty( $out['recipient'] ) ) {
				if ( is_array( $value ) ) {
					$parts = array();
					foreach ( array( 'first_name', 'middle_name', 'last_name' ) as $part ) {
						if ( ! empty( $value[ $part ] ) && is_scalar( $value[ $part ] ) ) {
							$parts[] = sanitize_text_field( (string) $value[ $part ] );
						}
					}
					$out['recipient'] = implode( ' ', $parts );
				} elseif ( is_scalar( $value ) ) {
					$out['recipient'] = sanitize_text_field( (string) $value );
				}
			}
		}

		return array_filter(
			$out,
			static function ( $value ) {
				return '' !== $value;
			}
		);
	}

	/**
	 * A form's payment currency.
	 *
	 * UNVERIFIED: read from the form's stored payment settings when present.
	 * An empty string is acceptable to the assessment API path, which omits
	 * fields it cannot fill.
	 *
	 * @param array $form Form row.
	 * @return string Currency code, or ''.
	 */
	private function form_currency( $form ) {
		foreach ( $this->form_meta_rows( $form['id'] ) as $row ) {
			$key = isset( $row['meta_key'] ) ? strtolower( (string) $row['meta_key'] ) : '';
			if ( false === strpos( $key, 'payment' ) && false === strpos( $key, 'currency' ) ) {
				continue;
			}

			$meta = json_decode( isset( $row['value'] ) ? (string) $row['value'] : '', true );
			if ( ! is_array( $meta ) ) {
				continue;
			}

			foreach ( array( 'currency', 'payment_currency', 'paymentCurrency' ) as $candidate ) {
				if ( ! empty( $meta[ $candidate ] ) && is_scalar( $meta[ $candidate ] ) ) {
					return strtoupper( sanitize_text_field( (string) $meta[ $candidate ] ) );
				}
			}
		}

		return '';
	}

	/**
	 * Persist the assessment name and any fail-open flag onto the new submission.
	 *
	 * PARTIAL: fluentform/submission_inserted is documented as firing after a
	 * submission is stored, with the new id first. Helper::setSubmissionMeta is
	 * documented on the Helper Classes page. When neither is available the meta
	 * is simply not written — which costs the Transaction Defense annotation
	 * and nothing else, and is preferable to writing into another plugin's
	 * tables by hand.
	 *
	 * @param int          $submission_id New submission id.
	 * @param array        $form_data     Submitted data.
	 * @param object|array $form          Form.
	 */
	public function store_submission_meta( $submission_id, $form_data = array(), $form = null ) {
		$submission_id = (int) $submission_id;
		$form_id       = $this->form_id_of( $form );

		if ( ! $submission_id || ! $form_id ) {
			return;
		}

		if ( ! empty( $this->pending_assessment[ $form_id ] ) ) {
			$this->set_submission_meta( $submission_id, self::META_ASSESSMENT, $this->pending_assessment[ $form_id ] );
		}

		if ( ! empty( $this->pending_unverified[ $form_id ] ) ) {
			// Flagged rather than silent: a real breakage in token generation
			// shows up as a burst of unverified submissions instead of nothing.
			$this->set_submission_meta( $submission_id, self::META_UNVERIFIED, '1' );
		}
	}

	/**
	 * Write a submission meta value through Fluent Forms' own helper.
	 *
	 * @param int    $submission_id Submission id.
	 * @param string $key           Meta key.
	 * @param string $value         Meta value.
	 * @return bool Whether it was written.
	 */
	private function set_submission_meta( $submission_id, $key, $value ) {
		$helper = '\FluentForm\App\Helpers\Helper';

		if ( ! class_exists( $helper ) || ! method_exists( $helper, 'setSubmissionMeta' ) ) {
			return false;
		}

		call_user_func( array( $helper, 'setSubmissionMeta' ), (int) $submission_id, $key, $value );

		return true;
	}

	/**
	 * Read a submission meta value through Fluent Forms' own helper.
	 *
	 * @param int    $submission_id Submission id.
	 * @param string $key           Meta key.
	 * @return string Value, or ''.
	 */
	private function get_submission_meta( $submission_id, $key ) {
		$helper = '\FluentForm\App\Helpers\Helper';

		if ( ! class_exists( $helper ) || ! method_exists( $helper, 'getSubmissionMeta' ) ) {
			return '';
		}

		$value = call_user_func( array( $helper, 'getSubmissionMeta' ), (int) $submission_id, $key );

		return is_scalar( $value ) ? (string) $value : '';
	}

	/**
	 * Annotate the assessment when a payment's status changes.
	 *
	 * One hook covers both directions, unlike Gravity Forms' pair. Only the two
	 * terminal states we have an opinion about are acted on; everything else
	 * (pending, processing) is left alone, because annotating an assessment
	 * with a verdict that has not been reached teaches Google the wrong thing.
	 *
	 * @param object|array $submission  Submission.
	 * @param object|array $transaction Transaction.
	 * @param int          $form_id     Form id.
	 * @param string       $old_status  Previous status.
	 * @param string       $new_status  New status.
	 */
	public function on_payment_status_change( $submission, $transaction = null, $form_id = 0, $old_status = '', $new_status = '' ) {
		$status = strtolower( (string) $new_status );

		if ( 'paid' === $status ) {
			$this->annotate( $submission, 'LEGITIMATE', 'PAYMENT' );

			return;
		}

		if ( in_array( $status, array( 'refunded', 'partially-refunded', 'partially_refunded' ), true ) ) {
			$this->annotate( $submission, 'FRAUDULENT', 'REFUND' );
		}
	}

	/**
	 * Send an annotation for a submission's stored assessment.
	 *
	 * @param object|array $submission Submission.
	 * @param string       $annotation LEGITIMATE or FRAUDULENT.
	 * @param string       $event_type transactionEvent eventType.
	 */
	private function annotate( $submission, $annotation, $event_type ) {
		$submission_id = 0;

		if ( is_object( $submission ) && isset( $submission->id ) ) {
			$submission_id = (int) $submission->id;
		} elseif ( is_array( $submission ) && isset( $submission['id'] ) ) {
			$submission_id = (int) $submission['id'];
		} elseif ( is_numeric( $submission ) ) {
			$submission_id = (int) $submission;
		}

		if ( ! $submission_id || ! class_exists( 'GSWP_Transaction_Defense' ) ) {
			return;
		}

		if ( '' !== $this->get_submission_meta( $submission_id, self::META_ANNOTATED ) ) {
			return;
		}

		$name = $this->get_submission_meta( $submission_id, self::META_ASSESSMENT );
		if ( '' === $name ) {
			return;
		}

		$sent = GSWP_Transaction_Defense::annotate_assessment( $name, $annotation, $event_type );
		if ( $sent ) {
			$this->set_submission_meta( $submission_id, self::META_ANNOTATED, $annotation );
		}
	}

	/**
	 * Log at warning level.
	 *
	 * @param string $message Log message.
	 */
	private function log( $message ) {
		GSWP_Log::warning( $message );
	}

	/**
	 * Log a coverage gap at error level.
	 *
	 * A form being submitted unscored is the loudest thing this class has to
	 * say, and on a site without WooCommerce there is no log viewer to find it
	 * in — so it goes to the PHP error log and the in-database tail as well.
	 *
	 * @param string $message Log message.
	 */
	private function log_error( $message ) {
		GSWP_Log::error( $message );
	}
}
