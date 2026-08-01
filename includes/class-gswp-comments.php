<?php
/**
 * Comment Form Protection Class
 *
 * Adds reCAPTCHA v3 scoring to the WordPress core comment form. A hidden
 * token field is injected into the form, populated by the shared bootstrap,
 * and verified server-side before the comment is saved. Trackbacks, pingbacks,
 * and privileged users (moderate_comments capability) are exempt.
 *
 * @package Google_Security_For_WordPress
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class GSWP_Comments {

	/**
	 * Shared verifier used to score submitted tokens.
	 *
	 * @var GSWP_Verifier
	 */
	private $verifier;

	/**
	 * Constructor.
	 *
	 * @param GSWP_Verifier $verifier Token verifier instance.
	 */
	public function __construct( GSWP_Verifier $verifier ) {
		$this->verifier = $verifier;

		if ( '1' !== get_option( 'gswp_enable_comments', '0' ) ) {
			return;
		}

		// Inject the hidden token field inside the comment form, just before
		// the submit button. The comment_form_defaults filter gives access to
		// the submit_field HTML which is rendered inside the <form> element.
		add_filter( 'comment_form_defaults', array( $this, 'append_token_to_submit_field' ) );

		// Enqueue the reCAPTCHA API script and token bootstrap on singular
		// pages where the comment form is open.
		add_action( 'wp_enqueue_scripts', array( $this, 'enqueue_assets' ), 20 );

		// Server-side validation before the comment is saved. Returning a
		// WP_Error from pre_comment_approved causes wp_new_comment() to call
		// wp_die() with the error message — standard comment rejection.
		add_filter( 'pre_comment_approved', array( $this, 'validate_comment' ), 10, 2 );
	}

	/**
	 * Inject the hidden reCAPTCHA token field into the comment form defaults.
	 *
	 * Prepends the field to submit_field so it renders inside the <form>
	 * element, just before the submit button.
	 *
	 * @param array $defaults Comment form default arguments.
	 * @return array Modified defaults.
	 */
	public function append_token_to_submit_field( $defaults ) {
		// Single gate shared with server-side enforcement: never print a token
		// field this plugin cannot populate.
		if ( ! GSWP_Recaptcha_Loader::will_load() ) {
			return $defaults;
		}

		$field = sprintf(
			'<input type="hidden" name="g-recaptcha-response" class="g-recaptcha-response" data-recaptcha-action="%s" value="" />',
			esc_attr( 'comment' )
		);

		if ( isset( $defaults['submit_field'] ) ) {
			$defaults['submit_field'] = $field . "\n" . $defaults['submit_field'];
		}

		return $defaults;
	}

	/**
	 * Enqueue the reCAPTCHA API script on singular pages with comments open.
	 *
	 * Runs at priority 20 (after other plugins have enqueued) so the loader
	 * sees the full picture when deduplicating at render time.
	 */
	public function enqueue_assets() {
		if ( ! is_singular() || ! comments_open() ) {
			return;
		}

		GSWP_Recaptcha_Loader::enqueue();
	}

	/**
	 * Validate the reCAPTCHA token on comment submission.
	 *
	 * @param int|string|WP_Error $approved    Current approval status.
	 * @param array               $commentdata Comment data array.
	 * @return int|string|WP_Error Unchanged on pass, WP_Error to reject.
	 */
	public function validate_comment( $approved, $commentdata ) {
		// Trackbacks and pingbacks have no form submission and no token.
		$comment_type = isset( $commentdata['comment_type'] ) ? $commentdata['comment_type'] : '';
		if ( in_array( $comment_type, array( 'pingback', 'trackback' ), true ) ) {
			return $approved;
		}

		// Trusted users (editors, admins) are exempt — their comments are
		// already privileged and never hit the spam queue.
		if ( current_user_can( 'moderate_comments' ) ) {
			return $approved;
		}

		$result = $this->verifier->verify_token( 'comments', 'comment' );
		if ( is_wp_error( $result ) ) {
			return $result;
		}

		return $approved;
	}
}
