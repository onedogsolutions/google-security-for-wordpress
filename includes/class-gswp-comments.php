<?php
/**
 * Comment Form Protection Class
 *
 * Adds reCAPTCHA v3 scoring to the WordPress core comment form. A hidden
 * token field is injected into the form, populated by the shared bootstrap,
 * and scored server-side before the comment is saved. Trackbacks, pingbacks,
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
	 * Whether a comment form was rendered this request, so the submit-hold
	 * snippet is printed only on pages that actually carry one.
	 *
	 * @var bool
	 */
	private $needs_inline_js = false;

	/**
	 * Whether this request is a genuine front-end comment form submission.
	 *
	 * @var bool
	 */
	private $is_form_submission = false;

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

		// Inject the hidden token field. The `comment_form` action fires
		// unconditionally at the bottom of comment_form(), inside the closing
		// </form> tag.
		//
		// Deliberately NOT the comment_form_defaults filter: core merges the
		// theme's own comment_form() arguments OVER the filtered defaults
		// (`$args = wp_parse_args( $args, apply_filters( 'comment_form_defaults',
		// $defaults ) )`), so a theme that customises `submit_field` would
		// silently drop the token field while server-side enforcement stayed
		// on — rejecting every comment from every non-privileged visitor. The
		// render gate and the enforcement gate must agree; see the A4 note in
		// GSWP_Verifier::verify_token().
		add_action( 'comment_form', array( $this, 'inject_field' ) );

		// Enqueue the reCAPTCHA API script and token bootstrap on singular
		// pages where the comment form is open.
		add_action( 'wp_enqueue_scripts', array( $this, 'enqueue_assets' ), 20 );

		// Hold a comment submit that would otherwise post an empty token.
		add_action( 'wp_footer', array( $this, 'print_inline_js' ), 25 );

		// Mark genuine comment-form submissions. See mark_form_submission().
		add_action( 'pre_comment_on_post', array( $this, 'mark_form_submission' ) );

		// Score the submission before the comment is saved. A WP_Error returned
		// here is passed straight back out of wp_new_comment(); the caller —
		// wp-comments-post.php — is what turns it into a wp_die() page.
		add_filter( 'pre_comment_approved', array( $this, 'validate_comment' ), 10, 2 );
	}

	/**
	 * Print the hidden reCAPTCHA response field inside the comment form.
	 */
	public function inject_field() {
		// Single gate shared with server-side enforcement: never print a token
		// field this plugin cannot populate.
		if ( ! GSWP_Recaptcha_Loader::will_load() ) {
			return;
		}

		printf(
			'<input type="hidden" name="g-recaptcha-response" class="g-recaptcha-response" data-recaptcha-action="%s" value="" />',
			esc_attr( 'comment' )
		);

		// enqueue_assets() covers the ordinary case from wp_enqueue_scripts,
		// but a theme can render a comment form on a screen that gate does not
		// predict. Asking again here is idempotent, and the loader registers
		// its handle for the footer, so a late enqueue still prints.
		GSWP_Recaptcha_Loader::enqueue();

		$this->needs_inline_js = true;
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
	 * Record that this request is a real comment-form submission.
	 *
	 * `pre_comment_on_post` fires only inside wp_handle_comment_submission(),
	 * the handler behind wp-comments-post.php. Every other caller that reaches
	 * `pre_comment_approved` skips it:
	 *
	 *  - WP_REST_Comments_Controller::create_item() calls wp_allow_comment()
	 *    directly, so the filter fires with no token in $_POST. Enforcing there
	 *    would fail every REST comment with "verification token is missing",
	 *    returned as an unstatused WP_Error and surfaced as HTTP 500 — breaking
	 *    mobile apps, headless front ends, and AJAX comment themes.
	 *  - XML-RPC pingbacks call wp_new_comment() directly.
	 *  - Programmatic wp_new_comment() calls have no request context at all.
	 *
	 * None of those paths can carry a token field, so they are exactly the
	 * paths enforcement must not apply to. This is not a bypass seam: a caller
	 * cannot reach wp_handle_comment_submission() while avoiding this action,
	 * and core disallows anonymous REST comment creation by default
	 * (rest_allow_anonymous_comments is false).
	 *
	 * @param int $comment_post_id Post being commented on (unused).
	 */
	public function mark_form_submission( $comment_post_id ) {
		$this->is_form_submission = true;
	}

	/**
	 * Validate the reCAPTCHA token on comment submission.
	 *
	 * @param int|string|WP_Error $approved    Current approval status.
	 * @param array               $commentdata Comment data array.
	 * @return int|string|WP_Error Unchanged on pass, WP_Error to reject.
	 */
	public function validate_comment( $approved, $commentdata ) {
		// Only the front-end comment form carries a token.
		if ( ! $this->is_form_submission ) {
			return $approved;
		}

		// Defence in depth: trackbacks and pingbacks have no form submission
		// and no token. wp_new_comment() normalises comment_type before
		// wp_allow_comment() runs, so this value is always populated here.
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

	/**
	 * Print the comment-form submit-hold snippet in the footer.
	 *
	 * The shared bootstrap (printed by GSWP_Recaptcha_Loader) populates the
	 * token field on load and refreshes it thereafter, and replaces the token a
	 * submission just spent. What it does not do for this form is hold a submit
	 * that would post an empty field: its own preventDefault-and-hold is scoped
	 * to `form.login, form.register` and deliberately not widened (see the
	 * INVARIANT note in GSWP_Recaptcha_Loader), so the comment form brings its
	 * own. That window is small but reachable — a page cache serves the comment
	 * form while the reCAPTCHA script is still loading — and the failure it
	 * prevents is a hard rejection of a legitimate comment.
	 */
	public function print_inline_js() {
		if ( ! $this->needs_inline_js || ! GSWP_Recaptcha_Loader::will_load() ) {
			return;
		}

		$site_key      = GSWP_Recaptcha_Loader::site_key();
		$is_enterprise = GSWP_Recaptcha_Loader::is_enterprise();

		ob_start();
		?>
		(function() {
			'use strict';

			if (window.gswpCommentInit) {
				return;
			}
			window.gswpCommentInit = true;

			var siteKey = <?php echo wp_json_encode( $site_key ); ?>;
			var isEnterprise = <?php echo $is_enterprise ? 'true' : 'false'; ?>;
			var SELECTOR = 'form#commentform, form.comment-form';

			// The core comment form's submit button is <input name="submit">,
			// which shadows form.submit on the element. Keep the native method.
			var nativeSubmit = HTMLFormElement.prototype.submit;

			function api() {
				if (typeof grecaptcha === 'undefined') {
					return null;
				}
				return isEnterprise ? grecaptcha.enterprise : grecaptcha;
			}

			document.addEventListener('submit', function(e) {
				var form = e.target;

				if (!form || !form.matches || !form.matches(SELECTOR)) {
					return;
				}

				// Already held for this submit, or nothing to do. A field that
				// already holds a token is left alone: the bootstrap replaces
				// spent tokens, and this only covers the never-yet-populated
				// case.
				var input = form.querySelector('.g-recaptcha-response');
				if (!input || input.value || !api()
					|| form.getAttribute('data-gswp-comment-ready') === '1') {
					return;
				}

				e.preventDefault();
				e.stopPropagation();

				var submit = function() {
					form.setAttribute('data-gswp-comment-ready', '1');
					nativeSubmit.call(form);
				};

				api().ready(function() {
					api().execute(siteKey, { action: 'comment' }).then(
						function(token) {
							input.value = token;
							submit();
						},
						submit
					);
				});
			}, true);
		})();
		<?php
		$js = ob_get_clean();

		printf(
			'<script>%s</script>',
			$js // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- JSON-encoded values, no HTML.
		);
	}
}
