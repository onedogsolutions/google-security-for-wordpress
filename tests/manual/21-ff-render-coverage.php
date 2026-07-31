<?php
/**
 * Fluent Forms replacement verification — chunk 21: render coverage (v2.23.0)
 *
 * THE IMPORTANT ONE. Renders every Fluent Form server-side and checks that our
 * hidden token field is actually in the markup.
 *
 * A FAIL here means that form is live and, once the provider is switched on and
 * Fluent Forms' own captcha retired, unprotected. There is no staged rollout to
 * discover a missed render path over time, so it has to be answered here.
 *
 * It also settles two bindings the provider rests on:
 *
 *   - which injection hook actually fires (fluentform/form_element_start, or
 *     the submit-button action), and on which render paths;
 *   - whether fluentform/before_form_render and after_form_render fire in
 *     BALANCED PAIRS. The coverage backstop is an output buffer opened on the
 *     first and closed on the second, because Fluent Forms has no equivalent of
 *     Gravity Forms' gform_get_form_filter. An unbalanced pair would leave a
 *     buffer open and truncate the page, so the provider refuses to close a
 *     buffer whose nesting level does not match — and this chunk is how we
 *     learn whether that guard will ever fire in practice.
 *
 * Read-only apart from the injection log the provider itself writes.
 *
 * @package Google_Security_For_WordPress
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

echo "=== RUN CONTEXT ===\n";
echo '  plugin version : ' . ( defined( 'GSWP_VERSION' ) ? GSWP_VERSION : 'NOT ACTIVE' ) . "\n";
echo '  site           : ' . wp_parse_url( home_url(), PHP_URL_HOST ) . "\n";
echo '  time (UTC)     : ' . gmdate( 'Y-m-d H:i:s' ) . "\n\n";

if ( ! class_exists( 'GSWP_Provider_Fluent_Forms' ) ) {
	echo "STOP: plugin not active or older than 2.23.0.\n";
	return;
}

$provider = GSWP_Form_Provider_Registry::get( 'fluent-forms' );
if ( ! $provider || ! $provider->is_active() ) {
	echo "STOP: Fluent Forms is not active on this site.\n";
	return;
}

// The provider only registers its hooks when it is switched on. Render coverage
// has to be measurable BEFORE the operator switches it on — that is the whole
// point — so wire up the RENDER hooks for this run.
//
// Deliberately not register_hooks(): that also attaches validation, submission
// and payment-lifecycle callbacks, and would need a GSWP_Verifier, whose
// constructor registers a dozen WooCommerce filters. None of that is wanted
// here, and a chunk that reports on rendering should not be able to affect a
// submission. The render path never touches the verifier.
$was_on = GSWP_Form_Provider_Registry::is_on( 'fluent-forms' );
if ( ! $was_on ) {
	add_action( 'fluentform/form_element_start', array( $provider, 'inject_token_field' ), 10, 1 );
	add_action( 'fluentform/before_form_render', array( $provider, 'open_backstop_buffer' ), 1, 1 );
	add_action( 'fluentform/after_form_render', array( $provider, 'close_backstop_buffer' ), 999, 1 );

	echo "NOTE: provider is switched off; its RENDER hooks were attached for this\n";
	echo "      run only. No option was changed and no validation hook was added.\n\n";
}

// ---------------------------------------------------------------------------
// Hook observation. Recorded per form so a form that renders through an
// unexpected path is visible as such rather than as a bare failure.
// ---------------------------------------------------------------------------
$observed = array();

// Accepts two args because the hooks disagree about their signature:
// form_element_start and before/after_form_render pass the FORM first, but
// render_item_submit_button passes the submit-button ITEM first and the form
// second. The first cut took one argument and reported every
// render_item_submit_button fire under "form #0", which reads like a failure
// and is not one.
$note = function ( $hook ) use ( &$observed ) {
	return function ( $a = null, $b = null ) use ( $hook, &$observed ) {
		$id = 0;
		foreach ( array( $a, $b ) as $form ) {
			if ( is_object( $form ) && isset( $form->id ) ) {
				$id = (int) $form->id;
				break;
			}
			if ( is_array( $form ) && isset( $form['id'] ) ) {
				$id = (int) $form['id'];
				break;
			}
		}
		if ( ! isset( $observed[ $id ] ) ) {
			$observed[ $id ] = array();
		}
		if ( ! isset( $observed[ $id ][ $hook ] ) ) {
			$observed[ $id ][ $hook ] = 0;
		}
		++$observed[ $id ][ $hook ];
	};
};

foreach (
	array(
		'fluentform/form_element_start',
		'fluentform/before_form_render',
		'fluentform/after_form_render',
		'fluentform/render_item_submit_button',
	) as $hook
) {
	// Priority 0 so we bracket the provider's own callbacks, and 2 accepted
	// args because render_item_submit_button passes ( $item, $form ).
	add_action( $hook, $note( $hook ), 0, 2 );
}

// ---------------------------------------------------------------------------
// Render every form.
// ---------------------------------------------------------------------------
$forms  = $provider->forms();
$rows   = array();
$passed = 0;
$failed = 0;

foreach ( $forms as $form_id => $title ) {
	$eligible = $provider->form_is_eligible( $form_id );

	if ( ! $eligible ) {
		$rows[] = array(
			'id'     => $form_id,
			'title'  => $title,
			'result' => 'skipped (not eligible: ' . $provider->native_captcha_state( $form_id ) . ')',
			'action' => '',
		);
		continue;
	}

	$markup = do_shortcode( '[fluentform id="' . (int) $form_id . '"]' );
	$markup = is_string( $markup ) ? $markup : '';

	$has_field = false !== strpos( $markup, 'name="gswp_ff_token"' );
	$has_form  = false !== stripos( $markup, '</form>' );

	// The action the rendered field carries. Compared against the provider's
	// resolver in chunk 26; printed here because a render that produces no
	// action attribute at all is a different failure from one that produces the
	// wrong one.
	$action = '';
	if ( preg_match( '/name="gswp_ff_token"[^>]*data-recaptcha-action="([^"]*)"/', $markup, $m ) ) {
		$action = $m[1];
	}

	if ( $has_field ) {
		++$passed;
		$result = 'PASS';
	} else {
		++$failed;
		$result = $has_form ? 'FAIL (form rendered, no token field)' : 'FAIL (no form markup produced)';
	}

	$rows[] = array(
		'id'     => $form_id,
		'title'  => $title,
		'result' => $result,
		'action' => $action,
		'bytes'  => strlen( $markup ),
	);
}

// ---------------------------------------------------------------------------
// Report.
// ---------------------------------------------------------------------------
echo "=== RENDER COVERAGE ===\n\n";
printf( "%-5s %-34s %-38s %s\n", 'ID', 'TITLE', 'RESULT', 'ACTION' );
echo str_repeat( '-', 100 ) . "\n";

foreach ( $rows as $row ) {
	printf(
		"%-5s %-34s %-38s %s\n",
		$row['id'],
		substr( (string) $row['title'], 0, 33 ),
		$row['result'],
		$row['action']
	);
}

echo "\nRenders passed: {$passed}   failed: {$failed}\n";

echo "\n  A result of 'skipped (not eligible: unsupported)' (2.23.2) is a Fluent\n";
echo "  Forms CONVERSATIONAL form. It renders through a separate Vue view that\n";
echo "  fires none of the hooks this provider injects into, so it is correctly\n";
echo "  reported as unsupported rather than left eligible and permanently\n";
echo "  logging a coverage gap on every submission. This is expected, not a\n";
echo "  failure — do not chase it.\n";

echo "\n=== HOOK OBSERVATION (settles the injection binding) ===\n\n";
if ( empty( $observed ) ) {
	echo "  NOTHING FIRED. Every hook name in the provider is wrong for this\n";
	echo "  version of Fluent Forms, or forms do not render through the\n";
	echo "  shortcode on this site. Report this and do not enable the provider.\n";
} else {
	foreach ( $observed as $form_id => $hooks ) {
		echo '  form #' . $form_id . "\n";
		foreach ( $hooks as $hook => $count ) {
			echo '    ' . str_pad( $hook, 44 ) . $count . "\n";
		}

		$before = isset( $hooks['fluentform/before_form_render'] ) ? $hooks['fluentform/before_form_render'] : 0;
		$after  = isset( $hooks['fluentform/after_form_render'] ) ? $hooks['fluentform/after_form_render'] : 0;

		if ( $before !== $after ) {
			echo "    *** UNBALANCED before/after_form_render ({$before} / {$after}).\n";
			echo "        The buffered coverage backstop is NOT safe on this install.\n";
		}
	}

	if ( isset( $observed[0] ) ) {
		echo "\n  A 'form #0' bucket means a hook fired without a form this probe\n";
		echo "  could identify in either of its first two arguments. That is only a\n";
		echo "  problem for a hook the PROVIDER uses — it uses form_element_start\n";
		echo "  and before/after_form_render, all of which pass the form first.\n";
	}
}

echo "\n=== WHAT THIS CHUNK CANNOT ANSWER ===\n";
echo "  This renders through the shortcode only. VERIFIED against source\n";
echo "  (2.23.2): the Gutenberg block, the Elementor widget, and Fluent Forms\n";
echo "  Pro's form modal all emit do_shortcode('[fluentform ...]') themselves,\n";
echo "  so all three route through the same FormBuilder::render() call this\n";
echo "  chunk exercises — that is a source-level fact, not yet an observation\n";
echo "  on THIS site. If this site uses any of those, load one of each in a\n";
echo "  browser, then re-run chunk 20 and check the form shows a token as\n";
echo "  seen, to move it from verified to observed.\n";
echo "\n  It also confirms only that the FIELD is present. Only a browser confirms\n";
echo "  JavaScript fills it.\n";

echo "\nReport the whole block above verbatim.\n";
