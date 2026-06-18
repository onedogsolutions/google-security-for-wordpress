/**
 * Two-Factor Authentication code-entry popup.
 *
 * When a 2FA-enrolled user submits any login form, the server holds the login
 * (blocked at `authenticate`) and sets a readable flag cookie. This script
 * detects that flag — on page load (form reload) or shortly after a login form
 * submit (AJAX logins that never reload) — opens a popup for the code, and
 * completes the login by posting the code to admin-ajax.
 *
 * @package Google_Security_For_WordPress
 */
( function () {
	'use strict';

	var data = window.gswp2fa || {};
	var i18n = data.i18n || {};
	var FLAG = data.flagCookie || 'gswp_2fa_challenge';

	function hasFlag() {
		return document.cookie.split( ';' ).some( function ( c ) {
			return c.trim().indexOf( FLAG + '=' ) === 0;
		} );
	}

	function clearFlag() {
		document.cookie =
			FLAG + '=; expires=Thu, 01 Jan 1970 00:00:00 GMT; path=/';
	}

	var built = false;
	var overlay, input, errorEl, submitBtn;

	function build() {
		if ( built ) {
			return;
		}
		built = true;

		overlay = document.createElement( 'div' );
		overlay.className = 'gswp-2fa-overlay';
		overlay.setAttribute( 'role', 'dialog' );
		overlay.setAttribute( 'aria-modal', 'true' );

		var modal = document.createElement( 'div' );
		modal.className = 'gswp-2fa-modal';

		var title = document.createElement( 'h2' );
		title.className = 'gswp-2fa-title';
		title.textContent = i18n.title || 'Two-Factor Authentication';

		var desc = document.createElement( 'p' );
		desc.className = 'gswp-2fa-desc';
		desc.textContent = i18n.desc || '';

		errorEl = document.createElement( 'div' );
		errorEl.className = 'gswp-2fa-error';
		errorEl.style.display = 'none';

		input = document.createElement( 'input' );
		input.type = 'text';
		input.className = 'gswp-2fa-input';
		input.setAttribute( 'inputmode', 'numeric' );
		input.setAttribute( 'autocomplete', 'one-time-code' );
		input.setAttribute( 'aria-label', i18n.label || 'Authentication code' );

		submitBtn = document.createElement( 'button' );
		submitBtn.type = 'button';
		submitBtn.className = 'gswp-2fa-submit';
		submitBtn.textContent = i18n.verify || 'Verify';

		var cancel = document.createElement( 'button' );
		cancel.type = 'button';
		cancel.className = 'gswp-2fa-cancel';
		cancel.textContent = i18n.cancel || 'Cancel';

		modal.appendChild( title );
		modal.appendChild( desc );
		modal.appendChild( errorEl );
		modal.appendChild( input );
		modal.appendChild( submitBtn );
		modal.appendChild( cancel );
		overlay.appendChild( modal );
		document.body.appendChild( overlay );

		submitBtn.addEventListener( 'click', submit );
		cancel.addEventListener( 'click', function () {
			// Abandon the challenge: the unused pending token expires server-side.
			clearFlag();
			close();
		} );
		input.addEventListener( 'keydown', function ( e ) {
			if ( e.key === 'Enter' ) {
				e.preventDefault();
				submit();
			}
		} );
	}

	function open() {
		build();
		overlay.classList.add( 'is-open' );
		document.body.classList.add( 'gswp-2fa-lock' );
		setTimeout( function () {
			input.focus();
		}, 50 );
	}

	function close() {
		if ( overlay ) {
			overlay.classList.remove( 'is-open' );
			document.body.classList.remove( 'gswp-2fa-lock' );
		}
	}

	function showError( msg ) {
		errorEl.textContent = msg;
		errorEl.style.display = 'block';
	}

	function submit() {
		var code = ( input.value || '' ).trim();
		if ( ! code ) {
			showError( i18n.empty || 'Enter your authentication code.' );
			return;
		}

		submitBtn.disabled = true;
		errorEl.style.display = 'none';

		var body = new window.FormData();
		body.append( 'action', 'gswp_2fa_verify' );
		body.append( 'code', code );

		window
			.fetch( data.ajaxUrl, {
				method: 'POST',
				credentials: 'same-origin',
				body: body,
			} )
			.then( function ( r ) {
				return r.json();
			} )
			.then( function ( res ) {
				submitBtn.disabled = false;
				if ( res && res.success ) {
					clearFlag();
					var url =
						res.data && res.data.redirect
							? res.data.redirect
							: data.home || '/';
					window.location.assign( url );
				} else {
					showError(
						( res && res.data ) ||
							i18n.invalid ||
							'Invalid verification code. Please try again.'
					);
					input.select();
				}
			} )
			.catch( function () {
				submitBtn.disabled = false;
				showError(
					i18n.invalid ||
						'Invalid verification code. Please try again.'
				);
			} );
	}

	var watching = false;
	function watchForChallenge() {
		if ( watching ) {
			return;
		}
		watching = true;
		var tries = 0;
		var iv = setInterval( function () {
			tries++;
			if ( hasFlag() ) {
				clearInterval( iv );
				watching = false;
				open();
			} else if ( tries > 40 ) {
				// ~10s.
				clearInterval( iv );
				watching = false;
			}
		}, 250 );
	}

	function init() {
		// Full page reload after a held login: the flag is already set.
		if ( hasFlag() ) {
			open();
			return;
		}

		// AJAX logins never reload, so watch for the flag appearing after a
		// password form is submitted.
		var forms = document.querySelectorAll( 'form' );
		Array.prototype.forEach.call( forms, function ( form ) {
			if ( form.querySelector( 'input[type="password"]' ) ) {
				form.addEventListener(
					'submit',
					function () {
						watchForChallenge();
					},
					true
				);
			}
		} );
	}

	if ( document.readyState === 'loading' ) {
		document.addEventListener( 'DOMContentLoaded', init );
	} else {
		init();
	}
} )();
