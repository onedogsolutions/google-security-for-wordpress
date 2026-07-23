import { useState } from '@wordpress/element';
import { __ } from '@wordpress/i18n';
import apiFetch from '@wordpress/api-fetch';

function StatusIcon( { ok } ) {
	if ( ok ) {
		return (
			<span className="inline-flex items-center justify-center h-5 w-5 rounded-full bg-green-100">
				<svg className="h-3 w-3 text-green-600" fill="currentColor" viewBox="0 0 20 20">
					<path fillRule="evenodd" d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z" clipRule="evenodd" />
				</svg>
			</span>
		);
	}
	return (
		<span className="inline-flex items-center justify-center h-5 w-5 rounded-full bg-red-100">
			<svg className="h-3 w-3 text-red-600" fill="currentColor" viewBox="0 0 20 20">
				<path fillRule="evenodd" d="M4.293 4.293a1 1 0 011.414 0L10 8.586l4.293-4.293a1 1 0 111.414 1.414L11.414 10l4.293 4.293a1 1 0 01-1.414 1.414L10 11.414l-4.293 4.293a1 1 0 01-1.414-1.414L8.586 10 4.293 5.707a1 1 0 010-1.414z" clipRule="evenodd" />
			</svg>
		</span>
	);
}

function JsonBlock( { data, label } ) {
	if ( ! data ) {
		return null;
	}
	return (
		<div className="mt-3">
			{ label && (
				<p className="text-xs font-medium text-gray-500 mb-1">{ label }</p>
			) }
			<pre className="text-xs bg-gray-900 text-gray-100 rounded-lg p-4 overflow-x-auto max-h-72 overflow-y-auto whitespace-pre-wrap break-words">
				{ JSON.stringify( data, null, 2 ) }
			</pre>
		</div>
	);
}

function TestCard( { title, result } ) {
	const [ expanded, setExpanded ] = useState( false );

	if ( ! result ) {
		return null;
	}

	const isSkipped = result.skipped;
	const statusColor = isSkipped
		? 'border-gray-200 bg-gray-50'
		: result.ok
			? 'border-green-200 bg-green-50/50'
			: 'border-red-200 bg-red-50/50';

	return (
		<div className={ `rounded-lg border p-4 ${ statusColor }` }>
			<div className="flex items-start gap-x-3">
				{ ! isSkipped && <StatusIcon ok={ result.ok } /> }
				{ isSkipped && (
					<span className="inline-flex items-center justify-center h-5 w-5 rounded-full bg-gray-200">
						<span className="text-gray-500 text-xs">—</span>
					</span>
				) }
				<div className="flex-1 min-w-0">
					<h4 className="text-sm font-semibold text-gray-900">{ title }</h4>
					<p className={ `mt-1 text-sm ${ result.ok ? 'text-green-700' : isSkipped ? 'text-gray-600' : 'text-red-700' }` }>
						{ result.message }
					</p>

					{ result.note && (
						<p className="mt-2 text-xs text-amber-700 bg-amber-50 border border-amber-200 rounded p-2">
							{ result.note }
						</p>
					) }

					{ ( result.request || result.response ) && (
						<button
							type="button"
							onClick={ () => setExpanded( ! expanded ) }
							className="mt-2 text-xs font-medium text-indigo-600 hover:text-indigo-500 transition"
						>
							{ expanded
								? __( 'Hide request/response details', 'google-security-for-wordpress' )
								: __( 'Show request/response details', 'google-security-for-wordpress' ) }
						</button>
					) }

					{ expanded && (
						<div className="mt-2 space-y-3">
							{ result.request && (
								<div>
									<JsonBlock label={ __( 'Request URL (key redacted)', 'google-security-for-wordpress' ) } data={ result.request.url } />
									<JsonBlock label={ __( 'Request Payload Sent to Google', 'google-security-for-wordpress' ) } data={ result.request.body } />
								</div>
							) }
							{ result.response && (
								<JsonBlock label={ __( 'Google Response', 'google-security-for-wordpress' ) } data={ result.response } />
							) }
						</div>
					) }
				</div>
			</div>
		</div>
	);
}

export default function Diagnostics( { settings } ) {
	const [ results, setResults ] = useState( null );
	const [ isRunning, setIsRunning ] = useState( false );
	const [ error, setError ] = useState( '' );

	const isEnterprise = settings.key_type === 'enterprise';

	const runDiagnostic = () => {
		setIsRunning( true );
		setError( '' );
		setResults( null );

		apiFetch( {
			path: '/gswp/v1/diagnose',
			method: 'POST',
			data: {},
		} )
			.then( ( data ) => {
				setResults( data );
				setIsRunning( false );
			} )
			.catch( ( err ) => {
				setError(
					err.message ||
						__( 'Diagnostic request failed. Please try again.', 'google-security-for-wordpress' )
				);
				setIsRunning( false );
			} );
	};

	return (
		<div className="bg-white shadow-sm ring-1 ring-gray-900/5 rounded-xl">
			<div className="px-4 py-6 sm:p-8">
				<h2 className="text-base font-semibold leading-7 text-gray-900">
					{ __( 'API Diagnostics', 'google-security-for-wordpress' ) }
				</h2>
				<p className="mt-1 text-sm leading-6 text-gray-600">
					{ __(
						'Run a live test against Google\'s reCAPTCHA API to verify connectivity, credentials, and payload structure. Sends a dummy token so no real user data is scored. Use this to debug errors shown in Google Cloud Console.',
						'google-security-for-wordpress'
					) }
				</p>

				<div className="mt-6">
					<button
						type="button"
						onClick={ runDiagnostic }
						disabled={ isRunning }
						className="inline-flex items-center gap-x-2 rounded-md bg-indigo-600 px-4 py-2.5 text-sm font-semibold text-white shadow-sm hover:bg-indigo-500 focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-indigo-600 transition disabled:opacity-50"
					>
						{ isRunning ? (
							<>
								<svg className="animate-spin -ml-1 mr-2 h-4 w-4 text-white" fill="none" viewBox="0 0 24 24">
									<circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
									<path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z" />
								</svg>
								{ __( 'Running tests…', 'google-security-for-wordpress' ) }
							</>
						) : (
							<>
								<svg className="h-4 w-4" fill="none" viewBox="0 0 24 24" strokeWidth="1.5" stroke="currentColor">
									<path strokeLinecap="round" strokeLinejoin="round" d="M21 21l-5.197-5.197m0 0A7.5 7.5 0 105.196 5.196a7.5 7.5 0 0010.607 10.607z" />
								</svg>
								{ __( 'Run Diagnostic', 'google-security-for-wordpress' ) }
							</>
						) }
					</button>
				</div>

				{ error && (
					<div className="mt-4 rounded-md bg-red-50 border border-red-200 p-4">
						<p className="text-sm text-red-800">{ error }</p>
					</div>
				) }

				{ results && (
					<div className="mt-6 space-y-4">
						<p className="text-xs text-gray-400">
							{ __( 'Run at:', 'google-security-for-wordpress' ) } { results.timestamp }
						</p>

						{ /* Configuration Checks */ }
						<div className="rounded-lg border border-gray-200 p-4">
							<div className="flex items-center gap-x-2 mb-3">
								<StatusIcon ok={ results.configuration.ok } />
								<h4 className="text-sm font-semibold text-gray-900">
									{ __( 'Configuration', 'google-security-for-wordpress' ) }
								</h4>
							</div>
							<div className="grid gap-2">
								{ Object.entries( results.configuration.checks ).map( ( [ key, check ] ) => (
									<div key={ key } className="flex items-center gap-x-2 text-sm">
										<StatusIcon ok={ check.ok } />
										<span className="text-gray-600">{ check.label }:</span>
										<span className={ `font-mono text-xs ${ check.ok ? 'text-gray-900' : 'text-red-600' }` }>
											{ check.value }
										</span>
									</div>
								) ) }
							</div>
						</div>

						{ /* Connectivity Test */ }
						<TestCard
							title={
								isEnterprise
									? __( 'Enterprise API Connectivity', 'google-security-for-wordpress' )
									: __( 'Classic siteverify Connectivity', 'google-security-for-wordpress' )
							}
							result={ results.connectivity }
						/>

						{ /* Account Defender Test */ }
						<TestCard
							title={ __( 'Account Defender Assessment', 'google-security-for-wordpress' ) }
							result={ results.account_defender }
						/>

						{ /* Transaction Defense Test */ }
						<TestCard
							title={ __( 'Transaction Defense Assessment', 'google-security-for-wordpress' ) }
							result={ results.transaction_defense }
						/>
					</div>
				) }
			</div>
		</div>
	);
}
