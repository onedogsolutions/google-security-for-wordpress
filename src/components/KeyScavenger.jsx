import { useState } from '@wordpress/element';
import { __ } from '@wordpress/i18n';
import apiFetch from '@wordpress/api-fetch';

export default function KeyScavenger( { onImport } ) {
	const [ isScanning, setIsScanning ] = useState( false );
	const [ scanPerformed, setScanPerformed ] = useState( false );
	const [ discoveredData, setDiscoveredData ] = useState( null );

	const handleInitiateScan = () => {
		setIsScanning( true );
		apiFetch( {
			path: '/gswp/v1/scan-keys',
			method: 'POST',
		} )
			.then( ( response ) => {
				setScanPerformed( true );
				if ( response.keys_found && response.keys?.length ) {
					setDiscoveredData( response.keys );
				} else {
					setDiscoveredData( null );
				}
			} )
			.catch( ( error ) => {
				// eslint-disable-next-line no-console
				console.error( 'Scan optimization runtime exception:', error );
			} )
			.finally( () => {
				setIsScanning( false );
			} );
	};

	return (
		<div className="bg-white shadow-sm ring-1 ring-gray-900/5 rounded-xl md:col-span-2">
			<div className="px-4 py-6 sm:p-8">
				<h2 className="text-base font-semibold leading-7 text-gray-900">
					{ __(
						'Smart Key Scavenger',
						'google-security-for-wordpress'
					) }
				</h2>
				<p className="mt-1 text-sm leading-6 text-gray-600">
					{ __(
						'We scanned your website database for existing Google reCAPTCHA configurations from other plugins. You can instantly import them with a single click.',
						'google-security-for-wordpress'
					) }
				</p>

				{ /* Initial State (Before Scan) */ }
				{ ! scanPerformed && ! isScanning && (
					<div className="mt-6 rounded-lg bg-gray-50 border border-dashed border-gray-200 p-6 text-center">
						<svg
							className="mx-auto h-8 w-8 text-gray-400"
							fill="none"
							viewBox="0 0 24 24"
							stroke="currentColor"
						>
							<path
								strokeLinecap="round"
								strokeLinejoin="round"
								strokeWidth={ 1.5 }
								d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"
							/>
						</svg>
						<h3 className="mt-2 text-sm font-semibold text-gray-900">
							{ __(
								'Scan for Existing Keys',
								'google-security-for-wordpress'
							) }
						</h3>
						<p className="mt-1 text-xs text-gray-500">
							{ __(
								'Click below to search your local database for reCAPTCHA configurations from Fluent Forms, Gravity Forms, Beaver Builder, and PowerPack Addons.',
								'google-security-for-wordpress'
							) }
						</p>
						<button
							type="button"
							onClick={ handleInitiateScan }
							className="mt-4 px-5 py-2.5 bg-blue-600 hover:bg-blue-700 text-white font-medium text-sm rounded-lg shadow-sm transition-colors cursor-pointer"
						>
							{ __(
								'Scan Website for Keys',
								'google-security-for-wordpress'
							) }
						</button>
					</div>
				) }

				{ /* Processing State (isScanning === true) */ }
				{ isScanning && (
					<div className="mt-6 flex flex-col items-center justify-center py-6">
						<svg
							className="animate-spin h-8 w-8 text-blue-600 mb-3"
							fill="none"
							viewBox="0 0 24 24"
						>
							<circle
								className="opacity-25"
								cx="12"
								cy="12"
								r="10"
								stroke="currentColor"
								strokeWidth="4"
							/>
							<path
								className="opacity-75"
								fill="currentColor"
								d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"
							/>
						</svg>
						<span className="text-sm font-medium text-gray-900">
							{ __(
								'Scanning website database…',
								'google-security-for-wordpress'
							) }
						</span>
						<span className="text-xs text-gray-500 mt-1">
							{ __(
								'Please wait, this may take a moment.',
								'google-security-for-wordpress'
							) }
						</span>
					</div>
				) }

				{ /* Discovered State (scanPerformed === true && discoveredData !== null) */ }
				{ scanPerformed && ! isScanning && discoveredData && (
					<div className="mt-6 overflow-hidden border border-gray-100 rounded-lg divide-y divide-gray-100 bg-gray-50/50">
						{ discoveredData.map( ( found ) => (
							<div
								key={ `${ found.source }-${ found.site_key }` }
								className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-y-4 gap-x-6 p-4"
							>
								<div className="flex-1">
									<div className="flex items-center gap-x-2">
										<span className="text-sm font-semibold text-gray-900">
											{ found.source }
										</span>
										<span className="inline-flex items-center rounded-md bg-blue-50 px-1.5 py-0.5 text-xs font-medium text-blue-700 ring-1 ring-inset ring-blue-700/10">
											{ __(
												'Found',
												'google-security-for-wordpress'
											) }
										</span>
										{ found.version === 'v3' && (
											<span className="inline-flex items-center rounded-md bg-green-50 px-1.5 py-0.5 text-xs font-medium text-green-700 ring-1 ring-inset ring-green-600/20">
												v3
											</span>
										) }
										{ found.version === 'v2' && (
											<span className="inline-flex items-center rounded-md bg-red-50 px-1.5 py-0.5 text-xs font-medium text-red-700 ring-1 ring-inset ring-red-600/10">
												v2
											</span>
										) }
									</div>
									<div className="mt-2 space-y-1 text-xs text-gray-500">
										<p>
											<span className="font-medium">
												{ __(
													'Site Key: ',
													'google-security-for-wordpress'
												) }
											</span>
											<code>
												{ found.site_key
													? `${ found.site_key.substring(
															0,
															10
													  ) }...`
													: '' }
											</code>
										</p>
										{ found.secret_key ? (
											<p>
												<span className="font-medium">
													{ __(
														'Secret Key: ',
														'google-security-for-wordpress'
													) }
												</span>
												<code>
													{ found.secret_key.substring(
														0,
														8
													) }
													...
												</code>
											</p>
										) : (
											<p className="text-amber-600">
												{ __(
													'Secret Key is not stored globally (module-specific). You will need to enter it manually.',
													'google-security-for-wordpress'
												) }
											</p>
										) }
										{ ! found.importable && (
											<p className="text-red-600">
												{ __(
													'This is a reCAPTCHA v2 (checkbox) key. It cannot be used with this plugin, which requires v3 keys.',
													'google-security-for-wordpress'
												) }
											</p>
										) }
									</div>
								</div>

								<div className="flex flex-col sm:flex-row items-center gap-3">
									<button
										type="button"
										disabled={ ! found.importable }
										onClick={ () =>
											onImport(
												found.site_key,
												found.secret_key
											)
										}
										className="inline-flex items-center rounded-md bg-white px-3 py-2 text-sm font-semibold text-indigo-600 shadow-sm ring-1 ring-inset ring-indigo-300 hover:bg-indigo-50 transition cursor-pointer disabled:opacity-50 disabled:cursor-not-allowed disabled:hover:bg-white"
									>
										{ __(
											'Import Found Credentials',
											'google-security-for-wordpress'
										) }
									</button>
								</div>
							</div>
						) ) }
						<div className="p-3 text-right">
							<button
								type="button"
								onClick={ handleInitiateScan }
								className="text-xs font-medium text-indigo-600 hover:text-indigo-500 underline transition cursor-pointer"
							>
								{ __(
									'Run Rescan',
									'google-security-for-wordpress'
								) }
							</button>
						</div>
					</div>
				) }

				{ /* Empty Result State (scanPerformed === true && discoveredData === null) */ }
				{ scanPerformed && ! isScanning && ! discoveredData && (
					<div className="mt-6 rounded-lg bg-gray-50 border border-dashed border-gray-200 p-6 text-center">
						<svg
							className="mx-auto h-8 w-8 text-gray-400"
							fill="none"
							viewBox="0 0 24 24"
							stroke="currentColor"
						>
							<path
								strokeLinecap="round"
								strokeLinejoin="round"
								strokeWidth={ 1.5 }
								d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"
							/>
						</svg>
						<h3 className="mt-2 text-sm font-semibold text-gray-900">
							{ __(
								'No keys detected',
								'google-security-for-wordpress'
							) }
						</h3>
						<p className="mt-1 text-xs text-gray-500">
							{ __(
								'No existing reCAPTCHA keys were found on this site from supported plugins.',
								'google-security-for-wordpress'
							) }
						</p>
						<button
							type="button"
							onClick={ handleInitiateScan }
							className="mt-4 inline-flex items-center text-xs font-semibold text-indigo-600 hover:text-indigo-500 transition cursor-pointer"
						>
							{ __(
								'Run Rescan',
								'google-security-for-wordpress'
							) }
						</button>
					</div>
				) }
			</div>
		</div>
	);
}
