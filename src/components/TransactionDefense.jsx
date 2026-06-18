import { __ } from '@wordpress/i18n';

function Toggle( { label, enabled, onToggle } ) {
	return (
		<div className="flex items-center gap-x-3">
			<span className="text-sm text-gray-600">
				{ enabled
					? __( 'Enabled', 'google-security-for-wordpress' )
					: __( 'Disabled', 'google-security-for-wordpress' ) }
			</span>
			<button
				type="button"
				aria-label={ label }
				className={ `relative inline-flex h-6 w-11 flex-shrink-0 cursor-pointer rounded-full border-2 border-transparent transition-colors duration-200 ease-in-out focus:outline-none focus:ring-2 focus:ring-indigo-600 focus:ring-offset-2 ${
					enabled ? 'bg-indigo-600' : 'bg-gray-200'
				}` }
				onClick={ onToggle }
			>
				<span
					aria-hidden="true"
					className={ `pointer-events-none inline-block h-5 w-5 transform rounded-full bg-white shadow ring-0 transition duration-200 ease-in-out ${
						enabled ? 'translate-x-5' : 'translate-x-0'
					}` }
				/>
			</button>
		</div>
	);
}

export default function TransactionDefense( { settings, onChange } ) {
	// Transaction defense is an Enterprise-only, WooCommerce checkout feature.
	const isEnterprise = settings.key_type === 'enterprise';
	const defenseOn =
		settings.txn_defense === '1' || settings.txn_defense === true;
	const blockOn = settings.txn_block === '1' || settings.txn_block === true;
	const threshold = parseFloat( settings.threshold_txn ) || 0.8;

	return (
		<div className="bg-white shadow-sm ring-1 ring-gray-900/5 rounded-xl md:col-span-2">
			<div className="px-4 py-6 sm:p-8">
				<h2 className="text-base font-semibold leading-7 text-gray-900">
					{ __(
						'Transaction Defense',
						'google-security-for-wordpress'
					) }
				</h2>
				<p className="mt-1 text-sm leading-6 text-gray-600">
					{ __(
						'reCAPTCHA Enterprise Fraud Prevention scores WooCommerce checkouts against carding, stolen instruments, and account takeover. The plugin sends the order’s billing/shipping address, amount, line items, and payment method with each assessment, then annotates the order’s outcome so Google’s model keeps learning.',
						'google-security-for-wordpress'
					) }
				</p>

				{ ! isEnterprise && (
					<div className="mt-6 rounded-md bg-amber-50 border border-amber-200 p-4">
						<p className="text-sm text-amber-800">
							{ __(
								'Transaction defense requires the Enterprise key type. Select Enterprise under API Credentials and enable it in the Google Cloud Console (Fraud Defense → your key → Transaction defense).',
								'google-security-for-wordpress'
							) }
						</p>
					</div>
				) }

				{ isEnterprise && (
					<div className="mt-6 divide-y divide-gray-100 border-t border-gray-100">
						{ /* Master enable */ }
						<div className="py-6 flex flex-col gap-y-4 sm:flex-row sm:items-center sm:justify-between sm:gap-x-8">
							<div className="flex-1">
								<h3 className="text-sm font-semibold text-gray-900">
									{ __(
										'Send transaction data',
										'google-security-for-wordpress'
									) }
								</h3>
								<p className="mt-1 text-sm text-gray-500">
									{ __(
										'Include payment transaction data in checkout assessments and annotate order outcomes. Requires the WooCommerce checkout protection above to be enabled.',
										'google-security-for-wordpress'
									) }
								</p>
							</div>
							<Toggle
								label={ __(
									'Send transaction data',
									'google-security-for-wordpress'
								) }
								enabled={ defenseOn }
								onToggle={ () =>
									onChange(
										'txn_defense',
										defenseOn ? '0' : '1'
									)
								}
							/>
						</div>

						{ /* Optional risk blocking */ }
						{ defenseOn && (
							<div className="py-6 flex flex-col gap-y-4 sm:flex-row sm:items-start sm:justify-between sm:gap-x-8 animate-fadeIn">
								<div className="flex-1">
									<h3 className="text-sm font-semibold text-gray-900">
										{ __(
											'Block high-risk transactions',
											'google-security-for-wordpress'
										) }
									</h3>
									<p className="mt-1 text-sm text-gray-500">
										{ __(
											'Reject checkout when the fraud risk meets the threshold. Leave off until you trust the scores — the reCAPTCHA score check still applies regardless.',
											'google-security-for-wordpress'
										) }
									</p>
								</div>

								<div className="flex flex-col items-start sm:items-end gap-y-3 min-w-[240px]">
									<Toggle
										label={ __(
											'Block high-risk transactions',
											'google-security-for-wordpress'
										) }
										enabled={ blockOn }
										onToggle={ () =>
											onChange(
												'txn_block',
												blockOn ? '0' : '1'
											)
										}
									/>

									{ blockOn && (
										<div className="w-full mt-2 animate-fadeIn">
											<div className="flex justify-between items-center text-xs text-gray-600 mb-1">
												<span>
													{ __(
														'Risk Threshold',
														'google-security-for-wordpress'
													) }
												</span>
												<span className="font-semibold text-indigo-600">
													{ threshold.toFixed( 1 ) }
												</span>
											</div>
											<div className="flex items-center gap-x-3">
												<span className="text-xs text-gray-400">
													0.0 (Low)
												</span>
												<input
													type="range"
													min="0.0"
													max="1.0"
													step="0.1"
													value={ threshold }
													onChange={ ( e ) =>
														onChange(
															'threshold_txn',
															e.target.value
														)
													}
													className="flex-1 h-1 bg-gray-200 rounded-lg appearance-none cursor-pointer accent-indigo-600 focus:outline-none focus:ring-2 focus:ring-indigo-600"
												/>
												<span className="text-xs text-gray-400">
													1.0 (High)
												</span>
											</div>
										</div>
									) }
								</div>
							</div>
						) }
					</div>
				) }
			</div>
		</div>
	);
}
