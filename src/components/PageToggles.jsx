import { __ } from '@wordpress/i18n';

export default function PageToggles( { settings, onChange } ) {
	const checkpoints = [
		{
			id: 'login',
			title: __(
				'WooCommerce Customer Login',
				'google-recaptcha-v3-for-woocommerce'
			),
			description: __(
				'Protects the customer login form from brute force attacks and credentials stuffing.',
				'google-recaptcha-v3-for-woocommerce'
			),
			toggleKey: 'enable_login',
			thresholdKey: 'threshold_login',
		},
		{
			id: 'registration',
			title: __(
				'WooCommerce Customer Registration',
				'google-recaptcha-v3-for-woocommerce'
			),
			description: __(
				'Prevents spam bots and bulk automated user registrations on your store.',
				'google-recaptcha-v3-for-woocommerce'
			),
			toggleKey: 'enable_registration',
			thresholdKey: 'threshold_registration',
		},
		{
			id: 'checkout',
			title: __(
				'WooCommerce Checkout Process',
				'google-recaptcha-v3-for-woocommerce'
			),
			description: __(
				'Guards order processing and payment gateways against automated checkout/carding abuse.',
				'google-recaptcha-v3-for-woocommerce'
			),
			toggleKey: 'enable_checkout',
			thresholdKey: 'threshold_checkout',
		},
	];

	return (
		<div className="bg-white shadow-sm ring-1 ring-gray-900/5 rounded-xl md:col-span-2">
			<div className="px-4 py-6 sm:p-8">
				<h2 className="text-base font-semibold leading-7 text-gray-900">
					{ __(
						'Protected Forms & Score Thresholds',
						'google-recaptcha-v3-for-woocommerce'
					) }
				</h2>
				<p className="mt-1 text-sm leading-6 text-gray-600">
					{ __(
						'Enable reCAPTCHA v3 on target forms and customize the spam verification threshold. A score closer to 1.0 represents a human, while a score closer to 0.0 represents a bot.',
						'google-recaptcha-v3-for-woocommerce'
					) }
				</p>

				<div className="mt-6 divide-y divide-gray-100 border-t border-gray-100">
					{ checkpoints.map( ( checkpoint ) => {
						const isEnabled =
							settings[ checkpoint.toggleKey ] === '1' ||
							settings[ checkpoint.toggleKey ] === true;
						const threshold =
							parseFloat( settings[ checkpoint.thresholdKey ] ) ||
							0.5;

						return (
							<div
								key={ checkpoint.id }
								className="py-6 flex flex-col gap-y-4 sm:flex-row sm:items-center sm:justify-between sm:gap-x-8"
							>
								<div className="flex-1">
									<h3 className="text-sm font-semibold text-gray-900">
										{ checkpoint.title }
									</h3>
									<p className="mt-1 text-sm text-gray-500">
										{ checkpoint.description }
									</p>
								</div>

								<div className="flex flex-col items-start sm:items-end gap-y-3 min-w-[240px]">
									{ /* Toggle Switch */ }
									<div className="flex items-center gap-x-3">
										<span className="text-sm text-gray-600">
											{ isEnabled
												? __(
														'Enabled',
														'google-recaptcha-v3-for-woocommerce'
												  )
												: __(
														'Disabled',
														'google-recaptcha-v3-for-woocommerce'
												  ) }
										</span>
										<button
											type="button"
											className={ `relative inline-flex h-6 w-11 flex-shrink-0 cursor-pointer rounded-full border-2 border-transparent transition-colors duration-200 ease-in-out focus:outline-none focus:ring-2 focus:ring-indigo-600 focus:ring-offset-2 ${
												isEnabled
													? 'bg-indigo-600'
													: 'bg-gray-200'
											}` }
											onClick={ () =>
												onChange(
													checkpoint.toggleKey,
													isEnabled ? '0' : '1'
												)
											}
										>
											<span
												aria-hidden="true"
												className={ `pointer-events-none inline-block h-5 w-5 transform rounded-full bg-white shadow ring-0 transition duration-200 ease-in-out ${
													isEnabled
														? 'translate-x-5'
														: 'translate-x-0'
												}` }
											/>
										</button>
									</div>

									{ /* Threshold Slider (Visible only if enabled) */ }
									{ isEnabled && (
										<div className="w-full mt-2 animate-fadeIn">
											<div className="flex justify-between items-center text-xs text-gray-600 mb-1">
												<span>
													{ __(
														'Score Threshold',
														'google-recaptcha-v3-for-woocommerce'
													) }
												</span>
												<span className="font-semibold text-indigo-600">
													{ threshold.toFixed( 1 ) }
												</span>
											</div>
											<div className="flex items-center gap-x-3">
												<span className="text-xs text-gray-400">
													0.0 (Bot)
												</span>
												<input
													type="range"
													min="0.0"
													max="1.0"
													step="0.1"
													value={ threshold }
													onChange={ ( e ) =>
														onChange(
															checkpoint.thresholdKey,
															e.target.value
														)
													}
													className="flex-1 h-1 bg-gray-200 rounded-lg appearance-none cursor-pointer accent-indigo-600 focus:outline-none focus:ring-2 focus:ring-indigo-600"
												/>
												<span className="text-xs text-gray-400">
													1.0 (Human)
												</span>
											</div>
										</div>
									) }
								</div>
							</div>
						);
					} ) }
				</div>
			</div>
		</div>
	);
}
