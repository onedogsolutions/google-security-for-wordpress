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

export default function AlertSettings( {
	settings,
	onChange,
	woocommerceActive,
} ) {
	// Both alert sources (Account Defender suspicious logins, Transaction defense
	// blocked checkouts) are reCAPTCHA Enterprise features.
	const isEnterprise = settings.key_type === 'enterprise';
	const alertsOn = settings.alerts === '1' || settings.alerts === true;
	const loginOn =
		settings.alert_login === '1' ||
		settings.alert_login === true ||
		settings.alert_login === undefined;
	const registrationOn =
		settings.alert_registration === '1' ||
		settings.alert_registration === true ||
		settings.alert_registration === undefined;
	const checkoutOn =
		settings.alert_checkout === '1' ||
		settings.alert_checkout === true ||
		settings.alert_checkout === undefined;
	const leakOn =
		settings.alert_leak === '1' ||
		settings.alert_leak === true ||
		settings.alert_leak === undefined;
	const mode = settings.alert_mode || 'immediate';

	return (
		<div className="bg-white shadow-sm ring-1 ring-gray-900/5 rounded-xl">
			<div className="px-4 py-6 sm:p-8">
				<h2 className="text-base font-semibold leading-7 text-gray-900">
					{ __( 'Email Alerts', 'google-security-for-wordpress' ) }
				</h2>
				<p className="mt-1 text-sm leading-6 text-gray-600">
					{ __(
						'Email the site operator when Account Defender flags a suspicious login on an administrator account or a suspicious new-account sign-up, or Transaction defense blocks a high-risk checkout. These events otherwise only reach the log. Alerts are throttled — repeats of the same event are suppressed and a burst rolls up into a single digest — so this never becomes spam.',
						'google-security-for-wordpress'
					) }
				</p>

				{ ! isEnterprise && (
					<div className="mt-6 rounded-md bg-amber-50 border border-amber-200 p-4">
						<p className="text-sm text-amber-800">
							{ __(
								'Alerts fire from reCAPTCHA Enterprise features (Account Defender and Transaction defense). Select the Enterprise key type and enable those features to generate the events these emails report.',
								'google-security-for-wordpress'
							) }
						</p>
					</div>
				) }

				<div className="mt-6 divide-y divide-gray-100 border-t border-gray-100">
					{ /* Master enable */ }
					<div className="py-6 flex flex-col gap-y-4 sm:flex-row sm:items-center sm:justify-between sm:gap-x-8">
						<div className="flex-1">
							<h3 className="text-sm font-semibold text-gray-900">
								{ __(
									'Send email alerts',
									'google-security-for-wordpress'
								) }
							</h3>
							<p className="mt-1 text-sm text-gray-500">
								{ __(
									'Turn on alert emails for flagged security events.',
									'google-security-for-wordpress'
								) }
							</p>
						</div>
						<Toggle
							label={ __(
								'Send email alerts',
								'google-security-for-wordpress'
							) }
							enabled={ alertsOn }
							onToggle={ () =>
								onChange( 'alerts', alertsOn ? '0' : '1' )
							}
						/>
					</div>

					{ alertsOn && (
						<>
							{ /* Recipients */ }
							<div className="py-6 animate-fadeIn">
								<label
									htmlFor="gswp-alert-email"
									className="block text-sm font-semibold text-gray-900"
								>
									{ __(
										'Recipients',
										'google-security-for-wordpress'
									) }
								</label>
								<input
									id="gswp-alert-email"
									type="text"
									value={ settings.alert_email || '' }
									onChange={ ( e ) =>
										onChange(
											'alert_email',
											e.target.value
										)
									}
									placeholder="alerts@example.com, ops@example.com"
									className="mt-2 block w-full rounded-md border-0 py-1.5 text-gray-900 shadow-sm ring-1 ring-inset ring-gray-300 placeholder:text-gray-400 focus:ring-2 focus:ring-inset focus:ring-indigo-600 sm:text-sm sm:leading-6"
								/>
								<p className="mt-2 text-sm text-gray-500">
									{ __(
										'Defaults to the site admin email. Separate multiple addresses with commas; invalid addresses are ignored.',
										'google-security-for-wordpress'
									) }
								</p>
							</div>

							{ /* Delivery mode */ }
							<div className="py-6 animate-fadeIn">
								<label
									htmlFor="gswp-alert-mode"
									className="block text-sm font-semibold text-gray-900"
								>
									{ __(
										'Delivery',
										'google-security-for-wordpress'
									) }
								</label>
								<select
									id="gswp-alert-mode"
									value={ mode }
									onChange={ ( e ) =>
										onChange( 'alert_mode', e.target.value )
									}
									className="mt-2 block w-full max-w-xs rounded-md border-0 py-1.5 pl-3 pr-10 text-gray-900 shadow-sm ring-1 ring-inset ring-gray-300 focus:ring-2 focus:ring-inset focus:ring-indigo-600 sm:text-sm sm:leading-6"
								>
									<option value="immediate">
										{ __(
											'Immediately (as events happen)',
											'google-security-for-wordpress'
										) }
									</option>
									<option value="hourly">
										{ __(
											'Hourly digest',
											'google-security-for-wordpress'
										) }
									</option>
									<option value="daily">
										{ __(
											'Daily digest',
											'google-security-for-wordpress'
										) }
									</option>
								</select>
								<p className="mt-2 text-sm text-gray-500">
									{ __(
										'Immediate still caps the volume: past a few emails an hour the rest roll into one digest. Digest modes send a single summary per period, and nothing when there is nothing to report.',
										'google-security-for-wordpress'
									) }
								</p>
							</div>

							{ /* Event: suspicious admin login */ }
							<div className="py-6 flex flex-col gap-y-4 sm:flex-row sm:items-center sm:justify-between sm:gap-x-8 animate-fadeIn">
								<div className="flex-1">
									<h3 className="text-sm font-semibold text-gray-900">
										{ __(
											'Suspicious admin login',
											'google-security-for-wordpress'
										) }
									</h3>
									<p className="mt-1 text-sm text-gray-500">
										{ __(
											'Alert when Account Defender flags SUSPICIOUS_LOGIN_ACTIVITY on an account that can manage the site.',
											'google-security-for-wordpress'
										) }
									</p>
								</div>
								<Toggle
									label={ __(
										'Suspicious admin login',
										'google-security-for-wordpress'
									) }
									enabled={ loginOn }
									onToggle={ () =>
										onChange(
											'alert_login',
											loginOn ? '0' : '1'
										)
									}
								/>
							</div>

							{ /* Event: suspicious sign-up */ }
							<div className="py-6 flex flex-col gap-y-4 sm:flex-row sm:items-center sm:justify-between sm:gap-x-8 animate-fadeIn">
								<div className="flex-1">
									<h3 className="text-sm font-semibold text-gray-900">
										{ __(
											'Suspicious sign-up',
											'google-security-for-wordpress'
										) }
									</h3>
									<p className="mt-1 text-sm text-gray-500">
										{ __(
											'Alert when Account Defender flags a new registration as SUSPICIOUS_ACCOUNT_CREATION, whether or not sign-up blocking is enabled under Account Defender.',
											'google-security-for-wordpress'
										) }
									</p>
								</div>
								<Toggle
									label={ __(
										'Suspicious sign-up',
										'google-security-for-wordpress'
									) }
									enabled={ registrationOn }
									onToggle={ () =>
										onChange(
											'alert_registration',
											registrationOn ? '0' : '1'
										)
									}
								/>
							</div>

							{ /* Event: blocked checkout (WooCommerce only) */ }
							{ woocommerceActive && (
								<div className="py-6 flex flex-col gap-y-4 sm:flex-row sm:items-center sm:justify-between sm:gap-x-8 animate-fadeIn">
									<div className="flex-1">
										<h3 className="text-sm font-semibold text-gray-900">
											{ __(
												'Blocked high-risk checkout',
												'google-security-for-wordpress'
											) }
										</h3>
										<p className="mt-1 text-sm text-gray-500">
											{ __(
												'Alert when Transaction defense blocks a checkout as high risk. Requires the high-risk block to be enabled under Transaction Defense.',
												'google-security-for-wordpress'
											) }
										</p>
									</div>
									<Toggle
										label={ __(
											'Blocked high-risk checkout',
											'google-security-for-wordpress'
										) }
										enabled={ checkoutOn }
										onToggle={ () =>
											onChange(
												'alert_checkout',
												checkoutOn ? '0' : '1'
											)
										}
									/>
								</div>
							) }

							{ /* Event: leaked credentials */ }
							<div className="py-6 flex flex-col gap-y-4 sm:flex-row sm:items-center sm:justify-between sm:gap-x-8 animate-fadeIn">
								<div className="flex-1">
									<h3 className="text-sm font-semibold text-gray-900">
										{ __(
											'Leaked credentials',
											'google-security-for-wordpress'
										) }
									</h3>
									<p className="mt-1 text-sm text-gray-500">
										{ __(
											'Alert when Password Defense finds a submitted username+password pair in a known data breach, at login or when a new password is chosen.',
											'google-security-for-wordpress'
										) }
									</p>
								</div>
								<Toggle
									label={ __(
										'Leaked credentials',
										'google-security-for-wordpress'
									) }
									enabled={ leakOn }
									onToggle={ () =>
										onChange(
											'alert_leak',
											leakOn ? '0' : '1'
										)
									}
								/>
							</div>
						</>
					) }
				</div>
			</div>
		</div>
	);
}
