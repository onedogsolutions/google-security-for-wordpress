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

export default function AccountDefender( { settings, onChange } ) {
	const isEnterprise = settings.key_type === 'enterprise';
	const defenderOn =
		settings.account_defender === '1' || settings.account_defender === true;
	const stepUpOn =
		settings.ad_step_up === '1' || settings.ad_step_up === true;

	return (
		<div className="bg-white shadow-sm ring-1 ring-gray-900/5 rounded-xl md:col-span-2">
			<div className="px-4 py-6 sm:p-8">
				<h2 className="text-base font-semibold leading-7 text-gray-900">
					{ __(
						'Account Defender',
						'google-security-for-wordpress'
					) }
				</h2>
				<p className="mt-1 text-sm leading-6 text-gray-600">
					{ __(
						'reCAPTCHA Enterprise Account Defender builds a site-specific model of your accounts to flag takeovers, fake signups, and account farming. The plugin sends an anonymous, salted account identifier with each login/registration assessment, logs the returned risk labels, and annotates login and two-factor outcomes so the model keeps learning.',
						'google-security-for-wordpress'
					) }
				</p>

				{ ! isEnterprise && (
					<div className="mt-6 rounded-md bg-amber-50 border border-amber-200 p-4">
						<p className="text-sm text-amber-800">
							{ __(
								'Account Defender requires the Enterprise key type. Select Enterprise under API Credentials and enable it in the Google Cloud Console (Fraud Defense → your key → Account Defender).',
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
										'Enable Account Defender',
										'google-security-for-wordpress'
									) }
								</h3>
								<p className="mt-1 text-sm text-gray-500">
									{ __(
										'Send account identifiers and annotate outcomes. Requires the matching login/registration checks above to be enabled, since that is where the assessment is made. Labels are sparse until the model has learned your traffic.',
										'google-security-for-wordpress'
									) }
								</p>
							</div>
							<Toggle
								label={ __(
									'Enable Account Defender',
									'google-security-for-wordpress'
								) }
								enabled={ defenderOn }
								onToggle={ () =>
									onChange(
										'account_defender',
										defenderOn ? '0' : '1'
									)
								}
							/>
						</div>

						{ /* Optional 2FA step-up */ }
						{ defenderOn && (
							<div className="py-6 flex flex-col gap-y-4 sm:flex-row sm:items-center sm:justify-between sm:gap-x-8 animate-fadeIn">
								<div className="flex-1">
									<h3 className="text-sm font-semibold text-gray-900">
										{ __(
											'Require 2FA on suspicious logins',
											'google-security-for-wordpress'
										) }
									</h3>
									<p className="mt-1 text-sm text-gray-500">
										{ __(
											'When a login is flagged as suspicious, force the two-factor challenge for users who have 2FA enrolled. Users without 2FA are logged only, never blocked.',
											'google-security-for-wordpress'
										) }
									</p>
								</div>
								<Toggle
									label={ __(
										'Require 2FA on suspicious logins',
										'google-security-for-wordpress'
									) }
									enabled={ stepUpOn }
									onToggle={ () =>
										onChange(
											'ad_step_up',
											stepUpOn ? '0' : '1'
										)
									}
								/>
							</div>
						) }
					</div>
				) }
			</div>
		</div>
	);
}
