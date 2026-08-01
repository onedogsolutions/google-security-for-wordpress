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
	const eventsOn =
		settings.ad_events === '1' ||
		settings.ad_events === true ||
		settings.ad_events === undefined;
	const blockSignupOn =
		settings.ad_block_signup === '1' || settings.ad_block_signup === true;
	const blockLostpwOn =
		settings.ad_block_lostpw === '1' || settings.ad_block_lostpw === true;
	const shareEmailOn =
		settings.ad_share_email === '1' || settings.ad_share_email === true;

	return (
		<div className="bg-white shadow-sm ring-1 ring-gray-900/5 rounded-xl">
			<div className="px-4 py-6 sm:p-8">
				<h2 className="text-base font-semibold leading-7 text-gray-900">
					{ __(
						'Account Defender',
						'google-security-for-wordpress'
					) }
				</h2>
				<p className="mt-1 text-sm leading-6 text-gray-600">
					{ __(
						'reCAPTCHA Enterprise Account Defender builds a site-specific model of your accounts to flag takeovers, fake signups, and account farming. The plugin sends an anonymous, salted account identifier with each login, registration, and account-change assessment, logs the returned risk labels, and annotates login, registration, two-factor, and account-modification outcomes so the model keeps learning. Note: the model only runs once Account Defense is also enabled for your key in the Google Cloud console (Fraud Defense → Configure Account defense) — that step lives in Google Cloud and cannot be performed by the plugin.',
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

						{ /* Account-modification events */ }
						{ defenderOn && (
							<div className="py-6 flex flex-col gap-y-4 sm:flex-row sm:items-center sm:justify-between sm:gap-x-8 animate-fadeIn">
								<div className="flex-1">
									<h3 className="text-sm font-semibold text-gray-900">
										{ __(
											'Assess account changes',
											'google-security-for-wordpress'
										) }
									</h3>
									<p className="mt-1 text-sm text-gray-500">
										{ __(
											'Also assess and annotate password resets, email changes, and two-factor enable/disable so the model sees account-takeover activity, not just logins. This loads the reCAPTCHA script on the profile and WooCommerce account pages. Turn off to keep login coverage without that script; account changes are never blocked either way.',
											'google-security-for-wordpress'
										) }
									</p>
								</div>
								<Toggle
									label={ __(
										'Assess account changes',
										'google-security-for-wordpress'
									) }
									enabled={ eventsOn }
									onToggle={ () =>
										onChange(
											'ad_events',
											eventsOn ? '0' : '1'
										)
									}
								/>
							</div>
						) }

						{ /* Block suspicious sign-ups */ }
						{ defenderOn && (
							<div className="py-6 flex flex-col gap-y-4 sm:flex-row sm:items-center sm:justify-between sm:gap-x-8 animate-fadeIn">
								<div className="flex-1">
									<h3 className="text-sm font-semibold text-gray-900">
										{ __(
											'Block suspicious sign-ups',
											'google-security-for-wordpress'
										) }
									</h3>
									<p className="mt-1 text-sm text-gray-500">
										{ __(
											'Reject a registration when Account Defender labels it a suspicious account creation, even if its reCAPTCHA score passed. Requires Account Defense to be enabled for your key in the Google Cloud console — labels only start flowing once it is, and are sparse until the model has learned your traffic. Flagged sign-ups are always logged and can email an alert either way.',
											'google-security-for-wordpress'
										) }
									</p>
								</div>
								<Toggle
									label={ __(
										'Block suspicious sign-ups',
										'google-security-for-wordpress'
									) }
									enabled={ blockSignupOn }
									onToggle={ () =>
										onChange(
											'ad_block_signup',
											blockSignupOn ? '0' : '1'
										)
									}
								/>
							</div>
						) }

						{ /* Block suspicious reset requests */ }
						{ defenderOn && (
							<div className="py-6 flex flex-col gap-y-4 sm:flex-row sm:items-center sm:justify-between sm:gap-x-8 animate-fadeIn">
								<div className="flex-1">
									<h3 className="text-sm font-semibold text-gray-900">
										{ __(
											'Block suspicious reset requests',
											'google-security-for-wordpress'
										) }
									</h3>
									<p className="mt-1 text-sm text-gray-500">
										{ __(
											'When a lost password request is flagged by Account Defender as suspicious activity, refuse to send the reset email. Off by default: requests are logged and alerted but not blocked, so a legitimate user is never locked out of recovery.',
											'google-security-for-wordpress'
										) }
									</p>
								</div>
								<Toggle
									label={ __(
										'Block suspicious reset requests',
										'google-security-for-wordpress'
									) }
									enabled={ blockLostpwOn }
									onToggle={ () =>
										onChange(
											'ad_block_lostpw',
											blockLostpwOn ? '0' : '1'
										)
									}
								/>
							</div>
						) }

						{ /* Share email identifiers */ }
						{ defenderOn && (
							<div className="py-6 flex flex-col gap-y-4 sm:flex-row sm:items-center sm:justify-between sm:gap-x-8 animate-fadeIn">
								<div className="flex-1">
									<h3 className="text-sm font-semibold text-gray-900">
										{ __(
											'Send email identifiers to Google',
											'google-security-for-wordpress'
										) }
									</h3>
									<p className="mt-1 text-sm text-gray-500">
										{ __(
											'By default only an anonymous, salted hash identifies each account. Turning this on additionally sends the account’s email address with login and registration assessments, which Google recommends for markedly better takeover and fake-signup detection (it can spot address aliasing itself). Privacy trade-off: real email addresses are shared with Google. Off by default.',
											'google-security-for-wordpress'
										) }
									</p>
								</div>
								<Toggle
									label={ __(
										'Send email identifiers to Google',
										'google-security-for-wordpress'
									) }
									enabled={ shareEmailOn }
									onToggle={ () =>
										onChange(
											'ad_share_email',
											shareEmailOn ? '0' : '1'
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
