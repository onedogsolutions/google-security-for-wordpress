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

export default function PasswordDefense( { settings, onChange } ) {
	const isEnterprise = settings.key_type === 'enterprise';
	const supported =
		settings.pd_supported === true || settings.pd_supported === '1';
	const defenseOn =
		settings.password_defense === '1' || settings.password_defense === true;
	const loginOn =
		settings.pd_login === '1' ||
		settings.pd_login === true ||
		settings.pd_login === undefined;
	const blockChoiceOn =
		settings.pd_block_choice === '1' ||
		settings.pd_block_choice === true ||
		settings.pd_block_choice === undefined;
	const forceResetOn =
		settings.pd_force_reset === '1' || settings.pd_force_reset === true;

	return (
		<div className="bg-white shadow-sm ring-1 ring-gray-900/5 rounded-xl">
			<div className="px-4 py-6 sm:p-8">
				<h2 className="text-base font-semibold leading-7 text-gray-900">
					{ __(
						'Password Defense',
						'google-security-for-wordpress'
					) }
				</h2>
				<p className="mt-1 text-sm leading-6 text-gray-600">
					{ __(
						'Checks a submitted username and password against Google’s database of billions of breached credentials using a privacy-preserving protocol: the site sends only a 26-bit bucket prefix of a salted username hash and a blinded (EC-encrypted) hash of the password pair. Google re-encrypts it with its own key and returns candidate matches; the site strips its own blinding locally and compares. Google never sees the password and never learns the verdict — this answers the Fraud Defense console’s "Configure Password defense" recommendation, which otherwise has no PHP client and cannot be enabled from the console alone.',
						'google-security-for-wordpress'
					) }
				</p>

				{ ! isEnterprise && (
					<div className="mt-6 rounded-md bg-amber-50 border border-amber-200 p-4">
						<p className="text-sm text-amber-800">
							{ __(
								'Password Defense requires the Enterprise key type. Select Enterprise under API Credentials.',
								'google-security-for-wordpress'
							) }
						</p>
					</div>
				) }

				{ isEnterprise && ! supported && (
					<div className="mt-6 rounded-md bg-amber-50 border border-amber-200 p-4">
						<p className="text-sm text-amber-800">
							{ __(
								'Password Defense requires the GMP or BCMath PHP extension (for the elliptic-curve math) on a 64-bit PHP build. Ask your host to enable one of them to use this feature.',
								'google-security-for-wordpress'
							) }
						</p>
					</div>
				) }

				{ isEnterprise && supported && (
					<div className="mt-6 divide-y divide-gray-100 border-t border-gray-100">
						{ /* Master enable */ }
						<div className="py-6 flex flex-col gap-y-4 sm:flex-row sm:items-center sm:justify-between sm:gap-x-8">
							<div className="flex-1">
								<h3 className="text-sm font-semibold text-gray-900">
									{ __(
										'Enable Password Defense',
										'google-security-for-wordpress'
									) }
								</h3>
								<p className="mt-1 text-sm text-gray-500">
									{ __(
										'Turn on leaked-credential checking. Each check is a billable reCAPTCHA Enterprise assessment; see the sub-options below for how often checks run.',
										'google-security-for-wordpress'
									) }
								</p>
							</div>
							<Toggle
								label={ __(
									'Enable Password Defense',
									'google-security-for-wordpress'
								) }
								enabled={ defenseOn }
								onToggle={ () =>
									onChange(
										'password_defense',
										defenseOn ? '0' : '1'
									)
								}
							/>
						</div>

						{ /* Check on login */ }
						{ defenseOn && (
							<div className="py-6 flex flex-col gap-y-4 sm:flex-row sm:items-center sm:justify-between sm:gap-x-8 animate-fadeIn">
								<div className="flex-1">
									<h3 className="text-sm font-semibold text-gray-900">
										{ __(
											'Check on login',
											'google-security-for-wordpress'
										) }
									</h3>
									<p className="mt-1 text-sm text-gray-500">
										{ __(
											'After a successful password check, check credentials for a leak in the background (after the response is sent, so login is never slowed down), at most once per user per week. A leaked login never blocks sign-in by itself unless "Force reset on leaked login" below is also on.',
											'google-security-for-wordpress'
										) }
									</p>
								</div>
								<Toggle
									label={ __(
										'Check on login',
										'google-security-for-wordpress'
									) }
									enabled={ loginOn }
									onToggle={ () =>
										onChange(
											'pd_login',
											loginOn ? '0' : '1'
										)
									}
								/>
							</div>
						) }

						{ /* Force reset on leaked login */ }
						{ defenseOn && loginOn && (
							<div className="py-6 flex flex-col gap-y-4 sm:flex-row sm:items-center sm:justify-between sm:gap-x-8 animate-fadeIn">
								<div className="flex-1">
									<h3 className="text-sm font-semibold text-gray-900">
										{ __(
											'Force reset on leaked login',
											'google-security-for-wordpress'
										) }
									</h3>
									<p className="mt-1 text-sm text-gray-500">
										{ __(
											'Once a login is flagged leaked, refuse further sign-ins with that password until it is changed. Off by default: leaves the account signed in and shows a persistent admin notice prompting a password change instead, so no one is locked out unexpectedly.',
											'google-security-for-wordpress'
										) }
									</p>
								</div>
								<Toggle
									label={ __(
										'Force reset on leaked login',
										'google-security-for-wordpress'
									) }
									enabled={ forceResetOn }
									onToggle={ () =>
										onChange(
											'pd_force_reset',
											forceResetOn ? '0' : '1'
										)
									}
								/>
							</div>
						) }

						{ /* Block newly chosen leaked passwords */ }
						{ defenseOn && (
							<div className="py-6 flex flex-col gap-y-4 sm:flex-row sm:items-center sm:justify-between sm:gap-x-8 animate-fadeIn">
								<div className="flex-1">
									<h3 className="text-sm font-semibold text-gray-900">
										{ __(
											'Block newly chosen leaked passwords',
											'google-security-for-wordpress'
										) }
									</h3>
									<p className="mt-1 text-sm text-gray-500">
										{ __(
											'When a user sets a new password (password reset, profile, or WooCommerce account details) that appears in a known breach, reject it with an inline error instead of only logging it.',
											'google-security-for-wordpress'
										) }
									</p>
								</div>
								<Toggle
									label={ __(
										'Block newly chosen leaked passwords',
										'google-security-for-wordpress'
									) }
									enabled={ blockChoiceOn }
									onToggle={ () =>
										onChange(
											'pd_block_choice',
											blockChoiceOn ? '0' : '1'
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
