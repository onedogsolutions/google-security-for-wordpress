import { __ } from '@wordpress/i18n';

export default function TwoFactorNotice( {
	profileUrl,
	settings,
	onChange,
	roles,
} ) {
	const href = profileUrl || 'profile.php#gswp-2fa';

	const isEnabled =
		settings.tfa_enabled === '1' || settings.tfa_enabled === true;

	const enforcedRoles = Array.isArray( settings.tfa_enforced_roles )
		? settings.tfa_enforced_roles
		: [];

	const roleList = roles && typeof roles === 'object' ? roles : {};

	const toggleRole = ( slug ) => {
		const next = enforcedRoles.includes( slug )
			? enforcedRoles.filter( ( r ) => r !== slug )
			: [ ...enforcedRoles, slug ];
		onChange( 'tfa_enforced_roles', next );
	};

	return (
		<div className="bg-white shadow-sm ring-1 ring-gray-900/5 rounded-xl md:col-span-2">
			<div className="px-4 py-6 sm:p-8">
				<h2 className="text-base font-semibold leading-7 text-gray-900">
					{ __(
						'Two-Factor Authentication',
						'google-security-for-wordpress'
					) }
				</h2>
				<p className="mt-1 text-sm leading-6 text-gray-600">
					{ __(
						'Time-based one-time passwords (TOTP) compatible with Google Authenticator, Authy, 1Password, and Microsoft Authenticator. Each user enables it from their own profile screen.',
						'google-security-for-wordpress'
					) }
				</p>

				{ /* Master switch */ }
				<div className="mt-6 flex items-start justify-between gap-x-6 border-t border-gray-100 pt-6">
					<div className="flex-1">
						<h3 className="text-sm font-semibold text-gray-900">
							{ __(
								'Enable feature',
								'google-security-for-wordpress'
							) }
						</h3>
						<p className="mt-1 text-sm text-gray-500">
							{ __(
								'When disabled, the login challenge is skipped for everyone (no one is locked out) and the profile enrolment UI is hidden.',
								'google-security-for-wordpress'
							) }
						</p>
					</div>
					<div className="flex items-center gap-x-3 pt-0.5">
						<span className="text-sm text-gray-600">
							{ isEnabled
								? __(
										'Enabled',
										'google-security-for-wordpress'
								  )
								: __(
										'Disabled',
										'google-security-for-wordpress'
								  ) }
						</span>
						<button
							type="button"
							aria-pressed={ isEnabled }
							className={ `relative inline-flex h-6 w-11 flex-shrink-0 cursor-pointer rounded-full border-2 border-transparent transition-colors duration-200 ease-in-out focus:outline-none focus:ring-2 focus:ring-indigo-600 focus:ring-offset-2 ${
								isEnabled ? 'bg-indigo-600' : 'bg-gray-200'
							}` }
							onClick={ () =>
								onChange( 'tfa_enabled', isEnabled ? '0' : '1' )
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
				</div>

				{ /* Per-role enforcement */ }
				{ isEnabled && (
					<div className="mt-6 border-t border-gray-100 pt-6 animate-fadeIn">
						<h3 className="text-sm font-semibold text-gray-900">
							{ __(
								'Require for roles',
								'google-security-for-wordpress'
							) }
						</h3>
						<p className="mt-1 text-sm text-gray-500">
							{ __(
								'Users in a selected role must set up two-factor authentication before they can use the admin. Leave all unchecked to keep enrolment optional.',
								'google-security-for-wordpress'
							) }
						</p>
						<div className="mt-4 grid grid-cols-1 gap-2 sm:grid-cols-2">
							{ Object.keys( roleList ).map( ( slug ) => (
								// eslint-disable-next-line jsx-a11y/label-has-associated-control -- the label wraps the checkbox and its text, but the rule cannot resolve the dynamic role name.
								<label
									key={ slug }
									className="flex items-center gap-x-2 text-sm text-gray-700"
								>
									<input
										type="checkbox"
										checked={ enforcedRoles.includes(
											slug
										) }
										onChange={ () => toggleRole( slug ) }
										className="h-4 w-4 rounded border-gray-300 text-indigo-600 focus:ring-indigo-600"
									/>
									{ roleList[ slug ] }
								</label>
							) ) }
						</div>
						<p className="mt-3 text-xs leading-5 text-gray-500">
							<strong>
								{ __(
									'Tip:',
									'google-security-for-wordpress'
								) }
							</strong>{ ' ' }
							{ __(
								'Enrol your own administrator account first so you do not lock yourself out when enforcing the Administrator role.',
								'google-security-for-wordpress'
							) }
						</p>
					</div>
				) }

				{ /* Per-user enrolment link */ }
				<div className="mt-6 rounded-lg bg-blue-50 border border-blue-100 p-6">
					<div className="flex items-start gap-x-3">
						<svg
							className="mt-0.5 h-5 w-5 flex-none text-blue-600"
							fill="none"
							viewBox="0 0 24 24"
							stroke="currentColor"
						>
							<path
								strokeLinecap="round"
								strokeLinejoin="round"
								strokeWidth={ 1.5 }
								d="M16.5 10.5V6.75a4.5 4.5 0 10-9 0v3.75m-.75 11.25h10.5a2.25 2.25 0 002.25-2.25v-6.75a2.25 2.25 0 00-2.25-2.25H6.75a2.25 2.25 0 00-2.25 2.25v6.75a2.25 2.25 0 002.25 2.25z"
							/>
						</svg>
						<div className="flex-1">
							<h3 className="text-sm font-semibold text-gray-900">
								{ __(
									'Set up 2FA from your user profile',
									'google-security-for-wordpress'
								) }
							</h3>
							<p className="mt-1 text-sm leading-6 text-gray-600">
								{ __(
									'To enroll a device, open your profile, scan the QR code with an authenticator app, and confirm the code. Each user manages their own two-factor settings there.',
									'google-security-for-wordpress'
								) }
							</p>
							<a
								href={ href }
								className="gswp-2fa-btn mt-4 inline-flex items-center gap-x-2 rounded-md bg-indigo-600 px-4 py-2.5 text-sm font-semibold text-white shadow-sm hover:bg-indigo-500 focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-indigo-600 transition no-underline"
							>
								{ __(
									'Set up Two-Factor Authentication',
									'google-security-for-wordpress'
								) }
								<svg
									className="h-4 w-4"
									fill="none"
									viewBox="0 0 24 24"
									stroke="currentColor"
								>
									<path
										strokeLinecap="round"
										strokeLinejoin="round"
										strokeWidth={ 1.5 }
										d="M13.5 6H5.25A2.25 2.25 0 003 8.25v10.5A2.25 2.25 0 005.25 21h10.5A2.25 2.25 0 0018 18.75V10.5m-10.5 6L21 3m0 0h-5.25M21 3v5.25"
									/>
								</svg>
							</a>
						</div>
					</div>
				</div>
			</div>
		</div>
	);
}
