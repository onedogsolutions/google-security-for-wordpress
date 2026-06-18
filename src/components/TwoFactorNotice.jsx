import { __ } from '@wordpress/i18n';

export default function TwoFactorNotice( { profileUrl } ) {
	const href = profileUrl || 'profile.php#gswp-2fa';

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
						'Two-factor authentication (TOTP, compatible with Google Authenticator) is enabled site-wide, but each account is set up individually.',
						'google-security-for-wordpress'
					) }
				</p>

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
								className="mt-4 inline-flex items-center gap-x-2 rounded-md bg-indigo-600 px-4 py-2.5 text-sm font-semibold text-white shadow-sm hover:bg-indigo-500 focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-indigo-600 transition no-underline"
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
