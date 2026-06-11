import { __ } from '@wordpress/i18n';

export default function SettingsPanel( { siteKey, secretKey, onChange } ) {
	return (
		<div className="bg-white shadow-sm ring-1 ring-gray-900/5 rounded-xl md:col-span-2">
			<div className="px-4 py-6 sm:p-8">
				<h2 className="text-base font-semibold leading-7 text-gray-900">
					{ __(
						'API Credentials',
						'google-recaptcha-v3-for-woocommerce'
					) }
				</h2>
				<p className="mt-1 text-sm leading-6 text-gray-600">
					{ __(
						'Enter your Google reCAPTCHA v3 API keys. You can register your site and generate keys in the ',
						'google-recaptcha-v3-for-woocommerce'
					) }
					<a
						href="https://www.google.com/recaptcha/admin"
						target="_blank"
						rel="noopener noreferrer"
						className="font-medium text-indigo-600 hover:text-indigo-500 transition"
					>
						{ __(
							'Google reCAPTCHA Admin Console',
							'google-recaptcha-v3-for-woocommerce'
						) }
					</a>
					.
				</p>

				<div className="mt-6 grid grid-cols-1 gap-x-6 gap-y-4 sm:grid-cols-6">
					<div className="sm:col-span-3">
						<label
							htmlFor="site-key"
							className="block text-sm font-medium leading-6 text-gray-900"
						>
							{ __(
								'Site Key',
								'google-recaptcha-v3-for-woocommerce'
							) }
						</label>
						<div className="mt-1.5">
							<input
								type="text"
								name="site-key"
								id="site-key"
								value={ siteKey }
								onChange={ ( e ) =>
									onChange( 'site_key', e.target.value )
								}
								placeholder="6Ld..."
								className="block w-full rounded-md border-0 py-1.5 text-gray-900 shadow-sm ring-1 ring-inset ring-gray-300 placeholder:text-gray-400 focus:ring-2 focus:ring-inset focus:ring-indigo-600 sm:text-sm sm:leading-6 px-3"
							/>
						</div>
					</div>

					<div className="sm:col-span-3">
						<label
							htmlFor="secret-key"
							className="block text-sm font-medium leading-6 text-gray-900"
						>
							{ __(
								'Secret Key',
								'google-recaptcha-v3-for-woocommerce'
							) }
						</label>
						<div className="mt-1.5">
							<input
								type="password"
								name="secret-key"
								id="secret-key"
								value={ secretKey }
								onChange={ ( e ) =>
									onChange( 'secret_key', e.target.value )
								}
								placeholder="••••••••••••••••••••••••••••••••••••••••"
								className="block w-full rounded-md border-0 py-1.5 text-gray-900 shadow-sm ring-1 ring-inset ring-gray-300 placeholder:text-gray-400 focus:ring-2 focus:ring-inset focus:ring-indigo-600 sm:text-sm sm:leading-6 px-3"
							/>
						</div>
					</div>
				</div>
			</div>
		</div>
	);
}
