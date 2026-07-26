import { __ } from '@wordpress/i18n';

const STAGES = [
	{
		id: 'off',
		label: __( 'Off', 'google-security-for-wordpress' ),
		description: __(
			'The form plugin uses its own reCAPTCHA. Nothing changes.',
			'google-security-for-wordpress'
		),
	},
	{
		id: 'shadow',
		label: __( 'Shadow', 'google-security-for-wordpress' ),
		description: __(
			'Score submissions and log the result, but never block. The form plugin’s own reCAPTCHA is still the real protection. Start here.',
			'google-security-for-wordpress'
		),
	},
	{
		id: 'active',
		label: __( 'Active', 'google-security-for-wordpress' ),
		description: __(
			'Block submissions that fail. Keep the form plugin’s own reCAPTCHA switched on as a backstop during this stage.',
			'google-security-for-wordpress'
		),
	},
	{
		id: 'sole',
		label: __( 'Sole', 'google-security-for-wordpress' ),
		description: __(
			'You have switched off the form plugin’s reCAPTCHA and this plugin is the only protection. Only available once every eligible form is covered.',
			'google-security-for-wordpress'
		),
	},
];

function nativeLabel( state ) {
	switch ( state ) {
		case 'off':
			return __( 'off', 'google-security-for-wordpress' );
		case 'v3':
			return __( 'v3 / Enterprise', 'google-security-for-wordpress' );
		case 'v2':
			return __( 'v2 checkbox', 'google-security-for-wordpress' );
		default:
			return __( 'unknown', 'google-security-for-wordpress' );
	}
}

export default function FormProtection( { settings, onChange } ) {
	const adminData =
		typeof window !== 'undefined' && window.gswpAdminData
			? window.gswpAdminData
			: {};

	const audit = adminData.formProviders || { enabled: true, providers: {} };
	const providers = Object.values( audit.providers || {} );

	const killed =
		settings.form_providers_enabled === '0' || audit.enabled === false;

	if ( providers.length === 0 ) {
		return (
			<div className="bg-white shadow-sm ring-1 ring-gray-900/5 rounded-xl">
				<div className="px-4 py-6 sm:p-8">
					<h2 className="text-base font-semibold leading-7 text-gray-900">
						{ __(
							'Form Protection',
							'google-security-for-wordpress'
						) }
					</h2>
					<p className="mt-1 text-sm leading-6 text-gray-600">
						{ __(
							'No supported form plugins are active. When Gravity Forms is installed, this panel lets this plugin take over its reCAPTCHA.',
							'google-security-for-wordpress'
						) }
					</p>
				</div>
			</div>
		);
	}

	return (
		<div className="bg-white shadow-sm ring-1 ring-gray-900/5 rounded-xl">
			<div className="px-4 py-6 sm:p-8">
				<h2 className="text-base font-semibold leading-7 text-gray-900">
					{ __( 'Form Protection', 'google-security-for-wordpress' ) }
				</h2>
				<p className="mt-1 text-sm leading-6 text-gray-600">
					{ __(
						'Replace a form plugin’s own reCAPTCHA with this one, so a single implementation scores every form and payment on the site. Move through the stages in order — each one is reversible, and the form plugin’s own reCAPTCHA stays as a backstop until the last.',
						'google-security-for-wordpress'
					) }
				</p>

				{ killed && (
					<div className="mt-6 rounded-lg border border-amber-300 bg-amber-50 p-4">
						<h3 className="text-sm font-semibold text-amber-800">
							{ __(
								'Form protection is switched off',
								'google-security-for-wordpress'
							) }
						</h3>
						<p className="mt-1 text-xs leading-5 text-amber-700">
							{ __(
								'The master switch is off, or GSWP_DISABLE_FORM_PROVIDERS is defined in wp-config.php. No form plugin is being intercepted, whatever the stages below say.',
								'google-security-for-wordpress'
							) }
						</p>
					</div>
				) }

				{ providers.map( ( provider ) => {
					const uncovered = ( provider.uncovered || [] ).length;
					const ineligible = ( provider.ineligible || [] ).length;
					const canGoSole = uncovered === 0;

					return (
						<div key={ provider.id } className="mt-8">
							<div className="flex items-baseline justify-between">
								<h3 className="text-sm font-semibold text-gray-900">
									{ provider.label }
								</h3>
								<span className="text-xs text-gray-500">
									{ ( provider.forms || [] ).length }{ ' ' }
									{ __(
										'forms',
										'google-security-for-wordpress'
									) }
								</span>
							</div>

							<fieldset className="mt-3">
								<legend className="sr-only">
									{ __(
										'Takeover stage',
										'google-security-for-wordpress'
									) }
								</legend>
								<div className="space-y-2">
									{ STAGES.map( ( stage ) => {
										const disabled =
											stage.id === 'sole' && ! canGoSole;
										const checked =
											provider.mode === stage.id;

										return (
											// eslint-disable-next-line jsx-a11y/label-has-associated-control -- the label wraps the input and its dynamic text.
											<label
												key={ stage.id }
												className={ `relative flex rounded-lg border p-3 shadow-sm transition ${
													disabled
														? 'cursor-not-allowed border-gray-200 bg-gray-50 opacity-60'
														: 'cursor-pointer'
												} ${
													checked && ! disabled
														? 'border-indigo-600 ring-1 ring-indigo-600 bg-indigo-50/50'
														: 'border-gray-300 bg-white'
												}` }
											>
												<input
													type="radio"
													name={ `stage-${ provider.id }` }
													value={ stage.id }
													checked={ checked }
													disabled={ disabled }
													onChange={ () =>
														onChange(
															'provider_modes',
															{
																[ provider.id ]:
																	stage.id,
															}
														)
													}
													className="sr-only"
												/>
												<span className="flex flex-col">
													<span className="block text-sm font-semibold text-gray-900">
														{ stage.label }
													</span>
													<span className="mt-1 block text-xs leading-5 text-gray-500">
														{ stage.description }
													</span>
													{ disabled && (
														<span className="mt-1 block text-xs leading-5 text-red-600">
															{ __(
																'Unavailable: some eligible forms are not yet covered.',
																'google-security-for-wordpress'
															) }
														</span>
													) }
												</span>
											</label>
										);
									} ) }
								</div>
							</fieldset>

							<div className="mt-4 overflow-x-auto">
								<table className="min-w-full text-left text-xs">
									<thead className="text-gray-500">
										<tr>
											<th className="py-2 pr-4 font-medium">
												{ __(
													'Form',
													'google-security-for-wordpress'
												) }
											</th>
											<th className="py-2 pr-4 font-medium">
												{ __(
													'Covered',
													'google-security-for-wordpress'
												) }
											</th>
											<th className="py-2 pr-4 font-medium">
												{ __(
													'Payment',
													'google-security-for-wordpress'
												) }
											</th>
											<th className="py-2 pr-4 font-medium">
												{ __(
													'Missing token',
													'google-security-for-wordpress'
												) }
											</th>
											<th className="py-2 font-medium">
												{ __(
													'Its own reCAPTCHA',
													'google-security-for-wordpress'
												) }
											</th>
										</tr>
									</thead>
									<tbody className="divide-y divide-gray-100">
										{ ( provider.forms || [] ).map(
											( form ) => (
												<tr key={ form.id }>
													<td className="py-2 pr-4 text-gray-900">
														{ form.title }
													</td>
													<td className="py-2 pr-4">
														{ form.eligible ? (
															<span
																className={
																	form.covered
																		? 'text-green-700'
																		: 'text-amber-700'
																}
															>
																{ form.covered
																	? __(
																			'yes',
																			'google-security-for-wordpress'
																	  )
																	: __(
																			'no',
																			'google-security-for-wordpress'
																	  ) }
															</span>
														) : (
															<span className="text-gray-400">
																{ __(
																	'not eligible',
																	'google-security-for-wordpress'
																) }
															</span>
														) }
													</td>
													<td className="py-2 pr-4 text-gray-600">
														{ form.payment
															? __(
																	'yes',
																	'google-security-for-wordpress'
															  )
															: '—' }
													</td>
													<td className="py-2 pr-4 text-gray-600">
														{ form.enforcement ===
														'reject'
															? __(
																	'reject',
																	'google-security-for-wordpress'
															  )
															: __(
																	'allow + flag',
																	'google-security-for-wordpress'
															  ) }
													</td>
													<td className="py-2 text-gray-600">
														{ nativeLabel(
															form.native
														) }
													</td>
												</tr>
											)
										) }
									</tbody>
								</table>
							</div>

							{ ineligible > 0 && (
								<p className="mt-3 text-xs leading-5 text-gray-500">
									{ __(
										'Forms using a visible “I’m not a robot” checkbox are not eligible — this plugin scores invisibly and has no equivalent challenge. Leave the form plugin’s own reCAPTCHA enabled for those.',
										'google-security-for-wordpress'
									) }
								</p>
							) }

							{ uncovered > 0 && (
								<p className="mt-3 text-xs leading-5 text-amber-700">
									{ __(
										'Some eligible forms are not covered. Do not switch off the form plugin’s reCAPTCHA until this reads zero — those forms would be left with no bot protection at all.',
										'google-security-for-wordpress'
									) }
								</p>
							) }
						</div>
					);
				} ) }

				<div className="mt-8 border-t border-gray-100 pt-6 flex flex-col gap-y-3 sm:flex-row sm:items-center sm:justify-between sm:gap-x-8">
					<div className="flex-1">
						<h3 className="text-sm font-semibold text-gray-900">
							{ __(
								'Form protection master switch',
								'google-security-for-wordpress'
							) }
						</h3>
						<p className="mt-1 text-sm text-gray-500">
							{ __(
								'Turning this off stops all form interception immediately without deactivating the plugin — two-factor authentication, WooCommerce protection, Account Defender and Password Defense keep running. Use it if form submissions start failing.',
								'google-security-for-wordpress'
							) }
						</p>
					</div>
					<div className="flex items-center gap-x-3">
						<span className="text-sm text-gray-600">
							{ killed
								? __(
										'Disabled',
										'google-security-for-wordpress'
								  )
								: __(
										'Enabled',
										'google-security-for-wordpress'
								  ) }
						</span>
						<button
							type="button"
							aria-label={ __(
								'Form protection master switch',
								'google-security-for-wordpress'
							) }
							className={ `relative inline-flex h-6 w-11 flex-shrink-0 cursor-pointer rounded-full border-2 border-transparent transition-colors duration-200 ease-in-out focus:outline-none focus:ring-2 focus:ring-indigo-600 focus:ring-offset-2 ${
								killed ? 'bg-gray-200' : 'bg-indigo-600'
							}` }
							onClick={ () =>
								onChange(
									'form_providers_enabled',
									killed ? '1' : '0'
								)
							}
						>
							<span
								aria-hidden="true"
								className={ `pointer-events-none inline-block h-5 w-5 transform rounded-full bg-white shadow ring-0 transition duration-200 ease-in-out ${
									killed ? 'translate-x-0' : 'translate-x-5'
								}` }
							/>
						</button>
					</div>
				</div>
			</div>
		</div>
	);
}
