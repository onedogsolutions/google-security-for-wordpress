import { __ } from '@wordpress/i18n';

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

	const pending = settings.provider_enabled || {};
	const isOn = ( provider ) =>
		pending[ provider.id ] !== undefined
			? pending[ provider.id ] === '1'
			: !! provider.on;

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
							'No supported form plugins are active. When Gravity Forms is installed, this panel lets this plugin score its forms.',
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
						'Scores a form plugin’s submissions here, so one reCAPTCHA implementation covers every form and payment on the site.',
						'google-security-for-wordpress'
					) }
				</p>
				<p className="mt-2 text-sm leading-6 text-gray-600">
					{ __(
						'This does not switch the form plugin’s own reCAPTCHA off — this plugin never writes to another plugin’s settings. Turn it off there yourself once the table below shows every form receiving a token. Until you do, both run: each submission is assessed twice, and the form plugin applies its own score threshold, so it can reject a submission for reasons that never reach this plugin’s logs.',
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
								'The master switch is off, or GSWP_DISABLE_FORM_PROVIDERS is defined in wp-config.php. No form plugin is being intercepted, whatever the switches below say.',
								'google-security-for-wordpress'
							) }
						</p>
					</div>
				) }

				{ providers.map( ( provider ) => {
					const ineligible = ( provider.ineligible || [] ).length;

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

							<div className="mt-3 flex items-center justify-between rounded-lg border border-gray-300 p-3">
								<div className="flex-1 pr-4">
									<p className="text-sm font-semibold text-gray-900">
										{ isOn( provider )
											? __(
													'This plugin is handling reCAPTCHA for these forms',
													'google-security-for-wordpress'
											  )
											: __(
													'This form plugin is using its own reCAPTCHA',
													'google-security-for-wordpress'
											  ) }
									</p>
									<p className="mt-1 text-xs leading-5 text-gray-500">
										{ isOn( provider )
											? __(
													'Payments are scored with transaction data and the outcome is reported back to Google. Check the “Its own reCAPTCHA” column below — where it is still on, turn it off in that plugin.',
													'google-security-for-wordpress'
											  )
											: __(
													'Turn this on to score these forms here instead, with one reCAPTCHA implementation across the whole site.',
													'google-security-for-wordpress'
											  ) }
									</p>
								</div>
								<button
									type="button"
									aria-label={ provider.label }
									className={ `relative inline-flex h-6 w-11 flex-shrink-0 cursor-pointer rounded-full border-2 border-transparent transition-colors duration-200 ease-in-out focus:outline-none focus:ring-2 focus:ring-indigo-600 focus:ring-offset-2 ${
										isOn( provider )
											? 'bg-indigo-600'
											: 'bg-gray-200'
									}` }
									onClick={ () =>
										onChange( 'provider_enabled', {
											[ provider.id ]: isOn( provider )
												? '0'
												: '1',
										} )
									}
								>
									<span
										aria-hidden="true"
										className={ `pointer-events-none inline-block h-5 w-5 transform rounded-full bg-white shadow ring-0 transition duration-200 ease-in-out ${
											isOn( provider )
												? 'translate-x-5'
												: 'translate-x-0'
										}` }
									/>
								</button>
							</div>

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
													'Token seen',
													'google-security-for-wordpress'
												) }
											</th>
											<th className="py-2 pr-4 font-medium">
												{ __(
													'Sensitive',
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
														{ ! form.eligible && (
															<span className="text-gray-400">
																{ __(
																	'not eligible',
																	'google-security-for-wordpress'
																) }
															</span>
														) }
														{ form.eligible &&
															! form.covered && (
																<span className="text-gray-400">
																	—
																</span>
															) }
														{ form.eligible &&
															form.covered && (
																<span
																	className={
																		form.injected
																			? 'text-green-700'
																			: 'text-amber-700'
																	}
																>
																	{ form.injected
																		? __(
																				'yes',
																				'google-security-for-wordpress'
																		  )
																		: __(
																				'not yet',
																				'google-security-for-wordpress'
																		  ) }
																</span>
															) }
													</td>
													<td className="py-2 pr-4 text-gray-600">
														{ form.payment &&
															__(
																'payment',
																'google-security-for-wordpress'
															) }
														{ ! form.payment &&
															form.account &&
															__(
																'creates account',
																'google-security-for-wordpress'
															) }
														{ ! form.payment &&
															! form.account &&
															'—' }
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

							{ isOn( provider ) &&
								( provider.forms || [] ).some(
									( form ) => form.covered && ! form.injected
								) && (
									<p className="mt-3 text-xs leading-5 text-amber-700">
										{ __(
											'Some forms have not yet been observed receiving a token field. Load each one on the front end and reload this page. A form that never receives a token is submitted unscored — you will also be emailed if that happens.',
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
