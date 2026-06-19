import { __ } from '@wordpress/i18n';

export default function Compatibility( { settings, onChange } ) {
	const mode =
		settings.conflict_mode === 'active' || settings.conflict_mode === 'site'
			? settings.conflict_mode
			: 'off';

	const verbose =
		settings.verbose_logging === '1' || settings.verbose_logging === true;

	const modes = [
		{
			id: 'off',
			label: __( 'Disabled', 'google-security-for-wordpress' ),
			description: __(
				'Leave other plugins to load their own reCAPTCHA scripts.',
				'google-security-for-wordpress'
			),
		},
		{
			id: 'active',
			label: __(
				'On this plugin’s reCAPTCHA pages',
				'google-security-for-wordpress'
			),
			description: __(
				'Recommended. Remove other reCAPTCHA scripts only on pages where this plugin already loads its own, so standalone forms elsewhere keep working.',
				'google-security-for-wordpress'
			),
		},
		{
			id: 'site',
			label: __( 'Site-wide', 'google-security-for-wordpress' ),
			description: __(
				'Remove other plugins’ reCAPTCHA on every front-end page. Use only when you have removed reCAPTCHA from those plugins’ forms, or their submissions may fail.',
				'google-security-for-wordpress'
			),
		},
	];

	return (
		<div className="bg-white shadow-sm ring-1 ring-gray-900/5 rounded-xl md:col-span-2">
			<div className="px-4 py-6 sm:p-8">
				<h2 className="text-base font-semibold leading-7 text-gray-900">
					{ __(
						'reCAPTCHA Conflict Handling',
						'google-security-for-wordpress'
					) }
				</h2>
				<p className="mt-1 text-sm leading-6 text-gray-600">
					{ __(
						'Google recommends loading reCAPTCHA only once per page. Suppress reCAPTCHA scripts from other plugins (such as Gravity Forms) so this implementation is the only one running.',
						'google-security-for-wordpress'
					) }
				</p>

				<fieldset className="mt-6">
					<legend className="sr-only">
						{ __(
							'Conflict handling mode',
							'google-security-for-wordpress'
						) }
					</legend>
					<div className="space-y-3">
						{ modes.map( ( option ) => (
							// eslint-disable-next-line jsx-a11y/label-has-associated-control -- the label wraps the radio input and its text, but the rule cannot resolve the dynamic text expression.
							<label
								key={ option.id }
								className={ `relative flex cursor-pointer rounded-lg border p-3 shadow-sm focus:outline-none transition ${
									mode === option.id
										? 'border-indigo-600 ring-1 ring-indigo-600 bg-indigo-50/50'
										: 'border-gray-300 bg-white hover:border-gray-400'
								}` }
							>
								<input
									type="radio"
									name="conflict-mode"
									value={ option.id }
									checked={ mode === option.id }
									onChange={ () =>
										onChange( 'conflict_mode', option.id )
									}
									className="sr-only"
								/>
								<span className="flex flex-col">
									<span className="block text-sm font-semibold text-gray-900">
										{ option.label }
									</span>
									<span className="mt-1 block text-xs leading-5 text-gray-500">
										{ option.description }
									</span>
								</span>
							</label>
						) ) }
					</div>
				</fieldset>

				{ /* Diagnostics: verbose logging */ }
				<div className="mt-8 border-t border-gray-100 pt-6 flex flex-col gap-y-3 sm:flex-row sm:items-center sm:justify-between sm:gap-x-8">
					<div className="flex-1">
						<h3 className="text-sm font-semibold text-gray-900">
							{ __(
								'Verbose logging',
								'google-security-for-wordpress'
							) }
						</h3>
						<p className="mt-1 text-sm text-gray-500">
							{ __(
								'By default only anomalies and failures are written to the WooCommerce log (source “gswp”). Turn this on to also log every assessment — Transaction risk per checkout and Account Defender labels per login. Useful for debugging; leave off in production to keep the log small.',
								'google-security-for-wordpress'
							) }
						</p>
					</div>
					<div className="flex items-center gap-x-3">
						<span className="text-sm text-gray-600">
							{ verbose
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
							aria-label={ __(
								'Verbose logging',
								'google-security-for-wordpress'
							) }
							className={ `relative inline-flex h-6 w-11 flex-shrink-0 cursor-pointer rounded-full border-2 border-transparent transition-colors duration-200 ease-in-out focus:outline-none focus:ring-2 focus:ring-indigo-600 focus:ring-offset-2 ${
								verbose ? 'bg-indigo-600' : 'bg-gray-200'
							}` }
							onClick={ () =>
								onChange(
									'verbose_logging',
									verbose ? '0' : '1'
								)
							}
						>
							<span
								aria-hidden="true"
								className={ `pointer-events-none inline-block h-5 w-5 transform rounded-full bg-white shadow ring-0 transition duration-200 ease-in-out ${
									verbose ? 'translate-x-5' : 'translate-x-0'
								}` }
							/>
						</button>
					</div>
				</div>
			</div>
		</div>
	);
}
