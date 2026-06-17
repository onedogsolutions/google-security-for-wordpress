import { __ } from '@wordpress/i18n';

export default function Compatibility( { settings, onChange } ) {
	const mode =
		settings.conflict_mode === 'active' || settings.conflict_mode === 'site'
			? settings.conflict_mode
			: 'off';

	const modes = [
		{
			id: 'off',
			label: __( 'Disabled', 'google-recaptcha-v3-for-woocommerce' ),
			description: __(
				'Leave other plugins to load their own reCAPTCHA scripts.',
				'google-recaptcha-v3-for-woocommerce'
			),
		},
		{
			id: 'active',
			label: __(
				'On this plugin’s reCAPTCHA pages',
				'google-recaptcha-v3-for-woocommerce'
			),
			description: __(
				'Recommended. Remove other reCAPTCHA scripts only on pages where this plugin already loads its own, so standalone forms elsewhere keep working.',
				'google-recaptcha-v3-for-woocommerce'
			),
		},
		{
			id: 'site',
			label: __( 'Site-wide', 'google-recaptcha-v3-for-woocommerce' ),
			description: __(
				'Remove other plugins’ reCAPTCHA on every front-end page. Use only when you have removed reCAPTCHA from those plugins’ forms, or their submissions may fail.',
				'google-recaptcha-v3-for-woocommerce'
			),
		},
	];

	return (
		<div className="bg-white shadow-sm ring-1 ring-gray-900/5 rounded-xl md:col-span-2">
			<div className="px-4 py-6 sm:p-8">
				<h2 className="text-base font-semibold leading-7 text-gray-900">
					{ __(
						'reCAPTCHA Conflict Handling',
						'google-recaptcha-v3-for-woocommerce'
					) }
				</h2>
				<p className="mt-1 text-sm leading-6 text-gray-600">
					{ __(
						'Google recommends loading reCAPTCHA only once per page. Suppress reCAPTCHA scripts from other plugins (such as Gravity Forms) so this implementation is the only one running.',
						'google-recaptcha-v3-for-woocommerce'
					) }
				</p>

				<fieldset className="mt-6">
					<legend className="sr-only">
						{ __(
							'Conflict handling mode',
							'google-recaptcha-v3-for-woocommerce'
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
			</div>
		</div>
	);
}
