import { __ } from '@wordpress/i18n';

function nativeLabel( state ) {
	switch ( state ) {
		case 'off':
			return __( 'off', 'google-security-for-wordpress' );
		case 'v3':
			return __( 'v3 / Enterprise', 'google-security-for-wordpress' );
		case 'v2':
			return __( 'v2 checkbox', 'google-security-for-wordpress' );
		// A challenge that is neither ours nor Google's — Fluent Forms ships
		// hCaptcha and Turnstile alongside reCAPTCHA. Naming it "v2 checkbox"
		// would send the operator looking for reCAPTCHA settings that do not
		// exist on their site.
		case 'other':
			return __(
				'hCaptcha / Turnstile',
				'google-security-for-wordpress'
			);
		// Fluent Forms only: a conversational form renders through a separate
		// Vue view that fires none of the hooks this provider injects into,
		// so it can never be covered. Distinct from 'unknown' so the operator
		// sees an explanation rather than a permanent coverage alarm.
		case 'unsupported':
			return __(
				'conversational form — not supported',
				'google-security-for-wordpress'
			);
		default:
			return __( 'unknown', 'google-security-for-wordpress' );
	}
}

/**
 * The settings-key prefix a provider's per-form options use.
 *
 * Each form plugin gets its own threshold dials and its own "not public" list.
 * Sharing them would mean tuning one plugin's registration threshold silently
 * retuned another's, and would let form #3 in one plugin silence the alarm on
 * form #3 in the other.
 *
 * @param {string} providerId Provider id.
 * @return {string} Option prefix.
 */
function prefixFor( providerId ) {
	return providerId === 'fluent-forms' ? 'ff' : 'gf';
}

/**
 * What a form does that makes it worth protecting.
 *
 * These are not alternatives. A registration form can take payment AND create
 * an account, and the earlier single-value column hid the second fact behind
 * the first — it reported "payment" and said nothing about the account, which
 * is the more security-relevant of the two.
 *
 * @param {Object} form Coverage row.
 * @return {string} Comma-separated labels, or an em dash when none apply.
 */
function sensitiveLabel( form ) {
	const labels = [];

	if ( form.payment ) {
		labels.push( __( 'payment', 'google-security-for-wordpress' ) );
	}

	// account_feed distinguishes creating an account from updating one and is
	// independent of payment. Providers that do not report it fall back to the
	// older derived flag, which is only meaningful on non-payment forms.
	if ( form.account_feed === 'create' ) {
		labels.push( __( 'creates account', 'google-security-for-wordpress' ) );
	} else if ( form.account_feed === 'update' ) {
		labels.push( __( 'updates account', 'google-security-for-wordpress' ) );
	} else if ( form.account_feed === undefined && form.account ) {
		labels.push( __( 'creates account', 'google-security-for-wordpress' ) );
	}

	return labels.length ? labels.join( ' + ' ) : '\u2014';
}

/**
 * Why a form last rejected a submission.
 *
 * "Why is this form rejecting people?" had no answer anywhere in wp-admin, and
 * none in the logs either, which is how a working customer came to be reported
 * as a suspected spammer. Only the cause and the time are shown — nothing about
 * whoever submitted it.
 *
 * @param {{reason: string, time: number}|null} rejection Recorded rejection.
 * @return {string} Human-readable cause, or an em dash when there is none.
 */
function rejectionLabel( rejection ) {
	if ( ! rejection || ! rejection.reason ) {
		return '—';
	}

	const reasons = {
		recaptcha_low_score: __( 'low score', 'google-security-for-wordpress' ),
		recaptcha_expired: __(
			'token expired',
			'google-security-for-wordpress'
		),
		recaptcha_action_mismatch: __(
			'action mismatch',
			'google-security-for-wordpress'
		),
		recaptcha_failed: __(
			'token rejected',
			'google-security-for-wordpress'
		),
		recaptcha_missing: __( 'no token', 'google-security-for-wordpress' ),
		'missing token': __( 'no token', 'google-security-for-wordpress' ),
		'low score': __( 'low score', 'google-security-for-wordpress' ),
		'transaction risk': __(
			'transaction risk',
			'google-security-for-wordpress'
		),
	};

	return reasons[ rejection.reason ] || rejection.reason;
}

export default function FormProtection( { settings, onChange } ) {
	const adminData =
		typeof window !== 'undefined' && window.gswpAdminData
			? window.gswpAdminData
			: {};

	// Prefer settings.form_providers: it's refreshed by both the initial
	// GET (App.jsx's mount effect) and every save response, whereas
	// adminData.formProviders is a snapshot baked into the page once, at
	// initial load, via wp_localize_script() — never updated again. Reading
	// only from adminData meant every toggle (and the whole coverage table:
	// "Token seen", rejections, "Its own reCAPTCHA") reverted to its
	// pre-save state immediately after Save, even though the setting had
	// already been persisted correctly server-side.
	const audit =
		settings.form_providers ||
		adminData.formProviders || { enabled: true, providers: {} };
	const providers = Object.values( audit.providers || {} );

	const pending = settings.provider_enabled || {};
	const isOn = ( provider ) =>
		pending[ provider.id ] !== undefined
			? pending[ provider.id ] === '1'
			: !! provider.on;

	const killed =
		settings.form_providers_enabled === '0' || audit.enabled === false;

	// Forms the operator has declared are driven programmatically. Held as a
	// pending list so the checkboxes behave like every other unsaved setting,
	// and kept per provider — form ids are only unique within their own plugin.
	const internalFormsFor = ( providerId ) => {
		const key = `${ prefixFor( providerId ) }_internal_forms`;

		return ( settings[ key ] || adminData.settings?.[ key ] || [] ).map(
			Number
		);
	};

	const isInternal = ( providerId, formId ) =>
		internalFormsFor( providerId ).includes( Number( formId ) );

	const toggleInternal = ( providerId, formId, checked ) => {
		const key = `${ prefixFor( providerId ) }_internal_forms`;
		const id = Number( formId );
		const current = internalFormsFor( providerId );
		const next = checked
			? [ ...current, id ]
			: current.filter( ( existing ) => existing !== id );

		onChange( key, [ ...new Set( next ) ] );
	};

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
							'No supported form plugins are active. When Gravity Forms or Fluent Forms is installed, this panel lets this plugin score its forms.',
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
					const prefix = prefixFor( provider.id );

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

							{ isOn( provider ) && (
								<div className="mt-4 rounded-md bg-gray-50 p-3">
									<p className="text-xs font-medium text-gray-700">
										{ __(
											'Score thresholds',
											'google-security-for-wordpress'
										) }
									</p>
									<p className="mt-1 text-xs text-gray-500">
										{ __(
											'A submission scoring below its threshold is rejected as spam. Each class of form has its own dial, and each form plugin has its own set of them, so tightening one to keep fake signups out does not silently tighten your contact forms — or the other plugin’s forms — with it. A signed-in user editing their own profile, or changing their own password, is scored but never blocked for a missing token.',
											'google-security-for-wordpress'
										) }
									</p>
									<div className="mt-3 space-y-3">
										{ [
											{
												key: `threshold_${ prefix }_submit`,
												label: __(
													'Ordinary submissions',
													'google-security-for-wordpress'
												),
											},
											{
												key: `threshold_${ prefix }_register`,
												label: __(
													'Creates an account',
													'google-security-for-wordpress'
												),
											},
											{
												key: `threshold_${ prefix }_account_update`,
												label: __(
													'Updates an account',
													'google-security-for-wordpress'
												),
											},
											// The password dial has existed as an option since
											// 2.22.0 but was never rendered, so the one class of
											// form most worth tuning — the step an account
											// takeover performs to lock the owner out — could
											// only be reached through the database.
											{
												key: `threshold_${ prefix }_password`,
												label: __(
													'Changes a password',
													'google-security-for-wordpress'
												),
											},
										].map( ( dial ) => {
											const value =
												parseFloat(
													settings[ dial.key ]
												) || 0.5;

											return (
												<div
													key={ dial.key }
													className="flex items-center gap-x-3"
												>
													<span className="w-44 shrink-0 text-xs text-gray-600">
														{ dial.label }
													</span>
													<input
														type="range"
														min="0.0"
														max="1.0"
														step="0.1"
														value={ value }
														onChange={ ( e ) =>
															onChange(
																dial.key,
																e.target.value
															)
														}
														className="h-1 flex-1 cursor-pointer appearance-none rounded-lg bg-gray-200 accent-indigo-600 focus:outline-none focus:ring-2 focus:ring-indigo-600"
													/>
													<span className="w-8 text-right text-xs font-semibold text-indigo-600">
														{ value.toFixed( 1 ) }
													</span>
												</div>
											);
										} ) }
									</div>
								</div>
							) }

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
											<th className="py-2 pr-4 font-medium">
												{ __(
													'Action / threshold',
													'google-security-for-wordpress'
												) }
											</th>
											<th className="py-2 pr-4 font-medium">
												{ __(
													'Last rejection',
													'google-security-for-wordpress'
												) }
											</th>
											<th className="py-2 pr-4 font-medium">
												{ __(
													'Its own reCAPTCHA',
													'google-security-for-wordpress'
												) }
											</th>
											<th className="py-2 font-medium">
												{ __(
													'Not public',
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
																{ form.internal
																	? __(
																			'not scored',
																			'google-security-for-wordpress'
																	  )
																	: __(
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
														{ sensitiveLabel(
															form
														) }
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
													<td className="py-2 pr-4 text-gray-600">
														{ form.action ? (
															<>
																<span className="font-mono">
																	{
																		form.action
																	}
																</span>
																<span className="block text-gray-400">
																	{
																		form.context
																	}
																</span>
															</>
														) : (
															'—'
														) }
													</td>
													<td className="py-2 pr-4 text-gray-600">
														{ rejectionLabel(
															form.last_rejection
														) }
													</td>
													<td className="py-2 pr-4 text-gray-600">
														{ nativeLabel(
															form.native
														) }
													</td>
													<td className="py-2">
														<input
															type="checkbox"
															checked={ isInternal(
																provider.id,
																form.id
															) }
															onChange={ ( e ) =>
																toggleInternal(
																	provider.id,
																	form.id,
																	e.target
																		.checked
																)
															}
															className="h-4 w-4 rounded border-gray-300 text-indigo-600 focus:ring-indigo-600"
															aria-label={ __(
																'This form is never submitted by a visitor',
																'google-security-for-wordpress'
															) }
														/>
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
									( form ) =>
										form.covered &&
										! form.injected &&
										! isInternal( provider.id, form.id )
								) && (
									<p className="mt-3 text-xs leading-5 text-amber-700">
										{ __(
											'Some forms have not yet been observed receiving a token field. Load each one on the front end and reload this page. A form that never receives a token is submitted unscored — you will also be emailed if that happens.',
											'google-security-for-wordpress'
										) }
									</p>
								) }

							{ isOn( provider ) && (
								<p className="mt-3 text-xs leading-5 text-gray-500">
									{ __(
										'Tick “Not public” for any form your site submits programmatically rather than a visitor filling in — one that generates a certificate on course completion, for example. It stops this plugin reporting a missing token on that form as a coverage gap. It does not stop the form being scored: a submission that arrives from a real browser with a token is always scored, whatever this is set to.',
										'google-security-for-wordpress'
									) }
								</p>
							) }

							{ isOn( provider ) &&
								( provider.forms || [] ).some(
									( form ) =>
										isInternal( provider.id, form.id ) &&
										( form.password ||
											form.payment ||
											form.account_feed )
								) && (
									<p className="mt-2 text-xs leading-5 text-amber-700">
										{ __(
											'A form marked “Not public” also takes payment, changes a password, or touches an account. That is allowed — those submissions are still scored whenever they carry a token — but check the mark is deliberate: it silences the alert that would otherwise tell you the form had stopped being protected.',
											'google-security-for-wordpress'
										) }
									</p>
								) }

							{ provider.id === 'fluent-forms' &&
								isOn( provider ) &&
								( provider.forms || [] ).some(
									( form ) => form.payment
								) && (
									<p className="mt-2 text-xs leading-5 text-gray-500">
										{ __(
											'Fluent Forms payments are scored and reported to Google, but a high-risk payment is not blocked here even when blocking is switched on elsewhere. Whether Fluent Forms authorises the card in the browser before the submission reaches this plugin has not been confirmed on a live install, and if it does, blocking would stop the order without releasing the hold on the customer’s card. The risk score is still recorded, and the outcome is still reported back to Google when the payment completes or is refunded.',
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
