import { __, sprintf } from '@wordpress/i18n';

export default function KeyScavenger({ keys, isLoading, onImport }) {
  return (
    <div className="bg-white shadow-sm ring-1 ring-gray-900/5 rounded-xl md:col-span-2">
      <div className="px-4 py-6 sm:p-8">
        <h2 className="text-base font-semibold leading-7 text-gray-900">
          {__('Smart Key Scavenger', 'google-recaptcha-v3-for-woocommerce')}
        </h2>
        <p className="mt-1 text-sm leading-6 text-gray-600">
          {__('We scanned your website database for existing Google reCAPTCHA configurations from other plugins. You can instantly import them with a single click.', 'google-recaptcha-v3-for-woocommerce')}
        </p>

        {isLoading ? (
          <div className="mt-6 flex items-center justify-center py-6">
            <svg className="animate-spin h-5 w-5 text-indigo-600 mr-3" fill="none" viewBox="0 0 24 24">
              <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
              <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z" />
            </svg>
            <span className="text-sm text-gray-500">{__('Scanning database for credentials...', 'google-recaptcha-v3-for-woocommerce')}</span>
          </div>
        ) : keys && keys.length > 0 ? (
          <div className="mt-6 overflow-hidden border border-gray-100 rounded-lg divide-y divide-gray-100">
            {keys.map((item, idx) => (
              <div key={idx} className="p-4 flex flex-col sm:flex-row sm:items-center sm:justify-between gap-y-4 gap-x-6 hover:bg-gray-50 transition">
                <div className="flex-1">
                  <div className="flex items-center gap-x-2">
                    <span className="text-sm font-semibold text-gray-900">{item.source}</span>
                    <span className="inline-flex items-center rounded-md bg-blue-50 px-1.5 py-0.5 text-xs font-medium text-blue-700 ring-1 ring-inset ring-blue-700/10">
                      {__('Found', 'google-recaptcha-v3-for-woocommerce')}
                    </span>
                  </div>
                  <div className="mt-2 space-y-1 text-xs text-gray-500">
                    <p>
                      <span className="font-medium">{__('Site Key: ', 'google-recaptcha-v3-for-woocommerce')}</span>
                      <code>{item.site_key.substring(0, 10)}...</code>
                    </p>
                    {item.secret_key ? (
                      <p>
                        <span className="font-medium">{__('Secret Key: ', 'google-recaptcha-v3-for-woocommerce')}</span>
                        <code>{item.secret_key.substring(0, 8)}...</code>
                      </p>
                    ) : (
                      <p className="text-amber-600">
                        {__('Secret Key is not stored globally (module-specific). You will need to enter it manually.', 'google-recaptcha-v3-for-woocommerce')}
                      </p>
                    )}
                  </div>
                </div>

                <div>
                  <button
                    type="button"
                    onClick={() => onImport(item.site_key, item.secret_key)}
                    className="inline-flex items-center rounded-md bg-white px-3 py-2 text-sm font-semibold text-indigo-600 shadow-sm ring-1 ring-inset ring-indigo-300 hover:bg-indigo-50 transition"
                  >
                    {__('Import Credentials', 'google-recaptcha-v3-for-woocommerce')}
                  </button>
                </div>
              </div>
            ))}
          </div>
        ) : (
          <div className="mt-6 rounded-lg bg-gray-50 border border-dashed border-gray-200 p-6 text-center">
            <svg className="mx-auto h-8 w-8 text-gray-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
            </svg>
            <h3 className="mt-2 text-sm font-semibold text-gray-900">{__('No keys detected', 'google-recaptcha-v3-for-woocommerce')}</h3>
            <p className="mt-1 text-xs text-gray-500">{__('No existing reCAPTCHA keys were found on this site from supported plugins.', 'google-recaptcha-v3-for-woocommerce')}</p>
          </div>
        )}
      </div>
    </div>
  );
}
