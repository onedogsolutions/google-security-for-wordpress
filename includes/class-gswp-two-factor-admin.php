<?php
/**
 * Two-Factor Settings Page
 *
 * Server-rendered settings screen (no build step) for the site-wide two-factor
 * options: the master switch and per-role enforcement. Per-user enrolment lives
 * on each user's profile screen.
 *
 * @package Google_Security_For_WordPress
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class GSWP_Two_Factor_Admin {

	const PAGE_SLUG  = 'gswp-2fa';
	const OPTION_GRP = 'gswp_2fa_settings';

	/**
	 * Constructor.
	 */
	public function __construct() {
		add_action( 'admin_menu', array( $this, 'register_page' ) );
		add_action( 'admin_init', array( $this, 'register_settings' ) );
	}

	/**
	 * Register the settings submenu under Settings.
	 */
	public function register_page() {
		add_options_page(
			__( 'Two-Factor Authentication', 'google-security-for-wordpress' ),
			__( 'Two-Factor Auth', 'google-security-for-wordpress' ),
			'manage_options',
			self::PAGE_SLUG,
			array( $this, 'render_page' )
		);
	}

	/**
	 * Register settings and sanitization callbacks.
	 */
	public function register_settings() {
		register_setting(
			self::OPTION_GRP,
			'gswp_2fa_enabled',
			array(
				'type'              => 'string',
				'sanitize_callback' => array( $this, 'sanitize_enabled' ),
				'default'           => '1',
			)
		);

		register_setting(
			self::OPTION_GRP,
			'gswp_2fa_enforced_roles',
			array(
				'type'              => 'array',
				'sanitize_callback' => array( $this, 'sanitize_roles' ),
				'default'           => array(),
			)
		);
	}

	/**
	 * Sanitize the master toggle.
	 *
	 * @param mixed $value Raw value.
	 * @return string '1' or '0'.
	 */
	public function sanitize_enabled( $value ) {
		return $value ? '1' : '0';
	}

	/**
	 * Sanitize the enforced-roles list against the site's real roles.
	 *
	 * @param mixed $value Raw value.
	 * @return string[] Valid role slugs.
	 */
	public function sanitize_roles( $value ) {
		if ( ! is_array( $value ) ) {
			return array();
		}

		$valid = array_keys( wp_roles()->get_names() );

		return array_values( array_intersect( array_map( 'sanitize_key', $value ), $valid ) );
	}

	/**
	 * Render the settings page.
	 */
	public function render_page() {
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}

		$enabled  = '1' === get_option( 'gswp_2fa_enabled', '1' );
		$enforced = (array) get_option( 'gswp_2fa_enforced_roles', array() );
		$roles    = wp_roles()->get_names();
		?>
		<div class="wrap">
			<h1><?php esc_html_e( 'Two-Factor Authentication', 'google-security-for-wordpress' ); ?></h1>
			<p><?php esc_html_e( 'Time-based one-time passwords (TOTP) compatible with Google Authenticator, Authy, 1Password, and Microsoft Authenticator. Each user enables it from their own profile screen under "Two-Factor Authentication".', 'google-security-for-wordpress' ); ?></p>

			<form method="post" action="options.php">
				<?php settings_fields( self::OPTION_GRP ); ?>
				<table class="form-table" role="presentation">
					<tbody>
						<tr>
							<th scope="row"><?php esc_html_e( 'Enable feature', 'google-security-for-wordpress' ); ?></th>
							<td>
								<label>
									<input type="checkbox" name="gswp_2fa_enabled" value="1" <?php checked( $enabled ); ?> />
									<?php esc_html_e( 'Allow users to set up two-factor authentication', 'google-security-for-wordpress' ); ?>
								</label>
								<p class="description"><?php esc_html_e( 'When disabled, the login challenge is skipped for everyone (no one is locked out) and the profile enrolment UI is hidden.', 'google-security-for-wordpress' ); ?></p>
							</td>
						</tr>
						<tr>
							<th scope="row"><?php esc_html_e( 'Require for roles', 'google-security-for-wordpress' ); ?></th>
							<td>
								<fieldset>
									<?php foreach ( $roles as $slug => $name ) : ?>
										<label style="display:block;margin-bottom:4px;">
											<input type="checkbox" name="gswp_2fa_enforced_roles[]" value="<?php echo esc_attr( $slug ); ?>" <?php checked( in_array( $slug, $enforced, true ) ); ?> />
											<?php echo esc_html( $name ); ?>
										</label>
									<?php endforeach; ?>
								</fieldset>
								<p class="description"><?php esc_html_e( 'Users in a selected role must set up two-factor authentication before they can use the admin. Leave all unchecked to keep enrolment optional.', 'google-security-for-wordpress' ); ?></p>
								<p class="description"><strong><?php esc_html_e( 'Tip:', 'google-security-for-wordpress' ); ?></strong> <?php esc_html_e( 'Enrol your own administrator account first so you do not lock yourself out when enforcing the Administrator role.', 'google-security-for-wordpress' ); ?></p>
							</td>
						</tr>
					</tbody>
				</table>
				<?php submit_button(); ?>
			</form>
		</div>
		<?php
	}
}
