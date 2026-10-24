# Google Security for WordPress 🛡️

[![WordPress](https://img.shields.io/badge/WordPress-5.8+-blue.svg)](https://wordpress.org/)
[![PHP Version](https://img.shields.io/badge/PHP-7.4%20|%208.0%20|%208.1%20|%208.2%20|%208.3-blue.svg)](https://php.net/)
[![License](https://img.shields.io/badge/License-GPLv2+-green.svg)](https://www.gnu.org/licenses/gpl-2.0.html)
[![MainWP Ready](https://img.shields.io/badge/MainWP-Compatible-brightgreen.svg)](https://mainwp.com/)

**Google Security for WordPress** by [One Dog Solutions](https://github.com/onedogsolutions) delivers enterprise-grade protection for your WordPress sites by integrating Google's proven security ecosystem—including reCAPTCHA, Google Identity, and Google Safe Browsing—alongside essential core WordPress hardening.

Designed specifically for agencies, developers, and high-traffic WordPress sites, this plugin stops brute-force bots, secures user authentication, and provides centralized management without bloating your database or slowing down page delivery.

---

## 🌟 Key Features

### 1. Google reCAPTCHA Integration (v2 & v3)
* **Intelligent Bot Defense:** Block automated spambots and credential-stuffing attacks using Google reCAPTCHA v2 (Checkbox / Invisible) or reCAPTCHA v3 (Score-based evaluation).
* **Targeted Form Protection:**
  * WordPress Login (`wp-login.php`)
  * User Registration
  * Password Reset / Lost Password
  * Native WordPress Comments
  * WooCommerce Checkout & Account Forms
  * Compatibility hooks for popular form builders (Gravity Forms, Fluent Forms, WPForms)

### 2. Google Identity & Multi-Factor Authentication
* **Google Authenticator (TOTP):** Enforce time-based one-time password (TOTP) two-factor authentication for Administrators and Editors to eliminate account takeovers.
* **Google Sign-In & One Tap:** Allow trusted users and clients to authenticate seamlessly using verified Google Workspace or Gmail accounts.
* **Role-Based Enforcement:** Require 2FA conditionally based on user role or custom user capabilities.

### 3. Google Safe Browsing & Reputation Monitoring
* **Malware & Phishing Detection:** Leverage the Google Safe Browsing / Web Risk API to check outgoing links and monitor your site’s domain reputation.
* **Proactive Security Alerts:** Receive email notifications if Google detects suspicious injection, unauthorized redirects, or deceptive content.

### 4. Core WordPress Hardening
* **XML-RPC Mitigation:** Block or disable `xmlrpc.php` to neutralize the most common WordPress DDoS and brute-force vector.
* **REST API Protection:** Restrict unauthenticated WP REST API endpoints and prevent author/username enumeration (`/wp-json/wp/v2/users`).
* **Admin Security Locks:** Disable the native Theme/Plugin file editor (`DISALLOW_FILE_EDIT`) to prevent PHP payload injection via compromised admin sessions.
* **Header Sanitization:** Remove the WordPress generator version tag, pingback links, and RSD headers from your site's `<head>`.

### 5. Multi-Site & MainWP Management
* **Centralized Configuration:** Deploy, manage, and audit security policies across all client sites from a single MainWP dashboard.
* **One-Click Rule Sync:** Push updated reCAPTCHA keys, lockout policies, and core hardening configurations to dozens of child sites instantly.

---

## ⚙️ Requirements

* **WordPress:** 5.8 or higher
* **PHP:** 7.4 or higher (8.1+ recommended)
* **Google Cloud Console Account:** For generating reCAPTCHA API keys and OAuth 2.0 Client credentials (free tier).

---

## 🚀 Installation

### Via WordPress Admin
1. Download the latest `.zip` release from the [Releases](../../releases) tab.
2. In your WordPress admin, go to **Plugins > Add New > Upload Plugin**.
3. Choose the `.zip` archive, click **Install Now**, and then **Activate**.

### Via WP-CLI
```bash
wp plugin install [https://github.com/onedogsolutions/google-security-for-wordpress/archive/refs/heads/main.zip](https://github.com/onedogsolutions/google-security-for-wordpress/archive/refs/heads/main.zip) --activate
