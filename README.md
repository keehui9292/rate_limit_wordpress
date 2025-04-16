# WP API Rate Limiter

**Simple but effective rate limiting for WordPress REST API with login protection**

## Introduction

WP API Rate Limiter is a security-focused WordPress plugin designed to protect your site from API abuse and brute force login attempts. In today's landscape where WordPress sites increasingly rely on the REST API for frontend applications and third-party integrations, protecting these endpoints has become essential.

This plugin offers a dual-layer protection approach by implementing rate limiting on API requests and providing a way to hide your WordPress login page from potential attackers. Whether you're running a headless WordPress setup, a WooCommerce store with heavy API usage, or simply want enhanced security for your site, WP API Rate Limiter provides the protection you need without complex configuration.

## Description

WP API Rate Limiter is a robust WordPress plugin that provides dual protection for your WordPress site:

1. **REST API Rate Limiting** - Prevents API abuse by controlling request frequency
2. **Login Page Protection** - Enhances security by hiding the WordPress login behind a custom URL

This plugin is perfect for WordPress sites that use the REST API extensively or that face brute force login attempts.

## Features

### API Rate Limiting
- Separate limits for anonymous and logged-in users
- Configurable time window for rate limiting (e.g., 60 seconds)
- Role-based whitelist capabilities 
- Path inclusion/exclusion options
- Standard rate limit headers (X-RateLimit-Limit, X-RateLimit-Remaining, X-RateLimit-Reset)
- IP address detection behind proxies and CDNs

### Login Protection
- Custom login URL (replaces wp-login.php)
- Blocks direct access to wp-login.php and wp-admin
- Configurable redirects for unauthorized attempts
- Compatible with password reset links and other login actions
- .htaccess integration for enhanced protection

## Installation

1. Upload the `wp-api-rate-limiter` folder to the `/wp-content/plugins/` directory
2. Activate the plugin through the 'Plugins' menu in WordPress
3. Go to 'Settings > API Rate Limiter' to configure the plugin
4. If using login protection, write down your custom login URL!

## Configuration

### Rate Limiting Options
- **Enable Rate Limiting**: Turn the API rate limiting on/off
- **Anonymous User Limit**: Maximum requests for non-logged in users
- **Logged-in User Limit**: Maximum requests for authenticated users
- **Time Window**: Duration in seconds for the rate limiting period
- **Whitelisted Roles**: User roles that bypass rate limiting
- **Bypass for Logged-in Users**: Option to skip rate limiting for all authenticated users
- **Include/Exclude Paths**: Specify which API paths to include or exclude from rate limiting

### Login Protection Options
- **Hide WP Login Page**: Enable custom login URL
- **Custom Login URL**: Your personalized login slug
- **Redirect Invalid Login Attempts**: Choose between home page or 404 error

## Usage

After configuration, the plugin works automatically. The REST API will return a 429 error when clients exceed their rate limits, and your login page will only be accessible via your custom URL.

### API Headers
When rate limiting is active, the following headers are added to API responses:
```
X-RateLimit-Limit: 60
X-RateLimit-Remaining: 59
X-RateLimit-Reset: 1681234567
```

### Custom Login
With login protection enabled, your login URL becomes:
```
https://your-site.com/your-custom-slug
```

## FAQ

### Will this plugin slow down my site?
No, the plugin is designed to be lightweight and only activates when processing API requests or login attempts.

### What happens when the rate limit is exceeded?
The client receives a 429 (Too Many Requests) HTTP status code with a message.

### Does this work with caching plugins?
Yes, since the plugin operates on the API and login levels, it's compatible with most caching solutions.

### How can I recover if I forget my custom login URL?
You can either check the database wp_options table or disable the plugin via FTP.

### Can I whitelist certain IP addresses?
Currently this is not a feature, but you can use role-based whitelisting instead.

## Requirements
- WordPress 5.0 or higher
- PHP 7.0 or higher

## Support

For bug reports or feature requests, please contact the developer or submit an issue on GitHub.

## About the Developer

Hello! I'm Hui from Hoowey Studio, the developer behind WP API Rate Limiter. You can access my website at https://hoowey.com or email me at hui@hoowey.com

I am open for freelance work and based in KL (Kuala Lumpur). If you need custom WordPress plugins, theme development, or any web development services, feel free to reach out!

## License

GPL v2 or later
