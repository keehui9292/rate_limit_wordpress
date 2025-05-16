<?php
/**
 * Plugin Name: WP API Rate Limiter
 * Description: Simple but effective rate limiting for WordPress REST API with login protection
 * Version: 1.0.2
 * Author: Hoowey Studio
 * Author URI: https://hoowey.com
 */

// Exit if accessed directly
if (!defined('ABSPATH')) {
    exit;
}

class WP_API_Rate_Limiter {
    // Default settings
    private $defaults = [
        'enabled' => true,
        'anonymous_limit' => 60,
        'logged_in_limit' => 300,
        'window_size' => 60,
        'whitelist_roles' => [],
        'bypass_logged_in' => false,
        'include_paths' => [],
        'exclude_paths' => [],
        'hide_login' => false,
        'login_slug' => 'private-login',
        'redirect_to' => 'home'
    ];

    // Singleton instance
    private static $instance = null;

    // Get singleton instance
    public static function get_instance() {
        if (null === self::$instance) {
            self::$instance = new self();
        }
        return self::$instance;
    }

    // Constructor
    private function __construct() {
        // Initialize the plugin
        add_action('init', [$this, 'init']);
        
        // Admin menu and settings
        add_action('admin_menu', [$this, 'add_admin_menu']);
        add_action('admin_init', [$this, 'register_settings']);
        add_action('template_redirect', array($this, 'block_frontend_access'));
        
        // Handle login hiding if enabled
        $settings = $this->get_settings();
        if ($settings['hide_login']) {
            add_action('plugins_loaded', [$this, 'handle_hidden_login']);
        }
    }

    // Initialize plugin
    public function init() {
        // Apply rate limiting to REST API
        add_filter('rest_pre_dispatch', [$this, 'limit_api_requests'], 10, 3);
    }

    /**
     * Block access to front-end pages with custom HTML response
     */
    public function block_frontend_access() {
        // Don't block API requests
        if (strpos($_SERVER['REQUEST_URI'], '/wp-json/') !== false) {
            return;
        }
        
        // Don't block admin access
        if (is_admin() || strpos($_SERVER['REQUEST_URI'], '/wp-admin/') !== false || strpos($_SERVER['REQUEST_URI'], '/wp-login.php') !== false) {
            return;
        }
        
        // Send 403 header
        status_header(403);
        
        // Output clean, custom HTML without WordPress references or API endpoints
        $html = '<!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>API Access Only</title>
            <style>
                body {
                    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Oxygen-Sans, Ubuntu, Cantarell, "Helvetica Neue", sans-serif;
                    background-color: #f5f5f5;
                    color: #333;
                    margin: 0;
                    padding: 0;
                    display: flex;
                    justify-content: center;
                    align-items: center;
                    height: 100vh;
                    text-align: center;
                }
                .container {
                    background-color: #fff;
                    border-radius: 8px;
                    box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
                    padding: 40px;
                    max-width: 500px;
                    width: 90%;
                }
                h1 {
                    color: #e74c3c;
                    margin-top: 0;
                }
                p {
                    font-size: 16px;
                    line-height: 1.6;
                    margin-bottom: 20px;
                }
                .status-code {
                    font-size: 12px;
                    color: #777;
                    margin-top: 30px;
                }
            </style>
        </head>
        <body>
            <div class="container">
                <h1>Access Restricted</h1>
                <p>This server provides API services to authorized applications only.</p>
                <p>Direct browser access to this resource is not permitted.</p>
                <div class="status-code">Status Code: 403 Forbidden</div>
            </div>
        </body>
        </html>';
        
        echo $html;
        exit;
    }
    
    /**
     * Handle hidden login functionality
     */
    public function handle_hidden_login() {
        $settings = $this->get_settings();
        $login_slug = sanitize_title($settings['login_slug']);
        
        // Register the query vars - keep this at high priority
        add_filter('query_vars', function($query_vars) {
            $query_vars[] = 'custom_login';
            $query_vars[] = 'login_action';
            return $query_vars;
        }, 1);
        
        // Register rewrite rules - IMPORTANT: set to priority 10 instead of 1
        add_action('init', function() use ($login_slug) {
            // Main login page - make this rule very specific and prioritized
            add_rewrite_rule(
                '^' . $login_slug . '/?$', 
                'index.php?custom_login=true', 
                'top'
            );
            
            // Login actions (like reset password, register, etc.)
            add_rewrite_rule(
                '^' . $login_slug . '/([^/]+)/?$', 
                'index.php?custom_login=true&login_action=$1', 
                'top'
            );
            
            // Force flush rewrite rules if option is set
            if (get_option('wp_api_rate_limiter_flush_rules', false) === false) {
                flush_rewrite_rules();
                update_option('wp_api_rate_limiter_flush_rules', true);
            }
        }, 10);
        
        // Add a debugging action - this helps identify if the rule is matching
        add_action('template_redirect', function() {
            if (isset($_GET['debug_login'])) {
                global $wp;
                echo '<pre>';
                echo 'Current request: ' . esc_html($_SERVER['REQUEST_URI']) . "\n";
                echo 'WP Query Vars: ';
                print_r($wp->query_vars);
                echo '</pre>';
                exit;
            }
        });
        
        // Handle the custom login request
        add_action('parse_request', function($wp) {
            if (isset($wp->query_vars['custom_login'])) {
                // Get the action if present
                $action = isset($wp->query_vars['login_action']) ? $wp->query_vars['login_action'] : '';
                
                // Set the action parameter if needed
                if (!empty($action)) {
                    $_REQUEST['action'] = $action;
                }
                
                // Add our form action filter right before loading the login page
                add_action('login_head', [$this, 'filter_login_form_action']);
                
                // Load the login page
                require_once(ABSPATH . 'wp-login.php');
                exit;
            }
        });
        
        // Block direct access to wp-login.php
        add_action('login_init', [$this, 'block_wp_login']);
        
        // Early interception for wp-admin URLs
        if (!is_user_logged_in() && $this->is_wp_admin_url()) {
            $this->handle_blocked_access();
        }
        
        // Another hook to catch wp-admin after WordPress init
        add_action('init', [$this, 'block_wp_admin'], 0);
        
        // Filter various WordPress URLs to use our custom login
        add_filter('login_url', [$this, 'filter_login_url'], 10, 3);
        add_filter('logout_url', [$this, 'filter_logout_url'], 10, 2);
        add_filter('lostpassword_url', [$this, 'filter_lostpassword_url'], 10, 2);
        add_filter('register_url', [$this, 'filter_register_url'], 10);
        
        // Maybe flush rewrite rules
        if (get_option('wp_api_rate_limiter_flush_rules', false) === false) {
            flush_rewrite_rules(false);
            update_option('wp_api_rate_limiter_flush_rules', true);
        }
    }

    /**
     * Check if current URL is a wp-admin URL
     */
    private function is_wp_admin_url() {
        $request_uri = isset($_SERVER['REQUEST_URI']) ? $_SERVER['REQUEST_URI'] : '';
        return (
            strpos($request_uri, '/wp-admin') !== false || 
            strpos($request_uri, '/admin') !== false
        );
    }

    /**
     * Handle blocked access based on settings, but exclude wp-json
     */
    private function handle_blocked_access() {
        // First check if this is a wp-json request and allow it if so
        $request_uri = isset($_SERVER['REQUEST_URI']) ? $_SERVER['REQUEST_URI'] : '';
        if (strpos($request_uri, '/wp-json/') !== false) {
            return; // Allow wp-json access
        }
        
        $settings = $this->get_settings();
        $redirect_to = $settings['redirect_to'];
        
        if ($redirect_to === '404') {
            // Make sure we have a proper global $wp_query
            global $wp_query;
            
            // Check if $wp_query is initialized, if not create it
            if (empty($wp_query) || !is_object($wp_query)) {
                $wp_query = new WP_Query();
            }
            
            // Now set the 404 status
            status_header(404);
            nocache_headers();
            $wp_query->set_404();
            
            // Try to include the 404 template if it exists
            $template_404 = get_404_template();
            if ($template_404 && file_exists($template_404)) {
                include($template_404);
            } else {
                // Fallback if template doesn't exist
                echo '<html><head><title>404 Not Found</title></head>';
                echo '<body><h1>404 Not Found</h1><p>The page you requested does not exist.</p></body></html>';
            }
            exit;
        } else {
            // Redirect instead of 404
            $redirect_url = home_url('/');
            if (filter_var($redirect_to, FILTER_VALIDATE_URL)) {
                $redirect_url = $redirect_to;
            }
            wp_safe_redirect($redirect_url);
            exit;
        }
    }

    public function block_wp_admin() {
        // Get the request URI
        $request_uri = isset($_SERVER['REQUEST_URI']) ? $_SERVER['REQUEST_URI'] : '';
        
        // Check if it's a wp-admin access attempt for non-logged in users
        if ((is_admin() || strpos($request_uri, '/wp-admin') !== false) && 
            !is_user_logged_in() && 
            !defined('DOING_AJAX')) {
            
            $settings = $this->get_settings();
            $redirect_to = $settings['redirect_to'];
            
            // Determine where to redirect
            $redirect_url = home_url('/');
            if ($redirect_to === '404') {
                global $wp_query;
                $wp_query->set_404();
                status_header(404);
                nocache_headers();
                include(get_query_template('404'));
                die;
            } elseif (filter_var($redirect_to, FILTER_VALIDATE_URL)) {
                $redirect_url = $redirect_to;
            }
            
            // Redirect
            wp_redirect($redirect_url);
            exit;
        }
    }
    
    /**
     * Block direct access to wp-login.php
     */
    public function block_wp_login() {
        $settings = $this->get_settings();
        $login_slug = sanitize_title($settings['login_slug']);
        $redirect_to = $settings['redirect_to'];
        
        // Get request URI
        $request_uri = isset($_SERVER['REQUEST_URI']) ? $_SERVER['REQUEST_URI'] : '';
        
        // Allow direct access for specific query params (useful for plugins)
        $allowed_actions = apply_filters('wp_api_rate_limiter_allowed_login_actions', [
            'postpass', // Password protected posts
            'logout',   // Logout action
            'lostpassword', // Password reset
            'retrievepassword', // Password reset
            'resetpass', // Password reset
            'rp'       // Password reset
        ]);
        
        // Get the requested action
        $action = isset($_REQUEST['action']) ? $_REQUEST['action'] : '';
        
        // Check if accessing wp-login.php directly and not through custom slug
        if (strpos($request_uri, 'wp-login.php') !== false) {
            // Allow for specific actions that need to work (like password reset links)
            if (!empty($action) && in_array($action, $allowed_actions)) {
                return;
            }
            
            // Check if this is the custom login path
            if (strpos($request_uri, $login_slug) !== false) {
                return; // Allow if coming through our custom slug
            }
            
            // Block access to direct wp-login.php
            $this->handle_blocked_access();
            exit;
        }
    }
    
    /**
     * Filter login URL
     */
    public function filter_login_url($login_url, $redirect, $force_reauth) {
        $settings = $this->get_settings();
        $login_slug = sanitize_title($settings['login_slug']);
        
        // Create the custom login URL
        $custom_login_url = home_url($login_slug);
        
        // Add redirect parameter if provided
        if (!empty($redirect)) {
            $custom_login_url = add_query_arg('redirect_to', urlencode($redirect), $custom_login_url);
        }
        
        // Add force reauth if needed
        if ($force_reauth) {
            $custom_login_url = add_query_arg('reauth', '1', $custom_login_url);
        }
        
        return $custom_login_url;
    }
    
    /**
     * Filter logout URL
     */
    public function filter_logout_url($logout_url, $redirect) {
        // Keep the logout URL as is, just make sure any redirect back to admin 
        // redirects to the custom login page instead
        if (!empty($redirect) && (
            strpos($redirect, 'wp-admin') !== false || 
            strpos($redirect, 'wp-login.php') !== false
        )) {
            $settings = $this->get_settings();
            $login_slug = sanitize_title($settings['login_slug']);
            $logout_url = add_query_arg('redirect_to', urlencode(home_url($login_slug)), $logout_url);
        }
        
        return $logout_url;
    }
    
    /**
     * Filter lostpassword URL
     */
    public function filter_lostpassword_url($lostpassword_url, $redirect) {
        $settings = $this->get_settings();
        $login_slug = sanitize_title($settings['login_slug']);
        
        // Replace wp-login.php with custom slug
        $lostpassword_url = str_replace('wp-login.php', $login_slug, $lostpassword_url);
        
        // Add redirect parameter if provided
        if (!empty($redirect)) {
            $lostpassword_url = add_query_arg('redirect_to', urlencode($redirect), $lostpassword_url);
        }
        
        return $lostpassword_url;
    }
    
    /**
     * Filter register URL
     */
    public function filter_register_url($register_url) {
        $settings = $this->get_settings();
        $login_slug = sanitize_title($settings['login_slug']);
        
        // Replace wp-login.php with custom slug
        $register_url = str_replace('wp-login.php', $login_slug, $register_url);
        
        return $register_url;
    }

    // Main rate limiting function
    public function limit_api_requests($response, $handler, $request) {
        // Get settings
        $settings = $this->get_settings();
        
        // Check if rate limiting is enabled
        if (!$settings['enabled']) {
            return $response;
        }
        
        // Get current path
        $current_path = $request->get_route();
        
        // Check include paths (if specified)
        if (!empty($settings['include_paths'])) {
            $included = false;
            foreach ($settings['include_paths'] as $path) {
                if (empty($path)) continue;
                if (strpos($current_path, $path) === 0) {
                    $included = true;
                    break;
                }
            }
            
            if (!$included) {
                return $response; // Skip rate limiting for this path
            }
        }
        
        // Check exclude paths
        foreach ($settings['exclude_paths'] as $path) {
            if (empty($path)) continue;
            if (strpos($current_path, $path) === 0) {
                return $response; // Skip rate limiting for this path
            }
        }
        
        // Check if user is logged in
        $user_id = get_current_user_id();
        $is_logged_in = $user_id > 0;
        
        // Bypass for logged-in users if enabled
        if ($is_logged_in && $settings['bypass_logged_in']) {
            return $response;
        }
        
        // Check whitelist roles for logged-in users
        if ($is_logged_in) {
            $user = get_userdata($user_id);
            if ($user && !empty($user->roles)) {
                $has_whitelisted_role = array_intersect($settings['whitelist_roles'], (array) $user->roles);
                if (!empty($has_whitelisted_role)) {
                    return $response; // Skip rate limiting for whitelisted roles
                }
            }
        }
        
        // Determine client identifier (IP + user ID if logged in)
        $client_ip = $this->get_client_ip();
        $identifier = $is_logged_in ? "user_{$user_id}_{$client_ip}" : "ip_{$client_ip}";
        
        // Create rate limit key
        $rate_key = 'wparl_' . md5($identifier . $request->get_route());
        
        // Get current count
        $count = get_transient($rate_key) ?: 0;
        
        // Determine applicable limit
        $limit = $is_logged_in ? $settings['logged_in_limit'] : $settings['anonymous_limit'];
        
        // Check if over limit
        if ($count >= $limit) {
            return new WP_Error(
                'rest_rate_limited',
                'API rate limit exceeded. Please try again later.',
                ['status' => 429]
            );
        }
        
        // Increment counter
        set_transient($rate_key, $count + 1, $settings['window_size']);
        
        // Set rate limit headers
        add_filter('rest_post_dispatch', function($served_response) use ($limit, $count, $settings) {
            if ($served_response instanceof WP_REST_Response) {
                $served_response->header('X-RateLimit-Limit', $limit);
                $served_response->header('X-RateLimit-Remaining', max(0, $limit - ($count + 1)));
                $served_response->header('X-RateLimit-Reset', time() + $settings['window_size']);
            }
            return $served_response;
        });
        
        return $response;
    }

    // Get client IP
    private function get_client_ip() {
        $ip = '';
        
        // Check for Cloudflare
        if (isset($_SERVER['HTTP_CF_CONNECTING_IP'])) {
            $ip = $_SERVER['HTTP_CF_CONNECTING_IP'];
        } 
        // Check for proxy
        else if (isset($_SERVER['HTTP_X_FORWARDED_FOR'])) {
            $ip = trim(current(explode(',', $_SERVER['HTTP_X_FORWARDED_FOR'])));
        }
        // Regular IP
        else if (isset($_SERVER['REMOTE_ADDR'])) {
            $ip = $_SERVER['REMOTE_ADDR'];
        }
        
        return $ip;
    }
    
    // Add admin menu
    public function add_admin_menu() {
        add_options_page(
            'API Rate Limiter',
            'API Rate Limiter',
            'manage_options',
            'wp-api-rate-limiter',
            [$this, 'render_settings_page']
        );
    }
    
    // Register settings
    public function register_settings() {
        register_setting('wp_api_rate_limiter_group', 'wp_api_rate_limiter_settings', [
            'sanitize_callback' => [$this, 'sanitize_settings']
        ]);

        // Rate Limiting Section
        add_settings_section(
            'wp_api_rate_limiter_main',
            'Rate Limiting Settings',
            [$this, 'settings_section_callback'],
            'wp-api-rate-limiter'
        );
        
        // Login Protection Section
        add_settings_section(
            'wp_api_rate_limiter_login',
            'Login Protection',
            [$this, 'login_section_callback'],
            'wp-api-rate-limiter'
        );

        add_settings_field(
            'enabled',
            'Enable Rate Limiting',
            [$this, 'enabled_callback'],
            'wp-api-rate-limiter',
            'wp_api_rate_limiter_main'
        );

        add_settings_field(
            'anonymous_limit',
            'Anonymous User Limit (requests)',
            [$this, 'anonymous_limit_callback'],
            'wp-api-rate-limiter',
            'wp_api_rate_limiter_main'
        );

        add_settings_field(
            'logged_in_limit',
            'Logged-in User Limit (requests)',
            [$this, 'logged_in_limit_callback'],
            'wp-api-rate-limiter',
            'wp_api_rate_limiter_main'
        );

        add_settings_field(
            'window_size',
            'Time Window (seconds)',
            [$this, 'window_size_callback'],
            'wp-api-rate-limiter',
            'wp_api_rate_limiter_main'
        );

        add_settings_field(
            'whitelist_roles',
            'Whitelisted Roles',
            [$this, 'whitelist_roles_callback'],
            'wp-api-rate-limiter',
            'wp_api_rate_limiter_main'
        );

        add_settings_field(
            'bypass_logged_in',
            'Bypass for Logged-in Users',
            [$this, 'bypass_logged_in_callback'],
            'wp-api-rate-limiter',
            'wp_api_rate_limiter_main'
        );

        add_settings_field(
            'include_paths',
            'Include Only These Paths (optional)',
            [$this, 'include_paths_callback'],
            'wp-api-rate-limiter',
            'wp_api_rate_limiter_main'
        );

        add_settings_field(
            'exclude_paths',
            'Exclude These Paths (optional)',
            [$this, 'exclude_paths_callback'],
            'wp-api-rate-limiter',
            'wp_api_rate_limiter_main'
        );
        
        // Login Protection Fields
        add_settings_field(
            'hide_login',
            'Hide WP Login Page',
            [$this, 'hide_login_callback'],
            'wp-api-rate-limiter',
            'wp_api_rate_limiter_login'
        );
        
        add_settings_field(
            'login_slug',
            'Custom Login URL',
            [$this, 'login_slug_callback'],
            'wp-api-rate-limiter',
            'wp_api_rate_limiter_login'
        );
        
        add_settings_field(
            'redirect_to',
            'Redirect Invalid Login Attempts',
            [$this, 'redirect_to_callback'],
            'wp-api-rate-limiter',
            'wp_api_rate_limiter_login'
        );
    }
    
    // Get settings
    private function get_settings() {
        $settings = get_option('wp_api_rate_limiter_settings', $this->defaults);
        return wp_parse_args($settings, $this->defaults);
    }
    
    // Sanitize settings
    public function sanitize_settings($input) {
        $new_input = [];
        
        $new_input['enabled'] = isset($input['enabled']) ? true : false;
        $new_input['anonymous_limit'] = absint($input['anonymous_limit']);
        $new_input['logged_in_limit'] = absint($input['logged_in_limit']);
        $new_input['window_size'] = absint($input['window_size']);
        $new_input['bypass_logged_in'] = isset($input['bypass_logged_in']) ? true : false;
        
        $new_input['whitelist_roles'] = isset($input['whitelist_roles']) && is_array($input['whitelist_roles']) 
            ? array_map('sanitize_text_field', $input['whitelist_roles']) 
            : $this->defaults['whitelist_roles'];
            
        // Handle path lists    
        $new_input['include_paths'] = [];
        if (isset($input['include_paths']) && !empty($input['include_paths'])) {
            $paths = explode("\n", $input['include_paths']);
            foreach ($paths as $path) {
                $path = trim($path);
                if (!empty($path)) {
                    $new_input['include_paths'][] = '/' . ltrim($path, '/');
                }
            }
        }
        
        $new_input['exclude_paths'] = [];
        if (isset($input['exclude_paths']) && !empty($input['exclude_paths'])) {
            $paths = explode("\n", $input['exclude_paths']);
            foreach ($paths as $path) {
                $path = trim($path);
                if (!empty($path)) {
                    $new_input['exclude_paths'][] = '/' . ltrim($path, '/');
                }
            }
        }
        
        // Login protection settings
        $new_input['hide_login'] = isset($input['hide_login']) ? true : false;
        
        // Check if login slug has changed
        $old_settings = $this->get_settings();
        $new_input['login_slug'] = isset($input['login_slug']) && !empty($input['login_slug']) 
            ? sanitize_title($input['login_slug']) 
            : $this->defaults['login_slug'];
            
        // If login slug changed, schedule a rewrite flush
        if ($new_input['hide_login'] && $old_settings['login_slug'] !== $new_input['login_slug']) {
            update_option('wp_api_rate_limiter_flush_rules', false);
        }
        
        // Redirect setting
        $new_input['redirect_to'] = isset($input['redirect_to']) ? sanitize_text_field($input['redirect_to']) : 'home';

        // Check if login slug was changed or login protection was enabled
        $old_settings = $this->get_settings();
        $login_slug_changed = ($new_input['login_slug'] !== $old_settings['login_slug']);
        $protection_enabled = ($new_input['hide_login'] && !$old_settings['hide_login']);
        
        // Update htaccess if needed
        if (($login_slug_changed || $protection_enabled) && $new_input['hide_login']) {
            $this->update_htaccess_rules($new_input['login_slug']);
        }
        
        return $new_input;
    }
    
    // Settings section callback
    public function settings_section_callback() {
        echo '<p>Configure rate limiting for the WordPress REST API.</p>';
    }
    
    // Login protection section callback
    public function login_section_callback() {
        echo '<p>Hide your WordPress login page from attackers by using a custom URL.</p>';
        echo '<p><strong>Note:</strong> After changing these settings, you may need to flush permalinks by going to Settings -> Permalinks and clicking "Save Changes".</p>';
    }
    
    // Settings field callbacks
    public function enabled_callback() {
        $settings = $this->get_settings();
        ?>
        <input type="checkbox" name="wp_api_rate_limiter_settings[enabled]" <?php checked($settings['enabled'], true); ?>>
        <span class="description">Enable or disable API rate limiting</span>
        <?php
    }
    
    public function anonymous_limit_callback() {
        $settings = $this->get_settings();
        ?>
        <input type="number" min="1" name="wp_api_rate_limiter_settings[anonymous_limit]" value="<?php echo esc_attr($settings['anonymous_limit']); ?>">
        <span class="description">Maximum number of requests for anonymous users per time window</span>
        <?php
    }
    
    public function logged_in_limit_callback() {
        $settings = $this->get_settings();
        ?>
        <input type="number" min="1" name="wp_api_rate_limiter_settings[logged_in_limit]" value="<?php echo esc_attr($settings['logged_in_limit']); ?>">
        <span class="description">Maximum number of requests for logged-in users per time window</span>
        <?php
    }
    
    public function window_size_callback() {
        $settings = $this->get_settings();
        ?>
        <input type="number" min="1" name="wp_api_rate_limiter_settings[window_size]" value="<?php echo esc_attr($settings['window_size']); ?>">
        <span class="description">Time window in seconds (e.g., 60 for one minute)</span>
        <?php
    }
    
    public function whitelist_roles_callback() {
        $settings = $this->get_settings();
        $roles = get_editable_roles();
        foreach ($roles as $role_id => $role_data) {
            ?>
            <label>
                <input type="checkbox" name="wp_api_rate_limiter_settings[whitelist_roles][]" value="<?php echo esc_attr($role_id); ?>" <?php checked(in_array($role_id, $settings['whitelist_roles']), true); ?>>
                <?php echo esc_html($role_data['name']); ?>
            </label><br>
            <?php
        }
        ?>
        <span class="description">Users with these roles will not be rate limited</span>
        <?php
    }
    
    public function bypass_logged_in_callback() {
        $settings = $this->get_settings();
        ?>
        <input type="checkbox" name="wp_api_rate_limiter_settings[bypass_logged_in]" <?php checked($settings['bypass_logged_in'], true); ?>>
        <span class="description">Bypass rate limiting for all logged-in users (regardless of role)</span>
        <?php
    }
    
    public function include_paths_callback() {
        $settings = $this->get_settings();
        $paths = implode("\n", $settings['include_paths']);
        ?>
        <textarea name="wp_api_rate_limiter_settings[include_paths]" rows="4" cols="50" class="large-text code"><?php echo esc_textarea($paths); ?></textarea>
        <p class="description">Only apply rate limiting to these paths (one per line). For example: /wp/v2/posts<br>Leave empty to include all paths.</p>
        <?php
    }
    
    public function exclude_paths_callback() {
        $settings = $this->get_settings();
        $paths = implode("\n", $settings['exclude_paths']);
        ?>
        <textarea name="wp_api_rate_limiter_settings[exclude_paths]" rows="4" cols="50" class="large-text code"><?php echo esc_textarea($paths); ?></textarea>
        <p class="description">Do not apply rate limiting to these paths (one per line). For example: /wp/v2/users</p>
        <?php
    }
    
    // Login protection field callbacks
    public function hide_login_callback() {
        $settings = $this->get_settings();
        ?>
        <input type="checkbox" name="wp_api_rate_limiter_settings[hide_login]" <?php checked($settings['hide_login'], true); ?>>
        <span class="description">Enable custom login URL (hide wp-login.php)</span>
        <?php
    }
    
    public function login_slug_callback() {
        $settings = $this->get_settings();
        ?>
        <input type="text" name="wp_api_rate_limiter_settings[login_slug]" value="<?php echo esc_attr($settings['login_slug']); ?>" class="regular-text">
        <p class="description">Your site login will be available at: <?php echo esc_html(home_url('/')); ?><strong>[your-custom-slug]</strong></p>
        <p class="description"><strong>Important:</strong> Remember this URL! If you forget it, you'll need to access the database directly to reset the plugin.</p>
        <?php
    }
    
    public function redirect_to_callback() {
        $settings = $this->get_settings();
        $selected = $settings['redirect_to'];
        ?>
        <select name="wp_api_rate_limiter_settings[redirect_to]">
            <option value="home" <?php selected($selected, 'home'); ?>>Home Page</option>
            <option value="404" <?php selected($selected, '404'); ?>>404 Not Found</option>
        </select>
        <p class="description">Where to send users who try to access wp-login.php directly</p>
        <?php
    }
    
    // Render settings page
    public function render_settings_page() {
        if (!current_user_can('manage_options')) {
            return;
        }
        ?>
        <div class="wrap">
            <h1><?php echo esc_html(get_admin_page_title()); ?></h1>
            <form action="options.php" method="post">
                <?php
                settings_fields('wp_api_rate_limiter_group');
                do_settings_sections('wp-api-rate-limiter');
                submit_button('Save Settings');
                ?>
            </form>
            
            <hr>
            
            <h2>Usage Information</h2>
            <p>This plugin adds rate limiting to WordPress REST API endpoints. When a client exceeds the configured request limit, they will receive a 429 (Too Many Requests) response.</p>
            
            <h3>Headers</h3>
            <p>The plugin adds the following headers to API responses:</p>
            <ul>
                <li><code>X-RateLimit-Limit</code>: The maximum number of requests allowed in the current time window</li>
                <li><code>X-RateLimit-Remaining</code>: The number of requests remaining in the current time window</li>
                <li><code>X-RateLimit-Reset</code>: The time when the current rate limit window resets (Unix timestamp)</li>
            </ul>
            
            <h3>Testing the Rate Limiter</h3>
            <p>To test if rate limiting is working, make repeated requests to any REST API endpoint (e.g., <code>/wp-json/wp/v2/posts</code>) within your configured time window.</p>
            
            <?php if ($this->get_settings()['hide_login']): ?>
            <h3>Login URL</h3>
            <p>Your custom login URL is: <strong><a href="<?php echo esc_url(wp_login_url()); ?>" target="_blank"><?php echo esc_html(wp_login_url()); ?></a></strong></p>
            <p>Bookmark this URL or save it somewhere secure!</p>
            <?php endif; ?>
        </div>
        <?php
    }

    /**
     * Update htaccess with custom login rules
     * 
     * @param string $login_slug The custom login slug
     * @return bool True if successful, false if not
     */
    private function update_htaccess_rules($login_slug) {
        // Path to .htaccess file
        $htaccess_file = ABSPATH . '.htaccess';
        
        // Check if file exists and is writable
        require_once(ABSPATH . 'wp-admin/includes/file.php');
        WP_Filesystem();
        global $wp_filesystem;

        if (!$wp_filesystem || !$wp_filesystem->exists($htaccess_file) || !$wp_filesystem->is_writable($htaccess_file)) {
            return false;
        }
        
        // Get current content
        $htaccess_content = $wp_filesystem->get_contents($htaccess_file);
        
        // Define our markers
        $start_marker = '# BEGIN WP API Rate Limiter';
        $end_marker = '# END WP API Rate Limiter';
        
        // Remove existing rules if they exist
        if (strpos($htaccess_content, $start_marker) !== false) {
            $pattern = '/' . preg_quote($start_marker, '/') . '.*?' . preg_quote($end_marker, '/') . '\s*/s';
            $htaccess_content = preg_replace($pattern, '', $htaccess_content);
        }
        
        // Create new rules
        $new_rules = $start_marker . "\n";
        $new_rules .= "<IfModule mod_rewrite.c>\n";
        $new_rules .= "RewriteEngine On\n";
        
        // Custom login URL rules
        $new_rules .= "RewriteRule ^{$login_slug}/?$ index.php?custom_login=true [QSA,L]\n";
        $new_rules .= "RewriteRule ^{$login_slug}/([^/]+)/?$ index.php?custom_login=true&login_action=\$1 [QSA,L]\n";
        
        // Block wp-login.php with 403 Forbidden
        $new_rules .= "RewriteCond %{REQUEST_URI} ^/wp-login\.php [NC]\n";
        $new_rules .= "RewriteCond %{QUERY_STRING} !^action=logout [NC]\n";
        $new_rules .= "RewriteCond %{QUERY_STRING} !^action=lostpassword [NC]\n";
        $new_rules .= "RewriteCond %{QUERY_STRING} !^action=resetpass [NC]\n";
        $new_rules .= "RewriteCond %{HTTP_COOKIE} !wordpress_logged_in [NC]\n";
        $new_rules .= "RewriteRule .* - [F,L]\n";
        
        // Block wp-admin with 403 Forbidden
        $new_rules .= "RewriteCond %{REQUEST_URI} ^/wp-admin [NC]\n"; 
        $new_rules .= "RewriteCond %{REQUEST_URI} !^/wp-admin/admin-ajax\.php [NC]\n";
        $new_rules .= "RewriteCond %{REQUEST_URI} !^/wp-admin/load-(scripts|styles)\.php [NC]\n";
        $new_rules .= "RewriteCond %{HTTP_COOKIE} !wordpress_logged_in [NC]\n";
        $new_rules .= "RewriteRule .* - [F,L]\n";
        
        $new_rules .= "</IfModule>\n";
        $new_rules .= $end_marker . "\n";
        
        // Add rules to .htaccess
        $htaccess_content = $new_rules . $htaccess_content;
        
        // Write back to file
        return $wp_filesystem->put_contents($htaccess_file, $htaccess_content, FS_CHMOD_FILE);
    }

    /**
     * Filter the login form to use our custom login URL as the form action
     */
    public function filter_login_form_action() {
        $settings = $this->get_settings();
        $login_slug = sanitize_title($settings['login_slug']);
        
        // Get the site URL
        $site_url = site_url();
        
        // Replace wp-login.php in form action with our custom slug
        echo '<script type="text/javascript">
            document.addEventListener("DOMContentLoaded", function() {
                var loginForm = document.getElementById("loginform");
                if (loginForm) {
                    loginForm.action = loginForm.action.replace("' . $site_url . '/wp-login.php", "' . $site_url . '/' . $login_slug . '");
                }
                
                var lostpasswordForm = document.getElementById("lostpasswordform");
                if (lostpasswordForm) {
                    lostpasswordForm.action = lostpasswordForm.action.replace("' . $site_url . '/wp-login.php", "' . $site_url . '/' . $login_slug . '");
                }
                
                var registerForm = document.getElementById("registerform");
                if (registerForm) {
                    registerForm.action = registerForm.action.replace("' . $site_url . '/wp-login.php", "' . $site_url . '/' . $login_slug . '");
                }
            });
        </script>';
    }
}

// Initialize the plugin
WP_API_Rate_Limiter::get_instance();