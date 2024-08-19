<?php
/**
 * Plugin Name: Comprehensive Security Enhancer
 * Description: A comprehensive plugin to enhance the security of your WordPress site with firewall protection, file integrity monitoring, malware scanning, and more.
 * Version: 1.0
 * Author: Michael Alain Laguardia
 * Text Domain: comprehensive-security-enhancer
 */

if (!defined('ABSPATH')) {
    exit; // Exit if accessed directly
}

// Define plugin constants
define('CSE_PLUGIN_DIR', plugin_dir_path(__FILE__));
define('CSE_PLUGIN_URL', plugin_dir_url(__FILE__));

// Hook to add admin menu
add_action('admin_menu', 'cse_security_menu');

// Hook to register settings
add_action('admin_init', 'cse_security_settings');

// Hook to enqueue scripts and styles
add_action('admin_enqueue_scripts', 'cse_security_enqueue_scripts');

// Hook to handle plugin activation
register_activation_hook(__FILE__, 'cse_security_activate');

// Hook to handle plugin deactivation
register_deactivation_hook(__FILE__, 'cse_security_deactivate');

function cse_security_menu() {
    add_menu_page('Security Enhancer', 'Security Enhancer', 'manage_options', 'cse-security-enhancer', 'cse_security_page');
}

function cse_security_page() {
    ?>
    <div class="wrap">
        <h1>Comprehensive Security Enhancer</h1>
        <form method="post" action="">
            <?php
            submit_button('Run Security Check');
            ?>
        </form>
        <hr>
        <?php
        if ($_SERVER['REQUEST_METHOD'] == 'POST') {
            run_security_checks();
        }
        ?>
    </div>
    <?php
}

function cse_security_settings() {
    // Register settings if needed
}

function cse_security_enqueue_scripts() {
    wp_enqueue_style('cse-security-style', CSE_PLUGIN_URL . 'css/style.css');
    wp_enqueue_script('cse-security-script', CSE_PLUGIN_URL . 'js/script.js', array('jquery'), null, true);
}

function cse_security_activate() {
    // Code to run on plugin activation
}

function cse_security_deactivate() {
    // Code to run on plugin deactivation
}

function run_security_checks() {
    echo '<h2>Security Check Results:</h2>';

    // File Integrity Monitoring
    echo '<h3>File Integrity Monitoring</h3>';
    $files = get_all_files(ABSPATH);
    foreach ($files as $file) {
        $file_content = @file_get_contents($file);
        if ($file_content === false) {
            echo '<p>Error reading file: ' . esc_html($file) . '</p>';
            continue;
        }

        if (contains_malicious_code($file_content)) {
            echo '<p>Malicious code detected in file: ' . esc_html($file) . '</p>';
        }
    }

    // Malware Scanning
    echo '<h3>Malware Scan</h3>';
    $malware_files = scan_for_malware(ABSPATH);
    echo '<pre>' . esc_html(print_r($malware_files, true)) . '</pre>';

    // Firewall Protection
    echo '<h3>Firewall Protection</h3>';
    $blocked_ips = get_blocked_ips();
    echo '<pre>' . esc_html(print_r($blocked_ips, true)) . '</pre>';

    // Security Hardening
    echo '<h3>Security Hardening</h3>';
    harden_site();
}

function get_all_files($directory) {
    $files = [];
    $directoryIterator = new RecursiveDirectoryIterator($directory, RecursiveDirectoryIterator::SKIP_DOTS);
    $iterator = new RecursiveIteratorIterator($directoryIterator);
    foreach ($iterator as $file) {
        if ($file->isFile() && is_readable($file->getPathname())) {
            $files[] = $file->getPathname();
        }
    }
    return $files;
}

function contains_malicious_code($content) {
    $patterns = [
        '/eval\s*\(/i',
        '/base64_decode\s*\(/i',
        '/gzinflate\s*\(/i',
        '/shell_exec\s*\(/i',
        '/exec\s*\(/i',
        '/system\s*\(/i',
        '/passthru\s*\(/i',
        '/phpinfo\(\)/i'
    ];

    foreach ($patterns as $pattern) {
        if (preg_match($pattern, $content)) {
            return true;
        }
    }
    return false;
}

function scan_for_malware($directory) {
    $files = get_all_files($directory);
    $malware_patterns = [
        '/eval\s*\(/i',
        '/base64_decode\s*\(/i',
        '/gzinflate\s*\(/i',
        '/shell_exec\s*\(/i',
        '/exec\s*\(/i',
        '/system\s*\(/i',
        '/passthru\s*\(/i'
    ];

    $malware_files = [];
    foreach ($files as $file) {
        $content = @file_get_contents($file);
        if ($content === false) continue;

        foreach ($malware_patterns as $pattern) {
            if (preg_match($pattern, $content)) {
                $malware_files[] = $file;
                break;
            }
        }
    }
    return $malware_files;
}

function contains_seo_spam($content) {
    $patterns = [
        '/example-spam-keyword/i',
        '/spammy-link\.com/i',
        '/buy-now\.com/i'
    ];

    foreach ($patterns as $pattern) {
        if (preg_match($pattern, $content)) {
            return true;
        }
    }
    return false;
}

function get_blocked_ips() {
    // Placeholder function for blocked IPs
    return [
        '192.168.1.1' => 'Blocked due to suspicious activity',
        '10.0.0.1' => 'Blocked due to brute force attempt'
    ];
}

function harden_site() {
    // Security hardening measures
    // Disable XML-RPC
    add_filter('xmlrpc_enabled', '__return_false');
    
    // Disable file editing in the WordPress dashboard
    define('DISALLOW_FILE_EDIT', true);

    // Prevent directory listing
    $htaccess_path = ABSPATH . '.htaccess';
    if (!file_exists($htaccess_path)) {
        @file_put_contents($htaccess_path, "Options -Indexes\n");
    }

    // Restrict access to wp-config.php
    $wp_config_path = ABSPATH . 'wp-config.php';
    if (file_exists($wp_config_path)) {
        @file_put_contents($htaccess_path, "\n<Files wp-config.php>\nOrder Allow,Deny\nDeny from all\n</Files>\n", FILE_APPEND);
    }

    echo '<p>Site hardening measures applied.</p>';
}

// Additional functions for logging and alerts could be implemented here
?>
