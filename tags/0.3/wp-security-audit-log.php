<?php
/*
Plugin Name: WP Security Audit Log
Plugin URI: http://www.wpwhitesecurity.com/wordpress-security-plugins/wp-security-audit-log/
Description: Identify WordPress security issues before they become a problem and keep track of everything happening on your WordPress, including WordPress users activity. Similar to Windows Event Log and Linux Syslog, WP Security Audit Log will generate a security alert for everything that happens on your WordPress blog or website. Use the Audit Log Viewer included in the plugin to see all the security alerts.
Author: WP White Security
Version: 0.3
Author URI: http://www.wpwhitesecurity.com/
License: GPL2

    WP Security Audit Log
    Copyright(c) 2013  Robert Abela  (email : robert@wpwhitesecurity.com)

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License, version 2, as
    published by the Free Software Foundation.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
*/
//#! Holds the plugin option name
define('WPPH_PLUGIN_VERSION','0.3');
define('WPPH_PLUGIN_VERSION_OPTION_NAME','WPPH_PLUGIN_VERSION');
define('WPPH_PLUGIN_ERROR_OPTION_NAME','WPPH_PLUGIN_ERROR');
define('WPPH_PLUGIN_SETTING_NAME', 'wpph_plugin_settings');
define('WPPH_PLUGIN_PREFIX', 'wpph_');
define('WPPH_PLUGIN_NAME', 'WP Security Audit Log');
define('WPPH_PLUGIN_URL', trailingslashit(plugins_url('', __FILE__)));
define('WPPH_PLUGIN_DIR', trailingslashit(plugin_dir_path(__FILE__)));
if(defined('__DIR__')) { define('WPPH_PLUGIN_BASE_NAME', basename(__DIR__)); }
else { define('WPPH_PLUGIN_BASE_NAME', basename(dirname(__FILE__))); }
define('WPPH_PLUGIN_DB_UPDATED', 'WPPH_PLUGIN_DB_UPDATED');
define('WPPH_PLUGIN_DEL_EVENTS_CRON_TASK_NAME', 'wpph_plugin_delete_events_cron');
/** @since v0.3 */
define('WPPH_USERS_CAN_REGISTER_OPT_NAME', 'wpph_users_can_register');
/**
 * @since v0.3
 * @see WPPH::onPluginActivate()
 */
$GLOBALS['WPPH_CAN_RUN'] = true;


//#! Load required files
require('inc/WPPHLogger.php');
require('inc/WPPHUtil.php');
require('inc/WPPHAdminNotices.php');
require('inc/WPPHDatabase.php');
require('inc/WPPHEvent.php');
require('inc/WPPH.php');
require('inc/wpphFunctions.php');


//#! 2000
$GLOBALS['WPPH_POST_IS_NEW'] = false;
add_action('wp_insert_post', 'wpphPostDetectNew', 1, 2);
function wpphPostDetectNew($post, $wp_error = false){
    wpphLog(__FUNCTION__.' triggered by hook: WP_INSERT_POST');
    if(isset($_POST['post_id'])){
        $GLOBALS['WPPH_POST_IS_NEW'] = true;
        wpphLog('POST IS NEW');
    }
}

/**
 * triggered when the plugin is uninstalled (with option files delete: true)
 */
function onPluginUninstall()
{
    if(WPPH::optionExists(WPPH_PLUGIN_DB_UPDATED)){ delete_option(WPPH_PLUGIN_DB_UPDATED); }
    if(WPPH::optionExists(WPPH_PLUGIN_VERSION_OPTION_NAME)){ delete_option(WPPH_PLUGIN_VERSION_OPTION_NAME); }
    if(WPPH::optionExists(WPPH_USERS_CAN_REGISTER_OPT_NAME)){ delete_option(WPPH_USERS_CAN_REGISTER_OPT_NAME); }
    global $wpdb;
    $wpdb->query("DROP TABLE IF EXISTS ".WPPHDatabase::getFullTableName('main'));
    $wpdb->query("DROP TABLE IF EXISTS ".WPPHDatabase::getFullTableName('events'));
}
//#! register callbacks
register_activation_hook( __FILE__, array('WPPH', 'onPluginActivate') );
register_deactivation_hook( __FILE__, array('WPPH', 'onPluginDeactivate') );
register_uninstall_hook( __FILE__, 'onPluginUninstall' );

// Add custom links on plugins page
function wpphCustomLinks($links) {
    return array_merge(array('<a href="admin.php?page=wpph_">Audit Log Viewer </a>', '<a href="admin.php?page=wpph_settings">'.__('Settings').'</a>'), $links);
}
add_filter("plugin_action_links_".plugin_basename(__FILE__), 'wpphCustomLinks' );

// $GLOBALS['WPPH_CAN_RUN']
// @since v0.3
// @see WPPH::onPluginActivate()
if($GLOBALS['WPPH_CAN_RUN'])
{
//#! Load the pluggable.php file if needed
    add_action('admin_init', array('WPPHUtil','loadPluggable'));

//#! Load resources
    add_action('admin_init', array('WPPH', 'loadBaseResources'));

//#! Add the sidebar menu
    add_action('admin_menu', array('WPPH', 'createPluginWpSidebar'));

//#! Plugin init
    add_action('init', 'wpphPluginInit');
    function wpphPluginInit()
    {
        if(is_admin())
        {
            if(isset($_POST)){
                //# 6001, 6002, 6003
                WPPHEvent::hookCheckWpGeneralSettings();
                if(isset($_POST['action']) && $_POST['action'] == 'editpost'){ $GLOBALS['WPPH_DEFAULT_EDITOR_ENABLED'] = true; }
                elseif(isset($_POST['screen']) && ($_POST['screen'] == 'edit-post' || $_POST['screen'] == 'edit-page') ){ $GLOBALS['WPPH_SCREEN_EDITOR_ENABLED'] = true;  wpphLog('WPPH_SCREEN_EDITOR_ENABLED');}
            }
            WPPHEvent::hookWatchPostStateBefore();
            WPPHEvent::hookWatchBlogActivity();
            WPPHEvent::hookWatchCategoryAdd();
            WPPHEvent::hookWatchCategoryDelete();
            WPPHEvent::hookFileDeletion();
            WPPHEvent::hookFileUploaded();
            WPPHEvent::hookFileUploadedDeleted();
            WPPHEvent::hookTrashPost();
            WPPHEvent::hookTrashPage();
            WPPHEvent::hookUntrashedPosts();
            WPPHEvent::hookUntrashedPages();
            WPPHEvent::hookThemeChange();
            WPPHEvent::hookUserRoleUpdated();
            WPPHEvent::hookUserPasswordUpdated();
            WPPHEvent::hookUserEmailUpdated();
            WPPHEvent::hookUserDeletion();
            WPPHEvent::hookEventsDeletion();
            WPPHEvent::hookWatchPluginActivity();
            /* Enable ajax functionality in the dashboard page */
            add_action('wp_ajax_wpph_get_events', array('WPPHUtil','get_events_html'));
        }
        WPPHEvent::hookLoginEvent();
        WPPHEvent::hookLogoutEvent();
        WPPHEvent::hookLoginFailure();
        WPPHEvent::hookUserRegisterEvent();
    }
}
//#! End wp-security-audit-log