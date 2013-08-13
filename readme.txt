=== WP Security Audit Log ===
Contributors: WPProHelp, WPWhiteSecurity
License: GPLv3
License URI: http://www.gnu.org/licenses/gpl.html
Tags: wordpress security plugin, wordpress security audit log, audit log, event log wordpress, wordpress user tracking, wordpress activity log, wordpress audit, security event log, audit trail, security audit trail
Requires at least: 3.0
Tested up to: 3.6
Stable tag: 0.2

Identify WordPress security issues before they become a problem. Keep an audit log of everything that happens on WordPress

== Description ==
Identify WordPress security issues before they become a problem by keeping an audit log of what is happening under the hood of your WordPress blog or website. This plugin is developed by WordPress Security Consultants and Specialists [WP White Security](http://www.wpwhitesecurity.com/wordpress-security-services/).

= Keep A WordPress Security Audit Log & Identify WordPress Security Issues =
WP Security Audit Log keeps track of everything that is happening on your WordPress blog or website. By using this WordPress security plugin it is very easy to track suspicious user activity before it becomes a problem. A security event is generated in each of the below cases:

* New user is created via registration or created by another user
* Existing user changes the role or password of another user
* User uploads a file, changes a password or email
* Failed login attempt
* and much more...

Refer to the complete list of [WordPress Security Audit Events](http://www.wpwhitesecurity.com/wordpress-security-plugins/wp-security-audit-log/security-audit-event-logs/) for more information.

= Monitor WordPress Users Activity & Productivity =
If you own a multi user WordPress blog or website you can use the WP Security Audit Log plugin to monitor your users' activity and productivity. With this WordPress security plugin you can monitor:

* When users logged in or out
* From where users are logging in
* Users who created or deleted categories
* Users who created a blog post or a page
* Users who published a blog post or a page
* Users who modified published WordPress content such as a page or a blog post
* and much more...

Refer to the complete list of [WordPress Security Audit Events](http://www.wpwhitesecurity.com/wordpress-security-plugins/wp-security-audit-log/security-audit-event-logs/) for more information.

= WordPress Audit Log in your Language! =
We need help translating the plugin and the WordPress Security Events. If you're good at translating, please drop us an email on plugins@wpwhitesecurity.com.

= WordPress Security Tips & Tricks =
Even if WordPress security is not your cup of tea, the security of your WordPress is your responsibility. Keep yourself up to date with the latest WordPress Security Tips & Tricks. WP White Security frequently publishes WordPress security tips & tricks on the [WordPress Security section](http://www.wpwhitesecurity.com/wordpress-security/) of their blog.


= Further Reading =
For more information and to get started with WordPress Security, check out the following:

* [Official WP Security Audit Log Page](http://www.wpwhitesecurity.com/wordpress-security-plugins/wp-security-audit-log/)
* [List of all WP Security Audit Log Events](http://www.wpwhitesecurity.com/wordpress-security-plugins/wp-security-audit-log/security-audit-event-logs/)
* [Recipe for ultimate WordPress Security](http://www.wpwhitesecurity.com/wordpress-security/recipe-ultimate-diy-wordpress-security/)

== Installation ==

1. Upload the `wordress-security-audit-log` folder to the `/wp-content/plugins/` directory
2. Activate the WP Security Audit Log plugin from the 'Plugins' menu in the WordPress Administration Screens
3. Access the Security audit logs and the plugin settings from the "Security Audit Log" menu that appears in your admin menu

== Frequently Asked Questions ==

= How can I prune WordPress security events? =

By default the plugin will keep up to 10,000 events. When this limit is reached, older events are deleted to make place for the new ones. You can configure the plugin to keep more events from the settings page. You can also configure the plugin to delete events which are older than a number of days.

= Is there a complete list of all WordPress security audit events? = 
Yes. A complete list can be found [here](http://www.wpwhitesecurity.com/wordpress-security-plugins/wp-security-audit-log/security-audit-event-logs/) 

== Screenshots ==

1. The Audit Log Viewer from where the WordPress administrator can see all the security events generated by WP Security Audit Log WordPress plugin.
2. The Auto Prune Security Events settings which the WordPress administrator can configure the auto deletion of security events.

== Changelog ==

= 0.2 =

* Restricted plugin options and WordPress Audit Log Event Viewer only to WordPress administrators
* Improved failed logins events (events generated from the same IP, or same username will be grouped to avoid mass flooding of security events)
* Security Events pruning now uses wp-cron functionality (improved stability and reliability of events pruning)
* Applied several performance improvements (faster loading of events etc)
* Added support for permalinks; now events will include page or blog post URL rather than ID
* Added new alerts for when a page or blog post status is changed from draft, pending review or published
* Added new alert for when a page or blog post URL or author is changed
* Added new alert for when a blog post category is changed
* Added new alerts for when a user creates or deletes a category
* Added new alert for when the author of a blog post or page is changed
* Added new plugin alerts for when a plugin is installed, uninstalled or upgraded
* Updated navigation menu to use standard WordPress dashboard icons etc

= 0.1 =

* Initial beta release of WP Security Audit Log.