<?php

class WSAL_Views_About extends WSAL_AbstractView {
	
	public function GetTitle() {
		return __('About WP Security Audit Log', 'wp-security-audit-log');
	}
	
	public function GetIcon() {
		return 'dashicons-editor-help';
	}
	
	public function GetName() {
		return __('About', 'wp-security-audit-log');
	}
	
	public function GetWeight(){
		return 4;
	}
	
	public function Render(){
		?><div class="metabox-holder" style="position: relative;">
		
			<div class="postbox" style="margin-right: 270px;">
				<!--h3 class="hndl"><span>About WP Security Audit Log</span></h3-->
				<div class="inside">
					<div class="activity-block">
						WP Security Audit Log enables WordPress administrators and owners to identify WordPress security issues before they become a security problem by keeping a security audit log. WP Security Audit Log is developed by WordPress security professionals WP White Security.
						
						<h2>Keep A WordPress Security Audit Log & Identify WordPress Security Issues</h2>
						<p>
							WP Security Audit Log logs everything happening on your WordPress blog or website and WordPress multisite network. By using WP Security Audit Log security plugin it is very easy to track suspicious user activity before it becomes a problem or a security issue. A WordPress security alert is generated by the plugin when:
						</p>
						<ul style="list-style-type: disc; margin-left: 2.5em; list-style-position: outside;">
							<li>User creates a new user or a new user is registered</li>
							<li>Existing user changes the role, password or other properties of another user</li>
							<li>Existing user on a WordPress multisite network is added to a site</li>
							<li>User uploads or deletes a file, changes a password or email address</li>
							<li>User installs, activates, deactivates, upgrades or uninstalls a plugin</li>
							<li>User creates, modifies or deletes a new post, page, category or a custom post type</li>
							<li>User installs or activates a WordPress theme</li>
							<li>User adds, modifies or deletes a widget</li>
							<li>User uses the dashboard file editor</li>
							<li>WordPress settings are changed</li>
							<li>Failed login attempts</li>
							<li>and much more&hellip;</li>
						</ul>
						<br/>
						Refer to the complete list of <a href="http://www.wpwhitesecurity.com/wordpress-security-plugins/wp-security-audit-log/security-audit-alerts-logs/?utm_source=wpsalabt&utm_medium=txtlink&utm_campaign=wpsal" target="_blank">WordPress Security Alerts</a> for more information.
					</div>
				</div>
			</div>
			
			<div style="position: absolute; right: 70px; width: 180px; top: 10px;">
				<div class="postbox">
					<h3 class="hndl"><span>WP Password Policy Manager</span></h3>
					<div class="inside">
						<p>
							Easily configure WordPress password policies and ensure users use strong passwords with our plugin WP Password Policy Manager.
						</p>
						<a class="button button-primary" href="http://wordpress.org/plugins/wp-password-policy-manager/" target="_blank">Download</a>
					</div>
				</div>
				<div class="postbox">
					<h3 class="hndl"><span>WP Security Audit Log in your Language!</span></h3>
					<div class="inside">
						If you are interested in translating our plugin please drop us an email on
						<a href="mailto:plugins@wpwhitesecurity.com">plugins@wpwhitesecurity.com</a>.
					</div>
				</div>
				<div class="postbox">
					<h3 class="hndl"><span>WordPress Security Services</span></h3>
					<div class="inside">
						Professional WordPress security services provided by WP White Security
						<ul>
							<li><a href="http://www.wpwhitesecurity.com/wordpress-security-services/wordpress-security-hardening/?utm_source=wpsalabt&utm_medium=txtlink&utm_campaign=wpsal" target="_blank">Security Hardening</a></li>
							<li><a href="http://www.wpwhitesecurity.com/wordpress-security-services/wordpress-security-audit/?utm_source=wpsalabt&utm_medium=txtlink&utm_campaign=wpsal" target="_blank">Security Audit</a></li>
							<li><a href="http://www.wpwhitesecurity.com/wordpress-security-services/wordpress-hacker-attack-malware-virus-removal-services/?utm_source=wpsalabt&utm_medium=txtlink&utm_campaign=wpsal" target="_blank">Hack Cleanup</a></li>
							<li><a href="http://www.wpwhitesecurity.com/wordpress-security-services/wordpress-plugins-security-code-audit-review/?utm_source=wpsalabt&utm_medium=txtlink&utm_campaign=wpsal" target="_blank">Plugin Security Code Audit</a></li>
						</ul>
					</div>
				</div>
			</div>
		</div><?php
	}
	
}