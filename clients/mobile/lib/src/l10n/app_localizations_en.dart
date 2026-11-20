// ignore: unused_import
import 'package:intl/intl.dart' as intl;

import 'app_localizations.dart';

// ignore_for_file: type=lint

/// The translations for English (`en`).
class AppLocalizationsEn extends AppLocalizations {
  AppLocalizationsEn([String locale = 'en']) : super(locale);

  @override
  String get stateConnected => 'Connected';

  @override
  String get stateConnecting => 'Connecting…';

  @override
  String get stateDisconnected => 'Disconnected';

  @override
  String get stateError => 'Error';

  @override
  String get navHome => 'Home';

  @override
  String get navApps => 'Apps';

  @override
  String get navRules => 'Rules';

  @override
  String get navDns => 'DNS';

  @override
  String get navActivity => 'Activity';

  @override
  String get navStats => 'Statistics';

  @override
  String get navSettings => 'Settings';

  @override
  String get actionBack => 'Back';

  @override
  String get actionSave => 'Save';

  @override
  String get actionCancel => 'Cancel';

  @override
  String get actionDelete => 'Delete';

  @override
  String get actionAdd => 'Add';

  @override
  String get actionEdit => 'Edit';

  @override
  String get actionSearch => 'Search';

  @override
  String get actionClear => 'Clear';

  @override
  String get actionDone => 'Done';

  @override
  String get msgSaved => 'Saved. A new policy snapshot was issued.';

  @override
  String get msgForbidden => 'Your organization does not allow personal rules.';

  @override
  String msgError(String error) {
    return 'Error: $error';
  }

  @override
  String get companyPolicy => 'Company policy';

  @override
  String get companyPolicyLocked => 'Set by your company policy';

  @override
  String get verdictAllow => 'Allowed';

  @override
  String get verdictBlock => 'Blocked';

  @override
  String get verdictAsk => 'Ask cloud';

  @override
  String get actionAllow => 'Allow';

  @override
  String get actionBlock => 'Block';

  @override
  String get actionAsk => 'Ask';

  @override
  String get networkWifi => 'Wi-Fi';

  @override
  String get networkCellular => 'Mobile data';

  @override
  String get networkRoaming => 'Roaming';

  @override
  String get networkEthernet => 'Ethernet';

  @override
  String get networkUnknown => 'Unknown';

  @override
  String get emptyNothingHere => 'Nothing here yet';

  @override
  String get onboardingTitle => 'Enroll this device';

  @override
  String get onboardingSubtitle =>
      'Connect this device to your organization. All traffic is filtered on the device and protected by a quantum-safe tunnel.';

  @override
  String get onboardingControlUrl => 'Control Plane URL';

  @override
  String get onboardingControlUrlInvalid => 'The URL must start with https://';

  @override
  String get onboardingKey => 'Provisioning key';

  @override
  String get onboardingKeyHint => 'Provided by your administrator';

  @override
  String get onboardingDeviceName => 'Device name';

  @override
  String get onboardingEnroll => 'Enroll';

  @override
  String get onboardingEnrolling => 'Enrolling…';

  @override
  String onboardingFailed(String error) {
    return 'Enrollment failed: $error';
  }

  @override
  String get homeProtection => 'Protection';

  @override
  String get homeToggleOn => 'Your traffic is protected';

  @override
  String get homeToggleOff => 'Tap to connect';

  @override
  String get homeEdge => 'Edge';

  @override
  String get homeSnapshotVersion => 'Policy version';

  @override
  String get homeStale => 'The policy is out of date. It is still enforced, but it could not be refreshed.';

  @override
  String homeQuantumSafe(String kex) {
    return 'Quantum-safe: $kex';
  }

  @override
  String get homeToday => 'Today';

  @override
  String get homeAllowed => 'Allowed';

  @override
  String get homeBlocked => 'Blocked';

  @override
  String get homeDnsBlocked => 'DNS blocked';

  @override
  String get homeTopBlocked => 'Top blocked apps';

  @override
  String get homeNoBlocked => 'No blocked connections yet';

  @override
  String homeBlockedCount(int count) {
    return '$count blocked';
  }

  @override
  String homeFailed(String error) {
    return 'Could not connect: $error';
  }

  @override
  String get appsSearchHint => 'Search apps';

  @override
  String get appsFilterAll => 'All';

  @override
  String get appsFilterUser => 'User';

  @override
  String get appsFilterSystem => 'System';

  @override
  String get appsFilterInternet => 'With internet';

  @override
  String get appsLoading => 'Loading apps…';

  @override
  String get appsEmpty => 'No apps match the filter';

  @override
  String get appsUserRulesDisabled => 'Your organization manages app access. Toggles are read-only.';

  @override
  String get appDetailRecent => 'Recent connections';

  @override
  String get appDetailNoFlows => 'No connections recorded';

  @override
  String get appDetailBlockAll => 'Block all';

  @override
  String get appDetailAllowAll => 'Allow all';

  @override
  String get appDetailTraffic => 'Traffic';

  @override
  String get appDetailIn => 'Received';

  @override
  String get appDetailOut => 'Sent';

  @override
  String get appDetailAccess => 'Network access';

  @override
  String get originDefault => 'Default';

  @override
  String get originUser => 'Your setting';

  @override
  String get originLockdown => 'Lockdown';

  @override
  String get rulesTenant => 'Company policy';

  @override
  String get rulesTenantHint => 'Mandatory rules from your organization, evaluated first.';

  @override
  String get rulesUser => 'My rules';

  @override
  String get rulesUserHint => 'Evaluated after the company policy. Drag the handle to reorder.';

  @override
  String get rulesUserDisabled => 'Your organization does not allow personal rules.';

  @override
  String get rulesEmptyUser => 'No personal rules';

  @override
  String get rulesAdd => 'New rule';

  @override
  String get rulesEditTitle => 'Edit rule';

  @override
  String get rulesNewTitle => 'New rule';

  @override
  String get rulesFieldAction => 'Action';

  @override
  String get rulesFieldDescription => 'Description';

  @override
  String get rulesFieldProtocols => 'Protocols';

  @override
  String get rulesFieldCidrs => 'Destination IPs / CIDRs';

  @override
  String get rulesFieldCidrsHint => 'e.g. 10.0.0.0/8, 2001:db8::/32';

  @override
  String get rulesFieldPorts => 'Ports';

  @override
  String get rulesFieldPortsHint => 'e.g. 443, 8000-8100';

  @override
  String get rulesFieldDomains => 'Domains';

  @override
  String get rulesFieldDomainsHint => 'e.g. example.com, *.ads.example';

  @override
  String get rulesFieldNetworks => 'Networks';

  @override
  String get rulesFieldApps => 'Apps';

  @override
  String get rulesFieldAppsAny => 'Any app';

  @override
  String get rulesFieldAppsChoose => 'Choose apps';

  @override
  String get rulesFieldLog => 'Log matching connections';

  @override
  String get rulesFieldPriority => 'Priority';

  @override
  String get rulesFieldPriorityHint => 'Lower runs first';

  @override
  String get rulesErrorCidrs => 'Invalid IP or CIDR';

  @override
  String get rulesErrorPorts => 'Invalid port or range';

  @override
  String get rulesErrorDomains => 'Invalid domain';

  @override
  String get rulesErrorPriority => 'Must be a number';

  @override
  String get rulesErrorEmpty => 'Add at least one condition';

  @override
  String get rulesAny => 'Any traffic';

  @override
  String rulesPriorityShort(int priority) {
    return '#$priority';
  }

  @override
  String get rulesLogged => 'Logged';

  @override
  String get rulesDeleteConfirm => 'Delete this rule?';

  @override
  String get dnsBlocklists => 'Blocklists';

  @override
  String get dnsBlocklistsHint => 'Managed by your organization';

  @override
  String dnsDomainCount(int count) {
    return '$count domains';
  }

  @override
  String dnsBlockResponse(String response) {
    return 'Blocked queries answer with $response';
  }

  @override
  String get dnsTenantDomains => 'Company domain rules';

  @override
  String get dnsCustom => 'My domains';

  @override
  String get dnsCustomHint => 'Saved as personal rules matching only the domain';

  @override
  String get dnsAddHint => 'example.com or *.example.com';

  @override
  String get dnsAddBlock => 'Block';

  @override
  String get dnsAddAllow => 'Allow';

  @override
  String get dnsInvalid => 'Invalid domain';

  @override
  String get dnsEmpty => 'No custom domains';

  @override
  String dnsBlockedToday(int count) {
    return '$count DNS queries blocked today';
  }

  @override
  String get activityPause => 'Pause';

  @override
  String get activityResume => 'Resume';

  @override
  String get activityFilterAll => 'All';

  @override
  String get activityFilterAllowed => 'Allowed';

  @override
  String get activityFilterBlocked => 'Blocked';

  @override
  String get activityFilterApp => 'App';

  @override
  String get activityAllApps => 'All apps';

  @override
  String get activityEmpty => 'No connections yet. Connect to see live traffic.';

  @override
  String get activityPaused => 'Paused';

  @override
  String activityRule(String layer, String rule) {
    return '$layer · $rule';
  }

  @override
  String get layerTenant => 'company';

  @override
  String get layerUser => 'my rule';

  @override
  String get layerApp => 'app';

  @override
  String get layerDefault => 'default';

  @override
  String get layerLockdown => 'lockdown';

  @override
  String get layerCloud => 'cloud';

  @override
  String get layerDns => 'DNS';

  @override
  String get statsSort => 'Sort by';

  @override
  String get statsSortTotal => 'Total';

  @override
  String get statsSortIn => 'Received';

  @override
  String get statsSortOut => 'Sent';

  @override
  String get statsSortAllowed => 'Allowed';

  @override
  String get statsSortBlocked => 'Blocked';

  @override
  String statsTotal(String received, String sent) {
    return '↓ $received · ↑ $sent';
  }

  @override
  String statsCounts(int allowed, int blocked) {
    return '$allowed allowed · $blocked blocked';
  }

  @override
  String get statsEmpty => 'No traffic recorded yet';

  @override
  String get settingsAlwaysOn => 'Always-on VPN';

  @override
  String get settingsAlwaysOnDesc =>
      'For the strongest protection, open the system VPN settings, tap the gear next to OpenSASE and enable “Always-on VPN” and “Block connections without VPN”.';

  @override
  String get settingsOpenVpnSettings => 'Open VPN settings';

  @override
  String get settingsConnectOnBoot => 'Reconnect after restart';

  @override
  String get settingsConnectOnBootDesc => 'Used only when always-on VPN is off';

  @override
  String get settingsPolicy => 'Policy';

  @override
  String get settingsDefaultAction => 'Default for unknown apps';

  @override
  String get settingsLockdown => 'Lockdown mode';

  @override
  String get settingsLockdownOn => 'On: only allowlisted apps can connect';

  @override
  String get settingsLockdownOff => 'Off';

  @override
  String get settingsUserRules => 'Personal rules';

  @override
  String get settingsUserRulesAllowed => 'Allowed by your organization';

  @override
  String get settingsUserRulesDenied => 'Not allowed by your organization';

  @override
  String get settingsSnapshot => 'Policy snapshot';

  @override
  String settingsSnapshotValue(int version, String expires) {
    return 'Version $version · expires $expires';
  }

  @override
  String get settingsDevice => 'Device';

  @override
  String get settingsExportLogs => 'Export connection log';

  @override
  String get settingsExportLogsDesc => 'Save the recent connections as JSON';

  @override
  String get settingsExportDone => 'Log exported';

  @override
  String get settingsUnenroll => 'Unenroll device';

  @override
  String get settingsUnenrollDesc => 'Removes the device certificate and keys from this phone';

  @override
  String get settingsUnenrollConfirm => 'Unenroll this device? You will need a new provisioning key to enroll again.';

  @override
  String get settingsAbout => 'About';

  @override
  String settingsVersion(String version, String engine) {
    return 'Version $version · engine $engine';
  }

  @override
  String get settingsLicenses => 'Open-source licences';

  @override
  String get settingsLicensesText =>
      'OpenSASE uses Flutter, Material and the Dart SDK (BSD 3-Clause), Riverpod, go_router and json_serializable (MIT / BSD 3-Clause), AndroidX and Kotlin (Apache License 2.0), the Go standard library (BSD 3-Clause) and wireguard-go (MIT). No analytics or Google Play Services are included. Tap for the full list.';

  @override
  String get settingsAppearance => 'Appearance';

  @override
  String get engineFake => 'Demo engine (fake data)';

  @override
  String get engineNative => 'Native engine';

  @override
  String appDetailUid(int uid) {
    return 'UID $uid';
  }

  @override
  String get onboardingCode => 'Enrollment code';

  @override
  String get onboardingCodeHint => 'Paste the code from your administrator (URL and key)';

  @override
  String get onboardingCodeInvalid => 'Not a valid enrollment code';

  @override
  String get onboardingPinned => 'Server certificate pinned (sha256)';

  @override
  String get onboardingScan => 'Scan QR code';

  @override
  String get onboardingScanSoon => 'QR scanning is coming soon. Paste the code instead.';

  @override
  String get onboardingOr => 'or enter the details';

  @override
  String get settingsEngine => 'Engine';

  @override
  String get homeLastHandshake => 'Last handshake';

  @override
  String get homeNetwork => 'Network';

  @override
  String get rulesOrderSaved => 'Rule order saved';

  @override
  String get activityLive => 'Live';

  @override
  String statsDns(int queries, int blocked) {
    return 'DNS $queries queries · $blocked blocked';
  }

  @override
  String get vpnConsentDenied => 'VPN permission was denied';

  @override
  String get settingsCertificate => 'Device certificate';

  @override
  String settingsCertificateExpires(String date) {
    return 'Expires $date';
  }

  @override
  String get onboardingCodeApplied => 'Code applied: check the details below and tap Enroll';
}
