// ignore: unused_import
import 'package:intl/intl.dart' as intl;

import 'app_localizations.dart';

// ignore_for_file: type=lint

/// The translations for English (`en`).
class AppLocalizationsEn extends AppLocalizations {
  AppLocalizationsEn([String locale = 'en']) : super(locale);

  @override
  String get appTitle => 'OpenSASE Admin';

  @override
  String get navOverview => 'Overview';

  @override
  String get navTenants => 'Tenants';

  @override
  String get navUsers => 'Users';

  @override
  String get navPolicy => 'Policy';

  @override
  String get navPrivateApps => 'Private apps';

  @override
  String get navConnectors => 'Connectors';

  @override
  String get navDevices => 'Devices';

  @override
  String get navEdges => 'Edges';

  @override
  String get navActivity => 'Activity';

  @override
  String get navSettings => 'Settings';

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
  String get actionCreate => 'Create';

  @override
  String get actionRevoke => 'Revoke';

  @override
  String get actionRefresh => 'Refresh';

  @override
  String get actionReload => 'Discard changes';

  @override
  String get actionClose => 'Close';

  @override
  String get actionCopy => 'Copy';

  @override
  String get actionLogout => 'Sign out';

  @override
  String get actionMoveUp => 'Move up';

  @override
  String get actionMoveDown => 'Move down';

  @override
  String get msgCopied => 'Copied to the clipboard';

  @override
  String get msgSaved => 'Saved. Device snapshots are being recompiled.';

  @override
  String msgError(String error) {
    return 'Error: $error';
  }

  @override
  String get msgSessionExpired => 'The admin token was rejected. Sign in again.';

  @override
  String get emptyNothingHere => 'Nothing here yet';

  @override
  String get emptyNoTenant => 'Create or select a tenant first.';

  @override
  String get tenantPicker => 'Tenant';

  @override
  String get loginTitle => 'OpenSASE administration';

  @override
  String get loginSubtitle => 'Paste the admin token of this Control Plane.';

  @override
  String get loginToken => 'Admin token';

  @override
  String get loginRemember => 'Remember for this tab';

  @override
  String get loginRememberHint =>
      'Kept in this tab\'s session storage until the tab is closed. Otherwise the token stays in memory only.';

  @override
  String get loginSubmit => 'Sign in';

  @override
  String loginFailed(String error) {
    return 'Sign-in failed: $error';
  }

  @override
  String get loginTokenRequired => 'Enter the admin token';

  @override
  String get fieldId => 'ID';

  @override
  String get fieldIdOptional => 'ID (optional, generated if empty)';

  @override
  String get fieldName => 'Name';

  @override
  String get fieldEmail => 'Email';

  @override
  String get fieldGroup => 'Group';

  @override
  String get fieldUser => 'User';

  @override
  String get fieldPlatform => 'Platform';

  @override
  String get fieldCreated => 'Created';

  @override
  String get fieldLastSeen => 'Last seen';

  @override
  String get fieldStatus => 'Status';

  @override
  String get fieldInvalidId => 'Letters, digits, \'.\', \'_\' and \'-\'; must start with a letter or digit';

  @override
  String get fieldRequired => 'Required';

  @override
  String get statusRevoked => 'Revoked';

  @override
  String get statusActive => 'Active';

  @override
  String get statusOnline => 'Online';

  @override
  String get statusOffline => 'Offline';

  @override
  String get never => 'never';

  @override
  String get tenantsCreate => 'New tenant';

  @override
  String get usersCreate => 'New user';

  @override
  String get usersProvisioningKey => 'Provisioning key';

  @override
  String provTitle(String user) {
    return 'Provisioning key for $user';
  }

  @override
  String get provMaxUses => 'Max uses';

  @override
  String get provValidHours => 'Valid for (hours)';

  @override
  String get provGenerate => 'Generate';

  @override
  String get provShownOnce => 'This key is shown only once. Copy it or let the user scan the QR code now.';

  @override
  String provExpires(String time) {
    return 'Expires $time';
  }

  @override
  String get provNoControlUrl => 'Set the control URL with its #sha256= pin in Settings to show an enrollment QR code.';

  @override
  String get provScan => 'Scan with the OpenSASE app to enroll';

  @override
  String get provLink => 'Enrollment link';

  @override
  String get settingsControlUrl => 'Control URL for enrollment';

  @override
  String get settingsControlUrlHint => 'https://cp.example.com:9443#sha256=<root CA SHA-256>';

  @override
  String get settingsControlUrlHelp =>
      'Put into enrollment QR codes. The #sha256= fragment pins the provider root CA (opensasectl prints it).';

  @override
  String get settingsUseOrigin => 'Use this origin';

  @override
  String get settingsTokenInfo =>
      'The admin token is held in memory, and in this tab\'s session storage only if you chose so at sign-in. It is never written to local storage.';

  @override
  String get policyTabForm => 'Form';

  @override
  String get policyTabJson => 'JSON';

  @override
  String get policyGeneral => 'General';

  @override
  String get policyDefaultAction => 'Default action';

  @override
  String get policyNotSet => 'Not set (server default)';

  @override
  String get policyAllowUserRules => 'Allow user rules';

  @override
  String get policyAllowUserRulesHelp => 'Users may add personal rules and per-app policies below the tenant layer.';

  @override
  String get policyLockdown => 'Lockdown';

  @override
  String get policyLockdownHelp => 'Apps without a tenant app policy are blocked; user rules can only block.';

  @override
  String get policyRules => 'Tenant rules';

  @override
  String get policyRulesHelp =>
      'Evaluated by priority, lowest first; the first match wins. All filled match fields must match.';

  @override
  String get policyApps => 'Per-app policies';

  @override
  String get policyAppsHelp => 'Mandatory verdicts per Android package and network.';

  @override
  String get policyDns => 'DNS';

  @override
  String get policyBlockResponse => 'Block response';

  @override
  String get policyBlocklists => 'Blocklists';

  @override
  String get policyAllowDomains => 'Allowed domains (override blocklists)';

  @override
  String get policyBlockDomains => 'Blocked domains';

  @override
  String get policyDecide => 'Cloud decisions (ask)';

  @override
  String get policyDecideDefault => 'Decide default';

  @override
  String get policyDecideBlockDomains => 'Domains blocked by the cloud';

  @override
  String get policyDecideBlockCidrs => 'CIDRs blocked by the cloud';

  @override
  String get policyOnePerLine => 'One per line; \"*.example.com\" also matches example.com';

  @override
  String policyJsonInvalid(String error) {
    return 'Invalid JSON: $error';
  }

  @override
  String get policyJsonLocked => 'The JSON tab has an error. Fix it to edit the form.';

  @override
  String get policyIssues => 'Fix these problems before saving:';

  @override
  String policyServerError(String error) {
    return 'The Control Plane rejected the policy: $error';
  }

  @override
  String get policyUnsaved => 'Unsaved changes';

  @override
  String get ruleNew => 'New rule';

  @override
  String get ruleEdit => 'Edit rule';

  @override
  String get rulePriority => 'Priority';

  @override
  String get ruleAction => 'Action';

  @override
  String get ruleLog => 'Log matching flows';

  @override
  String get ruleDescription => 'Description';

  @override
  String get ruleMatch => 'Match';

  @override
  String get ruleMatchAny => 'any';

  @override
  String get matchApps => 'Apps (package names)';

  @override
  String get matchNetworks => 'Networks';

  @override
  String get matchProtocols => 'Protocols';

  @override
  String get matchCidrs => 'Destination CIDRs';

  @override
  String get matchPorts => 'Destination ports';

  @override
  String get matchPortsHint => '443, 8000-8080';

  @override
  String get matchDomains => 'Domains';

  @override
  String get appPackage => 'Package name';

  @override
  String get appNew => 'New app policy';

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
  String get actionAllow => 'Allow';

  @override
  String get actionBlock => 'Block';

  @override
  String get actionAsk => 'Ask cloud';

  @override
  String get actionUnset => 'Not set';

  @override
  String get blocklistNew => 'New blocklist';

  @override
  String get blocklistCategory => 'Category';

  @override
  String blocklistDomainsCount(int count) {
    return '$count domains';
  }

  @override
  String get privateAppsHelp =>
      'Private apps are reachable by name only, through a Connector group (ZTNA). Saving updates the tenant policy.';

  @override
  String get privateAppNew => 'New private app';

  @override
  String get privateAppEdit => 'Edit private app';

  @override
  String get privateAppPorts => 'TCP ports';

  @override
  String get privateAppConnectorGroup => 'Connector group';

  @override
  String get privateAppUsers => 'Users (IDs or emails; empty = every user)';

  @override
  String get privateAppEveryone => 'everyone';

  @override
  String get connectorsCreate => 'New Connector';

  @override
  String connectorsCreated(String name) {
    return 'Connector $name created';
  }

  @override
  String get connectorsKeyHelp =>
      'Single-use key, valid 24 hours. Pass it to opensase-connector -key at its first start.';

  @override
  String get connectorsGroupHint => 'default';

  @override
  String revokeConfirmTitle(String name) {
    return 'Revoke $name?';
  }

  @override
  String get revokeConfirmConnector =>
      'The connector\'s certificate stops working on the next Edge sync (about 10 seconds). This cannot be undone.';

  @override
  String get revokeConfirmDevice => 'The device loses access and must enroll again. This cannot be undone.';

  @override
  String get revokeConfirmEdge =>
      'The Edge is refused by the Control Plane; its ID cannot be reused. This cannot be undone.';

  @override
  String get edgesCreate => 'Register Edge';

  @override
  String get edgesCreateHelp => 'Register the Edge ID before starting the Edge with its certificate.';

  @override
  String get edgesFieldTenant => 'Tenant (Private Edge)';

  @override
  String get edgesFieldTenantHelp =>
      'Optional. Binds the Edge to one tenant; leave empty for a public multi-tenant Edge.';

  @override
  String get edgesPublic => 'public';

  @override
  String get flowsVerdict => 'Verdict';

  @override
  String get flowsLayer => 'Layer';

  @override
  String get flowsWhere => 'Where';

  @override
  String get flowsDevice => 'Device';

  @override
  String get flowsSearch => 'Search domain, IP, port, app, rule';

  @override
  String get flowsAny => 'Any';

  @override
  String get flowsAutoRefresh => 'Auto refresh (10 s)';

  @override
  String get flowsTime => 'Time';

  @override
  String get flowsDestination => 'Destination';

  @override
  String get flowsApp => 'App';

  @override
  String get flowsRule => 'Rule';

  @override
  String get flowsBytes => 'Bytes out/in';

  @override
  String flowsShown(int shown, int total) {
    return '$shown of $total flows';
  }

  @override
  String get overviewDevices => 'Active devices';

  @override
  String get overviewConnectorsOnline => 'Connectors online';

  @override
  String get overviewEdges => 'Edges';

  @override
  String get overviewBlocksHour => 'Blocks in the last hour';

  @override
  String overviewChartTitle(int count) {
    return 'Verdicts by layer (last $count flows)';
  }

  @override
  String overviewOf(int total) {
    return 'of $total';
  }

  @override
  String get verdictAllow => 'Allowed';

  @override
  String get verdictBlock => 'Blocked';

  @override
  String get verdictOther => 'Other';

  @override
  String get msgSettingsSaved => 'Settings saved';

  @override
  String get navAdminTokens => 'Admin tokens';

  @override
  String get adminTokensCreate => 'New admin token';

  @override
  String get adminTokensCreateHelp =>
      'An admin token administers this tenant only: users, policy, private apps, connectors, devices and activity. It cannot see other tenants, create tenants or manage Edges.';

  @override
  String get adminTokensNameHint => 'who or what uses it, e.g. ops team';

  @override
  String get adminTokensFieldDays => 'Valid for (days)';

  @override
  String get adminTokensFieldDaysHelp => 'From 1 to 365 days';

  @override
  String adminTokensCreated(String name) {
    return 'Admin token $name created';
  }

  @override
  String get adminTokensShownOnce => 'This token is shown only once. Copy it now and store it in a password manager.';

  @override
  String get adminTokensUseHelp =>
      'Sign in to the portal with it, or use it with opensasectl (-token-file or \$OPENSASE_ADMIN_TOKEN).';

  @override
  String get adminTokensEmpty => 'No admin tokens for this tenant yet';

  @override
  String get adminTokensThisSession => '(this session)';

  @override
  String get adminTokensRevokeOwn => 'This is the token of the current session: you will be signed out.';

  @override
  String get revokeConfirmAdminToken => 'The token stops working at once. This cannot be undone.';

  @override
  String get fieldExpires => 'Expires';

  @override
  String get fieldLastUsed => 'Last used';

  @override
  String get statusExpired => 'Expired';
}
