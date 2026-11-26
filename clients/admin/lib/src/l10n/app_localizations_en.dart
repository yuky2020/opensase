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
  String get navPolicyTest => 'Policy test';

  @override
  String get navPrivateApps => 'Private apps';

  @override
  String get navConnectors => 'Connectors';

  @override
  String get navDevices => 'Devices';

  @override
  String get navEdges => 'Edges';

  @override
  String get navStatus => 'Status';

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

  @override
  String get navAudit => 'Audit';

  @override
  String get auditEmpty => 'No admin changes recorded for this tenant yet';

  @override
  String get auditHelp => 'Every admin change on this tenant, by whom and with what result. Kept for 365 days.';

  @override
  String get fieldActor => 'Actor';

  @override
  String get fieldMethod => 'Action';

  @override
  String get fieldPath => 'Path';

  @override
  String get fieldResult => 'Result';

  @override
  String get auditActorSuper => 'super-admin';

  @override
  String get fieldTime => 'Time';

  @override
  String get navSaas => 'SaaS apps';

  @override
  String get saasHelp =>
      'Block well-known SaaS apps or whole categories. Enforced on DNS by devices and Edges, and on the TLS server name of every Edge flow, so apps cannot be reached by address either.';

  @override
  String get saasBlockCategory => 'Block every app of this category';

  @override
  String get saasDiscovered => 'Seen in recent flows:';

  @override
  String saasSeen(int count) {
    return '$count flows';
  }

  @override
  String get statusBlocked => 'Blocked';

  @override
  String get statusAllowed => 'Allowed';

  @override
  String get saasCatFileSharing => 'File sharing';

  @override
  String get saasCatWebmail => 'Webmail';

  @override
  String get saasCatAiAssistant => 'AI assistants';

  @override
  String get saasCatSocialMedia => 'Social media';

  @override
  String get saasCatMessaging => 'Messaging';

  @override
  String get saasCatCollaboration => 'Collaboration';

  @override
  String get saasCatStreaming => 'Streaming';

  @override
  String get saasCatCodeHosting => 'Code hosting and paste sites';

  @override
  String get navWeb => 'Web inspection';

  @override
  String get webHelp =>
      'Decrypt the tenant\'s HTTPS at the Edge to enforce URL rules and set request headers. Devices must trust the tenant\'s inspection root.';

  @override
  String get webInspect => 'Inspect TLS';

  @override
  String get webInspectHelp =>
      'The Edge terminates TLS with a certificate from the tenant\'s inspection root and checks every request. QUIC and IPv6 web traffic of these devices is refused, so browsers use inspected TCP.';

  @override
  String get webBlockEch => 'Block Encrypted Client Hello';

  @override
  String get webBlockEchHelp => 'Remove ECH from DNS answers so the Edge sees real server names';

  @override
  String get webBypass => 'Never decrypt';

  @override
  String get webBypassHelp =>
      'One domain per line (*.bank.example). For certificate-pinned apps, banking and health sites.';

  @override
  String get webRules => 'URL rules';

  @override
  String get webRulesHelp =>
      'Matched in order on each request; the first match decides, no match allows. Paths are normalized and case-insensitive.';

  @override
  String get webAddRule => 'Add rule';

  @override
  String get webDomains => 'Domains (comma-separated)';

  @override
  String get webPaths => 'Path prefixes (empty = every path)';

  @override
  String get webPathsInvalid => 'Each path must start with /';

  @override
  String get webMethods => 'Methods (empty = every method)';

  @override
  String get webAction => 'Action (allow or block)';

  @override
  String get webHeaders => 'Request headers';

  @override
  String get webHeadersHelp =>
      'Set on every request to a matching host, replacing what the client sent, for example to restrict a SaaS login to the company\'s own account.';

  @override
  String get webAddHeader => 'Add header';

  @override
  String get webHeaderName => 'Header name';

  @override
  String get webHeaderValue => 'Value';

  @override
  String get webRootButton => 'Inspection root';

  @override
  String get webRootTitle => 'Tenant inspection root';

  @override
  String get webRootHelp =>
      'Install this certificate as a trusted root on the tenant\'s devices (MDM, system store). Devices that do not trust it cannot open inspected sites.';

  @override
  String get webDlp => 'Data loss prevention';

  @override
  String get webDlpHelp =>
      'Scans uploads, and file downloads where enabled, on the inspected path (up to 8 MiB), including the text inside Office documents, PDF files and ZIP archives. Matches are recorded, never the data. Switch: also block bodies that cannot be scanned (too large or compressed).';

  @override
  String get webAddDlp => 'Add DLP rule';

  @override
  String get webDlpDetectors => 'Detectors (comma-separated)';

  @override
  String webDlpDetectorsHelp(String list) {
    return 'Built-in detectors: $list. Card numbers, IBANs and tax codes are checksum-validated.';
  }

  @override
  String get webDlpUnknown => 'Unknown detector';

  @override
  String get webDlpPatterns => 'Custom patterns (regular expressions, one per line)';

  @override
  String get webDlpDomains => 'Domains (empty = every inspected host)';

  @override
  String get webDlpMin => 'Matches needed';

  @override
  String get webDlpMinInvalid => 'At least 1';

  @override
  String get webDlpLog => 'Log';

  @override
  String get webDlpAllHosts => 'every host';

  @override
  String webDlpPatternCount(int n) {
    return '$n patterns';
  }

  @override
  String get webDlpBlockUnscanned => 'Block bodies that cannot be scanned';

  @override
  String get webAvUploads => 'Scan uploads for malware';

  @override
  String get webAvDownloads => 'Scan file downloads for malware';

  @override
  String get webAvDownloadsHelp =>
      'Attachments and file types (archives, executables, documents); web pages and streamed media are not held back. ClamAV on the Edge, up to 20 MiB.';

  @override
  String get webAvBlockUnscanned => 'Block what cannot be scanned';

  @override
  String get webAvBlockUnscannedHelp => 'Files over 20 MiB, partial (range) downloads, or no scanner reachable.';

  @override
  String get webDlpDownloads => 'Also scan file downloads';

  @override
  String get webDlpBoth => 'uploads and downloads';

  @override
  String get webDlpUploadsOnly => 'uploads';

  @override
  String get navCategories => 'Web categories';

  @override
  String get categoriesHelp =>
      'Block whole categories of sites from a public category list. Enforced by the Edge on DNS and on the server name of every connection; the tenant\'s DNS allow list wins.';

  @override
  String get categoriesNotLoaded =>
      'No category list is loaded on the Control Plane (flags -categories-file / -categories-url). Selected categories are saved but not enforced yet.';

  @override
  String categoriesSource(String source, String licence, String when) {
    return 'Source: $source ($licence), updated $when.';
  }

  @override
  String get categoriesFilter => 'Filter categories';

  @override
  String categoriesDomains(String n) {
    return '$n domains';
  }

  @override
  String categoriesUrls(String n) {
    return '$n pages (blocked on inspected traffic)';
  }

  @override
  String get safeSearch => 'Force SafeSearch';

  @override
  String get safeSearchHelp =>
      'Search engines (Google, Bing, DuckDuckGo) answer with their safe results and YouTube runs in restricted mode, through DNS at the Edge; connections that try to reach them another way are reset.';

  @override
  String get adminTokensFieldRole => 'Role';

  @override
  String get adminTokensFieldRoleHelp =>
      'admin (everything in the tenant), policy-editor (read, and edit the policy) or viewer (read only)';

  @override
  String auditChainOk(int n) {
    return 'Audit chain intact: $n entries verified';
  }

  @override
  String auditChainBroken(int id, String reason) {
    return 'Audit chain broken at entry $id: $reason';
  }

  @override
  String auditChainHead(int id, String hash) {
    return 'Head: entry $id, $hash (keep a copy to check the history later)';
  }

  @override
  String get navSecurityEvents => 'Security events';

  @override
  String get secEventsHelp =>
      'Blocks and detections from DLP, malware scanning, URL rules, web categories, SafeSearch, SaaS control and TLS inspection, from the tenant\'s recent flows. The matched data itself is never recorded.';

  @override
  String secAll(int n) {
    return 'All · $n';
  }

  @override
  String get secEmpty => 'No security events in the recent flows.';

  @override
  String get secFieldKind => 'Kind';

  @override
  String get secFieldRule => 'Rule';

  @override
  String get secFieldHost => 'Host';

  @override
  String get secFieldDevice => 'Device';

  @override
  String get secLogged => 'Logged';

  @override
  String get secKindDlp => 'DLP';

  @override
  String get secKindMalware => 'Malware';

  @override
  String get secKindUrl => 'URL rule';

  @override
  String get secKindCategory => 'Category';

  @override
  String get secKindSafeSearch => 'SafeSearch';

  @override
  String get secKindSaas => 'SaaS';

  @override
  String get secKindInspection => 'Inspection';

  @override
  String get webDlpDatasets => 'Datasets (comma-separated)';

  @override
  String get webDlpDatasetsHelp =>
      'Exact values or protected documents uploaded with opensasectl dlp-dataset put; only their hashes are stored.';

  @override
  String get loginOidcTitle => 'Sign in with your organisation';

  @override
  String get loginOidcTenant => 'Tenant ID';

  @override
  String get loginOidcTenantRequired => 'Enter the tenant ID';

  @override
  String get loginOidcSubmit => 'Sign in with your organisation';

  @override
  String get loginOr => 'or';

  @override
  String get navSso => 'Single sign-on';

  @override
  String get ssoTitle => 'Single sign-on';

  @override
  String get ssoSubtitle => 'Authenticate portal administrators via an external identity provider.';

  @override
  String get ssoNotConfigured => 'Single sign-on is not configured for this tenant.';

  @override
  String get ssoConfigure => 'Configure SSO';

  @override
  String get ssoIssuer => 'Issuer URL';

  @override
  String get ssoClientId => 'Client ID';

  @override
  String get ssoSecretSet => 'Client secret configured';

  @override
  String get ssoRedirectUrl => 'Redirect URL';

  @override
  String get ssoRedirectUrlHelp => 'Register this callback URL with your identity provider.';

  @override
  String get ssoGroupRoles => 'Group to role mapping';

  @override
  String get ssoGroup => 'Identity provider group';

  @override
  String get ssoRole => 'Tenant role';

  @override
  String get ssoAddGroupMapping => 'Add group mapping';

  @override
  String get ssoEditTitle => 'Configure Single sign-on';

  @override
  String get ssoClientSecret => 'Client secret';

  @override
  String get ssoClientSecretHelp => 'Leave empty to keep the currently configured secret.';

  @override
  String get ssoDeleteConfirmTitle => 'Remove Single sign-on configuration?';

  @override
  String get ssoDeleteConfirmBody => 'Administrators will no longer be able to sign in via the identity provider.';

  @override
  String get ssoSaved => 'Single sign-on configuration saved';

  @override
  String get ssoDeleted => 'Single sign-on configuration removed';

  @override
  String get ssoErrorIssuer => 'Issuer must be HTTPS (or HTTP on localhost)';

  @override
  String get ssoErrorClientId => 'Client ID is required';

  @override
  String get ssoErrorGroups => 'At least one group mapping is required';

  @override
  String get yes => 'Yes';

  @override
  String get no => 'No';

  @override
  String get navDns => 'DNS';

  @override
  String get dnsTitle => 'DNS';

  @override
  String get dnsSubtitle => 'Manage resolver settings, internal DNS zone, and domain blocklists.';

  @override
  String get dnsResolver => 'Resolver';

  @override
  String get dnsBlockResponse => 'Block response';

  @override
  String get dnsBlockResponseNxdomain => 'NXDOMAIN';

  @override
  String get dnsBlockResponseZero => '0.0.0.0 / ::';

  @override
  String get dnsRedirectQueries => 'Redirect DNS queries to the Edge resolver';

  @override
  String get dnsRedirectQueriesHelp =>
      'Answers plain DNS queries sent to other resolvers with this policy instead of blocking them.';

  @override
  String get dnsLogQueries => 'Log allowed queries';

  @override
  String get dnsLogQueriesHelp => 'Record allowed DNS queries as flow records.';

  @override
  String get dnsInternalZone => 'Internal zone';

  @override
  String get dnsZoneName => 'Internal zone name';

  @override
  String get dnsZoneHelp => 'Devices receive names under <device>.<user>.<zone>.';

  @override
  String get dnsRecords => 'Records';

  @override
  String get dnsRecordName => 'Name';

  @override
  String get dnsRecordType => 'Type';

  @override
  String get dnsRecordValue => 'Value';

  @override
  String get dnsRecordTtl => 'TTL (seconds)';

  @override
  String get dnsAddRecord => 'Add record';

  @override
  String get dnsEditRecord => 'Edit record';

  @override
  String get dnsForwarders => 'Forwarders';

  @override
  String get dnsForwarderZone => 'Zone';

  @override
  String get dnsForwarderServers => 'Servers (comma-separated)';

  @override
  String get dnsAddForwarder => 'Add forwarder';

  @override
  String get dnsEditForwarder => 'Edit forwarder';

  @override
  String get dnsSecurityBlocklists => 'Security blocklists';

  @override
  String get dnsBuiltinLists => 'Built-in blocklists';

  @override
  String get dnsBuiltinEmpty => 'No built-in blocklists available';

  @override
  String get dnsCustomLists => 'Custom blocklists';

  @override
  String get dnsCustomListId => 'ID';

  @override
  String get dnsCustomListTitle => 'Title';

  @override
  String get dnsCustomListUrl => 'URL (https://)';

  @override
  String get dnsAddCustomList => 'Add custom list';

  @override
  String get dnsEditCustomList => 'Edit custom list';

  @override
  String get dnsDomainOverrides => 'Domain overrides';

  @override
  String get dnsAllowDomains => 'Allowed domains';

  @override
  String get dnsBlockDomains => 'Blocked domains';

  @override
  String get dnsAddDomain => 'Add domain';

  @override
  String get dnsDomainHint => 'example.com or *.example.com';

  @override
  String get dnsErrorNameRequired => 'Name is required';

  @override
  String get dnsErrorValueRequired => 'Value is required';

  @override
  String get dnsErrorInvalidIpv4 => 'Must be a valid IPv4 address';

  @override
  String get dnsErrorInvalidIpv6 => 'Must be a valid IPv6 address';

  @override
  String get dnsErrorInvalidTtl => 'TTL must be 0 or between 1 and 86400';

  @override
  String get dnsErrorZoneRequired => 'Zone is required';

  @override
  String get dnsErrorInvalidServers => 'Each server must be an IP or IP:port';

  @override
  String get dnsErrorInvalidListId => 'ID must contain only lowercase letters, numbers, and hyphens';

  @override
  String get dnsErrorInvalidHttpsUrl => 'Must be a valid https:// URL';

  @override
  String get navOnboarding => 'Get started';

  @override
  String get onboardingTitle => 'Get started';

  @override
  String get onboardingSubtitle => 'Initial setup wizard for OpenSASE';

  @override
  String get onboardingStepWelcome => 'Welcome';

  @override
  String get onboardingStepOrg => 'Organisation';

  @override
  String get onboardingStepSso => 'Sign-in';

  @override
  String get onboardingStepPolicy => 'First policy';

  @override
  String get onboardingStepDns => 'DNS';

  @override
  String get onboardingStepConnectors => 'Private apps';

  @override
  String get onboardingStepDevices => 'Devices';

  @override
  String get onboardingStepDone => 'Done';

  @override
  String get onboardingWelcomeSuper => 'Deployment health and readiness status.';

  @override
  String get onboardingWelcomeTenant =>
      'Welcome to the OpenSASE admin portal. Complete the steps below to configure your organization.';

  @override
  String onboardingEdgesReporting(int reporting, int total) => 'Edges reporting: $reporting of $total';

  @override
  String onboardingCertWarning(String name, int days) => 'Warning: Certificate \'$name\' expires in $days days';

  @override
  String get onboardingCertsHealthy => 'All certificates are healthy';

  @override
  String get onboardingStepStatusDone => 'Done';

  @override
  String get onboardingStepStatusTodo => 'Not done';

  @override
  String get onboardingOrgHelp => 'Configure the tenant display name.';

  @override
  String onboardingOrgCurrent(String name, String id) => 'Current organisation: $name ($id)';

  @override
  String get onboardingOrgCreate => 'Create organisation';

  @override
  String get onboardingSsoHelp => 'Configure Single Sign-On using your OpenID Connect identity provider.';

  @override
  String get onboardingTestSignin => 'Test sign-in';

  @override
  String get onboardingSkipSso => 'Skip, use provisioning keys';

  @override
  String get onboardingAddGroup => 'Add group mapping';

  @override
  String get onboardingPolicyHelp => 'Choose a baseline security policy template for your tenant.';

  @override
  String get onboardingTemplateRecommended => 'Recommended';

  @override
  String get onboardingTemplateRecommendedDesc =>
      'Allow default action, block malware and phishing categories, and enforce SafeSearch.';

  @override
  String get onboardingTemplatePermissive => 'Permissive';

  @override
  String get onboardingTemplatePermissiveDesc => 'Allow default action with no category blocking.';

  @override
  String get onboardingPolicyPreview => 'Policy JSON preview';

  @override
  String get onboardingDnsHelp => 'Set internal DNS resolution and security blocklists.';

  @override
  String get onboardingDnsZone => 'Internal zone name';

  @override
  String get onboardingDnsBlocklist => 'Security blocklist';

  @override
  String get onboardingConnectorHelp => 'Deploy a Connector to securely broker access to private network applications.';

  @override
  String get onboardingConnectorCreate => 'Create Connector';

  @override
  String get onboardingConnectorDocker => 'Run with Docker';

  @override
  String get onboardingConnectorDockerHelp => 'Run this command on your connector host. The key is shown only once.';

  @override
  String get onboardingConnectorStatus => 'Live Connector status';

  @override
  String get onboardingPrivateAppsLink => 'Add private apps';

  @override
  String get onboardingSkip => 'Skip';

  @override
  String get onboardingDevicesHelp => 'Enroll user devices using a provisioning key or QR code.';

  @override
  String get onboardingKeyCreate => 'Generate provisioning key';

  @override
  String get onboardingPlatformAndroid => 'Android';

  @override
  String get onboardingPlatformAndroidDesc => 'Install the OpenSASE app and scan the QR code to enroll.';

  @override
  String get onboardingPlatformWindows => 'Windows';

  @override
  String get onboardingPlatformWindowsDesc =>
      'Download and run the Windows MSI installer, then supply the control URL and provisioning key.';

  @override
  String get onboardingPlatformLinux => 'Linux';

  @override
  String get onboardingPlatformLinuxDesc =>
      'Install the Linux package (deb or rpm) and run the enrollment command with the provisioning key.';

  @override
  String get onboardingDevicesLive => 'Live enrolled devices';

  @override
  String get onboardingDoneTitle => 'Setup complete!';

  @override
  String get onboardingDoneSubtitle =>
      'Your OpenSASE deployment is ready to secure your traffic and private applications.';

  @override
  String get onboardingLinkStatus => 'Status page';

  @override
  String get onboardingLinkPolicy => 'Policy editor';

  @override
  String get onboardingLinkDns => 'DNS settings';

  @override
  String get onboardingLinkDocs => 'Documentation';

  @override
  String get onboardingNext => 'Next';

  @override
  String get onboardingBack => 'Back';

  @override
  String get onboardingApply => 'Apply';

  @override
  String get policyTestSubtitle => 'Evaluate a sample flow against a device\'s signed policy snapshot.';

  @override
  String get policyTestDevice => 'Device';

  @override
  String get policyTestSelectDevice => 'Select a device';

  @override
  String get policyTestNoDevices => 'No enrolled devices found in this tenant.';

  @override
  String get policyTestProtocol => 'Protocol';

  @override
  String get policyTestDstIp => 'Destination IP';

  @override
  String get policyTestDstPort => 'Destination port';

  @override
  String get policyTestDomain => 'Domain';

  @override
  String get policyTestApp => 'Application package';

  @override
  String get policyTestAppHelp => 'Android package name (disabled in Edge mode)';

  @override
  String get policyTestNetwork => 'Network type';

  @override
  String get policyTestEdge => 'Evaluate as the Edge';

  @override
  String get policyTestEdgeHelp =>
      'Simulate evaluation on an Edge node (device attributes like app and network are ignored)';

  @override
  String get policyTestActionTest => 'Test';

  @override
  String get policyTestTesting => 'Testing...';

  @override
  String get policyTestInvalidIp => 'Enter a valid IPv4 or IPv6 address';

  @override
  String get policyTestInvalidPort => 'Port must be between 0 and 65535';

  @override
  String get policyTestResultTitle => 'Evaluation result';

  @override
  String get policyTestResultAction => 'Action';

  @override
  String get policyTestResultLayer => 'Layer';

  @override
  String get policyTestResultRuleId => 'Rule ID';

  @override
  String get policyTestResultReason => 'Reason';

  @override
  String get policyTestResultSnapshot => 'Snapshot version';

  @override
  String get navExperience => 'Experience';

  @override
  String get experienceSubtitle => 'Digital experience telemetry across devices and Edges.';

  @override
  String get experiencePeriod => 'Period';

  @override
  String get experiencePeriodHour1 => '1 hour';

  @override
  String get experiencePeriodHours24 => '24 hours';

  @override
  String get experiencePeriodDays7 => '7 days';

  @override
  String get experiencePeriodDays30 => '30 days';

  @override
  String get experienceFilterDevice => 'Filter by device name';

  @override
  String get experienceStatDevicesMeasured => 'Devices measured';

  @override
  String get experienceStatMedianRtt => 'Median RTT p50';

  @override
  String get experienceStatHighLossRows => 'Rows with loss > 2%';

  @override
  String get experienceColDevice => 'Device';

  @override
  String get experienceColEdge => 'Edge';

  @override
  String get experienceColSamples => 'Samples';

  @override
  String get experienceColRttP50 => 'RTT p50';

  @override
  String get experienceColRttP95 => 'RTT p95';

  @override
  String get experienceColLoss => 'Loss';

  @override
  String get experienceColDnsP50 => 'DNS p50';

  @override
  String get experienceColLast => 'Last sample';

  @override
  String get experienceEmpty => 'No digital experience data for this period';
}
