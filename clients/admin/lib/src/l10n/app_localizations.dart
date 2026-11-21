import 'dart:async';

import 'package:flutter/foundation.dart';
import 'package:flutter/widgets.dart';
import 'package:flutter_localizations/flutter_localizations.dart';
import 'package:intl/intl.dart' as intl;

import 'app_localizations_en.dart';
import 'app_localizations_it.dart';

// ignore_for_file: type=lint

/// Callers can lookup localized strings with an instance of AppLocalizations
/// returned by `AppLocalizations.of(context)`.
///
/// Applications need to include `AppLocalizations.delegate()` in their app's
/// `localizationDelegates` list, and the locales they support in the app's
/// `supportedLocales` list. For example:
///
/// ```dart
/// import 'l10n/app_localizations.dart';
///
/// return MaterialApp(
///   localizationsDelegates: AppLocalizations.localizationsDelegates,
///   supportedLocales: AppLocalizations.supportedLocales,
///   home: MyApplicationHome(),
/// );
/// ```
///
/// ## Update pubspec.yaml
///
/// Please make sure to update your pubspec.yaml to include the following
/// packages:
///
/// ```yaml
/// dependencies:
///   # Internationalization support.
///   flutter_localizations:
///     sdk: flutter
///   intl: any # Use the pinned version from flutter_localizations
///
///   # Rest of dependencies
/// ```
///
/// ## iOS Applications
///
/// iOS applications define key application metadata, including supported
/// locales, in an Info.plist file that is built into the application bundle.
/// To configure the locales supported by your app, you’ll need to edit this
/// file.
///
/// First, open your project’s ios/Runner.xcworkspace Xcode workspace file.
/// Then, in the Project Navigator, open the Info.plist file under the Runner
/// project’s Runner folder.
///
/// Next, select the Information Property List item, select Add Item from the
/// Editor menu, then select Localizations from the pop-up menu.
///
/// Select and expand the newly-created Localizations item then, for each
/// locale your application supports, add a new item and select the locale
/// you wish to add from the pop-up menu in the Value field. This list should
/// be consistent with the languages listed in the AppLocalizations.supportedLocales
/// property.
abstract class AppLocalizations {
  AppLocalizations(String locale) : localeName = intl.Intl.canonicalizedLocale(locale.toString());

  final String localeName;

  static AppLocalizations of(BuildContext context) {
    return Localizations.of<AppLocalizations>(context, AppLocalizations)!;
  }

  static const LocalizationsDelegate<AppLocalizations> delegate = _AppLocalizationsDelegate();

  /// A list of this localizations delegate along with the default localizations
  /// delegates.
  ///
  /// Returns a list of localizations delegates containing this delegate along with
  /// GlobalMaterialLocalizations.delegate, GlobalCupertinoLocalizations.delegate,
  /// and GlobalWidgetsLocalizations.delegate.
  ///
  /// Additional delegates can be added by appending to this list in
  /// MaterialApp. This list does not have to be used at all if a custom list
  /// of delegates is preferred or required.
  static const List<LocalizationsDelegate<dynamic>> localizationsDelegates = <LocalizationsDelegate<dynamic>>[
    delegate,
    GlobalMaterialLocalizations.delegate,
    GlobalCupertinoLocalizations.delegate,
    GlobalWidgetsLocalizations.delegate,
  ];

  /// A list of this localizations delegate's supported locales.
  static const List<Locale> supportedLocales = <Locale>[Locale('en'), Locale('it')];

  /// No description provided for @appTitle.
  ///
  /// In en, this message translates to:
  /// **'OpenSASE Admin'**
  String get appTitle;

  /// No description provided for @navOverview.
  ///
  /// In en, this message translates to:
  /// **'Overview'**
  String get navOverview;

  /// No description provided for @navTenants.
  ///
  /// In en, this message translates to:
  /// **'Tenants'**
  String get navTenants;

  /// No description provided for @navUsers.
  ///
  /// In en, this message translates to:
  /// **'Users'**
  String get navUsers;

  /// No description provided for @navPolicy.
  ///
  /// In en, this message translates to:
  /// **'Policy'**
  String get navPolicy;

  /// No description provided for @navPrivateApps.
  ///
  /// In en, this message translates to:
  /// **'Private apps'**
  String get navPrivateApps;

  /// No description provided for @navConnectors.
  ///
  /// In en, this message translates to:
  /// **'Connectors'**
  String get navConnectors;

  /// No description provided for @navDevices.
  ///
  /// In en, this message translates to:
  /// **'Devices'**
  String get navDevices;

  /// No description provided for @navEdges.
  ///
  /// In en, this message translates to:
  /// **'Edges'**
  String get navEdges;

  /// No description provided for @navActivity.
  ///
  /// In en, this message translates to:
  /// **'Activity'**
  String get navActivity;

  /// No description provided for @navSettings.
  ///
  /// In en, this message translates to:
  /// **'Settings'**
  String get navSettings;

  /// No description provided for @actionSave.
  ///
  /// In en, this message translates to:
  /// **'Save'**
  String get actionSave;

  /// No description provided for @actionCancel.
  ///
  /// In en, this message translates to:
  /// **'Cancel'**
  String get actionCancel;

  /// No description provided for @actionDelete.
  ///
  /// In en, this message translates to:
  /// **'Delete'**
  String get actionDelete;

  /// No description provided for @actionAdd.
  ///
  /// In en, this message translates to:
  /// **'Add'**
  String get actionAdd;

  /// No description provided for @actionEdit.
  ///
  /// In en, this message translates to:
  /// **'Edit'**
  String get actionEdit;

  /// No description provided for @actionCreate.
  ///
  /// In en, this message translates to:
  /// **'Create'**
  String get actionCreate;

  /// No description provided for @actionRevoke.
  ///
  /// In en, this message translates to:
  /// **'Revoke'**
  String get actionRevoke;

  /// No description provided for @actionRefresh.
  ///
  /// In en, this message translates to:
  /// **'Refresh'**
  String get actionRefresh;

  /// No description provided for @actionReload.
  ///
  /// In en, this message translates to:
  /// **'Discard changes'**
  String get actionReload;

  /// No description provided for @actionClose.
  ///
  /// In en, this message translates to:
  /// **'Close'**
  String get actionClose;

  /// No description provided for @actionCopy.
  ///
  /// In en, this message translates to:
  /// **'Copy'**
  String get actionCopy;

  /// No description provided for @actionLogout.
  ///
  /// In en, this message translates to:
  /// **'Sign out'**
  String get actionLogout;

  /// No description provided for @actionMoveUp.
  ///
  /// In en, this message translates to:
  /// **'Move up'**
  String get actionMoveUp;

  /// No description provided for @actionMoveDown.
  ///
  /// In en, this message translates to:
  /// **'Move down'**
  String get actionMoveDown;

  /// No description provided for @msgCopied.
  ///
  /// In en, this message translates to:
  /// **'Copied to the clipboard'**
  String get msgCopied;

  /// No description provided for @msgSaved.
  ///
  /// In en, this message translates to:
  /// **'Saved. Device snapshots are being recompiled.'**
  String get msgSaved;

  /// No description provided for @msgError.
  ///
  /// In en, this message translates to:
  /// **'Error: {error}'**
  String msgError(String error);

  /// No description provided for @msgSessionExpired.
  ///
  /// In en, this message translates to:
  /// **'The admin token was rejected. Sign in again.'**
  String get msgSessionExpired;

  /// No description provided for @emptyNothingHere.
  ///
  /// In en, this message translates to:
  /// **'Nothing here yet'**
  String get emptyNothingHere;

  /// No description provided for @emptyNoTenant.
  ///
  /// In en, this message translates to:
  /// **'Create or select a tenant first.'**
  String get emptyNoTenant;

  /// No description provided for @tenantPicker.
  ///
  /// In en, this message translates to:
  /// **'Tenant'**
  String get tenantPicker;

  /// No description provided for @loginTitle.
  ///
  /// In en, this message translates to:
  /// **'OpenSASE administration'**
  String get loginTitle;

  /// No description provided for @loginSubtitle.
  ///
  /// In en, this message translates to:
  /// **'Paste the admin token of this Control Plane.'**
  String get loginSubtitle;

  /// No description provided for @loginToken.
  ///
  /// In en, this message translates to:
  /// **'Admin token'**
  String get loginToken;

  /// No description provided for @loginRemember.
  ///
  /// In en, this message translates to:
  /// **'Remember for this tab'**
  String get loginRemember;

  /// No description provided for @loginRememberHint.
  ///
  /// In en, this message translates to:
  /// **'Kept in this tab\'s session storage until the tab is closed. Otherwise the token stays in memory only.'**
  String get loginRememberHint;

  /// No description provided for @loginSubmit.
  ///
  /// In en, this message translates to:
  /// **'Sign in'**
  String get loginSubmit;

  /// No description provided for @loginFailed.
  ///
  /// In en, this message translates to:
  /// **'Sign-in failed: {error}'**
  String loginFailed(String error);

  /// No description provided for @loginTokenRequired.
  ///
  /// In en, this message translates to:
  /// **'Enter the admin token'**
  String get loginTokenRequired;

  /// No description provided for @fieldId.
  ///
  /// In en, this message translates to:
  /// **'ID'**
  String get fieldId;

  /// No description provided for @fieldIdOptional.
  ///
  /// In en, this message translates to:
  /// **'ID (optional, generated if empty)'**
  String get fieldIdOptional;

  /// No description provided for @fieldName.
  ///
  /// In en, this message translates to:
  /// **'Name'**
  String get fieldName;

  /// No description provided for @fieldEmail.
  ///
  /// In en, this message translates to:
  /// **'Email'**
  String get fieldEmail;

  /// No description provided for @fieldGroup.
  ///
  /// In en, this message translates to:
  /// **'Group'**
  String get fieldGroup;

  /// No description provided for @fieldUser.
  ///
  /// In en, this message translates to:
  /// **'User'**
  String get fieldUser;

  /// No description provided for @fieldPlatform.
  ///
  /// In en, this message translates to:
  /// **'Platform'**
  String get fieldPlatform;

  /// No description provided for @fieldCreated.
  ///
  /// In en, this message translates to:
  /// **'Created'**
  String get fieldCreated;

  /// No description provided for @fieldLastSeen.
  ///
  /// In en, this message translates to:
  /// **'Last seen'**
  String get fieldLastSeen;

  /// No description provided for @fieldStatus.
  ///
  /// In en, this message translates to:
  /// **'Status'**
  String get fieldStatus;

  /// No description provided for @fieldInvalidId.
  ///
  /// In en, this message translates to:
  /// **'Letters, digits, \'.\', \'_\' and \'-\'; must start with a letter or digit'**
  String get fieldInvalidId;

  /// No description provided for @fieldRequired.
  ///
  /// In en, this message translates to:
  /// **'Required'**
  String get fieldRequired;

  /// No description provided for @statusRevoked.
  ///
  /// In en, this message translates to:
  /// **'Revoked'**
  String get statusRevoked;

  /// No description provided for @statusActive.
  ///
  /// In en, this message translates to:
  /// **'Active'**
  String get statusActive;

  /// No description provided for @statusOnline.
  ///
  /// In en, this message translates to:
  /// **'Online'**
  String get statusOnline;

  /// No description provided for @statusOffline.
  ///
  /// In en, this message translates to:
  /// **'Offline'**
  String get statusOffline;

  /// No description provided for @never.
  ///
  /// In en, this message translates to:
  /// **'never'**
  String get never;

  /// No description provided for @tenantsCreate.
  ///
  /// In en, this message translates to:
  /// **'New tenant'**
  String get tenantsCreate;

  /// No description provided for @usersCreate.
  ///
  /// In en, this message translates to:
  /// **'New user'**
  String get usersCreate;

  /// No description provided for @usersProvisioningKey.
  ///
  /// In en, this message translates to:
  /// **'Provisioning key'**
  String get usersProvisioningKey;

  /// No description provided for @provTitle.
  ///
  /// In en, this message translates to:
  /// **'Provisioning key for {user}'**
  String provTitle(String user);

  /// No description provided for @provMaxUses.
  ///
  /// In en, this message translates to:
  /// **'Max uses'**
  String get provMaxUses;

  /// No description provided for @provValidHours.
  ///
  /// In en, this message translates to:
  /// **'Valid for (hours)'**
  String get provValidHours;

  /// No description provided for @provGenerate.
  ///
  /// In en, this message translates to:
  /// **'Generate'**
  String get provGenerate;

  /// No description provided for @provShownOnce.
  ///
  /// In en, this message translates to:
  /// **'This key is shown only once. Copy it or let the user scan the QR code now.'**
  String get provShownOnce;

  /// No description provided for @provExpires.
  ///
  /// In en, this message translates to:
  /// **'Expires {time}'**
  String provExpires(String time);

  /// No description provided for @provNoControlUrl.
  ///
  /// In en, this message translates to:
  /// **'Set the control URL with its #sha256= pin in Settings to show an enrollment QR code.'**
  String get provNoControlUrl;

  /// No description provided for @provScan.
  ///
  /// In en, this message translates to:
  /// **'Scan with the OpenSASE app to enroll'**
  String get provScan;

  /// No description provided for @provLink.
  ///
  /// In en, this message translates to:
  /// **'Enrollment link'**
  String get provLink;

  /// No description provided for @settingsControlUrl.
  ///
  /// In en, this message translates to:
  /// **'Control URL for enrollment'**
  String get settingsControlUrl;

  /// No description provided for @settingsControlUrlHint.
  ///
  /// In en, this message translates to:
  /// **'https://cp.example.com:9443#sha256=<root CA SHA-256>'**
  String get settingsControlUrlHint;

  /// No description provided for @settingsControlUrlHelp.
  ///
  /// In en, this message translates to:
  /// **'Put into enrollment QR codes. The #sha256= fragment pins the provider root CA (opensasectl prints it).'**
  String get settingsControlUrlHelp;

  /// No description provided for @settingsUseOrigin.
  ///
  /// In en, this message translates to:
  /// **'Use this origin'**
  String get settingsUseOrigin;

  /// No description provided for @settingsTokenInfo.
  ///
  /// In en, this message translates to:
  /// **'The admin token is held in memory, and in this tab\'s session storage only if you chose so at sign-in. It is never written to local storage.'**
  String get settingsTokenInfo;

  /// No description provided for @policyTabForm.
  ///
  /// In en, this message translates to:
  /// **'Form'**
  String get policyTabForm;

  /// No description provided for @policyTabJson.
  ///
  /// In en, this message translates to:
  /// **'JSON'**
  String get policyTabJson;

  /// No description provided for @policyGeneral.
  ///
  /// In en, this message translates to:
  /// **'General'**
  String get policyGeneral;

  /// No description provided for @policyDefaultAction.
  ///
  /// In en, this message translates to:
  /// **'Default action'**
  String get policyDefaultAction;

  /// No description provided for @policyNotSet.
  ///
  /// In en, this message translates to:
  /// **'Not set (server default)'**
  String get policyNotSet;

  /// No description provided for @policyAllowUserRules.
  ///
  /// In en, this message translates to:
  /// **'Allow user rules'**
  String get policyAllowUserRules;

  /// No description provided for @policyAllowUserRulesHelp.
  ///
  /// In en, this message translates to:
  /// **'Users may add personal rules and per-app policies below the tenant layer.'**
  String get policyAllowUserRulesHelp;

  /// No description provided for @policyLockdown.
  ///
  /// In en, this message translates to:
  /// **'Lockdown'**
  String get policyLockdown;

  /// No description provided for @policyLockdownHelp.
  ///
  /// In en, this message translates to:
  /// **'Apps without a tenant app policy are blocked; user rules can only block.'**
  String get policyLockdownHelp;

  /// No description provided for @policyRules.
  ///
  /// In en, this message translates to:
  /// **'Tenant rules'**
  String get policyRules;

  /// No description provided for @policyRulesHelp.
  ///
  /// In en, this message translates to:
  /// **'Evaluated by priority, lowest first; the first match wins. All filled match fields must match.'**
  String get policyRulesHelp;

  /// No description provided for @policyApps.
  ///
  /// In en, this message translates to:
  /// **'Per-app policies'**
  String get policyApps;

  /// No description provided for @policyAppsHelp.
  ///
  /// In en, this message translates to:
  /// **'Mandatory verdicts per Android package and network.'**
  String get policyAppsHelp;

  /// No description provided for @policyDns.
  ///
  /// In en, this message translates to:
  /// **'DNS'**
  String get policyDns;

  /// No description provided for @policyBlockResponse.
  ///
  /// In en, this message translates to:
  /// **'Block response'**
  String get policyBlockResponse;

  /// No description provided for @policyBlocklists.
  ///
  /// In en, this message translates to:
  /// **'Blocklists'**
  String get policyBlocklists;

  /// No description provided for @policyAllowDomains.
  ///
  /// In en, this message translates to:
  /// **'Allowed domains (override blocklists)'**
  String get policyAllowDomains;

  /// No description provided for @policyBlockDomains.
  ///
  /// In en, this message translates to:
  /// **'Blocked domains'**
  String get policyBlockDomains;

  /// No description provided for @policyDecide.
  ///
  /// In en, this message translates to:
  /// **'Cloud decisions (ask)'**
  String get policyDecide;

  /// No description provided for @policyDecideDefault.
  ///
  /// In en, this message translates to:
  /// **'Decide default'**
  String get policyDecideDefault;

  /// No description provided for @policyDecideBlockDomains.
  ///
  /// In en, this message translates to:
  /// **'Domains blocked by the cloud'**
  String get policyDecideBlockDomains;

  /// No description provided for @policyDecideBlockCidrs.
  ///
  /// In en, this message translates to:
  /// **'CIDRs blocked by the cloud'**
  String get policyDecideBlockCidrs;

  /// No description provided for @policyOnePerLine.
  ///
  /// In en, this message translates to:
  /// **'One per line; \"*.example.com\" also matches example.com'**
  String get policyOnePerLine;

  /// No description provided for @policyJsonInvalid.
  ///
  /// In en, this message translates to:
  /// **'Invalid JSON: {error}'**
  String policyJsonInvalid(String error);

  /// No description provided for @policyJsonLocked.
  ///
  /// In en, this message translates to:
  /// **'The JSON tab has an error. Fix it to edit the form.'**
  String get policyJsonLocked;

  /// No description provided for @policyIssues.
  ///
  /// In en, this message translates to:
  /// **'Fix these problems before saving:'**
  String get policyIssues;

  /// No description provided for @policyServerError.
  ///
  /// In en, this message translates to:
  /// **'The Control Plane rejected the policy: {error}'**
  String policyServerError(String error);

  /// No description provided for @policyUnsaved.
  ///
  /// In en, this message translates to:
  /// **'Unsaved changes'**
  String get policyUnsaved;

  /// No description provided for @ruleNew.
  ///
  /// In en, this message translates to:
  /// **'New rule'**
  String get ruleNew;

  /// No description provided for @ruleEdit.
  ///
  /// In en, this message translates to:
  /// **'Edit rule'**
  String get ruleEdit;

  /// No description provided for @rulePriority.
  ///
  /// In en, this message translates to:
  /// **'Priority'**
  String get rulePriority;

  /// No description provided for @ruleAction.
  ///
  /// In en, this message translates to:
  /// **'Action'**
  String get ruleAction;

  /// No description provided for @ruleLog.
  ///
  /// In en, this message translates to:
  /// **'Log matching flows'**
  String get ruleLog;

  /// No description provided for @ruleDescription.
  ///
  /// In en, this message translates to:
  /// **'Description'**
  String get ruleDescription;

  /// No description provided for @ruleMatch.
  ///
  /// In en, this message translates to:
  /// **'Match'**
  String get ruleMatch;

  /// No description provided for @ruleMatchAny.
  ///
  /// In en, this message translates to:
  /// **'any'**
  String get ruleMatchAny;

  /// No description provided for @matchApps.
  ///
  /// In en, this message translates to:
  /// **'Apps (package names)'**
  String get matchApps;

  /// No description provided for @matchNetworks.
  ///
  /// In en, this message translates to:
  /// **'Networks'**
  String get matchNetworks;

  /// No description provided for @matchProtocols.
  ///
  /// In en, this message translates to:
  /// **'Protocols'**
  String get matchProtocols;

  /// No description provided for @matchCidrs.
  ///
  /// In en, this message translates to:
  /// **'Destination CIDRs'**
  String get matchCidrs;

  /// No description provided for @matchPorts.
  ///
  /// In en, this message translates to:
  /// **'Destination ports'**
  String get matchPorts;

  /// No description provided for @matchPortsHint.
  ///
  /// In en, this message translates to:
  /// **'443, 8000-8080'**
  String get matchPortsHint;

  /// No description provided for @matchDomains.
  ///
  /// In en, this message translates to:
  /// **'Domains'**
  String get matchDomains;

  /// No description provided for @appPackage.
  ///
  /// In en, this message translates to:
  /// **'Package name'**
  String get appPackage;

  /// No description provided for @appNew.
  ///
  /// In en, this message translates to:
  /// **'New app policy'**
  String get appNew;

  /// No description provided for @networkWifi.
  ///
  /// In en, this message translates to:
  /// **'Wi-Fi'**
  String get networkWifi;

  /// No description provided for @networkCellular.
  ///
  /// In en, this message translates to:
  /// **'Mobile data'**
  String get networkCellular;

  /// No description provided for @networkRoaming.
  ///
  /// In en, this message translates to:
  /// **'Roaming'**
  String get networkRoaming;

  /// No description provided for @networkEthernet.
  ///
  /// In en, this message translates to:
  /// **'Ethernet'**
  String get networkEthernet;

  /// No description provided for @networkUnknown.
  ///
  /// In en, this message translates to:
  /// **'Unknown'**
  String get networkUnknown;

  /// No description provided for @actionAllow.
  ///
  /// In en, this message translates to:
  /// **'Allow'**
  String get actionAllow;

  /// No description provided for @actionBlock.
  ///
  /// In en, this message translates to:
  /// **'Block'**
  String get actionBlock;

  /// No description provided for @actionAsk.
  ///
  /// In en, this message translates to:
  /// **'Ask cloud'**
  String get actionAsk;

  /// No description provided for @actionUnset.
  ///
  /// In en, this message translates to:
  /// **'Not set'**
  String get actionUnset;

  /// No description provided for @blocklistNew.
  ///
  /// In en, this message translates to:
  /// **'New blocklist'**
  String get blocklistNew;

  /// No description provided for @blocklistCategory.
  ///
  /// In en, this message translates to:
  /// **'Category'**
  String get blocklistCategory;

  /// No description provided for @blocklistDomainsCount.
  ///
  /// In en, this message translates to:
  /// **'{count} domains'**
  String blocklistDomainsCount(int count);

  /// No description provided for @privateAppsHelp.
  ///
  /// In en, this message translates to:
  /// **'Private apps are reachable by name only, through a Connector group (ZTNA). Saving updates the tenant policy.'**
  String get privateAppsHelp;

  /// No description provided for @privateAppNew.
  ///
  /// In en, this message translates to:
  /// **'New private app'**
  String get privateAppNew;

  /// No description provided for @privateAppEdit.
  ///
  /// In en, this message translates to:
  /// **'Edit private app'**
  String get privateAppEdit;

  /// No description provided for @privateAppPorts.
  ///
  /// In en, this message translates to:
  /// **'TCP ports'**
  String get privateAppPorts;

  /// No description provided for @privateAppConnectorGroup.
  ///
  /// In en, this message translates to:
  /// **'Connector group'**
  String get privateAppConnectorGroup;

  /// No description provided for @privateAppUsers.
  ///
  /// In en, this message translates to:
  /// **'Users (IDs or emails; empty = every user)'**
  String get privateAppUsers;

  /// No description provided for @privateAppEveryone.
  ///
  /// In en, this message translates to:
  /// **'everyone'**
  String get privateAppEveryone;

  /// No description provided for @connectorsCreate.
  ///
  /// In en, this message translates to:
  /// **'New Connector'**
  String get connectorsCreate;

  /// No description provided for @connectorsCreated.
  ///
  /// In en, this message translates to:
  /// **'Connector {name} created'**
  String connectorsCreated(String name);

  /// No description provided for @connectorsKeyHelp.
  ///
  /// In en, this message translates to:
  /// **'Single-use key, valid 24 hours. Pass it to opensase-connector -key at its first start.'**
  String get connectorsKeyHelp;

  /// No description provided for @connectorsGroupHint.
  ///
  /// In en, this message translates to:
  /// **'default'**
  String get connectorsGroupHint;

  /// No description provided for @revokeConfirmTitle.
  ///
  /// In en, this message translates to:
  /// **'Revoke {name}?'**
  String revokeConfirmTitle(String name);

  /// No description provided for @revokeConfirmConnector.
  ///
  /// In en, this message translates to:
  /// **'The connector\'s certificate stops working on the next Edge sync (about 10 seconds). This cannot be undone.'**
  String get revokeConfirmConnector;

  /// No description provided for @revokeConfirmDevice.
  ///
  /// In en, this message translates to:
  /// **'The device loses access and must enroll again. This cannot be undone.'**
  String get revokeConfirmDevice;

  /// No description provided for @revokeConfirmEdge.
  ///
  /// In en, this message translates to:
  /// **'The Edge is refused by the Control Plane; its ID cannot be reused. This cannot be undone.'**
  String get revokeConfirmEdge;

  /// No description provided for @edgesCreate.
  ///
  /// In en, this message translates to:
  /// **'Register Edge'**
  String get edgesCreate;

  /// No description provided for @edgesCreateHelp.
  ///
  /// In en, this message translates to:
  /// **'Register the Edge ID before starting the Edge with its certificate.'**
  String get edgesCreateHelp;

  /// No description provided for @edgesFieldTenant.
  ///
  /// In en, this message translates to:
  /// **'Tenant (Private Edge)'**
  String get edgesFieldTenant;

  /// No description provided for @edgesFieldTenantHelp.
  ///
  /// In en, this message translates to:
  /// **'Optional. Binds the Edge to one tenant; leave empty for a public multi-tenant Edge.'**
  String get edgesFieldTenantHelp;

  /// No description provided for @edgesPublic.
  ///
  /// In en, this message translates to:
  /// **'public'**
  String get edgesPublic;

  /// No description provided for @flowsVerdict.
  ///
  /// In en, this message translates to:
  /// **'Verdict'**
  String get flowsVerdict;

  /// No description provided for @flowsLayer.
  ///
  /// In en, this message translates to:
  /// **'Layer'**
  String get flowsLayer;

  /// No description provided for @flowsWhere.
  ///
  /// In en, this message translates to:
  /// **'Where'**
  String get flowsWhere;

  /// No description provided for @flowsDevice.
  ///
  /// In en, this message translates to:
  /// **'Device'**
  String get flowsDevice;

  /// No description provided for @flowsSearch.
  ///
  /// In en, this message translates to:
  /// **'Search domain, IP, port, app, rule'**
  String get flowsSearch;

  /// No description provided for @flowsAny.
  ///
  /// In en, this message translates to:
  /// **'Any'**
  String get flowsAny;

  /// No description provided for @flowsAutoRefresh.
  ///
  /// In en, this message translates to:
  /// **'Auto refresh (10 s)'**
  String get flowsAutoRefresh;

  /// No description provided for @flowsTime.
  ///
  /// In en, this message translates to:
  /// **'Time'**
  String get flowsTime;

  /// No description provided for @flowsDestination.
  ///
  /// In en, this message translates to:
  /// **'Destination'**
  String get flowsDestination;

  /// No description provided for @flowsApp.
  ///
  /// In en, this message translates to:
  /// **'App'**
  String get flowsApp;

  /// No description provided for @flowsRule.
  ///
  /// In en, this message translates to:
  /// **'Rule'**
  String get flowsRule;

  /// No description provided for @flowsBytes.
  ///
  /// In en, this message translates to:
  /// **'Bytes out/in'**
  String get flowsBytes;

  /// No description provided for @flowsShown.
  ///
  /// In en, this message translates to:
  /// **'{shown} of {total} flows'**
  String flowsShown(int shown, int total);

  /// No description provided for @overviewDevices.
  ///
  /// In en, this message translates to:
  /// **'Active devices'**
  String get overviewDevices;

  /// No description provided for @overviewConnectorsOnline.
  ///
  /// In en, this message translates to:
  /// **'Connectors online'**
  String get overviewConnectorsOnline;

  /// No description provided for @overviewEdges.
  ///
  /// In en, this message translates to:
  /// **'Edges'**
  String get overviewEdges;

  /// No description provided for @overviewBlocksHour.
  ///
  /// In en, this message translates to:
  /// **'Blocks in the last hour'**
  String get overviewBlocksHour;

  /// No description provided for @overviewChartTitle.
  ///
  /// In en, this message translates to:
  /// **'Verdicts by layer (last {count} flows)'**
  String overviewChartTitle(int count);

  /// No description provided for @overviewOf.
  ///
  /// In en, this message translates to:
  /// **'of {total}'**
  String overviewOf(int total);

  /// No description provided for @verdictAllow.
  ///
  /// In en, this message translates to:
  /// **'Allowed'**
  String get verdictAllow;

  /// No description provided for @verdictBlock.
  ///
  /// In en, this message translates to:
  /// **'Blocked'**
  String get verdictBlock;

  /// No description provided for @verdictOther.
  ///
  /// In en, this message translates to:
  /// **'Other'**
  String get verdictOther;

  /// No description provided for @msgSettingsSaved.
  ///
  /// In en, this message translates to:
  /// **'Settings saved'**
  String get msgSettingsSaved;

  /// No description provided for @navAdminTokens.
  ///
  /// In en, this message translates to:
  /// **'Admin tokens'**
  String get navAdminTokens;

  /// No description provided for @adminTokensCreate.
  ///
  /// In en, this message translates to:
  /// **'New admin token'**
  String get adminTokensCreate;

  /// No description provided for @adminTokensCreateHelp.
  ///
  /// In en, this message translates to:
  /// **'An admin token administers this tenant only: users, policy, private apps, connectors, devices and activity. It cannot see other tenants, create tenants or manage Edges.'**
  String get adminTokensCreateHelp;

  /// No description provided for @adminTokensNameHint.
  ///
  /// In en, this message translates to:
  /// **'who or what uses it, e.g. ops team'**
  String get adminTokensNameHint;

  /// No description provided for @adminTokensFieldDays.
  ///
  /// In en, this message translates to:
  /// **'Valid for (days)'**
  String get adminTokensFieldDays;

  /// No description provided for @adminTokensFieldDaysHelp.
  ///
  /// In en, this message translates to:
  /// **'From 1 to 365 days'**
  String get adminTokensFieldDaysHelp;

  /// No description provided for @adminTokensCreated.
  ///
  /// In en, this message translates to:
  /// **'Admin token {name} created'**
  String adminTokensCreated(String name);

  /// No description provided for @adminTokensShownOnce.
  ///
  /// In en, this message translates to:
  /// **'This token is shown only once. Copy it now and store it in a password manager.'**
  String get adminTokensShownOnce;

  /// No description provided for @adminTokensUseHelp.
  ///
  /// In en, this message translates to:
  /// **'Sign in to the portal with it, or use it with opensasectl (-token-file or \$OPENSASE_ADMIN_TOKEN).'**
  String get adminTokensUseHelp;

  /// No description provided for @adminTokensEmpty.
  ///
  /// In en, this message translates to:
  /// **'No admin tokens for this tenant yet'**
  String get adminTokensEmpty;

  /// No description provided for @adminTokensThisSession.
  ///
  /// In en, this message translates to:
  /// **'(this session)'**
  String get adminTokensThisSession;

  /// No description provided for @adminTokensRevokeOwn.
  ///
  /// In en, this message translates to:
  /// **'This is the token of the current session: you will be signed out.'**
  String get adminTokensRevokeOwn;

  /// No description provided for @revokeConfirmAdminToken.
  ///
  /// In en, this message translates to:
  /// **'The token stops working at once. This cannot be undone.'**
  String get revokeConfirmAdminToken;

  /// No description provided for @fieldExpires.
  ///
  /// In en, this message translates to:
  /// **'Expires'**
  String get fieldExpires;

  /// No description provided for @fieldLastUsed.
  ///
  /// In en, this message translates to:
  /// **'Last used'**
  String get fieldLastUsed;

  /// No description provided for @statusExpired.
  ///
  /// In en, this message translates to:
  /// **'Expired'**
  String get statusExpired;
}

class _AppLocalizationsDelegate extends LocalizationsDelegate<AppLocalizations> {
  const _AppLocalizationsDelegate();

  @override
  Future<AppLocalizations> load(Locale locale) {
    return SynchronousFuture<AppLocalizations>(lookupAppLocalizations(locale));
  }

  @override
  bool isSupported(Locale locale) => <String>['en', 'it'].contains(locale.languageCode);

  @override
  bool shouldReload(_AppLocalizationsDelegate old) => false;
}

AppLocalizations lookupAppLocalizations(Locale locale) {
  // Lookup logic when only language code is specified.
  switch (locale.languageCode) {
    case 'en':
      return AppLocalizationsEn();
    case 'it':
      return AppLocalizationsIt();
  }

  throw FlutterError(
    'AppLocalizations.delegate failed to load unsupported locale "$locale". This is likely '
    'an issue with the localizations generation tool. Please file an issue '
    'on GitHub with a reproducible sample app and the gen-l10n configuration '
    'that was used.',
  );
}
