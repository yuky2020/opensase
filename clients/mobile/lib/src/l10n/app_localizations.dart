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

  /// No description provided for @stateConnected.
  ///
  /// In en, this message translates to:
  /// **'Connected'**
  String get stateConnected;

  /// No description provided for @stateConnecting.
  ///
  /// In en, this message translates to:
  /// **'Connecting…'**
  String get stateConnecting;

  /// No description provided for @stateDisconnected.
  ///
  /// In en, this message translates to:
  /// **'Disconnected'**
  String get stateDisconnected;

  /// No description provided for @stateError.
  ///
  /// In en, this message translates to:
  /// **'Error'**
  String get stateError;

  /// No description provided for @navHome.
  ///
  /// In en, this message translates to:
  /// **'Home'**
  String get navHome;

  /// No description provided for @navApps.
  ///
  /// In en, this message translates to:
  /// **'Apps'**
  String get navApps;

  /// No description provided for @navRules.
  ///
  /// In en, this message translates to:
  /// **'Rules'**
  String get navRules;

  /// No description provided for @navDns.
  ///
  /// In en, this message translates to:
  /// **'DNS'**
  String get navDns;

  /// No description provided for @navActivity.
  ///
  /// In en, this message translates to:
  /// **'Activity'**
  String get navActivity;

  /// No description provided for @navStats.
  ///
  /// In en, this message translates to:
  /// **'Statistics'**
  String get navStats;

  /// No description provided for @navSettings.
  ///
  /// In en, this message translates to:
  /// **'Settings'**
  String get navSettings;

  /// No description provided for @actionBack.
  ///
  /// In en, this message translates to:
  /// **'Back'**
  String get actionBack;

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

  /// No description provided for @actionSearch.
  ///
  /// In en, this message translates to:
  /// **'Search'**
  String get actionSearch;

  /// No description provided for @actionClear.
  ///
  /// In en, this message translates to:
  /// **'Clear'**
  String get actionClear;

  /// No description provided for @actionDone.
  ///
  /// In en, this message translates to:
  /// **'Done'**
  String get actionDone;

  /// No description provided for @msgSaved.
  ///
  /// In en, this message translates to:
  /// **'Saved. A new policy snapshot was issued.'**
  String get msgSaved;

  /// No description provided for @msgForbidden.
  ///
  /// In en, this message translates to:
  /// **'Your organization does not allow personal rules.'**
  String get msgForbidden;

  /// No description provided for @msgError.
  ///
  /// In en, this message translates to:
  /// **'Error: {error}'**
  String msgError(String error);

  /// No description provided for @companyPolicy.
  ///
  /// In en, this message translates to:
  /// **'Company policy'**
  String get companyPolicy;

  /// No description provided for @companyPolicyLocked.
  ///
  /// In en, this message translates to:
  /// **'Set by your company policy'**
  String get companyPolicyLocked;

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

  /// No description provided for @verdictAsk.
  ///
  /// In en, this message translates to:
  /// **'Ask cloud'**
  String get verdictAsk;

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
  /// **'Ask'**
  String get actionAsk;

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

  /// No description provided for @emptyNothingHere.
  ///
  /// In en, this message translates to:
  /// **'Nothing here yet'**
  String get emptyNothingHere;

  /// No description provided for @onboardingTitle.
  ///
  /// In en, this message translates to:
  /// **'Enroll this device'**
  String get onboardingTitle;

  /// No description provided for @onboardingSubtitle.
  ///
  /// In en, this message translates to:
  /// **'Connect this device to your organization. All traffic is filtered on the device and protected by a quantum-safe tunnel.'**
  String get onboardingSubtitle;

  /// No description provided for @onboardingControlUrl.
  ///
  /// In en, this message translates to:
  /// **'Control Plane URL'**
  String get onboardingControlUrl;

  /// No description provided for @onboardingControlUrlInvalid.
  ///
  /// In en, this message translates to:
  /// **'The URL must start with https://'**
  String get onboardingControlUrlInvalid;

  /// No description provided for @onboardingKey.
  ///
  /// In en, this message translates to:
  /// **'Provisioning key'**
  String get onboardingKey;

  /// No description provided for @onboardingKeyHint.
  ///
  /// In en, this message translates to:
  /// **'Provided by your administrator'**
  String get onboardingKeyHint;

  /// No description provided for @onboardingDeviceName.
  ///
  /// In en, this message translates to:
  /// **'Device name'**
  String get onboardingDeviceName;

  /// No description provided for @onboardingEnroll.
  ///
  /// In en, this message translates to:
  /// **'Enroll'**
  String get onboardingEnroll;

  /// No description provided for @onboardingEnrolling.
  ///
  /// In en, this message translates to:
  /// **'Enrolling…'**
  String get onboardingEnrolling;

  /// No description provided for @onboardingFailed.
  ///
  /// In en, this message translates to:
  /// **'Enrollment failed: {error}'**
  String onboardingFailed(String error);

  /// No description provided for @homeProtection.
  ///
  /// In en, this message translates to:
  /// **'Protection'**
  String get homeProtection;

  /// No description provided for @homeToggleOn.
  ///
  /// In en, this message translates to:
  /// **'Your traffic is protected'**
  String get homeToggleOn;

  /// No description provided for @homeToggleOff.
  ///
  /// In en, this message translates to:
  /// **'Tap to connect'**
  String get homeToggleOff;

  /// No description provided for @homeEdge.
  ///
  /// In en, this message translates to:
  /// **'Edge'**
  String get homeEdge;

  /// No description provided for @homeSnapshotVersion.
  ///
  /// In en, this message translates to:
  /// **'Policy version'**
  String get homeSnapshotVersion;

  /// No description provided for @homeStale.
  ///
  /// In en, this message translates to:
  /// **'The policy is out of date. It is still enforced, but it could not be refreshed.'**
  String get homeStale;

  /// No description provided for @homeQuantumSafe.
  ///
  /// In en, this message translates to:
  /// **'Quantum-safe: {kex}'**
  String homeQuantumSafe(String kex);

  /// No description provided for @homeToday.
  ///
  /// In en, this message translates to:
  /// **'Today'**
  String get homeToday;

  /// No description provided for @homeAllowed.
  ///
  /// In en, this message translates to:
  /// **'Allowed'**
  String get homeAllowed;

  /// No description provided for @homeBlocked.
  ///
  /// In en, this message translates to:
  /// **'Blocked'**
  String get homeBlocked;

  /// No description provided for @homeDnsBlocked.
  ///
  /// In en, this message translates to:
  /// **'DNS blocked'**
  String get homeDnsBlocked;

  /// No description provided for @homeTopBlocked.
  ///
  /// In en, this message translates to:
  /// **'Top blocked apps'**
  String get homeTopBlocked;

  /// No description provided for @homeNoBlocked.
  ///
  /// In en, this message translates to:
  /// **'No blocked connections yet'**
  String get homeNoBlocked;

  /// No description provided for @homeBlockedCount.
  ///
  /// In en, this message translates to:
  /// **'{count} blocked'**
  String homeBlockedCount(int count);

  /// No description provided for @homeFailed.
  ///
  /// In en, this message translates to:
  /// **'Could not connect: {error}'**
  String homeFailed(String error);

  /// No description provided for @appsSearchHint.
  ///
  /// In en, this message translates to:
  /// **'Search apps'**
  String get appsSearchHint;

  /// No description provided for @appsFilterAll.
  ///
  /// In en, this message translates to:
  /// **'All'**
  String get appsFilterAll;

  /// No description provided for @appsFilterUser.
  ///
  /// In en, this message translates to:
  /// **'User'**
  String get appsFilterUser;

  /// No description provided for @appsFilterSystem.
  ///
  /// In en, this message translates to:
  /// **'System'**
  String get appsFilterSystem;

  /// No description provided for @appsFilterInternet.
  ///
  /// In en, this message translates to:
  /// **'With internet'**
  String get appsFilterInternet;

  /// No description provided for @appsLoading.
  ///
  /// In en, this message translates to:
  /// **'Loading apps…'**
  String get appsLoading;

  /// No description provided for @appsEmpty.
  ///
  /// In en, this message translates to:
  /// **'No apps match the filter'**
  String get appsEmpty;

  /// No description provided for @appsUserRulesDisabled.
  ///
  /// In en, this message translates to:
  /// **'Your organization manages app access. Toggles are read-only.'**
  String get appsUserRulesDisabled;

  /// No description provided for @appDetailRecent.
  ///
  /// In en, this message translates to:
  /// **'Recent connections'**
  String get appDetailRecent;

  /// No description provided for @appDetailNoFlows.
  ///
  /// In en, this message translates to:
  /// **'No connections recorded'**
  String get appDetailNoFlows;

  /// No description provided for @appDetailBlockAll.
  ///
  /// In en, this message translates to:
  /// **'Block all'**
  String get appDetailBlockAll;

  /// No description provided for @appDetailAllowAll.
  ///
  /// In en, this message translates to:
  /// **'Allow all'**
  String get appDetailAllowAll;

  /// No description provided for @appDetailTraffic.
  ///
  /// In en, this message translates to:
  /// **'Traffic'**
  String get appDetailTraffic;

  /// No description provided for @appDetailIn.
  ///
  /// In en, this message translates to:
  /// **'Received'**
  String get appDetailIn;

  /// No description provided for @appDetailOut.
  ///
  /// In en, this message translates to:
  /// **'Sent'**
  String get appDetailOut;

  /// No description provided for @appDetailAccess.
  ///
  /// In en, this message translates to:
  /// **'Network access'**
  String get appDetailAccess;

  /// No description provided for @originDefault.
  ///
  /// In en, this message translates to:
  /// **'Default'**
  String get originDefault;

  /// No description provided for @originUser.
  ///
  /// In en, this message translates to:
  /// **'Your setting'**
  String get originUser;

  /// No description provided for @originLockdown.
  ///
  /// In en, this message translates to:
  /// **'Lockdown'**
  String get originLockdown;

  /// No description provided for @rulesTenant.
  ///
  /// In en, this message translates to:
  /// **'Company policy'**
  String get rulesTenant;

  /// No description provided for @rulesTenantHint.
  ///
  /// In en, this message translates to:
  /// **'Mandatory rules from your organization, evaluated first.'**
  String get rulesTenantHint;

  /// No description provided for @rulesUser.
  ///
  /// In en, this message translates to:
  /// **'My rules'**
  String get rulesUser;

  /// No description provided for @rulesUserHint.
  ///
  /// In en, this message translates to:
  /// **'Evaluated after the company policy. Drag the handle to reorder.'**
  String get rulesUserHint;

  /// No description provided for @rulesUserDisabled.
  ///
  /// In en, this message translates to:
  /// **'Your organization does not allow personal rules.'**
  String get rulesUserDisabled;

  /// No description provided for @rulesEmptyUser.
  ///
  /// In en, this message translates to:
  /// **'No personal rules'**
  String get rulesEmptyUser;

  /// No description provided for @rulesAdd.
  ///
  /// In en, this message translates to:
  /// **'New rule'**
  String get rulesAdd;

  /// No description provided for @rulesEditTitle.
  ///
  /// In en, this message translates to:
  /// **'Edit rule'**
  String get rulesEditTitle;

  /// No description provided for @rulesNewTitle.
  ///
  /// In en, this message translates to:
  /// **'New rule'**
  String get rulesNewTitle;

  /// No description provided for @rulesFieldAction.
  ///
  /// In en, this message translates to:
  /// **'Action'**
  String get rulesFieldAction;

  /// No description provided for @rulesFieldDescription.
  ///
  /// In en, this message translates to:
  /// **'Description'**
  String get rulesFieldDescription;

  /// No description provided for @rulesFieldProtocols.
  ///
  /// In en, this message translates to:
  /// **'Protocols'**
  String get rulesFieldProtocols;

  /// No description provided for @rulesFieldCidrs.
  ///
  /// In en, this message translates to:
  /// **'Destination IPs / CIDRs'**
  String get rulesFieldCidrs;

  /// No description provided for @rulesFieldCidrsHint.
  ///
  /// In en, this message translates to:
  /// **'e.g. 10.0.0.0/8, 2001:db8::/32'**
  String get rulesFieldCidrsHint;

  /// No description provided for @rulesFieldPorts.
  ///
  /// In en, this message translates to:
  /// **'Ports'**
  String get rulesFieldPorts;

  /// No description provided for @rulesFieldPortsHint.
  ///
  /// In en, this message translates to:
  /// **'e.g. 443, 8000-8100'**
  String get rulesFieldPortsHint;

  /// No description provided for @rulesFieldDomains.
  ///
  /// In en, this message translates to:
  /// **'Domains'**
  String get rulesFieldDomains;

  /// No description provided for @rulesFieldDomainsHint.
  ///
  /// In en, this message translates to:
  /// **'e.g. example.com, *.ads.example'**
  String get rulesFieldDomainsHint;

  /// No description provided for @rulesFieldNetworks.
  ///
  /// In en, this message translates to:
  /// **'Networks'**
  String get rulesFieldNetworks;

  /// No description provided for @rulesFieldApps.
  ///
  /// In en, this message translates to:
  /// **'Apps'**
  String get rulesFieldApps;

  /// No description provided for @rulesFieldAppsAny.
  ///
  /// In en, this message translates to:
  /// **'Any app'**
  String get rulesFieldAppsAny;

  /// No description provided for @rulesFieldAppsChoose.
  ///
  /// In en, this message translates to:
  /// **'Choose apps'**
  String get rulesFieldAppsChoose;

  /// No description provided for @rulesFieldLog.
  ///
  /// In en, this message translates to:
  /// **'Log matching connections'**
  String get rulesFieldLog;

  /// No description provided for @rulesFieldPriority.
  ///
  /// In en, this message translates to:
  /// **'Priority'**
  String get rulesFieldPriority;

  /// No description provided for @rulesFieldPriorityHint.
  ///
  /// In en, this message translates to:
  /// **'Lower runs first'**
  String get rulesFieldPriorityHint;

  /// No description provided for @rulesErrorCidrs.
  ///
  /// In en, this message translates to:
  /// **'Invalid IP or CIDR'**
  String get rulesErrorCidrs;

  /// No description provided for @rulesErrorPorts.
  ///
  /// In en, this message translates to:
  /// **'Invalid port or range'**
  String get rulesErrorPorts;

  /// No description provided for @rulesErrorDomains.
  ///
  /// In en, this message translates to:
  /// **'Invalid domain'**
  String get rulesErrorDomains;

  /// No description provided for @rulesErrorPriority.
  ///
  /// In en, this message translates to:
  /// **'Must be a number'**
  String get rulesErrorPriority;

  /// No description provided for @rulesErrorEmpty.
  ///
  /// In en, this message translates to:
  /// **'Add at least one condition'**
  String get rulesErrorEmpty;

  /// No description provided for @rulesAny.
  ///
  /// In en, this message translates to:
  /// **'Any traffic'**
  String get rulesAny;

  /// No description provided for @rulesPriorityShort.
  ///
  /// In en, this message translates to:
  /// **'#{priority}'**
  String rulesPriorityShort(int priority);

  /// No description provided for @rulesLogged.
  ///
  /// In en, this message translates to:
  /// **'Logged'**
  String get rulesLogged;

  /// No description provided for @rulesDeleteConfirm.
  ///
  /// In en, this message translates to:
  /// **'Delete this rule?'**
  String get rulesDeleteConfirm;

  /// No description provided for @dnsBlocklists.
  ///
  /// In en, this message translates to:
  /// **'Blocklists'**
  String get dnsBlocklists;

  /// No description provided for @dnsBlocklistsHint.
  ///
  /// In en, this message translates to:
  /// **'Managed by your organization'**
  String get dnsBlocklistsHint;

  /// No description provided for @dnsDomainCount.
  ///
  /// In en, this message translates to:
  /// **'{count} domains'**
  String dnsDomainCount(int count);

  /// No description provided for @dnsBlockResponse.
  ///
  /// In en, this message translates to:
  /// **'Blocked queries answer with {response}'**
  String dnsBlockResponse(String response);

  /// No description provided for @dnsTenantDomains.
  ///
  /// In en, this message translates to:
  /// **'Company domain rules'**
  String get dnsTenantDomains;

  /// No description provided for @dnsCustom.
  ///
  /// In en, this message translates to:
  /// **'My domains'**
  String get dnsCustom;

  /// No description provided for @dnsCustomHint.
  ///
  /// In en, this message translates to:
  /// **'Saved as personal rules matching only the domain'**
  String get dnsCustomHint;

  /// No description provided for @dnsAddHint.
  ///
  /// In en, this message translates to:
  /// **'example.com or *.example.com'**
  String get dnsAddHint;

  /// No description provided for @dnsAddBlock.
  ///
  /// In en, this message translates to:
  /// **'Block'**
  String get dnsAddBlock;

  /// No description provided for @dnsAddAllow.
  ///
  /// In en, this message translates to:
  /// **'Allow'**
  String get dnsAddAllow;

  /// No description provided for @dnsInvalid.
  ///
  /// In en, this message translates to:
  /// **'Invalid domain'**
  String get dnsInvalid;

  /// No description provided for @dnsEmpty.
  ///
  /// In en, this message translates to:
  /// **'No custom domains'**
  String get dnsEmpty;

  /// No description provided for @dnsBlockedToday.
  ///
  /// In en, this message translates to:
  /// **'{count} DNS queries blocked today'**
  String dnsBlockedToday(int count);

  /// No description provided for @activityPause.
  ///
  /// In en, this message translates to:
  /// **'Pause'**
  String get activityPause;

  /// No description provided for @activityResume.
  ///
  /// In en, this message translates to:
  /// **'Resume'**
  String get activityResume;

  /// No description provided for @activityFilterAll.
  ///
  /// In en, this message translates to:
  /// **'All'**
  String get activityFilterAll;

  /// No description provided for @activityFilterAllowed.
  ///
  /// In en, this message translates to:
  /// **'Allowed'**
  String get activityFilterAllowed;

  /// No description provided for @activityFilterBlocked.
  ///
  /// In en, this message translates to:
  /// **'Blocked'**
  String get activityFilterBlocked;

  /// No description provided for @activityFilterApp.
  ///
  /// In en, this message translates to:
  /// **'App'**
  String get activityFilterApp;

  /// No description provided for @activityAllApps.
  ///
  /// In en, this message translates to:
  /// **'All apps'**
  String get activityAllApps;

  /// No description provided for @activityEmpty.
  ///
  /// In en, this message translates to:
  /// **'No connections yet. Connect to see live traffic.'**
  String get activityEmpty;

  /// No description provided for @activityPaused.
  ///
  /// In en, this message translates to:
  /// **'Paused'**
  String get activityPaused;

  /// No description provided for @activityRule.
  ///
  /// In en, this message translates to:
  /// **'{layer} · {rule}'**
  String activityRule(String layer, String rule);

  /// No description provided for @layerTenant.
  ///
  /// In en, this message translates to:
  /// **'company'**
  String get layerTenant;

  /// No description provided for @layerUser.
  ///
  /// In en, this message translates to:
  /// **'my rule'**
  String get layerUser;

  /// No description provided for @layerApp.
  ///
  /// In en, this message translates to:
  /// **'app'**
  String get layerApp;

  /// No description provided for @layerDefault.
  ///
  /// In en, this message translates to:
  /// **'default'**
  String get layerDefault;

  /// No description provided for @layerLockdown.
  ///
  /// In en, this message translates to:
  /// **'lockdown'**
  String get layerLockdown;

  /// No description provided for @layerCloud.
  ///
  /// In en, this message translates to:
  /// **'cloud'**
  String get layerCloud;

  /// No description provided for @layerDns.
  ///
  /// In en, this message translates to:
  /// **'DNS'**
  String get layerDns;

  /// No description provided for @statsSort.
  ///
  /// In en, this message translates to:
  /// **'Sort by'**
  String get statsSort;

  /// No description provided for @statsSortTotal.
  ///
  /// In en, this message translates to:
  /// **'Total'**
  String get statsSortTotal;

  /// No description provided for @statsSortIn.
  ///
  /// In en, this message translates to:
  /// **'Received'**
  String get statsSortIn;

  /// No description provided for @statsSortOut.
  ///
  /// In en, this message translates to:
  /// **'Sent'**
  String get statsSortOut;

  /// No description provided for @statsSortAllowed.
  ///
  /// In en, this message translates to:
  /// **'Allowed'**
  String get statsSortAllowed;

  /// No description provided for @statsSortBlocked.
  ///
  /// In en, this message translates to:
  /// **'Blocked'**
  String get statsSortBlocked;

  /// No description provided for @statsTotal.
  ///
  /// In en, this message translates to:
  /// **'↓ {received} · ↑ {sent}'**
  String statsTotal(String received, String sent);

  /// No description provided for @statsCounts.
  ///
  /// In en, this message translates to:
  /// **'{allowed} allowed · {blocked} blocked'**
  String statsCounts(int allowed, int blocked);

  /// No description provided for @statsEmpty.
  ///
  /// In en, this message translates to:
  /// **'No traffic recorded yet'**
  String get statsEmpty;

  /// No description provided for @settingsAlwaysOn.
  ///
  /// In en, this message translates to:
  /// **'Always-on VPN'**
  String get settingsAlwaysOn;

  /// No description provided for @settingsAlwaysOnDesc.
  ///
  /// In en, this message translates to:
  /// **'For the strongest protection, open the system VPN settings, tap the gear next to OpenSASE and enable “Always-on VPN” and “Block connections without VPN”.'**
  String get settingsAlwaysOnDesc;

  /// No description provided for @settingsOpenVpnSettings.
  ///
  /// In en, this message translates to:
  /// **'Open VPN settings'**
  String get settingsOpenVpnSettings;

  /// No description provided for @settingsConnectOnBoot.
  ///
  /// In en, this message translates to:
  /// **'Reconnect after restart'**
  String get settingsConnectOnBoot;

  /// No description provided for @settingsConnectOnBootDesc.
  ///
  /// In en, this message translates to:
  /// **'Used only when always-on VPN is off'**
  String get settingsConnectOnBootDesc;

  /// No description provided for @settingsPolicy.
  ///
  /// In en, this message translates to:
  /// **'Policy'**
  String get settingsPolicy;

  /// No description provided for @settingsDefaultAction.
  ///
  /// In en, this message translates to:
  /// **'Default for unknown apps'**
  String get settingsDefaultAction;

  /// No description provided for @settingsLockdown.
  ///
  /// In en, this message translates to:
  /// **'Lockdown mode'**
  String get settingsLockdown;

  /// No description provided for @settingsLockdownOn.
  ///
  /// In en, this message translates to:
  /// **'On: only allowlisted apps can connect'**
  String get settingsLockdownOn;

  /// No description provided for @settingsLockdownOff.
  ///
  /// In en, this message translates to:
  /// **'Off'**
  String get settingsLockdownOff;

  /// No description provided for @settingsUserRules.
  ///
  /// In en, this message translates to:
  /// **'Personal rules'**
  String get settingsUserRules;

  /// No description provided for @settingsUserRulesAllowed.
  ///
  /// In en, this message translates to:
  /// **'Allowed by your organization'**
  String get settingsUserRulesAllowed;

  /// No description provided for @settingsUserRulesDenied.
  ///
  /// In en, this message translates to:
  /// **'Not allowed by your organization'**
  String get settingsUserRulesDenied;

  /// No description provided for @settingsSnapshot.
  ///
  /// In en, this message translates to:
  /// **'Policy snapshot'**
  String get settingsSnapshot;

  /// No description provided for @settingsSnapshotValue.
  ///
  /// In en, this message translates to:
  /// **'Version {version} · expires {expires}'**
  String settingsSnapshotValue(int version, String expires);

  /// No description provided for @settingsDevice.
  ///
  /// In en, this message translates to:
  /// **'Device'**
  String get settingsDevice;

  /// No description provided for @settingsExportLogs.
  ///
  /// In en, this message translates to:
  /// **'Export connection log'**
  String get settingsExportLogs;

  /// No description provided for @settingsExportLogsDesc.
  ///
  /// In en, this message translates to:
  /// **'Save the recent connections as JSON'**
  String get settingsExportLogsDesc;

  /// No description provided for @settingsExportDone.
  ///
  /// In en, this message translates to:
  /// **'Log exported'**
  String get settingsExportDone;

  /// No description provided for @settingsUnenroll.
  ///
  /// In en, this message translates to:
  /// **'Unenroll device'**
  String get settingsUnenroll;

  /// No description provided for @settingsUnenrollDesc.
  ///
  /// In en, this message translates to:
  /// **'Removes the device certificate and keys from this phone'**
  String get settingsUnenrollDesc;

  /// No description provided for @settingsUnenrollConfirm.
  ///
  /// In en, this message translates to:
  /// **'Unenroll this device? You will need a new provisioning key to enroll again.'**
  String get settingsUnenrollConfirm;

  /// No description provided for @settingsAbout.
  ///
  /// In en, this message translates to:
  /// **'About'**
  String get settingsAbout;

  /// No description provided for @settingsVersion.
  ///
  /// In en, this message translates to:
  /// **'Version {version} · engine {engine}'**
  String settingsVersion(String version, String engine);

  /// No description provided for @settingsLicenses.
  ///
  /// In en, this message translates to:
  /// **'Open-source licences'**
  String get settingsLicenses;

  /// No description provided for @settingsLicensesText.
  ///
  /// In en, this message translates to:
  /// **'OpenSASE uses Flutter, Material and the Dart SDK (BSD 3-Clause), Riverpod, go_router and json_serializable (MIT / BSD 3-Clause), AndroidX and Kotlin (Apache License 2.0), the Go standard library (BSD 3-Clause) and wireguard-go (MIT). No analytics or Google Play Services are included. Tap for the full list.'**
  String get settingsLicensesText;

  /// No description provided for @settingsAppearance.
  ///
  /// In en, this message translates to:
  /// **'Appearance'**
  String get settingsAppearance;

  /// No description provided for @engineFake.
  ///
  /// In en, this message translates to:
  /// **'Demo engine (fake data)'**
  String get engineFake;

  /// No description provided for @engineNative.
  ///
  /// In en, this message translates to:
  /// **'Native engine'**
  String get engineNative;

  /// No description provided for @appDetailUid.
  ///
  /// In en, this message translates to:
  /// **'UID {uid}'**
  String appDetailUid(int uid);

  /// No description provided for @onboardingCode.
  ///
  /// In en, this message translates to:
  /// **'Enrollment code'**
  String get onboardingCode;

  /// No description provided for @onboardingCodeHint.
  ///
  /// In en, this message translates to:
  /// **'Paste the code from your administrator (URL and key)'**
  String get onboardingCodeHint;

  /// No description provided for @onboardingCodeInvalid.
  ///
  /// In en, this message translates to:
  /// **'Not a valid enrollment code'**
  String get onboardingCodeInvalid;

  /// No description provided for @onboardingPinned.
  ///
  /// In en, this message translates to:
  /// **'Server certificate pinned (sha256)'**
  String get onboardingPinned;

  /// No description provided for @onboardingScan.
  ///
  /// In en, this message translates to:
  /// **'Scan QR code'**
  String get onboardingScan;

  /// No description provided for @onboardingScanSoon.
  ///
  /// In en, this message translates to:
  /// **'QR scanning is coming soon. Paste the code instead.'**
  String get onboardingScanSoon;

  /// No description provided for @onboardingOr.
  ///
  /// In en, this message translates to:
  /// **'or enter the details'**
  String get onboardingOr;

  /// No description provided for @settingsEngine.
  ///
  /// In en, this message translates to:
  /// **'Engine'**
  String get settingsEngine;

  /// No description provided for @homeLastHandshake.
  ///
  /// In en, this message translates to:
  /// **'Last handshake'**
  String get homeLastHandshake;

  /// No description provided for @homeNetwork.
  ///
  /// In en, this message translates to:
  /// **'Network'**
  String get homeNetwork;

  /// No description provided for @rulesOrderSaved.
  ///
  /// In en, this message translates to:
  /// **'Rule order saved'**
  String get rulesOrderSaved;

  /// No description provided for @activityLive.
  ///
  /// In en, this message translates to:
  /// **'Live'**
  String get activityLive;

  /// No description provided for @statsDns.
  ///
  /// In en, this message translates to:
  /// **'DNS {queries} queries · {blocked} blocked'**
  String statsDns(int queries, int blocked);

  /// No description provided for @vpnConsentDenied.
  ///
  /// In en, this message translates to:
  /// **'VPN permission was denied'**
  String get vpnConsentDenied;

  /// No description provided for @settingsCertificate.
  ///
  /// In en, this message translates to:
  /// **'Device certificate'**
  String get settingsCertificate;

  /// No description provided for @settingsCertificateExpires.
  ///
  /// In en, this message translates to:
  /// **'Expires {date}'**
  String settingsCertificateExpires(String date);

  /// No description provided for @onboardingCodeApplied.
  ///
  /// In en, this message translates to:
  /// **'Code applied: check the details below and tap Enroll'**
  String get onboardingCodeApplied;

  /// No description provided for @daemonNotRunning.
  ///
  /// In en, this message translates to:
  /// **'The OpenSASE service is not running'**
  String get daemonNotRunning;

  /// No description provided for @daemonHintLinux.
  ///
  /// In en, this message translates to:
  /// **'sudo systemctl start opensased'**
  String get daemonHintLinux;

  /// No description provided for @daemonHintWindows.
  ///
  /// In en, this message translates to:
  /// **'start the OpenSASE service'**
  String get daemonHintWindows;

  /// No description provided for @onboardingOrSso.
  ///
  /// In en, this message translates to:
  /// **'Sign in with your organization'**
  String get onboardingOrSso;

  /// No description provided for @onboardingSsoTitle.
  ///
  /// In en, this message translates to:
  /// **'Sign in with your organization'**
  String get onboardingSsoTitle;

  /// No description provided for @onboardingSsoTenant.
  ///
  /// In en, this message translates to:
  /// **'Organization ID'**
  String get onboardingSsoTenant;

  /// No description provided for @onboardingSsoTenantHint.
  ///
  /// In en, this message translates to:
  /// **'e.g. acme-corp'**
  String get onboardingSsoTenantHint;

  /// No description provided for @onboardingSsoTenantInvalid.
  ///
  /// In en, this message translates to:
  /// **'Only lowercase letters, numbers, and hyphens are allowed'**
  String get onboardingSsoTenantInvalid;

  /// No description provided for @onboardingSsoButton.
  ///
  /// In en, this message translates to:
  /// **'Sign in'**
  String get onboardingSsoButton;

  /// No description provided for @onboardingSsoError.
  ///
  /// In en, this message translates to:
  /// **'Single sign-on failed: session expired or invalid state'**
  String get onboardingSsoError;

  /// No description provided for @onboardingOrKey.
  ///
  /// In en, this message translates to:
  /// **'or enter a provisioning key'**
  String get onboardingOrKey;

  /// No description provided for @postureAttention.
  ///
  /// In en, this message translates to:
  /// **'Device needs attention'**
  String get postureAttention;

  /// No description provided for @postureHintOsVersion.
  ///
  /// In en, this message translates to:
  /// **'Update Android'**
  String get postureHintOsVersion;

  /// No description provided for @postureHintClientVersion.
  ///
  /// In en, this message translates to:
  /// **'Update the OpenSASE app'**
  String get postureHintClientVersion;

  /// No description provided for @postureHintDiskEncryption.
  ///
  /// In en, this message translates to:
  /// **'Turn on device encryption'**
  String get postureHintDiskEncryption;

  /// No description provided for @postureHintScreenLock.
  ///
  /// In en, this message translates to:
  /// **'Set a screen lock'**
  String get postureHintScreenLock;

  /// No description provided for @postureHintManaged.
  ///
  /// In en, this message translates to:
  /// **'Use your work profile or a company device'**
  String get postureHintManaged;

  /// No description provided for @postureHintFirewall.
  ///
  /// In en, this message translates to:
  /// **'Turn on device firewall'**
  String get postureHintFirewall;
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
