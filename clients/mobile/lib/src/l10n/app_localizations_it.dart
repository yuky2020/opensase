// ignore: unused_import
import 'package:intl/intl.dart' as intl;

import 'app_localizations.dart';

// ignore_for_file: type=lint

/// The translations for Italian (`it`).
class AppLocalizationsIt extends AppLocalizations {
  AppLocalizationsIt([String locale = 'it']) : super(locale);

  @override
  String get stateConnected => 'Connesso';

  @override
  String get stateConnecting => 'Connessione in corso…';

  @override
  String get stateDisconnected => 'Disconnesso';

  @override
  String get stateError => 'Errore';

  @override
  String get navHome => 'Home';

  @override
  String get navApps => 'App';

  @override
  String get navRules => 'Regole';

  @override
  String get navDns => 'DNS';

  @override
  String get navActivity => 'Attività';

  @override
  String get navStats => 'Statistiche';

  @override
  String get navSettings => 'Impostazioni';

  @override
  String get actionBack => 'Indietro';

  @override
  String get actionSave => 'Salva';

  @override
  String get actionCancel => 'Annulla';

  @override
  String get actionDelete => 'Elimina';

  @override
  String get actionAdd => 'Aggiungi';

  @override
  String get actionEdit => 'Modifica';

  @override
  String get actionSearch => 'Cerca';

  @override
  String get actionClear => 'Cancella';

  @override
  String get actionDone => 'Fine';

  @override
  String get msgSaved => 'Salvato. È stato emesso un nuovo snapshot della policy.';

  @override
  String get msgForbidden => 'La tua organizzazione non consente regole personali.';

  @override
  String msgError(String error) {
    return 'Errore: $error';
  }

  @override
  String get companyPolicy => 'Policy aziendale';

  @override
  String get companyPolicyLocked => 'Impostato dalla policy aziendale';

  @override
  String get verdictAllow => 'Consentito';

  @override
  String get verdictBlock => 'Bloccato';

  @override
  String get verdictAsk => 'Chiedi al cloud';

  @override
  String get actionAllow => 'Consenti';

  @override
  String get actionBlock => 'Blocca';

  @override
  String get actionAsk => 'Chiedi';

  @override
  String get networkWifi => 'Wi-Fi';

  @override
  String get networkCellular => 'Dati mobili';

  @override
  String get networkRoaming => 'Roaming';

  @override
  String get networkEthernet => 'Ethernet';

  @override
  String get networkUnknown => 'Sconosciuta';

  @override
  String get emptyNothingHere => 'Non c\'è ancora nulla qui';

  @override
  String get onboardingTitle => 'Registra questo dispositivo';

  @override
  String get onboardingSubtitle =>
      'Connetti questo dispositivo alla tua organizzazione. Tutto il traffico viene filtrato sul dispositivo e protetto da un tunnel resistente ai quantum.';

  @override
  String get onboardingControlUrl => 'URL del Control Plane';

  @override
  String get onboardingControlUrlInvalid => 'L\'URL deve iniziare con https://';

  @override
  String get onboardingKey => 'Chiave di provisioning';

  @override
  String get onboardingKeyHint => 'Fornita dal tuo amministratore';

  @override
  String get onboardingDeviceName => 'Nome dispositivo';

  @override
  String get onboardingEnroll => 'Registra';

  @override
  String get onboardingEnrolling => 'Registrazione in corso…';

  @override
  String onboardingFailed(String error) {
    return 'Registrazione non riuscita: $error';
  }

  @override
  String get homeProtection => 'Protezione';

  @override
  String get homeToggleOn => 'Il tuo traffico è protetto';

  @override
  String get homeToggleOff => 'Tocca per connetterti';

  @override
  String get homeEdge => 'Edge';

  @override
  String get homeSnapshotVersion => 'Versione della policy';

  @override
  String get homeStale => 'La policy non è aggiornata. È ancora applicata, ma non è stato possibile aggiornarla.';

  @override
  String homeQuantumSafe(String kex) {
    return 'Resistente ai quantum: $kex';
  }

  @override
  String get homeToday => 'Oggi';

  @override
  String get homeAllowed => 'Consentite';

  @override
  String get homeBlocked => 'Bloccate';

  @override
  String get homeDnsBlocked => 'DNS bloccati';

  @override
  String get homeTopBlocked => 'App più bloccate';

  @override
  String get homeNoBlocked => 'Nessuna connessione bloccata finora';

  @override
  String homeBlockedCount(int count) {
    return '$count bloccate';
  }

  @override
  String homeFailed(String error) {
    return 'Impossibile connettersi: $error';
  }

  @override
  String get appsSearchHint => 'Cerca app';

  @override
  String get appsFilterAll => 'Tutte';

  @override
  String get appsFilterUser => 'Utente';

  @override
  String get appsFilterSystem => 'Sistema';

  @override
  String get appsFilterInternet => 'Con Internet';

  @override
  String get appsLoading => 'Caricamento app in corso…';

  @override
  String get appsEmpty => 'Nessuna app corrisponde al filtro';

  @override
  String get appsUserRulesDisabled =>
      'La tua organizzazione gestisce l\'accesso alle app. Gli interruttori sono di sola lettura.';

  @override
  String get appDetailRecent => 'Connessioni recenti';

  @override
  String get appDetailNoFlows => 'Nessuna connessione registrata';

  @override
  String get appDetailBlockAll => 'Blocca tutto';

  @override
  String get appDetailAllowAll => 'Consenti tutto';

  @override
  String get appDetailTraffic => 'Traffico';

  @override
  String get appDetailIn => 'Ricevuto';

  @override
  String get appDetailOut => 'Inviato';

  @override
  String get appDetailAccess => 'Accesso alla rete';

  @override
  String get originDefault => 'Predefinito';

  @override
  String get originUser => 'La tua impostazione';

  @override
  String get originLockdown => 'Blocco totale';

  @override
  String get rulesTenant => 'Policy aziendale';

  @override
  String get rulesTenantHint => 'Regole obbligatorie della tua organizzazione, valutate per prime.';

  @override
  String get rulesUser => 'Le mie regole';

  @override
  String get rulesUserHint => 'Valutate dopo la policy aziendale. Trascina la maniglia per riordinarle.';

  @override
  String get rulesUserDisabled => 'La tua organizzazione non consente regole personali.';

  @override
  String get rulesEmptyUser => 'Nessuna regola personale';

  @override
  String get rulesAdd => 'Nuova regola';

  @override
  String get rulesEditTitle => 'Modifica regola';

  @override
  String get rulesNewTitle => 'Nuova regola';

  @override
  String get rulesFieldAction => 'Azione';

  @override
  String get rulesFieldDescription => 'Descrizione';

  @override
  String get rulesFieldProtocols => 'Protocolli';

  @override
  String get rulesFieldCidrs => 'IP / CIDR di destinazione';

  @override
  String get rulesFieldCidrsHint => 'es. 10.0.0.0/8, 2001:db8::/32';

  @override
  String get rulesFieldPorts => 'Porte';

  @override
  String get rulesFieldPortsHint => 'es. 443, 8000-8100';

  @override
  String get rulesFieldDomains => 'Domini';

  @override
  String get rulesFieldDomainsHint => 'es. example.com, *.ads.example';

  @override
  String get rulesFieldNetworks => 'Reti';

  @override
  String get rulesFieldApps => 'App';

  @override
  String get rulesFieldAppsAny => 'Qualsiasi app';

  @override
  String get rulesFieldAppsChoose => 'Scegli app';

  @override
  String get rulesFieldLog => 'Registra le connessioni corrispondenti';

  @override
  String get rulesFieldPriority => 'Priorità';

  @override
  String get rulesFieldPriorityHint => 'Il valore più basso viene eseguito prima';

  @override
  String get rulesErrorCidrs => 'IP o CIDR non valido';

  @override
  String get rulesErrorPorts => 'Porta o intervallo non valido';

  @override
  String get rulesErrorDomains => 'Dominio non valido';

  @override
  String get rulesErrorPriority => 'Deve essere un numero';

  @override
  String get rulesErrorEmpty => 'Aggiungi almeno una condizione';

  @override
  String get rulesAny => 'Qualsiasi traffico';

  @override
  String rulesPriorityShort(int priority) {
    return '#$priority';
  }

  @override
  String get rulesLogged => 'Registrato';

  @override
  String get rulesDeleteConfirm => 'Eliminare questa regola?';

  @override
  String get dnsBlocklists => 'Liste di blocco';

  @override
  String get dnsBlocklistsHint => 'Gestite dalla tua organizzazione';

  @override
  String dnsDomainCount(int count) {
    return '$count domini';
  }

  @override
  String dnsBlockResponse(String response) {
    return 'Le query bloccate rispondono con $response';
  }

  @override
  String get dnsTenantDomains => 'Regole di dominio aziendali';

  @override
  String get dnsCustom => 'I miei domini';

  @override
  String get dnsCustomHint => 'Salvate come regole personali che corrispondono solo al dominio';

  @override
  String get dnsAddHint => 'example.com o *.example.com';

  @override
  String get dnsAddBlock => 'Blocca';

  @override
  String get dnsAddAllow => 'Consenti';

  @override
  String get dnsInvalid => 'Dominio non valido';

  @override
  String get dnsEmpty => 'Nessun dominio personalizzato';

  @override
  String dnsBlockedToday(int count) {
    return '$count query DNS bloccate oggi';
  }

  @override
  String get activityPause => 'Pausa';

  @override
  String get activityResume => 'Riprendi';

  @override
  String get activityFilterAll => 'Tutte';

  @override
  String get activityFilterAllowed => 'Consentite';

  @override
  String get activityFilterBlocked => 'Bloccate';

  @override
  String get activityFilterApp => 'App';

  @override
  String get activityAllApps => 'Tutte le app';

  @override
  String get activityEmpty => 'Nessuna connessione registrata. Connettiti per vedere il traffico in tempo reale.';

  @override
  String get activityPaused => 'In pausa';

  @override
  String activityRule(String layer, String rule) {
    return '$layer · $rule';
  }

  @override
  String get layerTenant => 'aziendale';

  @override
  String get layerUser => 'mia regola';

  @override
  String get layerApp => 'app';

  @override
  String get layerDefault => 'predefinito';

  @override
  String get layerLockdown => 'blocco totale';

  @override
  String get layerCloud => 'cloud';

  @override
  String get layerDns => 'DNS';

  @override
  String get statsSort => 'Ordina per';

  @override
  String get statsSortTotal => 'Totale';

  @override
  String get statsSortIn => 'Ricevuto';

  @override
  String get statsSortOut => 'Inviato';

  @override
  String get statsSortAllowed => 'Consentite';

  @override
  String get statsSortBlocked => 'Bloccate';

  @override
  String statsTotal(String received, String sent) {
    return '↓ $received · ↑ $sent';
  }

  @override
  String statsCounts(int allowed, int blocked) {
    return '$allowed consentite · $blocked bloccate';
  }

  @override
  String get statsEmpty => 'Nessun traffico registrato finora';

  @override
  String get settingsAlwaysOn => 'VPN sempre attiva';

  @override
  String get settingsAlwaysOnDesc =>
      'Per la massima protezione, apri le impostazioni VPN di sistema, tocca l\'ingranaggio accanto a OpenSASE e attiva “VPN sempre attiva” e “Blocca connessioni senza VPN”.';

  @override
  String get settingsOpenVpnSettings => 'Apri impostazioni VPN';

  @override
  String get settingsConnectOnBoot => 'Riconnetti dopo il riavvio';

  @override
  String get settingsConnectOnBootDesc => 'Usato solo quando la VPN sempre attiva è disattivata';

  @override
  String get settingsPolicy => 'Policy';

  @override
  String get settingsDefaultAction => 'Azione predefinita per le app sconosciute';

  @override
  String get settingsLockdown => 'Modalità blocco totale';

  @override
  String get settingsLockdownOn => 'Attivo: possono connettersi solo le app consentite';

  @override
  String get settingsLockdownOff => 'Disattivo';

  @override
  String get settingsUserRules => 'Regole personali';

  @override
  String get settingsUserRulesAllowed => 'Consentite dalla tua organizzazione';

  @override
  String get settingsUserRulesDenied => 'Non consentite dalla tua organizzazione';

  @override
  String get settingsSnapshot => 'Snapshot della policy';

  @override
  String settingsSnapshotValue(int version, String expires) {
    return 'Versione $version · scadenza $expires';
  }

  @override
  String get settingsDevice => 'Dispositivo';

  @override
  String get settingsExportLogs => 'Esporta registro delle connessioni';

  @override
  String get settingsExportLogsDesc => 'Salva le connessioni recenti in formato JSON';

  @override
  String get settingsExportDone => 'Registro esportato';

  @override
  String get settingsUnenroll => 'Annulla registrazione dispositivo';

  @override
  String get settingsUnenrollDesc => 'Rimuove il certificato del dispositivo e le chiavi da questo telefono';

  @override
  String get settingsUnenrollConfirm =>
      'Annullare la registrazione di questo dispositivo? Sarà necessaria una nuova chiave di provisioning per registrarlo di nuovo.';

  @override
  String get settingsAbout => 'Informazioni';

  @override
  String settingsVersion(String version, String engine) {
    return 'Versione $version · motore $engine';
  }

  @override
  String get settingsLicenses => 'Licenze open source';

  @override
  String get settingsLicensesText =>
      'OpenSASE usa Flutter, Material e Dart SDK (BSD 3-Clause), Riverpod, go_router e json_serializable (MIT / BSD 3-Clause), AndroidX e Kotlin (Apache License 2.0), la libreria standard di Go (BSD 3-Clause) e wireguard-go (MIT). Non include strumenti di analisi né Google Play Services. Tocca per l\'elenco completo.';

  @override
  String get settingsAppearance => 'Aspetto';

  @override
  String get engineFake => 'Motore demo (dati simulati)';

  @override
  String get engineNative => 'Motore nativo';

  @override
  String appDetailUid(int uid) {
    return 'UID $uid';
  }

  @override
  String get onboardingCode => 'Codice di registrazione';

  @override
  String get onboardingCodeHint => 'Incolla il codice ricevuto dall\'amministratore (URL e chiave)';

  @override
  String get onboardingCodeInvalid => 'Codice di registrazione non valido';

  @override
  String get onboardingPinned => 'Certificato del server fissato (sha256)';

  @override
  String get onboardingScan => 'Scansiona codice QR';

  @override
  String get onboardingScanSoon => 'La scansione QR arriverà presto. Incolla il codice.';

  @override
  String get onboardingOr => 'oppure inserisci i dati';

  @override
  String get settingsEngine => 'Motore';

  @override
  String get homeLastHandshake => 'Ultimo handshake';

  @override
  String get homeNetwork => 'Rete';

  @override
  String get rulesOrderSaved => 'Ordine delle regole salvato';

  @override
  String get activityLive => 'In diretta';

  @override
  String statsDns(int queries, int blocked) {
    return 'DNS $queries richieste · $blocked bloccate';
  }

  @override
  String get vpnConsentDenied => 'Autorizzazione VPN negata';

  @override
  String get settingsCertificate => 'Certificato del dispositivo';

  @override
  String settingsCertificateExpires(String date) {
    return 'Scade il $date';
  }

  @override
  String get onboardingCodeApplied => 'Codice applicato: controlla i dati qui sotto e tocca Registra';
}
