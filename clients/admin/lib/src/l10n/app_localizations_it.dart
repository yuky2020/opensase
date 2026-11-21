// ignore: unused_import
import 'package:intl/intl.dart' as intl;

import 'app_localizations.dart';

// ignore_for_file: type=lint

/// The translations for Italian (`it`).
class AppLocalizationsIt extends AppLocalizations {
  AppLocalizationsIt([String locale = 'it']) : super(locale);

  @override
  String get appTitle => 'OpenSASE Admin';

  @override
  String get navOverview => 'Panoramica';

  @override
  String get navTenants => 'Tenant';

  @override
  String get navUsers => 'Utenti';

  @override
  String get navPolicy => 'Policy';

  @override
  String get navPrivateApps => 'App private';

  @override
  String get navConnectors => 'Connettori';

  @override
  String get navDevices => 'Dispositivi';

  @override
  String get navEdges => 'Edge';

  @override
  String get navActivity => 'Attività';

  @override
  String get navSettings => 'Impostazioni';

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
  String get actionCreate => 'Crea';

  @override
  String get actionRevoke => 'Revoca';

  @override
  String get actionRefresh => 'Aggiorna';

  @override
  String get actionReload => 'Annulla modifiche';

  @override
  String get actionClose => 'Chiudi';

  @override
  String get actionCopy => 'Copia';

  @override
  String get actionLogout => 'Esci';

  @override
  String get actionMoveUp => 'Sposta su';

  @override
  String get actionMoveDown => 'Sposta giù';

  @override
  String get msgCopied => 'Copiato negli appunti';

  @override
  String get msgSaved => 'Salvato. Gli snapshot dei dispositivi vengono ricompilati.';

  @override
  String msgError(String error) {
    return 'Errore: $error';
  }

  @override
  String get msgSessionExpired => 'Il token admin è stato rifiutato. Accedi di nuovo.';

  @override
  String get emptyNothingHere => 'Ancora nessun elemento';

  @override
  String get emptyNoTenant => 'Crea o seleziona prima un tenant.';

  @override
  String get tenantPicker => 'Tenant';

  @override
  String get loginTitle => 'Amministrazione OpenSASE';

  @override
  String get loginSubtitle => 'Incolla il token admin di questo Control Plane.';

  @override
  String get loginToken => 'Token admin';

  @override
  String get loginRemember => 'Ricorda per questa scheda';

  @override
  String get loginRememberHint =>
      'Conservato nel session storage di questa scheda fino alla sua chiusura. Altrimenti il token resta solo in memoria.';

  @override
  String get loginSubmit => 'Accedi';

  @override
  String loginFailed(String error) {
    return 'Accesso non riuscito: $error';
  }

  @override
  String get loginTokenRequired => 'Inserisci il token admin';

  @override
  String get fieldId => 'ID';

  @override
  String get fieldIdOptional => 'ID (facoltativo, generato se vuoto)';

  @override
  String get fieldName => 'Nome';

  @override
  String get fieldEmail => 'Email';

  @override
  String get fieldGroup => 'Gruppo';

  @override
  String get fieldUser => 'Utente';

  @override
  String get fieldPlatform => 'Piattaforma';

  @override
  String get fieldCreated => 'Creato';

  @override
  String get fieldLastSeen => 'Ultimo contatto';

  @override
  String get fieldStatus => 'Stato';

  @override
  String get fieldInvalidId => 'Lettere, cifre, \'.\', \'_\' e \'-\'; deve iniziare con lettera o cifra';

  @override
  String get fieldRequired => 'Obbligatorio';

  @override
  String get statusRevoked => 'Revocato';

  @override
  String get statusActive => 'Attivo';

  @override
  String get statusOnline => 'Online';

  @override
  String get statusOffline => 'Offline';

  @override
  String get never => 'mai';

  @override
  String get tenantsCreate => 'Nuovo tenant';

  @override
  String get usersCreate => 'Nuovo utente';

  @override
  String get usersProvisioningKey => 'Chiave di provisioning';

  @override
  String provTitle(String user) {
    return 'Chiave di provisioning per $user';
  }

  @override
  String get provMaxUses => 'Utilizzi massimi';

  @override
  String get provValidHours => 'Valida per (ore)';

  @override
  String get provGenerate => 'Genera';

  @override
  String get provShownOnce =>
      'Questa chiave viene mostrata una sola volta. Copiala o fai scansionare il codice QR ora.';

  @override
  String provExpires(String time) {
    return 'Scade $time';
  }

  @override
  String get provNoControlUrl =>
      'Imposta l\'URL di controllo con il pin #sha256= nelle Impostazioni per mostrare il codice QR di registrazione.';

  @override
  String get provScan => 'Scansiona con l\'app OpenSASE per registrare il dispositivo';

  @override
  String get provLink => 'Link di registrazione';

  @override
  String get settingsControlUrl => 'URL di controllo per la registrazione';

  @override
  String get settingsControlUrlHint => 'https://cp.example.com:9443#sha256=<SHA-256 della root CA>';

  @override
  String get settingsControlUrlHelp =>
      'Inserito nei codici QR di registrazione. Il frammento #sha256= fissa la root CA del provider (lo stampa opensasectl).';

  @override
  String get settingsUseOrigin => 'Usa questa origine';

  @override
  String get settingsTokenInfo =>
      'Il token admin è tenuto in memoria, e nel session storage di questa scheda solo se lo hai scelto all\'accesso. Non viene mai scritto nel local storage.';

  @override
  String get policyTabForm => 'Modulo';

  @override
  String get policyTabJson => 'JSON';

  @override
  String get policyGeneral => 'Generale';

  @override
  String get policyDefaultAction => 'Azione predefinita';

  @override
  String get policyNotSet => 'Non impostato (predefinito del server)';

  @override
  String get policyAllowUserRules => 'Consenti regole utente';

  @override
  String get policyAllowUserRulesHelp =>
      'Gli utenti possono aggiungere regole personali e policy per app sotto il livello tenant.';

  @override
  String get policyLockdown => 'Lockdown';

  @override
  String get policyLockdownHelp =>
      'Le app senza una policy tenant sono bloccate; le regole utente possono solo bloccare.';

  @override
  String get policyRules => 'Regole tenant';

  @override
  String get policyRulesHelp =>
      'Valutate per priorità, dalla più bassa; vince la prima corrispondenza. Tutti i campi compilati devono corrispondere.';

  @override
  String get policyApps => 'Policy per app';

  @override
  String get policyAppsHelp => 'Verdetti obbligatori per pacchetto Android e rete.';

  @override
  String get policyDns => 'DNS';

  @override
  String get policyBlockResponse => 'Risposta di blocco';

  @override
  String get policyBlocklists => 'Blocklist';

  @override
  String get policyAllowDomains => 'Domini consentiti (prevalgono sulle blocklist)';

  @override
  String get policyBlockDomains => 'Domini bloccati';

  @override
  String get policyDecide => 'Decisioni cloud (ask)';

  @override
  String get policyDecideDefault => 'Predefinito decisione';

  @override
  String get policyDecideBlockDomains => 'Domini bloccati dal cloud';

  @override
  String get policyDecideBlockCidrs => 'CIDR bloccati dal cloud';

  @override
  String get policyOnePerLine => 'Uno per riga; \"*.example.com\" corrisponde anche a example.com';

  @override
  String policyJsonInvalid(String error) {
    return 'JSON non valido: $error';
  }

  @override
  String get policyJsonLocked => 'La scheda JSON contiene un errore. Correggilo per modificare il modulo.';

  @override
  String get policyIssues => 'Correggi questi problemi prima di salvare:';

  @override
  String policyServerError(String error) {
    return 'Il Control Plane ha rifiutato la policy: $error';
  }

  @override
  String get policyUnsaved => 'Modifiche non salvate';

  @override
  String get ruleNew => 'Nuova regola';

  @override
  String get ruleEdit => 'Modifica regola';

  @override
  String get rulePriority => 'Priorità';

  @override
  String get ruleAction => 'Azione';

  @override
  String get ruleLog => 'Registra i flussi corrispondenti';

  @override
  String get ruleDescription => 'Descrizione';

  @override
  String get ruleMatch => 'Corrispondenza';

  @override
  String get ruleMatchAny => 'qualsiasi';

  @override
  String get matchApps => 'App (nomi pacchetto)';

  @override
  String get matchNetworks => 'Reti';

  @override
  String get matchProtocols => 'Protocolli';

  @override
  String get matchCidrs => 'CIDR di destinazione';

  @override
  String get matchPorts => 'Porte di destinazione';

  @override
  String get matchPortsHint => '443, 8000-8080';

  @override
  String get matchDomains => 'Domini';

  @override
  String get appPackage => 'Nome pacchetto';

  @override
  String get appNew => 'Nuova policy app';

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
  String get actionAllow => 'Consenti';

  @override
  String get actionBlock => 'Blocca';

  @override
  String get actionAsk => 'Chiedi al cloud';

  @override
  String get actionUnset => 'Non impostato';

  @override
  String get blocklistNew => 'Nuova blocklist';

  @override
  String get blocklistCategory => 'Categoria';

  @override
  String blocklistDomainsCount(int count) {
    return '$count domini';
  }

  @override
  String get privateAppsHelp =>
      'Le app private sono raggiungibili solo per nome, tramite un gruppo di connettori (ZTNA). Il salvataggio aggiorna la policy del tenant.';

  @override
  String get privateAppNew => 'Nuova app privata';

  @override
  String get privateAppEdit => 'Modifica app privata';

  @override
  String get privateAppPorts => 'Porte TCP';

  @override
  String get privateAppConnectorGroup => 'Gruppo connettori';

  @override
  String get privateAppUsers => 'Utenti (ID o email; vuoto = tutti)';

  @override
  String get privateAppEveryone => 'tutti';

  @override
  String get connectorsCreate => 'Nuovo connettore';

  @override
  String connectorsCreated(String name) {
    return 'Connettore $name creato';
  }

  @override
  String get connectorsKeyHelp => 'Chiave monouso, valida 24 ore. Passala a opensase-connector -key al primo avvio.';

  @override
  String get connectorsGroupHint => 'default';

  @override
  String revokeConfirmTitle(String name) {
    return 'Revocare $name?';
  }

  @override
  String get revokeConfirmConnector =>
      'Il certificato del connector smette di funzionare alla prossima sincronizzazione degli Edge (circa 10 secondi). Operazione irreversibile.';

  @override
  String get revokeConfirmDevice =>
      'Il dispositivo perde l\'accesso e deve registrarsi di nuovo. Operazione irreversibile.';

  @override
  String get revokeConfirmEdge =>
      'L\'Edge viene rifiutato dal Control Plane; il suo ID non può essere riutilizzato. Operazione irreversibile.';

  @override
  String get edgesCreate => 'Registra Edge';

  @override
  String get edgesCreateHelp => 'Registra l\'ID dell\'Edge prima di avviarlo con il suo certificato.';

  @override
  String get edgesFieldTenant => 'Tenant (Private Edge)';

  @override
  String get edgesFieldTenantHelp =>
      'Facoltativo. Lega l\'Edge a un solo tenant; vuoto per un Edge pubblico multi-tenant.';

  @override
  String get edgesPublic => 'pubblico';

  @override
  String get flowsVerdict => 'Verdetto';

  @override
  String get flowsLayer => 'Livello';

  @override
  String get flowsWhere => 'Dove';

  @override
  String get flowsDevice => 'Dispositivo';

  @override
  String get flowsSearch => 'Cerca dominio, IP, porta, app, regola';

  @override
  String get flowsAny => 'Qualsiasi';

  @override
  String get flowsAutoRefresh => 'Aggiornamento automatico (10 s)';

  @override
  String get flowsTime => 'Ora';

  @override
  String get flowsDestination => 'Destinazione';

  @override
  String get flowsApp => 'App';

  @override
  String get flowsRule => 'Regola';

  @override
  String get flowsBytes => 'Byte uscita/entrata';

  @override
  String flowsShown(int shown, int total) {
    return '$shown di $total flussi';
  }

  @override
  String get overviewDevices => 'Dispositivi attivi';

  @override
  String get overviewConnectorsOnline => 'Connettori online';

  @override
  String get overviewEdges => 'Edge';

  @override
  String get overviewBlocksHour => 'Blocchi nell\'ultima ora';

  @override
  String overviewChartTitle(int count) {
    return 'Verdetti per livello (ultimi $count flussi)';
  }

  @override
  String overviewOf(int total) {
    return 'su $total';
  }

  @override
  String get verdictAllow => 'Consentito';

  @override
  String get verdictBlock => 'Bloccato';

  @override
  String get verdictOther => 'Altro';

  @override
  String get msgSettingsSaved => 'Impostazioni salvate';

  @override
  String get navAdminTokens => 'Token admin';

  @override
  String get adminTokensCreate => 'Nuovo token admin';

  @override
  String get adminTokensCreateHelp =>
      'Un token admin amministra solo questo tenant: utenti, policy, app private, connector, dispositivi e attività. Non vede gli altri tenant, non crea tenant e non gestisce gli Edge.';

  @override
  String get adminTokensNameHint => 'chi o cosa lo usa, ad es. team ops';

  @override
  String get adminTokensFieldDays => 'Validità (giorni)';

  @override
  String get adminTokensFieldDaysHelp => 'Da 1 a 365 giorni';

  @override
  String adminTokensCreated(String name) {
    return 'Token admin $name creato';
  }

  @override
  String get adminTokensShownOnce =>
      'Questo token viene mostrato una sola volta. Copialo ora e salvalo in un password manager.';

  @override
  String get adminTokensUseHelp =>
      'Usalo per accedere al portale, oppure con opensasectl (-token-file o \$OPENSASE_ADMIN_TOKEN).';

  @override
  String get adminTokensEmpty => 'Nessun token admin per questo tenant';

  @override
  String get adminTokensThisSession => '(questa sessione)';

  @override
  String get adminTokensRevokeOwn => 'È il token della sessione corrente: verrai disconnesso.';

  @override
  String get revokeConfirmAdminToken => 'Il token smette di funzionare subito. L\'operazione non si può annullare.';

  @override
  String get fieldExpires => 'Scade';

  @override
  String get fieldLastUsed => 'Ultimo uso';

  @override
  String get statusExpired => 'Scaduto';

  @override
  String get navAudit => 'Audit';

  @override
  String get auditEmpty => 'Nessuna modifica admin registrata per questo tenant';

  @override
  String get auditHelp =>
      'Ogni modifica admin su questo tenant, chi l\'ha fatta e con quale esito. Conservata per 365 giorni.';

  @override
  String get fieldActor => 'Autore';

  @override
  String get fieldMethod => 'Azione';

  @override
  String get fieldPath => 'Percorso';

  @override
  String get fieldResult => 'Esito';

  @override
  String get auditActorSuper => 'super-admin';

  @override
  String get fieldTime => 'Ora';
}
