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
  String get navPolicyTest => 'Test policy';

  @override
  String get navPrivateApps => 'App private';

  @override
  String get navConnectors => 'Connettori';

  @override
  String get navDevices => 'Dispositivi';

  @override
  String get navEdges => 'Edge';

  @override
  String get navStatus => 'Stato';

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

  @override
  String get navSaas => 'App SaaS';

  @override
  String get saasHelp =>
      'Blocca app SaaS note o intere categorie. Applicato al DNS da dispositivi ed Edge, e al nome del server TLS di ogni flusso sull\'Edge, così le app non sono raggiungibili nemmeno per indirizzo.';

  @override
  String get saasBlockCategory => 'Blocca tutte le app di questa categoria';

  @override
  String get saasDiscovered => 'Viste nei flussi recenti:';

  @override
  String saasSeen(int count) {
    return '$count flussi';
  }

  @override
  String get statusBlocked => 'Bloccata';

  @override
  String get statusAllowed => 'Consentita';

  @override
  String get saasCatFileSharing => 'Condivisione file';

  @override
  String get saasCatWebmail => 'Webmail';

  @override
  String get saasCatAiAssistant => 'Assistenti AI';

  @override
  String get saasCatSocialMedia => 'Social media';

  @override
  String get saasCatMessaging => 'Messaggistica';

  @override
  String get saasCatCollaboration => 'Collaborazione';

  @override
  String get saasCatStreaming => 'Streaming';

  @override
  String get saasCatCodeHosting => 'Hosting di codice e paste';

  @override
  String get navWeb => 'Ispezione web';

  @override
  String get webHelp =>
      'Decifra l\'HTTPS del tenant sull\'Edge per applicare regole sugli URL e impostare header delle richieste. I dispositivi devono fidarsi della root di ispezione del tenant.';

  @override
  String get webInspect => 'Ispeziona TLS';

  @override
  String get webInspectHelp =>
      'L\'Edge termina il TLS con un certificato della root di ispezione del tenant e controlla ogni richiesta. Il traffico web QUIC e IPv6 di questi dispositivi viene rifiutato, così i browser usano TCP ispezionato.';

  @override
  String get webBlockEch => 'Blocca Encrypted Client Hello';

  @override
  String get webBlockEchHelp => 'Rimuove ECH dalle risposte DNS così l\'Edge vede i nomi reali dei server';

  @override
  String get webBypass => 'Non decifrare mai';

  @override
  String get webBypassHelp =>
      'Un dominio per riga (*.banca.example). Per app con certificate pinning, banche e siti sanitari.';

  @override
  String get webRules => 'Regole URL';

  @override
  String get webRulesHelp =>
      'Valutate in ordine su ogni richiesta; decide la prima che corrisponde, nessuna corrispondenza consente. I percorsi sono normalizzati e senza distinzione di maiuscole.';

  @override
  String get webAddRule => 'Aggiungi regola';

  @override
  String get webDomains => 'Domini (separati da virgola)';

  @override
  String get webPaths => 'Prefissi di percorso (vuoto = tutti)';

  @override
  String get webPathsInvalid => 'Ogni percorso deve iniziare con /';

  @override
  String get webMethods => 'Metodi (vuoto = tutti)';

  @override
  String get webAction => 'Azione (allow o block)';

  @override
  String get webHeaders => 'Header delle richieste';

  @override
  String get webHeadersHelp =>
      'Impostati su ogni richiesta verso un host corrispondente, sostituendo quelli del client, ad esempio per limitare il login a un SaaS all\'account aziendale.';

  @override
  String get webAddHeader => 'Aggiungi header';

  @override
  String get webHeaderName => 'Nome header';

  @override
  String get webHeaderValue => 'Valore';

  @override
  String get webRootButton => 'Root di ispezione';

  @override
  String get webRootTitle => 'Root di ispezione del tenant';

  @override
  String get webRootHelp =>
      'Installa questo certificato come root attendibile sui dispositivi del tenant (MDM, archivio di sistema). I dispositivi che non lo considerano attendibile non possono aprire i siti ispezionati.';

  @override
  String get webDlp => 'Prevenzione perdita di dati (DLP)';

  @override
  String get webDlpHelp =>
      'Analizza gli upload, e i download di file dove attivato, sul percorso ispezionato (fino a 8 MiB), compreso il testo dentro documenti Office, PDF e archivi ZIP. Vengono registrate le corrispondenze, mai i dati. Interruttore: blocca anche i contenuti non analizzabili (troppo grandi o compressi).';

  @override
  String get webAddDlp => 'Aggiungi regola DLP';

  @override
  String get webDlpDetectors => 'Rilevatori (separati da virgola)';

  @override
  String webDlpDetectorsHelp(String list) {
    return 'Rilevatori integrati: $list. Numeri di carta, IBAN e codici fiscali sono verificati col checksum.';
  }

  @override
  String get webDlpUnknown => 'Rilevatore sconosciuto';

  @override
  String get webDlpPatterns => 'Pattern personalizzati (espressioni regolari, uno per riga)';

  @override
  String get webDlpDomains => 'Domini (vuoto = tutti gli host ispezionati)';

  @override
  String get webDlpMin => 'Corrispondenze necessarie';

  @override
  String get webDlpMinInvalid => 'Almeno 1';

  @override
  String get webDlpLog => 'Registra';

  @override
  String get webDlpAllHosts => 'tutti gli host';

  @override
  String webDlpPatternCount(int n) {
    return '$n pattern';
  }

  @override
  String get webDlpBlockUnscanned => 'Blocca i contenuti non analizzabili';

  @override
  String get webAvUploads => 'Scansiona gli upload per malware';

  @override
  String get webAvDownloads => 'Scansiona i download di file per malware';

  @override
  String get webAvDownloadsHelp =>
      'Allegati e tipi di file (archivi, eseguibili, documenti); pagine web e media in streaming non vengono trattenuti. ClamAV sull\'Edge, fino a 20 MiB.';

  @override
  String get webAvBlockUnscanned => 'Blocca ciò che non si può analizzare';

  @override
  String get webAvBlockUnscannedHelp => 'File oltre 20 MiB, download parziali (range) o scanner non raggiungibile.';

  @override
  String get webDlpDownloads => 'Analizza anche i download di file';

  @override
  String get webDlpBoth => 'upload e download';

  @override
  String get webDlpUploadsOnly => 'upload';

  @override
  String get navCategories => 'Categorie web';

  @override
  String get categoriesHelp =>
      'Blocca intere categorie di siti da una lista pubblica di categorie. Applicato dall\'Edge sul DNS e sul nome del server di ogni connessione; la allow list DNS del tenant ha la precedenza.';

  @override
  String get categoriesNotLoaded =>
      'Nessuna lista di categorie caricata sul Control Plane (flag -categories-file / -categories-url). Le categorie scelte vengono salvate ma non ancora applicate.';

  @override
  String categoriesSource(String source, String licence, String when) {
    return 'Fonte: $source ($licence), aggiornata il $when.';
  }

  @override
  String get categoriesFilter => 'Filtra le categorie';

  @override
  String categoriesDomains(String n) {
    return '$n domini';
  }

  @override
  String categoriesUrls(String n) {
    return '$n pagine (bloccate sul traffico ispezionato)';
  }

  @override
  String get safeSearch => 'Forza SafeSearch';

  @override
  String get safeSearchHelp =>
      'I motori di ricerca (Google, Bing, DuckDuckGo) rispondono con i risultati filtrati e YouTube è in modalità con restrizioni, tramite il DNS dell\'Edge; le connessioni che provano a raggiungerli in altro modo vengono chiuse.';

  @override
  String get adminTokensFieldRole => 'Ruolo';

  @override
  String get adminTokensFieldRoleHelp =>
      'admin (tutto nel tenant), policy-editor (lettura e modifica della policy) o viewer (sola lettura)';

  @override
  String auditChainOk(int n) {
    return 'Catena di audit integra: $n voci verificate';
  }

  @override
  String auditChainBroken(int id, String reason) {
    return 'Catena di audit interrotta alla voce $id: $reason';
  }

  @override
  String auditChainHead(int id, String hash) {
    return 'Testa: voce $id, $hash (conservane una copia per verificare la storia in futuro)';
  }

  @override
  String get navSecurityEvents => 'Eventi di sicurezza';

  @override
  String get secEventsHelp =>
      'Blocchi e rilevazioni di DLP, scansione malware, regole URL, categorie web, SafeSearch, controllo SaaS e ispezione TLS, dai flussi recenti del tenant. Il dato trovato non viene mai registrato.';

  @override
  String secAll(int n) {
    return 'Tutti · $n';
  }

  @override
  String get secEmpty => 'Nessun evento di sicurezza nei flussi recenti.';

  @override
  String get secFieldKind => 'Tipo';

  @override
  String get secFieldRule => 'Regola';

  @override
  String get secFieldHost => 'Host';

  @override
  String get secFieldDevice => 'Dispositivo';

  @override
  String get secLogged => 'Registrato';

  @override
  String get secKindDlp => 'DLP';

  @override
  String get secKindMalware => 'Malware';

  @override
  String get secKindUrl => 'Regola URL';

  @override
  String get secKindCategory => 'Categoria';

  @override
  String get secKindSafeSearch => 'SafeSearch';

  @override
  String get secKindSaas => 'SaaS';

  @override
  String get secKindInspection => 'Ispezione';

  @override
  String get webDlpDatasets => 'Dataset (separati da virgola)';

  @override
  String get webDlpDatasetsHelp =>
      'Valori esatti o documenti protetti caricati con opensasectl dlp-dataset put; ne vengono conservati solo gli hash.';

  @override
  String get loginOidcTitle => 'Accedi con la tua organizzazione';

  @override
  String get loginOidcTenant => 'ID tenant';

  @override
  String get loginOidcTenantRequired => 'Inserisci l\'ID del tenant';

  @override
  String get loginOidcSubmit => 'Accedi con la tua organizzazione';

  @override
  String get loginOr => 'oppure';

  @override
  String get navSso => 'Single sign-on';

  @override
  String get ssoTitle => 'Single sign-on';

  @override
  String get ssoSubtitle => 'Autentica gli amministratori del portale tramite un provider di identità esterno.';

  @override
  String get ssoNotConfigured => 'Il Single sign-on non è configurato per questo tenant.';

  @override
  String get ssoConfigure => 'Configura SSO';

  @override
  String get ssoIssuer => 'URL dell\'emittente';

  @override
  String get ssoClientId => 'ID client';

  @override
  String get ssoSecretSet => 'Segreto client configurato';

  @override
  String get ssoRedirectUrl => 'URL di reindirizzamento';

  @override
  String get ssoRedirectUrlHelp => 'Registra questo URL di callback presso il tuo provider di identità.';

  @override
  String get ssoGroupRoles => 'Mappatura gruppi-ruoli';

  @override
  String get ssoGroup => 'Gruppo provider di identità';

  @override
  String get ssoRole => 'Ruolo tenant';

  @override
  String get ssoAddGroupMapping => 'Aggiungi mappatura gruppo';

  @override
  String get ssoEditTitle => 'Configura Single sign-on';

  @override
  String get ssoClientSecret => 'Segreto client';

  @override
  String get ssoClientSecretHelp => 'Lascia vuoto per mantenere il segreto attualmente configurato.';

  @override
  String get ssoDeleteConfirmTitle => 'Rimuovere la configurazione di Single sign-on?';

  @override
  String get ssoDeleteConfirmBody => 'Gli amministratori non potranno più accedere tramite il provider di identità.';

  @override
  String get ssoSaved => 'Configurazione Single sign-on salvata';

  @override
  String get ssoDeleted => 'Configurazione Single sign-on rimossa';

  @override
  String get ssoErrorIssuer => 'L\'emittente deve essere HTTPS (o HTTP su localhost)';

  @override
  String get ssoErrorClientId => 'L\'ID client è obbligatorio';

  @override
  String get ssoErrorGroups => 'È richiesta almeno una mappatura di gruppo';

  @override
  String get yes => 'Sì';

  @override
  String get no => 'No';

  @override
  String get navDns => 'DNS';

  @override
  String get dnsTitle => 'DNS';

  @override
  String get dnsSubtitle => 'Gestisci le impostazioni del resolver, la zona DNS interna e le blocklist di domini.';

  @override
  String get dnsResolver => 'Resolver';

  @override
  String get dnsBlockResponse => 'Risposta di blocco';

  @override
  String get dnsBlockResponseNxdomain => 'NXDOMAIN';

  @override
  String get dnsBlockResponseZero => '0.0.0.0 / ::';

  @override
  String get dnsRedirectQueries => 'Reindirizza le query DNS al resolver Edge';

  @override
  String get dnsRedirectQueriesHelp =>
      'Risponde alle query DNS in chiaro inviate ad altri resolver con questa policy invece di bloccarle.';

  @override
  String get dnsLogQueries => 'Registra le query consentite';

  @override
  String get dnsLogQueriesHelp => 'Registra le query DNS consentite come record di flusso.';

  @override
  String get dnsInternalZone => 'Zona interna';

  @override
  String get dnsZoneName => 'Nome della zona interna';

  @override
  String get dnsZoneHelp => 'I dispositivi ricevono nomi del tipo <device>.<user>.<zone>.';

  @override
  String get dnsRecords => 'Record';

  @override
  String get dnsRecordName => 'Nome';

  @override
  String get dnsRecordType => 'Tipo';

  @override
  String get dnsRecordValue => 'Valore';

  @override
  String get dnsRecordTtl => 'TTL (secondi)';

  @override
  String get dnsAddRecord => 'Aggiungi record';

  @override
  String get dnsEditRecord => 'Modifica record';

  @override
  String get dnsForwarders => 'Inoltri';

  @override
  String get dnsForwarderZone => 'Zona';

  @override
  String get dnsForwarderServers => 'Server (separati da virgola)';

  @override
  String get dnsAddForwarder => 'Aggiungi inoltro';

  @override
  String get dnsEditForwarder => 'Modifica inoltro';

  @override
  String get dnsSecurityBlocklists => 'Blocklist di sicurezza';

  @override
  String get dnsBuiltinLists => 'Blocklist integrate';

  @override
  String get dnsBuiltinEmpty => 'Nessuna blocklist integrata disponibile';

  @override
  String get dnsCustomLists => 'Blocklist personalizzate';

  @override
  String get dnsCustomListId => 'ID';

  @override
  String get dnsCustomListTitle => 'Titolo';

  @override
  String get dnsCustomListUrl => 'URL (https://)';

  @override
  String get dnsAddCustomList => 'Aggiungi blocklist personalizzata';

  @override
  String get dnsEditCustomList => 'Modifica blocklist personalizzata';

  @override
  String get dnsDomainOverrides => 'Override dei domini';

  @override
  String get dnsAllowDomains => 'Domini consentiti';

  @override
  String get dnsBlockDomains => 'Domini bloccati';

  @override
  String get dnsAddDomain => 'Aggiungi dominio';

  @override
  String get dnsDomainHint => 'example.com o *.example.com';

  @override
  String get dnsErrorNameRequired => 'Il nome è obbligatorio';

  @override
  String get dnsErrorValueRequired => 'Il valore è obbligatorio';

  @override
  String get dnsErrorInvalidIpv4 => 'Deve essere un indirizzo IPv4 valido';

  @override
  String get dnsErrorInvalidIpv6 => 'Deve essere un indirizzo IPv6 valido';

  @override
  String get dnsErrorInvalidTtl => 'Il TTL deve essere 0 o compreso tra 1 e 86400';

  @override
  String get dnsErrorZoneRequired => 'La zona è obbligatoria';

  @override
  String get dnsErrorInvalidServers => 'Ciascun server deve essere un IP o IP:porta';

  @override
  String get dnsErrorInvalidListId => 'L\'ID deve contenere solo lettere minuscole, numeri e trattini';

  @override
  String get dnsErrorInvalidHttpsUrl => 'Deve essere un URL https:// valido';

  @override
  String get navOnboarding => 'Per iniziare';

  @override
  String get onboardingTitle => 'Per iniziare';

  @override
  String get onboardingSubtitle => 'Procedura guidata di configurazione iniziale per OpenSASE';

  @override
  String get onboardingStepWelcome => 'Benvenuto';

  @override
  String get onboardingStepOrg => 'Organizzazione';

  @override
  String get onboardingStepSso => 'Accesso';

  @override
  String get onboardingStepPolicy => 'Prima policy';

  @override
  String get onboardingStepDns => 'DNS';

  @override
  String get onboardingStepConnectors => 'App private';

  @override
  String get onboardingStepDevices => 'Dispositivi';

  @override
  String get onboardingStepDone => 'Completato';

  @override
  String get onboardingWelcomeSuper => 'Stato di salute e preparazione della distribuzione.';

  @override
  String get onboardingWelcomeTenant =>
      'Benvenuto nel portale di amministrazione di OpenSASE. Completa i passaggi seguenti per configurare la tua organizzazione.';

  @override
  String onboardingEdgesReporting(int reporting, int total) => 'Edge attivi: $reporting su $total';

  @override
  String onboardingCertWarning(String name, int days) => 'Attenzione: Il certificato \'$name\' scade tra $days giorni';

  @override
  String get onboardingCertsHealthy => 'Tutti i certificati sono validi';

  @override
  String get onboardingStepStatusDone => 'Completato';

  @override
  String get onboardingStepStatusTodo => 'Da completare';

  @override
  String get onboardingOrgHelp => 'Configura il nome visualizzato del tenant.';

  @override
  String onboardingOrgCurrent(String name, String id) => 'Organizzazione attuale: $name ($id)';

  @override
  String get onboardingOrgCreate => 'Crea organizzazione';

  @override
  String get onboardingSsoHelp => 'Configura il Single Sign-On utilizzando il tuo provider di identità OpenID Connect.';

  @override
  String get onboardingTestSignin => 'Verifica accesso';

  @override
  String get onboardingSkipSso => 'Salta, usa chiavi di provisioning';

  @override
  String get onboardingAddGroup => 'Aggiungi mappatura gruppo';

  @override
  String get onboardingPolicyHelp => 'Scegli un modello di policy di sicurezza di base per il tuo tenant.';

  @override
  String get onboardingTemplateRecommended => 'Consigliato';

  @override
  String get onboardingTemplateRecommendedDesc =>
      'Azione predefinita consenti, blocca categorie malware e phishing e applica SafeSearch.';

  @override
  String get onboardingTemplatePermissive => 'Permissivo';

  @override
  String get onboardingTemplatePermissiveDesc => 'Azione predefinita consenti senza alcun blocco di categoria.';

  @override
  String get onboardingPolicyPreview => 'Anteprima JSON della policy';

  @override
  String get onboardingDnsHelp => 'Imposta la risoluzione DNS interna e le blocklist di sicurezza.';

  @override
  String get onboardingDnsZone => 'Nome zona interna';

  @override
  String get onboardingDnsBlocklist => 'Blocklist di sicurezza';

  @override
  String get onboardingConnectorHelp =>
      'Distribuisci un Connector per instradare l\'accesso sicuro alle applicazioni di rete privata.';

  @override
  String get onboardingConnectorCreate => 'Crea Connector';

  @override
  String get onboardingConnectorDocker => 'Esegui con Docker';

  @override
  String get onboardingConnectorDockerHelp =>
      'Esegui questo comando sull\'host del connector. La chiave viene mostrata solo una volta.';

  @override
  String get onboardingConnectorStatus => 'Stato del Connector in tempo reale';

  @override
  String get onboardingPrivateAppsLink => 'Aggiungi app private';

  @override
  String get onboardingSkip => 'Salta';

  @override
  String get onboardingDevicesHelp =>
      'Registra i dispositivi utente utilizzando una chiave di provisioning o un codice QR.';

  @override
  String get onboardingKeyCreate => 'Genera chiave di provisioning';

  @override
  String get onboardingPlatformAndroid => 'Android';

  @override
  String get onboardingPlatformAndroidDesc => 'Installa l\'app OpenSASE e scansiona il codice QR per registrarti.';

  @override
  String get onboardingPlatformWindows => 'Windows';

  @override
  String get onboardingPlatformWindowsDesc =>
      'Scarica ed esegui il programma di installazione MSI per Windows, quindi inserisci l\'URL di controllo e la chiave di provisioning.';

  @override
  String get onboardingPlatformLinux => 'Linux';

  @override
  String get onboardingPlatformLinuxDesc =>
      'Installa il pacchetto Linux (deb o rpm) ed esegui il comando di registrazione con la chiave di provisioning.';

  @override
  String get onboardingDevicesLive => 'Dispositivi registrati in tempo reale';

  @override
  String get onboardingDoneTitle => 'Configurazione completata!';

  @override
  String get onboardingDoneSubtitle =>
      'La tua distribuzione OpenSASE è pronta per proteggere il traffico e le applicazioni private.';

  @override
  String get onboardingLinkStatus => 'Pagina di stato';

  @override
  String get onboardingLinkPolicy => 'Editor policy';

  @override
  String get onboardingLinkDns => 'Impostazioni DNS';

  @override
  String get onboardingLinkDocs => 'Documentazione';

  @override
  String get onboardingNext => 'Avanti';

  @override
  String get onboardingBack => 'Indietro';

  @override
  String get onboardingApply => 'Applica';

  @override
  String get policyTestSubtitle =>
      'Valuta un flusso di esempio rispetto allo snapshot firmato della policy del dispositivo.';

  @override
  String get policyTestDevice => 'Dispositivo';

  @override
  String get policyTestSelectDevice => 'Seleziona un dispositivo';

  @override
  String get policyTestNoDevices => 'Nessun dispositivo registrato trovato in questo tenant.';

  @override
  String get policyTestProtocol => 'Protocollo';

  @override
  String get policyTestDstIp => 'IP di destinazione';

  @override
  String get policyTestDstPort => 'Porta di destinazione';

  @override
  String get policyTestDomain => 'Dominio';

  @override
  String get policyTestApp => 'Pacchetto applicazione';

  @override
  String get policyTestAppHelp => 'Nome pacchetto Android (disabilitato in modalità Edge)';

  @override
  String get policyTestNetwork => 'Tipo di rete';

  @override
  String get policyTestEdge => 'Valuta come Edge';

  @override
  String get policyTestEdgeHelp =>
      'Simula la valutazione su un nodo Edge (gli attributi del dispositivo come app e rete vengono ignorati)';

  @override
  String get policyTestActionTest => 'Test';

  @override
  String get policyTestTesting => 'Test in corso...';

  @override
  String get policyTestInvalidIp => 'Inserisci un indirizzo IPv4 o IPv6 valido';

  @override
  String get policyTestInvalidPort => 'La porta deve essere compresa tra 0 e 65535';

  @override
  String get policyTestResultTitle => 'Risultato della valutazione';

  @override
  String get policyTestResultAction => 'Azione';

  @override
  String get policyTestResultLayer => 'Livello';

  @override
  String get policyTestResultRuleId => 'ID regola';

  @override
  String get policyTestResultReason => 'Motivo';

  @override
  String get policyTestResultSnapshot => 'Versione snapshot';

  @override
  String get navExperience => 'Esperienza';

  @override
  String get experienceSubtitle => 'Telemetria dell\'esperienza digitale tra dispositivi ed Edge.';

  @override
  String get experiencePeriod => 'Periodo';

  @override
  String get experiencePeriodHour1 => '1 ora';

  @override
  String get experiencePeriodHours24 => '24 ore';

  @override
  String get experiencePeriodDays7 => '7 giorni';

  @override
  String get experiencePeriodDays30 => '30 giorni';

  @override
  String get experienceFilterDevice => 'Filtra per nome dispositivo';

  @override
  String get experienceStatDevicesMeasured => 'Dispositivi misurati';

  @override
  String get experienceStatMedianRtt => 'RTT p50 mediano';

  @override
  String get experienceStatHighLossRows => 'Righe con perdita > 2%';

  @override
  String get experienceColDevice => 'Dispositivo';

  @override
  String get experienceColEdge => 'Edge';

  @override
  String get experienceColSamples => 'Campioni';

  @override
  String get experienceColRttP50 => 'RTT p50';

  @override
  String get experienceColRttP95 => 'RTT p95';

  @override
  String get experienceColLoss => 'Perdita';

  @override
  String get experienceColDnsP50 => 'DNS p50';

  @override
  String get experienceColLast => 'Ultimo campione';

  @override
  String get experienceEmpty => 'Nessun dato di esperienza digitale per questo periodo';
}
