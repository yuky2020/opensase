import 'dart:async';
import 'dart:convert';
import 'dart:math';

import '../contracts/api.dart';
import '../contracts/engine_types.dart';
import '../contracts/policy.dart';
import 'engine.dart';

/// Pure-Dart stand-in for the native side and the Go core: realistic snapshot, flows,
/// stats, installed apps and a fake VPN lifecycle. It speaks exactly the same JSON as the
/// real engine, so the parsing code is exercised too.
///
/// Enable in the app with `--dart-define=FAKE_ENGINE=true`; used directly by tests.
class FakeEngine implements Engine {
  FakeEngine({
    this.allowUserRules = true,
    this.liveTraffic = true,
    this.postureFailing = const [],
    this._enrolled = false,
    int seed = 42,
    DateTime Function()? clock,
  }) : _random = Random(seed),
       _clock = clock ?? DateTime.now {
    if (_enrolled) _seedHistory();
  }

  final bool allowUserRules;
  final bool liveTraffic;
  List<String> postureFailing;
  final Random _random;
  final DateTime Function() _clock;
  final _events = StreamController<EngineEvent>.broadcast();

  bool _enrolled;
  String _state = EngineStatus.stopped;
  VpnStatus _vpn = const VpnStatus();
  NetworkType _network = NetworkType.wifi;
  int _version = 41;
  UserRules _user = UserRules(rules: initialUserRules, apps: initialUserApps);
  final List<FlowRecord> _flows = [];
  final Map<String, AppStat> _stats = {};
  TrafficCounters _counters = const TrafficCounters();
  Timer? _timer;

  /// Calls received, for tests.
  final List<String> calls = [];

  @override
  String get name => 'fake';

  @override
  Stream<EngineEvent> get events => _events.stream;

  @override
  Future<bool> isEnrolled() async => _enrolled;

  @override
  Future<void> enroll(String controlUrl, String provisioningKey, String deviceName) async {
    calls.add('enroll');
    if (!controlUrl.startsWith('https://')) throw const EngineException('control URL must use https');
    if (provisioningKey.trim().isEmpty) throw const EngineException('provisioning key required');
    if (provisioningKey == 'invalid') throw const EngineException('enroll: 401 provisioning key rejected');
    if (liveTraffic) await Future<void>.delayed(const Duration(milliseconds: 600));
    _enrolled = true;
    _seedHistory();
  }

  @override
  Future<void> unenroll() async {
    await disconnect();
    _enrolled = false;
    _flows.clear();
    _stats.clear();
    _counters = const TrafficCounters();
    _user = UserRules(rules: initialUserRules, apps: initialUserApps);
  }

  @override
  Future<bool> prepareVpn() async => true;

  @override
  Future<void> connect() async {
    calls.add('connect');
    if (!_enrolled) {
      _setVpn(const VpnStatus(phase: VpnPhase.failed, message: 'not enrolled'));
      return;
    }
    _state = EngineStatus.connecting;
    _setVpn(const VpnStatus(phase: VpnPhase.connecting));
    _emit(EngineEvent.state, jsonEncode({'state': _state, 'error': ''}));
    void up() {
      _state = EngineStatus.connected;
      _setVpn(const VpnStatus(phase: VpnPhase.running));
      _emit(EngineEvent.state, jsonEncode({'state': _state, 'error': ''}));
    }

    if (!liveTraffic) {
      up();
      return;
    }
    Timer(const Duration(milliseconds: 700), up);
    _timer?.cancel();
    _timer = Timer.periodic(const Duration(milliseconds: 900), (_) {
      if (_state == EngineStatus.connected) generate(1);
    });
  }

  @override
  Future<void> disconnect() async {
    calls.add('disconnect');
    _timer?.cancel();
    _timer = null;
    if (_state != EngineStatus.stopped) {
      _state = EngineStatus.stopped;
      _emit(EngineEvent.state, jsonEncode({'state': _state, 'error': ''}));
    }
    _setVpn(const VpnStatus());
  }

  @override
  Future<String> status() async => jsonEncode(
    EngineStatus(
      state: _state,
      edge: _state == EngineStatus.stopped ? '' : 'edge-eu-south-1',
      snapshotVersion: _enrolled ? _version : 0,
      pq: _state == EngineStatus.connected,
      certExpiresAt: _enrolled ? _clock().toUtc().add(const Duration(days: 30)).toIso8601String() : '',
      kex: _state == EngineStatus.connected ? 'X25519MLKEM768' : '',
      postureFailing: postureFailing,
    ).toJson(),
  );

  @override
  Future<String> snapshot() async => _enrolled ? jsonEncode(_buildSnapshot().toJson()) : '';

  @override
  Future<void> setUserRules(String json) async {
    calls.add('setUserRules');
    final UserRules parsed;
    try {
      parsed = UserRules.fromJson(jsonDecode(json) as Map<String, dynamic>);
    } catch (e) {
      throw EngineException('invalid user rules: $e');
    }
    if (!allowUserRules) {
      throw const UserRulesForbiddenException('PUT /v1/self/rules: 403 Forbidden: tenant does not allow user rules');
    }
    for (final r in parsed.rules) {
      if (r.source != RuleSource.user) throw EngineException('rule ${r.id}: source must be user');
    }
    _user = parsed;
    _version++;
    _emit(EngineEvent.snapshot, jsonEncode({'version': _version, 'stale': false}));
  }

  @override
  Future<void> setAppPolicy(String pkg, String wifi, String cellular, String roaming) async {
    Verdict? v(String s) => switch (s) {
      'allow' => Verdict.allow,
      'block' => Verdict.block,
      'ask' => Verdict.ask,
      _ => null,
    };
    final p = AppPolicy(wifi: v(wifi), cellular: v(cellular), roaming: v(roaming));
    final apps = Map<String, AppPolicy>.of(_user.apps);
    if (p.isEmpty) {
      apps.remove(pkg);
    } else {
      apps[pkg] = p;
    }
    await setUserRules(jsonEncode(_user.copyWith(apps: apps).toJson()));
  }

  @override
  Future<String> recentFlows(int limit) async => jsonEncode(_flows.take(max(0, limit)).map((f) => f.toJson()).toList());

  @override
  Future<String> appStats() async => jsonEncode(_stats.values.map((s) => s.toJson()).toList());

  @override
  Future<List<InstalledApp>> installedApps() async => fakeApps;

  @override
  Future<VpnStatus> vpnStatus() async => _vpn;

  @override
  Future<void> openVpnSettings() async => calls.add('openVpnSettings');

  String? lastOpenedUrl;
  final List<String> openedUrls = [];

  @override
  Future<void> openBrowser(String url) async {
    calls.add('openBrowser');
    lastOpenedUrl = url;
    openedUrls.add(url);
  }

  @override
  Future<bool> saveFile(String fileName, String content) async {
    calls.add('saveFile:$fileName');
    return true;
  }

  /// Set by tests to simulate a deep link.
  String? pendingEnrollLink;

  @override
  Future<String?> takeEnrollLink() async {
    final l = pendingEnrollLink;
    pendingEnrollLink = null;
    return l;
  }

  /// Simulates a deep link arriving while the app runs.
  void deliverEnrollLink(String uri) => _emit(EngineEvent.enrollLink, uri);

  @override
  Future<void> setConnectOnBoot(bool enabled) async => calls.add('setConnectOnBoot:$enabled');

  /// Changes the simulated network type (the native side does this from NetworkCallback).
  void setNetwork(NetworkType n) => _network = n;

  /// Totals since enrollment (what Home shows as "today").
  TrafficCounters get counters => _counters;

  /// Generates [n] synthetic flows and emits them as `flow` and `stats` events.
  void generate(int n) {
    for (var i = 0; i < n; i++) {
      final r = _nextFlow(_clock());
      _record(r);
      _emit(EngineEvent.flow, jsonEncode(r.toJson()));
    }
    // Like the core: "stats" carries the appStats() array.
    if (n > 0) appStats().then((s) => _emit(EngineEvent.stats, s));
  }

  Future<void> dispose() async {
    _timer?.cancel();
    await _events.close();
  }

  // ---- internals ----

  void _emit(String kind, String payload) {
    if (!_events.isClosed) _events.add(EngineEvent(kind, payload));
  }

  void _setVpn(VpnStatus s) {
    _vpn = s;
    _emit(EngineEvent.vpn, jsonEncode(s.toJson()));
  }

  Snapshot _buildSnapshot() {
    final now = _clock().toUtc();
    final apps = Map<String, AppPolicy>.of(tenantApps);
    if (allowUserRules) apps.addAll(_user.apps);
    return Snapshot(
      version: _version,
      tenantId: 't-acme',
      userId: 'u-mrossi',
      deviceId: 'd-pixel-7f3a',
      issuedAt: now.subtract(const Duration(minutes: 12)).toIso8601String(),
      expiresAt: now.add(const Duration(days: 1)).toIso8601String(),
      firewall: FirewallPolicy(
        defaultAction: Verdict.allow,
        allowUserRules: allowUserRules,
        rules: [...tenantRules, if (allowUserRules) ..._user.rules],
        apps: apps,
      ),
      dns: const DnsPolicy(blockResponse: 'nxdomain', blocklists: blocklists),
    );
  }

  void _seedHistory() {
    if (_flows.isNotEmpty) return;
    final now = _clock();
    for (var i = 120; i >= 1; i--) {
      _record(_nextFlow(now.subtract(Duration(seconds: i * 37))));
    }
  }

  void _record(FlowRecord r) {
    _flows.insert(0, r);
    if (_flows.length > 1000) _flows.removeLast();
    final blocked = r.decision.action == Verdict.block;
    final s = _stats[r.flow.app] ?? AppStat(app: r.flow.app);
    final dns = r.flow.dstPort == 53;
    _stats[r.flow.app] = AppStat(
      app: s.app,
      bytesIn: s.bytesIn + r.bytesIn,
      bytesOut: s.bytesOut + r.bytesOut,
      allowed: s.allowed + (blocked ? 0 : 1),
      blocked: s.blocked + (blocked ? 1 : 0),
      dnsQueries: s.dnsQueries + (dns ? 1 : 0),
      dnsBlocked: s.dnsBlocked + (dns && blocked ? 1 : 0),
    );
    _counters = TrafficCounters(
      allowed: _counters.allowed + (blocked ? 0 : 1),
      blocked: _counters.blocked + (blocked ? 1 : 0),
      dnsBlocked: _counters.dnsBlocked + (blocked && r.decision.layer == 'dns' ? 1 : 0),
    );
  }

  int _between(int lo, int hi) => lo + _random.nextInt(hi - lo);

  FlowRecord _nextFlow(DateTime at) {
    final pkgs = fakeApps.where((a) => a.hasInternet).map((a) => a.packageName).toList();
    // Skewed choice: a few apps dominate, like real traffic.
    final x = _random.nextDouble();
    final app = pkgs[min(pkgs.length - 1, (x * x * pkgs.length).floor())];
    final dest = _destinations[_random.nextInt(_destinations.length)];
    final isDns = _random.nextInt(5) == 0;
    final tracker = _trackers[_random.nextInt(_trackers.length)];
    final net = _network == NetworkType.unknown ? NetworkType.wifi : _network;
    final flow = isDns
        ? NetFlow(
            app: app,
            uid: _uidFor(app),
            network: net,
            protocol: 'udp',
            dstIp: '100.64.0.1',
            dstPort: 53,
            domain: tracker,
          )
        : NetFlow(
            app: app,
            uid: _uidFor(app),
            network: net,
            protocol: _random.nextInt(6) == 0 ? 'udp' : 'tcp',
            dstIp: dest.$2,
            dstPort: _random.nextInt(10) == 0 ? 853 : 443,
            domain: dest.$1,
          );
    final Decision decision;
    if (isDns) {
      final list = blocklists.firstWhere((l) => l.domains.any((d) => matchesDomain(d, tracker)));
      decision = Decision(action: Verdict.block, ruleId: 'dns:${list.id}', layer: 'dns', log: true);
    } else {
      decision = _evaluate(flow);
    }
    final allowed = decision.action == Verdict.allow;
    return FlowRecord(
      start: at.toUtc().toIso8601String(),
      end: at.add(Duration(milliseconds: _between(200, 30000))).toUtc().toIso8601String(),
      flow: flow,
      decision: decision,
      bytesOut: allowed ? _between(400, 60000) : 0,
      bytesIn: allowed ? _between(1000, 2500000) : 0,
      where: 'device',
      deviceId: 'd-pixel-7f3a',
    );
  }

  /// Small approximation of pkg/policy Evaluate, enough for believable data.
  Decision _evaluate(NetFlow f) {
    final snap = _buildSnapshot();
    final rules = [...snap.firewall.rules]
      ..sort((a, b) => a.source != b.source ? a.source.index - b.source.index : a.priority - b.priority);
    for (final r in rules) {
      if (_matches(r.match, f)) {
        final ask = r.action == Verdict.ask;
        return Decision(
          action: ask ? Verdict.allow : r.action,
          ruleId: r.id,
          layer: ask ? 'cloud' : r.source.name,
          log: r.log,
        );
      }
    }
    final a = snap.firewall.apps[f.app]?.forNetwork(f.network);
    if (a != null) return Decision(action: a == Verdict.ask ? Verdict.allow : a, ruleId: 'app:${f.app}', layer: 'app');
    return Decision(action: snap.firewall.defaultAction, layer: 'default');
  }

  bool _matches(Match m, NetFlow f) {
    if (m.apps.isNotEmpty && !m.apps.contains(f.app)) return false;
    if (m.networks.isNotEmpty && !m.networks.contains(f.network)) return false;
    if (m.protocols.isNotEmpty && !m.protocols.contains(f.protocol)) return false;
    if (m.ports.isNotEmpty && !m.ports.any((p) => f.dstPort >= p.from && f.dstPort <= p.last)) return false;
    if (m.domains.isNotEmpty && !m.domains.any((d) => matchesDomain(d, f.domain))) return false;
    if (m.cidrs.isNotEmpty &&
        !m.cidrs.any((c) => f.dstIp.startsWith(c.split('/').first.replaceAll(RegExp(r'[0.]+$'), '')))) {
      return false;
    }
    return true;
  }

  static int _uidFor(String app) => 10000 + (app.hashCode & 0x3ff);

  static bool matchesDomain(String pattern, String name) {
    if (name.isEmpty) return false;
    if (pattern.startsWith('*.')) {
      final apex = pattern.substring(2);
      return name == apex || name.endsWith('.$apex');
    }
    return name == pattern;
  }

  // ---- fixtures ----

  static const fakeApps = <InstalledApp>[
    InstalledApp(packageName: 'com.android.chrome', label: 'Chrome', uid: 10101),
    InstalledApp(packageName: 'com.google.android.youtube', label: 'YouTube', uid: 10102),
    InstalledApp(packageName: 'com.whatsapp', label: 'WhatsApp', uid: 10103),
    InstalledApp(packageName: 'com.instagram.android', label: 'Instagram', uid: 10104),
    InstalledApp(packageName: 'com.spotify.music', label: 'Spotify', uid: 10105),
    InstalledApp(packageName: 'com.facebook.katana', label: 'Facebook', uid: 10106),
    InstalledApp(packageName: 'com.google.android.gm', label: 'Gmail', uid: 10107),
    InstalledApp(packageName: 'com.zhiliaoapp.musically', label: 'TikTok', uid: 10108),
    InstalledApp(packageName: 'com.google.android.apps.maps', label: 'Maps', uid: 10109),
    InstalledApp(packageName: 'com.microsoft.teams', label: 'Microsoft Teams', uid: 10110),
    InstalledApp(packageName: 'org.telegram.messenger', label: 'Telegram', uid: 10111),
    InstalledApp(packageName: 'com.android.calculator2', label: 'Calculator', uid: 10112, hasInternet: false),
    InstalledApp(packageName: 'com.google.android.gms', label: 'Google Play services', uid: 10113, isSystem: true),
    InstalledApp(packageName: 'com.android.settings', label: 'Settings', uid: 1000, isSystem: true),
    InstalledApp(
      packageName: 'com.google.android.webview',
      label: 'Android System WebView',
      uid: 10114,
      isSystem: true,
    ),
  ];

  static const tenantRules = <Rule>[
    Rule(
      id: 't-100',
      source: RuleSource.tenant,
      priority: 10,
      action: Verdict.block,
      match: Match(protocols: ['tcp'], ports: [PortRange(from: 25)]),
      log: true,
      description: 'Block outbound SMTP',
    ),
    Rule(
      id: 't-110',
      source: RuleSource.tenant,
      priority: 20,
      action: Verdict.block,
      match: Match(apps: ['com.zhiliaoapp.musically']),
      log: true,
      description: 'TikTok not allowed on company devices',
    ),
    Rule(
      id: 't-120',
      source: RuleSource.tenant,
      priority: 30,
      action: Verdict.block,
      match: Match(apps: ['com.facebook.katana'], networks: [NetworkType.cellular, NetworkType.roaming]),
      description: 'Facebook only on Wi-Fi',
    ),
    Rule(
      id: 't-130',
      source: RuleSource.tenant,
      priority: 40,
      action: Verdict.allow,
      match: Match(cidrs: ['10.0.0.0/8', 'fd00::/8']),
      description: 'Corporate network',
    ),
    Rule(
      id: 't-140',
      source: RuleSource.tenant,
      priority: 50,
      action: Verdict.ask,
      match: Match(protocols: ['udp'], ports: [PortRange(from: 853)]),
      log: true,
      description: 'DNS-over-TLS needs cloud decision',
    ),
  ];

  static const tenantApps = <String, AppPolicy>{
    'com.microsoft.teams': AppPolicy(wifi: Verdict.allow, cellular: Verdict.allow, roaming: Verdict.allow),
  };

  static const initialUserRules = <Rule>[
    Rule(
      id: 'u-1',
      priority: 100,
      action: Verdict.block,
      match: Match(domains: ['*.doubleclick.net']),
      log: true,
      description: 'Ads',
    ),
    Rule(
      id: 'u-2',
      priority: 110,
      action: Verdict.block,
      match: Match(apps: ['com.instagram.android'], networks: [NetworkType.roaming]),
      description: 'Instagram not in roaming',
    ),
    Rule(
      id: 'u-3',
      priority: 120,
      action: Verdict.allow,
      match: Match(domains: ['*.spotify.com']),
    ),
  ];

  static const initialUserApps = <String, AppPolicy>{
    'com.google.android.youtube': AppPolicy(wifi: Verdict.allow, cellular: Verdict.block, roaming: Verdict.block),
  };

  static const blocklists = <Blocklist>[
    Blocklist(
      id: 'bl-ads',
      name: 'Ads',
      category: 'ads',
      domains: ['*.doubleclick.net', '*.googlesyndication.com', '*.adnxs.com', 'ads.example.com'],
    ),
    Blocklist(
      id: 'bl-trackers',
      name: 'Trackers',
      category: 'trackers',
      domains: [
        '*.app-measurement.com',
        '*.scorecardresearch.com',
        'graph.facebook.com',
        '*.branch.io',
        '*.adjust.com',
      ],
    ),
    Blocklist(
      id: 'bl-malware',
      name: 'Malware',
      category: 'malware',
      domains: ['*.malware-c2.test', 'evil.example.net'],
    ),
  ];

  static const _trackers = [
    'pagead2.googlesyndication.com',
    'stats.doubleclick.net',
    'app-measurement.com',
    'sb.scorecardresearch.com',
    'graph.facebook.com',
    'api2.branch.io',
    'app.adjust.com',
    'ib.adnxs.com',
  ];

  static const _destinations = [
    ('www.google.com', '142.250.180.4'),
    ('i.ytimg.com', '142.250.184.86'),
    ('web.whatsapp.com', '157.240.231.60'),
    ('scontent.cdninstagram.com', '157.240.231.174'),
    ('spclient.wg.spotify.com', '35.186.224.25'),
    ('api.github.com', '140.82.121.6'),
    ('mail.google.com', '142.250.180.5'),
    ('teams.microsoft.com', '52.113.194.132'),
    ('intranet.acme.local', '10.20.0.15'),
    ('www.tiktok.com', '23.40.43.101'),
    ('smtp.example.org', '93.184.215.14'),
  ];
}
