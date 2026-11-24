import 'dart:async';

import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../contracts/api.dart';
import '../contracts/engine_types.dart';
import '../contracts/policy.dart';
import '../engine/engine.dart';
import '../platform_info.dart';
import 'parsers.dart';
import 'policy_logic.dart';
import 'user_layer_store.dart';

/// Overridden in main() (native or fake) and in tests.
final engineProvider = Provider<Engine>((ref) => throw UnimplementedError('engineProvider not overridden'));

final userLayerStoreProvider = Provider<UserLayerStore>((ref) => PrefsUserLayerStore());

/// Status/stats polling period; tests set it to null to disable polling.
final pollIntervalProvider = Provider<Duration?>((ref) => const Duration(seconds: 2));

final installedAppsProvider = FutureProvider<List<InstalledApp>>((ref) => ref.watch(engineProvider).installedApps());

final appsByPackageProvider = Provider<Map<String, InstalledApp>>((ref) {
  final apps = ref.watch(installedAppsProvider).value ?? const <InstalledApp>[];
  return {for (final a in apps) a.packageName: a};
});

class PolicyState {
  const PolicyState({this.snapshot, this.user = const UserRules(), this.tenantApps = const {}});

  final Snapshot? snapshot;

  /// The user layer as last accepted by the Control Plane.
  final UserRules user;

  /// Best estimate of tenant-mandated per-app entries.
  // CONTRACT-CHANGE-REQUEST: policy.FirewallPolicy.Apps merges tenant and user entries, so
  // the device cannot tell which per-app entries are tenant-mandated (and there is no
  // GET /v1/self/rules to read the user layer back). Proposal: add `source` to AppPolicy or
  // a separate `tenantApps` map in the snapshot.
  final Map<String, AppPolicy> tenantApps;

  bool get allowUserRules => snapshot?.firewall.allowUserRules ?? false;

  /// UI may edit the user layer (true while there is no snapshot yet: the cloud decides).
  bool get userLayerEditable => snapshot == null || allowUserRules;

  /// Splits the merged snapshot back into layers. User rules come from the snapshot
  /// (source=user). Per-app entries cannot be told apart, so the user's apps come from the
  /// locally stored layer; without one (and with user rules allowed) the snapshot apps are
  /// adopted as the starting point.
  static PolicyState derive(Snapshot? snap, UserRules? stored) {
    if (snap == null) return PolicyState(user: stored ?? const UserRules());
    final fw = snap.firewall;
    final userApps = !fw.allowUserRules ? const <String, AppPolicy>{} : (stored?.apps ?? fw.apps);
    final tenantApps = fw.allowUserRules && stored == null
        ? const <String, AppPolicy>{}
        : {
            for (final e in fw.apps.entries)
              if (!_samePolicy(userApps[e.key], e.value)) e.key: e.value,
          };
    return PolicyState(
      snapshot: snap,
      user: UserRules(rules: PolicyLogic.userRules(snap), apps: userApps),
      tenantApps: tenantApps,
    );
  }

  static bool _samePolicy(AppPolicy? a, AppPolicy b) =>
      a != null && a.wifi == b.wifi && a.cellular == b.cellular && a.roaming == b.roaming;
}

class CoreState {
  const CoreState({
    this.enrolled,
    this.status = const EngineStatus(),
    this.vpn = const VpnStatus(),
    this.policy = const PolicyState(),
    this.flows = const [],
    this.stats = const [],
    this.lastError = '',
    this.daemonConnected = true,
  });

  /// null while still checking.
  final bool? enrolled;
  final EngineStatus status;
  final VpnStatus vpn;
  final PolicyState policy;

  /// Newest first, capped at [CoreNotifier.maxFlows].
  final List<FlowRecord> flows;
  final List<AppStat> stats;

  /// Last background error from the core (`error` event), for diagnostics.
  final String lastError;

  /// Whether the desktop daemon is currently connected and reachable.
  final bool daemonConnected;

  TrafficCounters get counters => Parsers.counters(stats);

  /// The quantum-safe badge is shown only when the core reports pq=true on a live tunnel.
  bool get quantumSafe => status.isConnected && status.pq;

  CoreState copyWith({
    bool? enrolled,
    EngineStatus? status,
    VpnStatus? vpn,
    PolicyState? policy,
    List<FlowRecord>? flows,
    List<AppStat>? stats,
    String? lastError,
    bool? daemonConnected,
  }) => CoreState(
    enrolled: enrolled ?? this.enrolled,
    status: status ?? this.status,
    vpn: vpn ?? this.vpn,
    policy: policy ?? this.policy,
    flows: flows ?? this.flows,
    stats: stats ?? this.stats,
    lastError: lastError ?? this.lastError,
    daemonConnected: daemonConnected ?? this.daemonConnected,
  );
}

sealed class SaveResult {
  const SaveResult();
}

class SaveOk extends SaveResult {
  const SaveOk();
}

/// The tenant does not allow user rules (403).
class SaveForbidden extends SaveResult {
  const SaveForbidden();
}

class SaveFailed extends SaveResult {
  const SaveFailed(this.message);
  final String message;
}

final coreProvider = NotifierProvider<CoreNotifier, CoreState>(CoreNotifier.new);

/// Single source of UI state derived from the engine. The engine and the cloud remain
/// authoritative; this only caches and turns events into state.
class CoreNotifier extends Notifier<CoreState> {
  static const maxFlows = 500;

  late Engine _engine;
  late UserLayerStore _store;
  StreamSubscription<EngineEvent>? _sub;
  Timer? _poll;
  Future<void>? _saving;

  @override
  CoreState build() {
    _engine = ref.watch(engineProvider);
    _store = ref.watch(userLayerStoreProvider);
    _sub = _engine.events.listen(_onEvent);
    final period = ref.watch(pollIntervalProvider);
    if (period != null) {
      _poll = Timer.periodic(period, (_) {
        if (state.enrolled ?? false) {
          refreshStatus();
          refreshStats();
        }
      });
    }
    ref.onDispose(() {
      _sub?.cancel();
      _poll?.cancel();
    });
    Future.microtask(refreshAll);
    return const CoreState();
  }

  Engine get engine => _engine;

  Future<void> refreshAll() async {
    final enrolled = await _guard(_engine.isEnrolled, false);
    final vpn = await _guard(_engine.vpnStatus, state.vpn);
    if (!ref.mounted) return;
    state = state.copyWith(enrolled: enrolled, vpn: vpn);
    if (!enrolled) return;
    await Future.wait([refreshStatus(), refreshSnapshot(), refreshStats(), refreshFlows()]);
  }

  // Note: always await into a local first. `state = state.copyWith(x: await f())` would
  // capture `state` before the await and drop updates made concurrently.

  Future<void> refreshStatus() async {
    final st = Parsers.status(await _guard(_engine.status, ''));
    final vpn = isDesktop ? await _guard(_engine.vpnStatus, state.vpn) : state.vpn;
    if (ref.mounted) state = state.copyWith(status: st, vpn: vpn);
  }

  Future<void> refreshStats() async {
    final stats = Parsers.appStats(await _guard(_engine.appStats, '[]'));
    if (ref.mounted) state = state.copyWith(stats: stats);
  }

  Future<void> refreshFlows() async {
    final flows = Parsers.flows(await _guard(() => _engine.recentFlows(maxFlows), '[]'));
    if (ref.mounted) state = state.copyWith(flows: flows);
  }

  Future<void> refreshSnapshot() async {
    final snap = Parsers.snapshot(await _guard(_engine.snapshot, ''));
    final stored = await _store.load();
    if (ref.mounted) state = state.copyWith(policy: PolicyState.derive(snap, stored));
  }

  Future<void> enroll(String controlUrl, String key, String deviceName) async {
    await _engine.enroll(controlUrl.trim(), key.trim(), deviceName.trim());
    if (!ref.mounted) return;
    state = state.copyWith(enrolled: true);
    await refreshAll();
  }

  Future<void> unenroll() async {
    await _engine.unenroll();
    await _store.save(null);
    if (ref.mounted) state = const CoreState(enrolled: false);
  }

  /// Asks for VPN consent if needed, then starts the VpnService. Returns false if denied.
  Future<bool> connect() async {
    if (!await _engine.prepareVpn()) {
      state = state.copyWith(
        vpn: const VpnStatus(phase: VpnPhase.failed, message: 'consent'),
      );
      return false;
    }
    await _engine.connect();
    return true;
  }

  Future<void> disconnect() => _engine.disconnect();

  /// Applies [transform] to the user layer and sends the whole layer to the cloud.
  /// Saves are serialized so concurrent toggles do not overwrite each other.
  Future<SaveResult> updateUserLayer(UserRules Function(UserRules) transform) async {
    while (_saving != null) {
      await _saving;
    }
    final done = Completer<void>();
    _saving = done.future;
    try {
      final current = state.policy;
      if (!current.userLayerEditable) return const SaveForbidden();
      final next = transform(current.user);
      if (Parsers.encodeUserRules(next) == Parsers.encodeUserRules(current.user)) return const SaveOk();
      try {
        await _engine.setUserRules(Parsers.encodeUserRules(next));
      } on UserRulesForbiddenException {
        return const SaveForbidden();
      } on EngineException catch (e) {
        return SaveFailed(e.message);
      }
      await _store.save(next);
      if (!ref.mounted) return const SaveOk();
      // Optimistic; the refresh brings the signed snapshot.
      state = state.copyWith(
        policy: PolicyState(snapshot: current.snapshot, user: next, tenantApps: current.tenantApps),
      );
      await refreshSnapshot();
      return const SaveOk();
    } finally {
      _saving = null;
      done.complete();
    }
  }

  Future<T> _guard<T>(Future<T> Function() f, T fallback) async {
    try {
      return await f();
    } catch (_) {
      if (isDesktop) {
        state = state.copyWith(daemonConnected: false);
      }
      return fallback;
    }
  }

  void _onEvent(EngineEvent ev) {
    switch (ev.kind) {
      case EngineEvent.daemon:
        try {
          final m = Parsers.decodeMap(ev.payload);
          final connected = m['connected'] as bool? ?? true;
          state = state.copyWith(daemonConnected: connected);
          if (connected) {
            refreshAll();
          }
        } catch (_) {}
      case EngineEvent.flow:
        final r = Parsers.flow(ev.payload);
        if (r != null) {
          final list = [r, ...state.flows];
          state = state.copyWith(flows: list.length > maxFlows ? list.sublist(0, maxFlows) : list);
        }
      case EngineEvent.stats:
        state = state.copyWith(stats: Parsers.appStats(ev.payload));
      case EngineEvent.state:
        // Partial payload ({"state","error"} or {"state","epoch"}): re-read the full status.
        refreshStatus();
      case EngineEvent.snapshot:
        refreshSnapshot();
        refreshStatus();
      case EngineEvent.vpn:
        try {
          state = state.copyWith(vpn: VpnStatus.fromJson(Parsers.decodeMap(ev.payload)));
        } catch (_) {}
        refreshStatus();
      case EngineEvent.error:
        state = state.copyWith(lastError: ev.payload);
    }
  }
}
