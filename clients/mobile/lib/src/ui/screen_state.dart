import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../contracts/api.dart';
import '../contracts/engine_types.dart';
import '../contracts/policy.dart';
import '../data/core_state.dart';
import '../data/policy_logic.dart';
import '../engine/engine.dart';

// ---- Apps ----

enum AppKind { all, user, system }

class AppsFilter {
  const AppsFilter({this.query = '', this.kind = AppKind.user, this.internetOnly = true});
  final String query;
  final AppKind kind;
  final bool internetOnly;
  AppsFilter copyWith({String? query, AppKind? kind, bool? internetOnly}) =>
      AppsFilter(query: query ?? this.query, kind: kind ?? this.kind, internetOnly: internetOnly ?? this.internetOnly);
}

class AppsFilterNotifier extends Notifier<AppsFilter> {
  @override
  AppsFilter build() => const AppsFilter();
  void setQuery(String q) => state = state.copyWith(query: q);
  void setKind(AppKind k) => state = state.copyWith(kind: k);
  void setInternetOnly(bool v) => state = state.copyWith(internetOnly: v);
}

final appsFilterProvider = NotifierProvider<AppsFilterNotifier, AppsFilter>(AppsFilterNotifier.new);

class AppRow {
  const AppRow(this.app, this.verdicts);
  final InstalledApp app;
  final List<NetworkVerdict> verdicts;
  bool get anyLocked => verdicts.any((v) => v.locked);
}

/// Filtered app rows with their effective per-network verdicts.
final appRowsProvider = Provider<AsyncValue<List<AppRow>>>((ref) {
  final apps = ref.watch(installedAppsProvider);
  final f = ref.watch(appsFilterProvider);
  final policy = ref.watch(coreProvider.select((s) => s.policy));
  return apps.whenData((list) {
    final q = f.query.trim().toLowerCase();
    return list
        .where((a) => f.kind == AppKind.all || (f.kind == AppKind.system) == a.isSystem)
        .where((a) => !f.internetOnly || a.hasInternet)
        .where((a) => q.isEmpty || a.label.toLowerCase().contains(q) || a.packageName.toLowerCase().contains(q))
        .map((a) => AppRow(a, PolicyLogic.verdicts(a.packageName, policy.snapshot, policy.user, policy.tenantApps)))
        .toList();
  });
});

/// Verdicts for one app (detail page).
final appVerdictsProvider = Provider.family<List<NetworkVerdict>, String>((ref, pkg) {
  final p = ref.watch(coreProvider.select((s) => s.policy));
  return PolicyLogic.verdicts(pkg, p.snapshot, p.user, p.tenantApps);
});

// ---- Activity ----

enum VerdictFilter { all, allowed, blocked }

class ActivityControls {
  const ActivityControls({this.verdict = VerdictFilter.all, this.app, this.paused = false, this.frozen});
  final VerdictFilter verdict;
  final String? app;
  final bool paused;
  final List<FlowRecord>? frozen;
}

class ActivityNotifier extends Notifier<ActivityControls> {
  @override
  ActivityControls build() => const ActivityControls();

  void setVerdict(VerdictFilter v) =>
      state = ActivityControls(verdict: v, app: state.app, paused: state.paused, frozen: state.frozen);
  void setApp(String? pkg) =>
      state = ActivityControls(verdict: state.verdict, app: pkg, paused: state.paused, frozen: state.frozen);
  void setPaused(bool p) => state = ActivityControls(
    verdict: state.verdict,
    app: state.app,
    paused: p,
    frozen: p ? ref.read(coreProvider).flows : null,
  );
}

final activityProvider = NotifierProvider<ActivityNotifier, ActivityControls>(ActivityNotifier.new);

class ActivityView {
  const ActivityView(this.records, this.apps);
  final List<FlowRecord> records;
  final List<String> apps;
}

final activityViewProvider = Provider<ActivityView>((ref) {
  final c = ref.watch(activityProvider);
  final live = ref.watch(coreProvider.select((s) => s.flows));
  final source = c.paused ? (c.frozen ?? const <FlowRecord>[]) : live;
  final records = source.where((r) {
    if (c.app != null && r.flow.app != c.app) return false;
    return switch (c.verdict) {
      VerdictFilter.all => true,
      VerdictFilter.allowed => r.decision.action == Verdict.allow,
      VerdictFilter.blocked => r.decision.action == Verdict.block,
    };
  }).toList();
  final apps = source.map((r) => r.flow.app).where((a) => a.isNotEmpty).toSet().toList()..sort();
  return ActivityView(records, apps);
});

// ---- Stats ----

enum StatsSort { total, bytesIn, bytesOut, allowed, blocked }

class StatsSortNotifier extends Notifier<StatsSort> {
  @override
  StatsSort build() => StatsSort.total;
  void set(StatsSort s) => state = s;
}

final statsSortProvider = NotifierProvider<StatsSortNotifier, StatsSort>(StatsSortNotifier.new);

List<AppStat> sortStats(List<AppStat> stats, StatsSort s) {
  int Function(AppStat) key = switch (s) {
    StatsSort.total => (a) => a.bytesIn + a.bytesOut,
    StatsSort.bytesIn => (a) => a.bytesIn,
    StatsSort.bytesOut => (a) => a.bytesOut,
    StatsSort.allowed => (a) => a.allowed,
    StatsSort.blocked => (a) => a.blocked,
  };
  return [...stats]..sort((a, b) => key(b).compareTo(key(a)));
}

final sortedStatsProvider = Provider<List<AppStat>>((ref) {
  final stats = ref.watch(coreProvider.select((s) => s.stats));
  return sortStats(stats, ref.watch(statsSortProvider));
});
