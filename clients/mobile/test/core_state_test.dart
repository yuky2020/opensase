import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:opensase/src/contracts/engine_types.dart';
import 'package:opensase/src/contracts/policy.dart';
import 'package:opensase/src/data/core_state.dart';
import 'package:opensase/src/data/policy_logic.dart';
import 'package:opensase/src/data/user_layer_store.dart';
import 'package:opensase/src/engine/engine.dart';
import 'package:opensase/src/engine/fake_engine.dart';
import 'package:opensase/src/ui/screen_state.dart';

ProviderContainer containerFor(FakeEngine engine, {UserLayerStore? store}) {
  final c = ProviderContainer(
    overrides: [
      engineProvider.overrideWithValue(engine),
      userLayerStoreProvider.overrideWithValue(store ?? InMemoryUserLayerStore()),
      pollIntervalProvider.overrideWithValue(null),
    ],
  );
  addTearDown(c.dispose);
  return c;
}

Future<void> settle() => Future<void>.delayed(const Duration(milliseconds: 10));

void main() {
  test('not enrolled -> enrolled flag false, then enroll loads the snapshot', () async {
    final e = FakeEngine(liveTraffic: false);
    final c = containerFor(e);
    c.read(coreProvider);
    await settle();
    expect(c.read(coreProvider).enrolled, isFalse);
    await c.read(coreProvider.notifier).enroll('https://10.0.2.2:9443#sha256=00', 'PK', 'Pixel');
    final s = c.read(coreProvider);
    expect(s.enrolled, isTrue);
    expect(s.policy.snapshot?.version, 41);
    expect(s.flows, isNotEmpty);
    expect(s.counters.allowed + s.counters.blocked, s.flows.length);
  });

  test('enroll errors surface as EngineException', () async {
    final c = containerFor(FakeEngine(liveTraffic: false));
    expect(() => c.read(coreProvider.notifier).enroll('https://x', 'invalid', 'n'), throwsA(isA<EngineException>()));
  });

  test('connect: vpn running, quantum-safe only once connected', () async {
    final e = FakeEngine(liveTraffic: false, enrolled: true);
    final c = containerFor(e);
    c.read(coreProvider);
    await settle();
    expect(c.read(coreProvider).quantumSafe, isFalse);
    expect(await c.read(coreProvider.notifier).connect(), isTrue);
    await settle();
    final s = c.read(coreProvider);
    expect(s.vpn.phase, VpnPhase.running);
    expect(s.status.isConnected, isTrue);
    expect(s.quantumSafe, isTrue);
    await c.read(coreProvider.notifier).disconnect();
    await settle();
    expect(c.read(coreProvider).vpn.phase, VpnPhase.idle);
    expect(c.read(coreProvider).quantumSafe, isFalse);
  });

  test('toggling an app sends the whole user layer and stores it', () async {
    final e = FakeEngine(liveTraffic: false, enrolled: true);
    final store = InMemoryUserLayerStore();
    final c = containerFor(e, store: store);
    c.read(coreProvider);
    await settle();
    final r = await c
        .read(coreProvider.notifier)
        .updateUserLayer((u) => PolicyLogic.setAppNetwork(u, 'com.whatsapp', NetworkType.cellular, false));
    expect(r, isA<SaveOk>());
    expect(e.calls, contains('setUserRules'));
    final stored = await store.load();
    expect(stored!.apps['com.whatsapp']!.cellular, Verdict.block);
    expect(stored.rules.map((x) => x.id), ['u-1', 'u-2', 'u-3']);
    final s = c.read(coreProvider);
    expect(s.policy.snapshot!.version, 42);
    final v = PolicyLogic.verdicts('com.whatsapp', s.policy.snapshot, s.policy.user, s.policy.tenantApps);
    expect(v[1].allowed, isFalse);
  });

  test('tenant disallows user rules -> SaveForbidden, nothing sent', () async {
    final e = FakeEngine(liveTraffic: false, enrolled: true, allowUserRules: false);
    final c = containerFor(e);
    c.read(coreProvider);
    await settle();
    final r = await c
        .read(coreProvider.notifier)
        .updateUserLayer((u) => PolicyLogic.addDomainRule(u, 'x.example', Verdict.block));
    expect(r, isA<SaveForbidden>());
    expect(e.calls, isNot(contains('setUserRules')));
  });

  test('403 from the engine maps to SaveForbidden', () async {
    // Snapshot says allowed but the cloud refuses (policy changed in between).
    final e = _ForbiddingEngine(liveTraffic: false, enrolled: true);
    final c = containerFor(e);
    c.read(coreProvider);
    await settle();
    final r = await c
        .read(coreProvider.notifier)
        .updateUserLayer((u) => PolicyLogic.addDomainRule(u, 'x.example', Verdict.block));
    expect(r, isA<SaveForbidden>());
  });

  test('flow and stats events update state; activity filters and pause', () async {
    final e = FakeEngine(liveTraffic: false, enrolled: true);
    final c = containerFor(e);
    c.read(coreProvider);
    await settle();
    final before = c.read(coreProvider).flows.length;
    c.read(activityProvider.notifier).setPaused(true);
    e.generate(5);
    await settle();
    expect(c.read(coreProvider).flows.length, before + 5);
    expect(c.read(activityViewProvider).records.length, before, reason: 'paused view is frozen');
    c.read(activityProvider.notifier).setPaused(false);
    c.read(activityProvider.notifier).setVerdict(VerdictFilter.blocked);
    final blocked = c.read(activityViewProvider).records;
    expect(blocked, isNotEmpty);
    expect(blocked.every((r) => r.decision.action == Verdict.block), isTrue);
    final stats = c.read(coreProvider).stats;
    expect(stats.fold<int>(0, (a, s) => a + s.allowed + s.blocked), before + 5);
  });

  test('stats sorting', () {
    const a = AppStat(app: 'a', bytesIn: 10, bytesOut: 1, allowed: 5, blocked: 0);
    const b = AppStat(app: 'b', bytesIn: 1, bytesOut: 50, allowed: 1, blocked: 9);
    expect(sortStats([a, b], StatsSort.total).first.app, 'b');
    expect(sortStats([a, b], StatsSort.bytesIn).first.app, 'a');
    expect(sortStats([a, b], StatsSort.blocked).first.app, 'b');
    expect(sortStats([a, b], StatsSort.allowed).first.app, 'a');
  });

  test('apps rows: filters and lock flags', () async {
    final e = FakeEngine(liveTraffic: false, enrolled: true);
    final c = containerFor(e);
    c.read(coreProvider);
    await settle();
    await c.read(installedAppsProvider.future);
    var rows = c.read(appRowsProvider).value!;
    expect(rows.any((r) => r.app.isSystem), isFalse);
    expect(rows.any((r) => r.app.packageName == 'com.android.calculator2'), isFalse, reason: 'no INTERNET permission');
    expect(rows.firstWhere((r) => r.app.packageName == 'com.zhiliaoapp.musically').anyLocked, isTrue);
    c.read(appsFilterProvider.notifier).setKind(AppKind.system);
    rows = c.read(appRowsProvider).value!;
    expect(rows.every((r) => r.app.isSystem), isTrue);
    c.read(appsFilterProvider.notifier)
      ..setKind(AppKind.all)
      ..setQuery('tele');
    expect(c.read(appRowsProvider).value!.map((r) => r.app.label), ['Telegram']);
  });
}

class _ForbiddingEngine extends FakeEngine {
  _ForbiddingEngine({super.liveTraffic, super.enrolled});

  @override
  Future<void> setUserRules(String json) async =>
      throw const UserRulesForbiddenException('PUT /v1/self/rules: 403 Forbidden');
}
