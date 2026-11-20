import 'dart:convert';

import 'package:flutter/services.dart';

import 'engine.dart';

/// [Engine] backed by the native Android side (VpnService + gomobile core).
///
/// Every call goes through MethodChannel `eu.opensase/engine`. Native errors arrive as
/// PlatformException with code "forbidden" (HTTP 403 on user rules), "core" (any Go core
/// error) or "vpn" (VPN consent/service problems).
class MethodChannelEngine implements Engine {
  MethodChannelEngine({MethodChannel? methods, EventChannel? events})
    : _m = methods ?? const MethodChannel('eu.opensase/engine'),
      _e = events ?? const EventChannel('eu.opensase/events');

  final MethodChannel _m;
  final EventChannel _e;
  Stream<EngineEvent>? _events;

  @override
  String get name => 'native';

  Future<T> _call<T>(String method, [Map<String, Object?>? args]) async {
    try {
      return (await _m.invokeMethod<T>(method, args)) as T;
    } on PlatformException catch (e) {
      final msg = e.message ?? e.code;
      if (e.code == 'forbidden') throw UserRulesForbiddenException(msg);
      throw EngineException(msg);
    }
  }

  @override
  Future<bool> isEnrolled() => _call<bool>('isEnrolled');

  @override
  Future<void> enroll(String controlUrl, String provisioningKey, String deviceName) =>
      _call<void>('enroll', {'controlUrl': controlUrl, 'provisioningKey': provisioningKey, 'deviceName': deviceName});

  @override
  Future<void> unenroll() => _call<void>('unenroll');

  @override
  Future<bool> prepareVpn() => _call<bool>('prepareVpn');

  @override
  Future<void> connect() => _call<void>('connect');

  @override
  Future<void> disconnect() => _call<void>('disconnect');

  @override
  Future<String> status() => _call<String>('status');

  @override
  Future<String> snapshot() => _call<String>('snapshot');

  @override
  Future<void> setUserRules(String json) => _call<void>('setUserRules', {'json': json});

  @override
  Future<void> setAppPolicy(String pkg, String wifi, String cellular, String roaming) =>
      _call<void>('setAppPolicy', {'pkg': pkg, 'wifi': wifi, 'cellular': cellular, 'roaming': roaming});

  @override
  Future<String> recentFlows(int limit) => _call<String>('recentFlows', {'limit': limit});

  @override
  Future<String> appStats() => _call<String>('appStats');

  @override
  Future<List<InstalledApp>> installedApps() async {
    final list = await _call<List<Object?>>('installedApps');
    return list.whereType<Map<Object?, Object?>>().map(InstalledApp.fromMap).toList();
  }

  @override
  Future<VpnStatus> vpnStatus() async =>
      VpnStatus.fromJson(jsonDecode(await _call<String>('vpnStatus')) as Map<String, dynamic>);

  @override
  Future<void> openVpnSettings() => _call<void>('openVpnSettings');

  @override
  Future<bool> saveFile(String fileName, String content) =>
      _call<bool>('saveFile', {'fileName': fileName, 'content': content});

  @override
  Future<String?> takeEnrollLink() => _call<String?>('takeEnrollLink');

  @override
  Future<void> setConnectOnBoot(bool enabled) => _call<void>('setConnectOnBoot', {'enabled': enabled});

  @override
  Stream<EngineEvent> get events => _events ??= _e.receiveBroadcastStream().map((e) {
    final m = e as Map<Object?, Object?>;
    return EngineEvent(m['kind'] as String, (m['payload'] as String?) ?? '');
  }).asBroadcastStream();
}
