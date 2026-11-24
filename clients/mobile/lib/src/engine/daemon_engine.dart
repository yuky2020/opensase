import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:path_provider/path_provider.dart';

import 'daemon_transport.dart';
import 'engine.dart';
import 'http_parse.dart';

/// Desktop implementation of [Engine] backed by the local opensased daemon.
class DaemonEngine implements Engine {
  DaemonEngine(
    this.transport, {
    this.initialBackoff = const Duration(seconds: 1),
    this.maxBackoff = const Duration(seconds: 30),
  });

  final DaemonTransport transport;
  final Duration initialBackoff;
  final Duration maxBackoff;

  StreamController<EngineEvent>? _eventController;
  StreamSubscription<String>? _sseSub;
  Timer? _reconnectTimer;
  bool _disposed = false;
  late Duration _currentBackoff = initialBackoff;

  @override
  String get name => 'daemon';

  @override
  Future<bool> isEnrolled() async {
    final st = await status();
    try {
      final map = jsonDecode(st) as Map<String, dynamic>;
      return map['enrolled'] as bool? ?? false;
    } catch (_) {
      return false;
    }
  }

  @override
  Future<String> status() async {
    try {
      final resp = await transport.request('GET', '/v1/status');
      if (resp.statusCode != 200) {
        throw EngineException('Failed to get status (HTTP ${resp.statusCode})');
      }
      return resp.body;
    } catch (e) {
      _emitDaemon(connected: false);
      rethrow;
    }
  }

  @override
  Future<void> enroll(String controlUrl, String provisioningKey, String deviceName) async {
    final body = jsonEncode({'controlUrl': controlUrl, 'provisioningKey': provisioningKey, 'deviceName': deviceName});
    final resp = await transport.request('POST', '/v1/enroll', body: body);
    if (resp.statusCode == 200 || resp.statusCode == 204) {
      return;
    }
    if (resp.statusCode == 403) {
      throw const EngineException('Administrator rights are needed to enroll this device');
    }
    if (resp.statusCode == 409) {
      throw const EngineException('Disconnect before enrolling');
    }
    String msg = 'Enrollment failed (HTTP ${resp.statusCode})';
    try {
      final errMap = jsonDecode(resp.body) as Map<String, dynamic>;
      if (errMap.containsKey('error')) {
        msg = errMap['error'] as String;
      }
    } catch (_) {}
    throw EngineException(msg);
  }

  @override
  Future<void> unenroll() async {
    final resp = await transport.request('POST', '/v1/unenroll');
    if (resp.statusCode != 200 && resp.statusCode != 204) {
      String msg = 'Unenroll failed (HTTP ${resp.statusCode})';
      try {
        final errMap = jsonDecode(resp.body) as Map<String, dynamic>;
        if (errMap.containsKey('error')) msg = errMap['error'] as String;
      } catch (_) {}
      throw EngineException(msg);
    }
  }

  @override
  Future<void> connect() async {
    final resp = await transport.request('POST', '/v1/connect');
    if (resp.statusCode != 200 && resp.statusCode != 204) {
      String msg = 'Connect failed (HTTP ${resp.statusCode})';
      try {
        final errMap = jsonDecode(resp.body) as Map<String, dynamic>;
        if (errMap.containsKey('error')) msg = errMap['error'] as String;
      } catch (_) {}
      throw EngineException(msg);
    }
  }

  @override
  Future<void> disconnect() async {
    final resp = await transport.request('POST', '/v1/disconnect');
    if (resp.statusCode != 200 && resp.statusCode != 204) {
      String msg = 'Disconnect failed (HTTP ${resp.statusCode})';
      try {
        final errMap = jsonDecode(resp.body) as Map<String, dynamic>;
        if (errMap.containsKey('error')) msg = errMap['error'] as String;
      } catch (_) {}
      throw EngineException(msg);
    }
  }

  @override
  Future<String> recentFlows(int limit) async {
    final resp = await transport.request('GET', '/v1/flows?limit=$limit');
    if (resp.statusCode != 200) {
      throw EngineException('Failed to get flows (HTTP ${resp.statusCode})');
    }
    return resp.body;
  }

  @override
  Future<VpnStatus> vpnStatus() async {
    try {
      final st = await status();
      if (st.isEmpty) return const VpnStatus();
      final map = jsonDecode(st) as Map<String, dynamic>;
      final isConn = map['connected'] as bool? ?? false;
      final stateStr = map['state'] as String? ?? '';
      final err = map['error'] as String? ?? '';
      final phase = isConn || stateStr == 'connected'
          ? VpnPhase.running
          : (stateStr == 'connecting' ? VpnPhase.connecting : (stateStr == 'error' ? VpnPhase.failed : VpnPhase.idle));
      return VpnStatus(phase: phase, message: err);
    } catch (_) {
      return const VpnStatus();
    }
  }

  @override
  Future<bool> prepareVpn() async => true;

  @override
  Future<List<InstalledApp>> installedApps() async => const [];

  @override
  Future<String> appStats() async => '[]';

  @override
  Future<void> setAppPolicy(String pkg, String wifi, String cellular, String roaming) {
    throw UnsupportedError('setAppPolicy is not supported on desktop');
  }

  @override
  Future<void> openVpnSettings() async {}

  @override
  Future<String?> takeEnrollLink() async => null;

  @override
  Future<void> setConnectOnBoot(bool enabled) async {}

  @override
  Future<String> snapshot() async => '';

  @override
  Future<void> setUserRules(String json) async {
    throw const EngineException('Not available on desktop yet');
  }

  @override
  Future<bool> saveFile(String fileName, String content) async {
    try {
      final dir = await getDownloadsDirectory();
      if (dir == null) return false;
      final file = File('${dir.path}/$fileName');
      await file.writeAsString(content);
      return true;
    } catch (_) {
      return false;
    }
  }

  @override
  Stream<EngineEvent> get events {
    _eventController ??= StreamController<EngineEvent>.broadcast(onListen: _startSse, onCancel: _stopSse);
    return _eventController!.stream;
  }

  void _emitDaemon({required bool connected}) {
    if (_eventController != null && !_eventController!.isClosed) {
      _eventController!.add(EngineEvent(EngineEvent.daemon, '{"connected": $connected}'));
    }
  }

  void _startSse() {
    _disposed = false;
    _currentBackoff = initialBackoff;
    _connectSse();
  }

  void _stopSse() {
    _sseSub?.cancel();
    _sseSub = null;
    _reconnectTimer?.cancel();
    _reconnectTimer = null;
  }

  void _connectSse() {
    if (_disposed || _eventController == null || !_eventController!.hasListener) return;
    _sseSub?.cancel();
    _sseSub = null;

    try {
      final stream = transport.sse('/v1/events');
      _sseSub = stream.listen(
        (data) {
          if (_currentBackoff > initialBackoff) {
            _currentBackoff = initialBackoff;
            _emitDaemon(connected: true);
          }
          final ev = parseSseEvent(data);
          if (ev.event.isNotEmpty) {
            _eventController?.add(EngineEvent(ev.event, ev.data));
          }
        },
        onError: (_) => _handleSseDrop(),
        onDone: () => _handleSseDrop(),
        cancelOnError: true,
      );
    } catch (_) {
      _handleSseDrop();
    }
  }

  void _handleSseDrop() {
    if (_disposed || _eventController == null || !_eventController!.hasListener) return;
    _emitDaemon(connected: false);
    _sseSub?.cancel();
    _sseSub = null;
    _reconnectTimer?.cancel();

    final waitDuration = _currentBackoff;
    final nextMs = _currentBackoff.inMilliseconds * 2;
    _currentBackoff = nextMs > maxBackoff.inMilliseconds ? maxBackoff : Duration(milliseconds: nextMs);

    _reconnectTimer = Timer(waitDuration, _connectSse);
  }

  Future<void> dispose() async {
    _disposed = true;
    _stopSse();
    await _eventController?.close();
  }
}
