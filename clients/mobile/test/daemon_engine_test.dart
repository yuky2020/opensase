import 'dart:async';

import 'package:flutter_test/flutter_test.dart';
import 'package:opensase/src/engine/daemon_engine.dart';
import 'package:opensase/src/engine/daemon_transport.dart';
import 'package:opensase/src/engine/engine.dart';
import 'package:opensase/src/engine/http_parse.dart';

class FakeTransport implements DaemonTransport {
  final List<({String method, String path, String? body})> calls = [];
  final Map<String, DaemonResponse> responses = {};

  StreamController<String>? currentSseController;

  void emitSse(String event, String data) {
    currentSseController?.add(formatSseEvent(event: event, data: data));
  }

  void dropSse() {
    currentSseController?.close();
  }

  @override
  Future<DaemonResponse> request(String method, String path, {String? body}) async {
    calls.add((method: method, path: path, body: body));
    final key = '$method $path';
    if (responses.containsKey(key)) {
      return responses[key]!;
    }
    return const DaemonResponse(200, '{}');
  }

  @override
  Stream<String> sse(String path) {
    calls.add((method: 'GET', path: path, body: null));
    final controller = StreamController<String>();
    currentSseController = controller;
    return controller.stream;
  }
}

void main() {
  group('DaemonEngine', () {
    test('status and isEnrolled parsing', () async {
      final transport = FakeTransport();
      const statusJson =
          '{"enrolled":true,"connected":true,"state":"connected","edge":"edge-eu-south-1","snapshotVersion":4}';
      transport.responses['GET /v1/status'] = const DaemonResponse(200, statusJson);

      final engine = DaemonEngine(transport);
      expect(engine.name, 'daemon');

      final enrolled = await engine.isEnrolled();
      expect(enrolled, isTrue);

      final st = await engine.status();
      expect(st, statusJson);

      final vpn = await engine.vpnStatus();
      expect(vpn.phase, VpnPhase.running);
      expect(vpn.isOn, isTrue);

      expect(transport.calls.where((c) => c.path == '/v1/status').length, 3);
    });

    test('vpnStatus idle when disconnected', () async {
      final transport = FakeTransport();
      const statusJson = '{"enrolled":true,"connected":false,"state":"stopped"}';
      transport.responses['GET /v1/status'] = const DaemonResponse(200, statusJson);

      final engine = DaemonEngine(transport);
      final vpn = await engine.vpnStatus();
      expect(vpn.phase, VpnPhase.idle);
      expect(vpn.isOn, isFalse);
    });

    test('enroll error mapping 403 and 409', () async {
      final transport = FakeTransport();
      final engine = DaemonEngine(transport);

      // 403 Forbidden -> Administrator rights required
      transport.responses['POST /v1/enroll'] = const DaemonResponse(
        403,
        '{"error":"forbidden: administrator privileges required"}',
      );
      expect(
        () => engine.enroll('https://cp:8443', 'key-123', 'my-pc'),
        throwsA(
          isA<EngineException>().having(
            (e) => e.message,
            'message',
            'Administrator rights are needed to enroll this device',
          ),
        ),
      );

      // 409 Conflict -> Disconnect before enrolling
      transport.responses['POST /v1/enroll'] = const DaemonResponse(409, '{"error":"cannot enroll while connected"}');
      expect(
        () => engine.enroll('https://cp:8443', 'key-123', 'my-pc'),
        throwsA(isA<EngineException>().having((e) => e.message, 'message', 'Disconnect before enrolling')),
      );

      // 200 OK -> success
      transport.responses['POST /v1/enroll'] = const DaemonResponse(200, '{"enrolled":true}');
      await engine.enroll('https://cp:8443', 'key-123', 'my-pc');
      expect(transport.calls.last.body, contains('key-123'));
    });

    test('connect, disconnect, and unenroll call appropriate endpoints', () async {
      final transport = FakeTransport();
      final engine = DaemonEngine(transport);

      transport.responses['POST /v1/connect'] = const DaemonResponse(200, '{"connected":true}');
      await engine.connect();
      expect(transport.calls.last.path, '/v1/connect');

      transport.responses['POST /v1/disconnect'] = const DaemonResponse(200, '{"connected":false}');
      await engine.disconnect();
      expect(transport.calls.last.path, '/v1/disconnect');

      transport.responses['POST /v1/unenroll'] = const DaemonResponse(200, '{"enrolled":false}');
      await engine.unenroll();
      expect(transport.calls.last.path, '/v1/unenroll');
    });

    test('recentFlows calls /v1/flows with limit parameter', () async {
      final transport = FakeTransport();
      transport.responses['GET /v1/flows?limit=25'] = const DaemonResponse(200, '[{"id":"flow-1"}]');

      final engine = DaemonEngine(transport);
      final flows = await engine.recentFlows(25);
      expect(flows, '[{"id":"flow-1"}]');
      expect(transport.calls.last.path, '/v1/flows?limit=25');
    });

    test('desktop no-op methods behave as expected', () async {
      final transport = FakeTransport();
      final engine = DaemonEngine(transport);

      expect(await engine.prepareVpn(), isTrue);
      expect(await engine.installedApps(), isEmpty);
      expect(await engine.appStats(), '[]');
      expect(await engine.takeEnrollLink(), isNull);
      expect(await engine.snapshot(), '');
      expect(() => engine.setAppPolicy('pkg', 'wifi', 'cellular', 'roaming'), throwsUnsupportedError);
      expect(() => engine.setUserRules('{}'), throwsA(isA<EngineException>()));
    });

    test('events reconnect emits "daemon" disconnected event then resumes', () async {
      final transport = FakeTransport();
      final engine = DaemonEngine(
        transport,
        initialBackoff: const Duration(milliseconds: 20),
        maxBackoff: const Duration(milliseconds: 50),
      );

      final receivedEvents = <EngineEvent>[];
      final sub = engine.events.listen(receivedEvents.add);
      addTearDown(() async {
        await sub.cancel();
        await engine.dispose();
      });

      // Wait for SSE connection to open
      await Future<void>.delayed(const Duration(milliseconds: 10));
      expect(transport.calls.any((c) => c.path == '/v1/events'), isTrue);

      // Emit normal state event
      transport.emitSse('state', '{"state":"connected"}');
      await Future<void>.delayed(const Duration(milliseconds: 10));

      expect(receivedEvents.any((e) => e.kind == 'state' && e.payload == '{"state":"connected"}'), isTrue);

      // Drop the SSE connection
      transport.dropSse();
      await Future<void>.delayed(const Duration(milliseconds: 10));

      // Should emit daemon disconnected event
      final daemonEvents = receivedEvents.where((e) => e.kind == EngineEvent.daemon).toList();
      expect(daemonEvents, isNotEmpty);
      expect(daemonEvents.last.payload, '{"connected": false}');

      // Wait for backoff reconnect (20 ms)
      await Future<void>.delayed(const Duration(milliseconds: 35));

      // New SSE connection established, emit new event
      transport.emitSse('state', '{"state":"reconnected"}');
      await Future<void>.delayed(const Duration(milliseconds: 10));

      // Verifies resume
      expect(receivedEvents.any((e) => e.kind == 'state' && e.payload == '{"state":"reconnected"}'), isTrue);
    });
  });
}
