import 'package:flutter_test/flutter_test.dart';
import 'package:opensase/src/engine/http_parse.dart';

void main() {
  group('HTTP/1.1 response parsing', () {
    test('parses status line', () {
      const raw200 = 'HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n';
      final resp200 = parseHttpResponse(raw200);
      expect(resp200.statusCode, 200);
      expect(resp200.statusText, 'OK');

      const raw403 = 'HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n';
      final resp403 = parseHttpResponse(raw403);
      expect(resp403.statusCode, 403);
      expect(resp403.statusText, 'Forbidden');

      const raw409 = 'HTTP/1.1 409 Conflict\r\nContent-Length: 0\r\n\r\n';
      final resp409 = parseHttpResponse(raw409);
      expect(resp409.statusCode, 409);
      expect(resp409.statusText, 'Conflict');
    });

    test('parses headers with case-insensitivity and whitespace stripping', () {
      const raw =
          'HTTP/1.1 200 OK\r\n'
          'Content-Type: application/json; charset=utf-8\r\n'
          'X-Custom-Header:   custom-value  \r\n'
          'CONTENT-LENGTH: 13\r\n'
          '\r\n'
          '{"foo":"bar"}';
      final resp = parseHttpResponse(raw);
      expect(resp.statusCode, 200);
      expect(resp.headers['content-type'], 'application/json; charset=utf-8');
      expect(resp.headers['x-custom-header'], 'custom-value');
      expect(resp.headers['content-length'], '13');
      expect(resp.body, '{"foo":"bar"}');
    });

    test('parses Content-Length body exactly', () {
      const body = '{"enrolled":true,"connected":false}';
      final raw =
          'HTTP/1.1 200 OK\r\n'
          'Content-Type: application/json\r\n'
          'Content-Length: ${body.length}\r\n'
          '\r\n'
          '$body';
      final resp = parseHttpResponse(raw);
      expect(resp.statusCode, 200);
      expect(resp.body, body);
    });

    test('parses chunked body', () {
      const raw =
          'HTTP/1.1 200 OK\r\n'
          'Transfer-Encoding: chunked\r\n'
          'Content-Type: text/plain\r\n'
          '\r\n'
          '7\r\n'
          'Mozilla\r\n'
          '9\r\n'
          'Developer\r\n'
          '7\r\n'
          'Network\r\n'
          '0\r\n'
          '\r\n';
      final resp = parseHttpResponse(raw);
      expect(resp.statusCode, 200);
      expect(resp.body, 'MozillaDeveloperNetwork');
    });

    test('chunked stream decoder incrementally processes chunks', () {
      final decoder = ChunkedStreamDecoder();
      final part1 = decoder.addData('5\r\nHello\r\n6\r\n ');
      expect(part1, ['Hello']);

      final part2 = decoder.addData('World\r\n0\r\n\r\n');
      expect(part2, [' World']);
    });
  });

  group('SSE parsing', () {
    test('parses SSE events split across chunks', () {
      final parser = SseParser();

      // Chunk 1: partial event line
      final ev1 = parser.addChunk('event: sta');
      expect(ev1, isEmpty);

      // Chunk 2: complete event line, start data
      final ev2 = parser.addChunk('te\ndata: {"state":');
      expect(ev2, isEmpty);

      // Chunk 3: end data and event boundary
      final ev3 = parser.addChunk('"connected"}\n\n');
      expect(ev3, hasLength(1));
      expect(ev3.first.event, 'state');
      expect(ev3.first.data, '{"state":"connected"}');
    });

    test('parses multi-line data in SSE', () {
      final parser = SseParser();
      const sseText =
          'event: flow\n'
          'data: {\n'
          'data:   "app": "browser",\n'
          'data:   "action": "allow"\n'
          'data: }\n'
          '\n';

      final events = parser.addChunk(sseText);
      expect(events, hasLength(1));
      expect(events.first.event, 'flow');
      expect(
        events.first.data,
        '{\n'
        '  "app": "browser",\n'
        '  "action": "allow"\n'
        '}',
      );
    });

    test('parseSseEvent helper parses complete event block', () {
      const text = 'event: test\ndata: line 1\ndata: line 2\n\n';
      final msg = parseSseEvent(text);
      expect(msg.event, 'test');
      expect(msg.data, 'line 1\nline 2');
    });

    test('formatSseEvent formats multi-line payloads correctly', () {
      final formatted = formatSseEvent(event: 'log', data: 'hello\nworld');
      expect(formatted, 'event: log\ndata: hello\ndata: world\n\n');

      final parsed = parseSseEvent(formatted);
      expect(parsed.event, 'log');
      expect(parsed.data, 'hello\nworld');
    });
  });
}
