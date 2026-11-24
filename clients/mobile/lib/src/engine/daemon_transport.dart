import 'dart:async';
import 'dart:convert';
import 'dart:ffi';
import 'dart:io';
import 'dart:isolate';

import 'package:ffi/ffi.dart';
import 'package:win32/win32.dart';

import 'http_parse.dart';

/// Response returned by [DaemonTransport.request].
class DaemonResponse {
  const DaemonResponse(this.statusCode, this.body);

  final int statusCode;
  final String body;

  @override
  String toString() => 'DaemonResponse($statusCode, body: $body)';
}

/// Abstract transport for communicating with the local desktop daemon (opensased).
abstract class DaemonTransport {
  Future<DaemonResponse> request(String method, String path, {String? body});
  Stream<String> sse(String path);
}

/// Linux daemon transport over a Unix domain socket using [HttpClient].
class UnixSocketTransport implements DaemonTransport {
  UnixSocketTransport(this.socketPath);

  final String socketPath;

  HttpClient _createClient() {
    final client = HttpClient();
    client.connectionFactory = (uri, host, port) {
      return Socket.startConnect(InternetAddress(socketPath, type: InternetAddressType.unix), 0);
    };
    return client;
  }

  @override
  Future<DaemonResponse> request(String method, String path, {String? body}) async {
    final client = _createClient();
    try {
      final uri = Uri.parse('http://localhost$path');
      final req = await client.openUrl(method, uri);
      req.headers.set('Host', 'localhost');
      if (body != null) {
        req.headers.contentType = ContentType.json;
        final bodyBytes = utf8.encode(body);
        req.contentLength = bodyBytes.length;
        req.add(bodyBytes);
      }
      final resp = await req.close();
      final respBody = await utf8.decodeStream(resp);
      return DaemonResponse(resp.statusCode, respBody);
    } finally {
      client.close(force: true);
    }
  }

  @override
  Stream<String> sse(String path) async* {
    final client = _createClient();
    try {
      final uri = Uri.parse('http://localhost$path');
      final req = await client.openUrl('GET', uri);
      req.headers.set('Host', 'localhost');
      req.headers.set('Accept', 'text/event-stream');
      final resp = await req.close();
      if (resp.statusCode != HttpStatus.ok) {
        throw HttpException('SSE failed with status ${resp.statusCode}', uri: uri);
      }
      final parser = SseParser();
      await for (final chunk in resp.transform(utf8.decoder)) {
        final events = parser.addChunk(chunk);
        for (final ev in events) {
          yield formatSseEvent(event: ev.event, data: ev.data);
        }
      }
    } finally {
      client.close(force: true);
    }
  }
}

/// Helper data class for spawning the Windows SSE isolate.
class _SseIsolateArgs {
  const _SseIsolateArgs(this.pipePath, this.path, this.sendPort);

  final String pipePath;
  final String path;
  final SendPort sendPort;
}

/// Windows daemon transport over a named pipe using Win32 API in separate Isolates.
class NamedPipeTransport implements DaemonTransport {
  NamedPipeTransport([this.pipePath = r'\\.\pipe\opensase']);

  final String pipePath;

  @override
  Future<DaemonResponse> request(String method, String path, {String? body}) {
    return Isolate.run(() => _executeRequest(pipePath, method, path, body));
  }

  static DaemonResponse _executeRequest(String pipePath, String method, String path, String? body) {
    final bodyBytes = body != null ? utf8.encode(body) : const <int>[];
    final buffer = StringBuffer()
      ..write('$method $path HTTP/1.1\r\n')
      ..write('Host: localhost\r\n')
      ..write('Connection: close\r\n');
    if (body != null) {
      buffer.write('Content-Type: application/json\r\n');
      buffer.write('Content-Length: ${bodyBytes.length}\r\n');
    }
    buffer.write('\r\n');
    final reqBytes = [...utf8.encode(buffer.toString()), ...bodyBytes];

    final pPipe = pipePath.toNativeUtf16();
    final handle = CreateFile(pPipe, GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, NULL);
    calloc.free(pPipe);

    if (handle == INVALID_HANDLE_VALUE) {
      final err = GetLastError();
      throw SocketException('Failed to open named pipe $pipePath (error $err)');
    }

    try {
      if (reqBytes.isNotEmpty) {
        final pBytes = calloc<Uint8>(reqBytes.length);
        pBytes.asTypedList(reqBytes.length).setAll(0, reqBytes);
        final pWritten = calloc<DWORD>();
        try {
          final ok = WriteFile(handle, pBytes.cast(), reqBytes.length, pWritten, nullptr);
          if (ok == 0) {
            final err = GetLastError();
            throw SocketException('Failed to write to named pipe (error $err)');
          }
        } finally {
          calloc.free(pBytes);
          calloc.free(pWritten);
        }
      }

      final respBytes = <int>[];
      const readChunkSize = 4096;
      final pReadBuf = calloc<Uint8>(readChunkSize);
      final pBytesRead = calloc<DWORD>();
      try {
        while (true) {
          final ok = ReadFile(handle, pReadBuf.cast(), readChunkSize, pBytesRead, nullptr);
          final n = pBytesRead.value;
          if (ok == 0 || n == 0) {
            break;
          }
          respBytes.addAll(pReadBuf.asTypedList(n));
        }
      } finally {
        calloc.free(pReadBuf);
        calloc.free(pBytesRead);
      }

      final raw = utf8.decode(respBytes, allowMalformed: true);
      final parsed = parseHttpResponse(raw);
      return DaemonResponse(parsed.statusCode, parsed.body);
    } finally {
      CloseHandle(handle);
    }
  }

  @override
  Stream<String> sse(String path) {
    final controller = StreamController<String>();
    final receivePort = ReceivePort();

    Isolate.spawn<_SseIsolateArgs>(_runSseIsolate, _SseIsolateArgs(pipePath, path, receivePort.sendPort))
        .then((isolate) {
          controller.onCancel = () {
            receivePort.close();
            isolate.kill(priority: Isolate.immediate);
          };
        })
        .catchError((err, st) {
          controller.addError(err, st);
          controller.close();
        });

    receivePort.listen((msg) {
      if (msg is String) {
        controller.add(msg);
      } else if (msg == null) {
        controller.close();
      } else if (msg is List && msg.length == 2) {
        controller.addError(msg[0], msg[1]);
      }
    });

    return controller.stream;
  }

  static void _runSseIsolate(_SseIsolateArgs args) {
    final sendPort = args.sendPort;
    final pipePath = args.pipePath;
    final path = args.path;

    final pPipe = pipePath.toNativeUtf16();
    final handle = CreateFile(pPipe, GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, NULL);
    calloc.free(pPipe);

    if (handle == INVALID_HANDLE_VALUE) {
      final err = GetLastError();
      sendPort.send([SocketException('Failed to open named pipe for SSE (error $err)'), null]);
      sendPort.send(null);
      return;
    }

    try {
      final reqStr = 'GET $path HTTP/1.1\r\nHost: localhost\r\nAccept: text/event-stream\r\n\r\n';
      final reqBytes = utf8.encode(reqStr);
      final pBytes = calloc<Uint8>(reqBytes.length);
      pBytes.asTypedList(reqBytes.length).setAll(0, reqBytes);
      final pWritten = calloc<DWORD>();
      try {
        final ok = WriteFile(handle, pBytes.cast(), reqBytes.length, pWritten, nullptr);
        if (ok == 0) {
          final err = GetLastError();
          sendPort.send([SocketException('Failed to write SSE request (error $err)'), null]);
          sendPort.send(null);
          return;
        }
      } finally {
        calloc.free(pBytes);
        calloc.free(pWritten);
      }

      const readChunkSize = 4096;
      final pReadBuf = calloc<Uint8>(readChunkSize);
      final pBytesRead = calloc<DWORD>();

      var headersParsed = false;
      var rawAccumulator = '';
      final chunkDecoder = ChunkedStreamDecoder();
      final sseParser = SseParser();

      try {
        while (true) {
          final ok = ReadFile(handle, pReadBuf.cast(), readChunkSize, pBytesRead, nullptr);
          final n = pBytesRead.value;
          if (ok == 0 || n == 0) {
            break;
          }
          final chunkText = utf8.decode(pReadBuf.asTypedList(n), allowMalformed: true);
          if (!headersParsed) {
            rawAccumulator += chunkText;
            final headerEnd = rawAccumulator.indexOf('\r\n\r\n');
            if (headerEnd != -1) {
              headersParsed = true;
              final remainingBody = rawAccumulator.substring(headerEnd + 4);
              final chunks = chunkDecoder.addData(remainingBody);
              for (final c in chunks) {
                final events = sseParser.addChunk(c);
                for (final ev in events) {
                  sendPort.send(formatSseEvent(event: ev.event, data: ev.data));
                }
              }
            }
          } else {
            final chunks = chunkDecoder.addData(chunkText);
            for (final c in chunks) {
              final events = sseParser.addChunk(c);
              for (final ev in events) {
                sendPort.send(formatSseEvent(event: ev.event, data: ev.data));
              }
            }
          }
        }
      } finally {
        calloc.free(pReadBuf);
        calloc.free(pBytesRead);
      }
    } catch (e, st) {
      sendPort.send([e, st]);
    } finally {
      CloseHandle(handle);
      sendPort.send(null);
    }
  }
}
