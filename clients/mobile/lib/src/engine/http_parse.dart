/// Represents a parsed HTTP/1.1 response.
class HttpResponse {
  const HttpResponse({required this.statusCode, required this.statusText, required this.headers, required this.body});

  final int statusCode;
  final String statusText;
  final Map<String, String> headers;
  final String body;

  @override
  String toString() => 'HttpResponse($statusCode $statusText, body length: ${body.length})';
}

/// Represents a single Server-Sent Event (SSE).
class SseMessage {
  const SseMessage({this.event = '', required this.data});

  final String event;
  final String data;

  @override
  bool operator ==(Object other) =>
      identical(this, other) ||
      other is SseMessage && runtimeType == other.runtimeType && event == other.event && data == other.data;

  @override
  int get hashCode => event.hashCode ^ data.hashCode;

  @override
  String toString() => 'SseMessage(event: $event, data: $data)';
}

/// Parses a raw HTTP/1.1 response string (status line, headers, and body).
/// Handles both Content-Length and chunked transfer encoding.
HttpResponse parseHttpResponse(String raw) {
  var headerEnd = raw.indexOf('\r\n\r\n');
  int bodyStart;
  if (headerEnd != -1) {
    bodyStart = headerEnd + 4;
  } else {
    headerEnd = raw.indexOf('\n\n');
    if (headerEnd != -1) {
      bodyStart = headerEnd + 2;
    } else {
      headerEnd = raw.length;
      bodyStart = raw.length;
    }
  }

  final headerText = raw.substring(0, headerEnd);
  final rawBody = raw.substring(bodyStart);

  final lines = headerText.split(RegExp(r'\r?\n'));
  final statusLine = lines.isNotEmpty ? lines.first : '';
  final statusParts = statusLine.split(' ');
  final statusCode = statusParts.length > 1 ? int.tryParse(statusParts[1]) ?? 0 : 0;
  final statusText = statusParts.length > 2 ? statusParts.sublist(2).join(' ') : '';

  final headers = <String, String>{};
  for (var i = 1; i < lines.length; i++) {
    final line = lines[i];
    final colon = line.indexOf(':');
    if (colon != -1) {
      final key = line.substring(0, colon).trim().toLowerCase();
      final value = line.substring(colon + 1).trim();
      headers[key] = value;
    }
  }

  String body;
  final isChunked = headers['transfer-encoding']?.toLowerCase().contains('chunked') ?? false;
  if (isChunked) {
    body = decodeChunked(rawBody);
  } else if (headers.containsKey('content-length')) {
    final len = int.tryParse(headers['content-length'] ?? '') ?? rawBody.length;
    body = rawBody.length > len ? rawBody.substring(0, len) : rawBody;
  } else {
    body = rawBody;
  }

  return HttpResponse(statusCode: statusCode, statusText: statusText, headers: headers, body: body);
}

/// Decodes an HTTP/1.1 chunked transfer-encoded string.
String decodeChunked(String rawBody) {
  final buffer = StringBuffer();
  var pos = 0;
  while (pos < rawBody.length) {
    final lineEnd = rawBody.indexOf('\n', pos);
    if (lineEnd == -1) break;
    var sizeLine = rawBody.substring(pos, lineEnd);
    if (sizeLine.endsWith('\r')) {
      sizeLine = sizeLine.substring(0, sizeLine.length - 1);
    }
    final semi = sizeLine.indexOf(';');
    if (semi != -1) {
      sizeLine = sizeLine.substring(0, semi);
    }
    sizeLine = sizeLine.trim();
    if (sizeLine.isEmpty) {
      pos = lineEnd + 1;
      continue;
    }
    final chunkSize = int.tryParse(sizeLine, radix: 16);
    if (chunkSize == null || chunkSize <= 0) {
      break;
    }
    final chunkStart = lineEnd + 1;
    final chunkEnd = chunkStart + chunkSize;
    if (chunkEnd <= rawBody.length) {
      buffer.write(rawBody.substring(chunkStart, chunkEnd));
      pos = chunkEnd;
      if (pos < rawBody.length && rawBody[pos] == '\r') pos++;
      if (pos < rawBody.length && rawBody[pos] == '\n') pos++;
    } else {
      buffer.write(rawBody.substring(chunkStart));
      break;
    }
  }
  return buffer.toString();
}

/// Incremental decoder for chunked transfer streams over a raw connection.
class ChunkedStreamDecoder {
  String _buffer = '';
  int _state = 0; // 0: chunk size, 1: chunk data, 2: trailing crlf
  int _chunkSize = 0;

  List<String> addData(String data) {
    _buffer += data;
    final result = <String>[];
    while (true) {
      if (_state == 0) {
        final idx = _buffer.indexOf('\n');
        if (idx == -1) break;
        var sizeLine = _buffer.substring(0, idx);
        _buffer = _buffer.substring(idx + 1);
        if (sizeLine.endsWith('\r')) {
          sizeLine = sizeLine.substring(0, sizeLine.length - 1);
        }
        final semi = sizeLine.indexOf(';');
        if (semi != -1) sizeLine = sizeLine.substring(0, semi);
        sizeLine = sizeLine.trim();
        if (sizeLine.isEmpty) continue;
        final size = int.tryParse(sizeLine, radix: 16);
        if (size == null || size == 0) {
          return result;
        }
        _chunkSize = size;
        _state = 1;
      }
      if (_state == 1) {
        if (_buffer.length < _chunkSize) {
          break;
        }
        final chunk = _buffer.substring(0, _chunkSize);
        _buffer = _buffer.substring(_chunkSize);
        result.add(chunk);
        _state = 2;
      }
      if (_state == 2) {
        if (_buffer.startsWith('\r\n')) {
          _buffer = _buffer.substring(2);
          _state = 0;
        } else if (_buffer.startsWith('\n')) {
          _buffer = _buffer.substring(1);
          _state = 0;
        } else if (_buffer.isEmpty) {
          break;
        } else if (_buffer.startsWith('\r')) {
          break;
        } else {
          _state = 0;
        }
      }
    }
    return result;
  }
}

/// Parser for Server-Sent Events (SSE) that handles chunks arriving in arbitrary sizes
/// and supports multiple data lines.
class SseParser {
  String _buffer = '';
  String _currentEvent = '';
  final List<String> _currentData = [];

  List<SseMessage> addChunk(String chunk) {
    _buffer += chunk;
    final messages = <SseMessage>[];
    while (true) {
      final newlineIdx = _buffer.indexOf('\n');
      if (newlineIdx == -1) break;
      var line = _buffer.substring(0, newlineIdx);
      _buffer = _buffer.substring(newlineIdx + 1);
      if (line.endsWith('\r')) {
        line = line.substring(0, line.length - 1);
      }
      if (line.isEmpty) {
        if (_currentData.isNotEmpty || _currentEvent.isNotEmpty) {
          messages.add(SseMessage(event: _currentEvent, data: _currentData.join('\n')));
          _currentEvent = '';
          _currentData.clear();
        }
      } else if (line.startsWith(':')) {
        // SSE comment, ignore
        continue;
      } else if (line.startsWith('event:')) {
        _currentEvent = _sseValue(line, 6);
      } else if (line.startsWith('data:')) {
        _currentData.add(_sseValue(line, 5));
      }
    }
    return messages;
  }
}

/// The value of an SSE field line after the "name:" prefix of [prefixLen] characters:
/// one leading space is removed, as the SSE format specifies, and nothing else.
String _sseValue(String line, int prefixLen) {
  final v = line.substring(prefixLen);
  return v.startsWith(' ') ? v.substring(1) : v;
}

/// Parses a single SSE event string block into an [SseMessage].
SseMessage parseSseEvent(String text) {
  final parser = SseParser();
  final normalized = text.endsWith('\n\n') ? text : (text.endsWith('\n') ? '$text\n' : '$text\n\n');
  final events = parser.addChunk(normalized);
  if (events.isNotEmpty) return events.first;
  return const SseMessage(data: '');
}

/// Formats an event name and payload into an SSE wire block.
String formatSseEvent({String event = '', required String data}) {
  final b = StringBuffer();
  if (event.isNotEmpty) {
    b.write('event: $event\n');
  }
  for (final line in data.split('\n')) {
    b.write('data: $line\n');
  }
  b.write('\n');
  return b.toString();
}
