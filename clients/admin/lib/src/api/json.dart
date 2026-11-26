/// JSON helpers that reproduce Go's encoding/json behaviour for the wire types.
library;

typedef Json = Map<String, dynamic>;

/// Go's zero time.Time, which encoding/json writes for an unset (non-pointer) time field.
const goZeroTime = '0001-01-01T00:00:00Z';

/// Reads a JSON string field; null or missing gives ''.
String str(Json j, String key) {
  final v = j[key];
  if (v == null) return '';
  if (v is String) return v;
  throw FormatException('"$key" must be a string, got ${v.runtimeType}');
}

int integer(Json j, String key) {
  final v = j[key];
  if (v == null) return 0;
  if (v is int) return v;
  if (v is num && v == v.roundToDouble()) return v.toInt();
  throw FormatException('"$key" must be an integer, got $v');
}

bool boolean(Json j, String key) {
  final v = j[key];
  if (v == null) return false;
  if (v is bool) return v;
  throw FormatException('"$key" must be a boolean, got $v');
}

double floating(Json j, String key) {
  final v = j[key];
  if (v == null) return 0.0;
  if (v is double) return v;
  if (v is num) return v.toDouble();
  throw FormatException('"$key" must be a number, got $v');
}

/// Reads a list of strings; Go writes a nil slice as null.
List<String> strList(Json j, String key) {
  final v = j[key];
  if (v == null) return <String>[];
  if (v is! List) throw FormatException('"$key" must be an array');
  return [
    for (final e in v)
      if (e is String) e else throw FormatException('"$key" must contain only strings'),
  ];
}

List<T> objList<T>(Json j, String key, T Function(Json) f) {
  final v = j[key];
  if (v == null) return <T>[];
  if (v is! List) throw FormatException('"$key" must be an array');
  return [for (final e in v) f(obj(e, key))];
}

Json obj(Object? v, String key) {
  if (v is Map<String, dynamic>) return v;
  if (v is Map) return v.cast<String, dynamic>();
  throw FormatException('"$key" must be an object');
}

Json objOrEmpty(Json j, String key) => j[key] == null ? <String, dynamic>{} : obj(j[key], key);

/// Parses an RFC 3339 time. Go's zero time and a missing value give null.
DateTime? time(Json j, String key) {
  final s = str(j, key);
  if (s.isEmpty) return null;
  final t = DateTime.tryParse(s);
  if (t == null) throw FormatException('"$key" is not an RFC 3339 time: $s');
  if (t.toUtc().year <= 1) return null;
  return t.toUtc();
}

/// Formats like Go's time.Time MarshalJSON (RFC 3339 with trimmed fractional seconds, UTC "Z").
String goTime(DateTime? t) {
  if (t == null) return goZeroTime;
  final u = t.toUtc();
  String two(int n) => n.toString().padLeft(2, '0');
  final base =
      '${u.year.toString().padLeft(4, '0')}-${two(u.month)}-${two(u.day)}T${two(u.hour)}:${two(u.minute)}:${two(u.second)}';
  final micros = u.millisecond * 1000 + u.microsecond;
  if (micros == 0) return '${base}Z';
  var frac = micros.toString().padLeft(6, '0');
  while (frac.endsWith('0')) {
    frac = frac.substring(0, frac.length - 1);
  }
  return '$base.${frac}Z';
}

/// Adds [key] only when [v] is non-empty, like a Go `omitempty` tag.
void putOmit(Json j, String key, Object? v) {
  if (v == null) return;
  if (v is String && v.isEmpty) return;
  if (v is int && v == 0) return;
  if (v is bool && !v) return;
  if (v is List && v.isEmpty) return;
  if (v is Map && v.isEmpty) return;
  j[key] = v;
}
