import '../api/policy_models.dart';

/// Splits on newlines and commas, trims, drops empty entries.
List<String> parseList(String s) => [
  for (final p in s.split(RegExp(r'[\n,]')))
    if (p.trim().isNotEmpty) p.trim(),
];

/// Parses "443, 8000-8080" into port ranges. Throws [FormatException] on bad input.
List<PortRange> parsePorts(String s) {
  final out = <PortRange>[];
  for (final part in parseList(s)) {
    final m = RegExp(r'^(\d{1,5})(?:\s*-\s*(\d{1,5}))?$').firstMatch(part);
    if (m == null) throw FormatException('invalid port or range "$part"');
    final from = int.parse(m.group(1)!);
    final to = m.group(2) == null ? 0 : int.parse(m.group(2)!);
    if (from < 1 || from > 65535 || to > 65535) throw FormatException('port out of range in "$part"');
    if (to != 0 && to < from) throw FormatException('range "$part" ends before it starts');
    out.add(PortRange(from: from, to: to == from ? 0 : to));
  }
  return out;
}

String formatPorts(List<PortRange> ports) => ports.map((p) => p.toString()).join(', ');

/// Same identifier rule as pkg/pki.ValidID (tenant, device, edge, app IDs).
bool validId(String id) => RegExp(r'^[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}$').hasMatch(id) && id != '.' && id != '..';

/// Checks a domain pattern like pkg/policy normalizePattern: "example.com" or "*.example.com".
/// Returns null if valid, else the reason.
String? domainError(String pattern) {
  var p = pattern.toLowerCase();
  if (p.endsWith('.')) p = p.substring(0, p.length - 1);
  if (p.startsWith('*.')) p = p.substring(2);
  if (p.isEmpty) return 'empty domain';
  if (p.length > 253) return 'domain longer than 253 characters';
  for (final label in p.split('.')) {
    if (label.isEmpty) return 'empty label in "$p"';
    if (label.length > 63) return 'label longer than 63 characters in "$p"';
    if (!RegExp(r'^[a-z0-9_-]+$').hasMatch(label)) return 'invalid character in "$p"';
    if (label.startsWith('-') || label.endsWith('-')) return "label starts or ends with '-' in \"$p\"";
  }
  return null;
}

/// Checks a prefix ("10.0.0.0/8", "fd00::/8") or a bare address, like pkg/policy parsePrefix.
String? cidrError(String s) {
  final slash = s.indexOf('/');
  final addr = slash < 0 ? s : s.substring(0, slash);
  final isV6 = addr.contains(':');
  try {
    isV6 ? Uri.parseIPv6Address(addr) : Uri.parseIPv4Address(addr);
  } on FormatException {
    return 'invalid address "$addr"';
  }
  if (slash >= 0) {
    final bits = int.tryParse(s.substring(slash + 1));
    if (bits == null || bits < 0 || bits > (isV6 ? 128 : 32)) return 'invalid prefix length in "$s"';
  }
  return null;
}
