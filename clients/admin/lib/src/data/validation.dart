import '../api/admin_models.dart';
import '../api/policy_models.dart';
import 'parsers.dart';

/// One problem in a TenantPolicy. [field] uses the server's path syntax, e.g. "rules[2].match.cidrs[0]".
class PolicyIssue {
  const PolicyIssue(this.field, this.message);

  final String field;
  final String message;

  @override
  String toString() => '$field: $message';
}

/// Client-side mirror of the Control Plane's validateTenantPolicy plus the PrivateApp rules of
/// ADR-0013. The server stays authoritative; this only catches mistakes before the PUT.
List<PolicyIssue> validateTenantPolicy(TenantPolicy p) {
  final out = <PolicyIssue>[];
  void add(String f, String m) => out.add(PolicyIssue(f, m));

  if (p.defaultAction.isNotEmpty && !Verdicts.all.contains(p.defaultAction)) {
    add('defaultAction', 'invalid action "${p.defaultAction}"');
  }
  if (!['', Verdicts.allow, Verdicts.block].contains(p.decideDefault)) {
    add('decideDefault', 'must be allow or block, got "${p.decideDefault}"');
  }

  final ruleIds = <String>{};
  for (var i = 0; i < p.rules.length; i++) {
    final r = p.rules[i];
    final f = 'rules[$i]';
    if (r.id.isEmpty) {
      add('$f.id', 'empty');
    } else if (!ruleIds.add(r.id)) {
      add('$f.id', 'duplicate rule id "${r.id}"');
    }
    if (r.source.isNotEmpty && r.source != 'tenant') add('$f.source', 'must be "tenant"');
    if (!Verdicts.all.contains(r.action)) add('$f.action', 'invalid action "${r.action}"');
    if (!['', 'compliant', 'noncompliant'].contains(r.posture)) {
      add('$f.posture', 'must be "compliant", "noncompliant" or empty');
    }
    final m = r.match;
    for (var j = 0; j < m.apps.length; j++) {
      if (m.apps[j].isEmpty) add('$f.match.apps[$j]', 'empty');
    }
    for (var j = 0; j < m.networks.length; j++) {
      if (!Networks.all.contains(m.networks[j])) add('$f.match.networks[$j]', 'invalid network "${m.networks[j]}"');
    }
    for (var j = 0; j < m.protocols.length; j++) {
      if (!Protocols.all.contains(m.protocols[j].toLowerCase())) {
        add('$f.match.protocols[$j]', 'invalid protocol "${m.protocols[j]}"');
      }
    }
    for (var j = 0; j < m.cidrs.length; j++) {
      final e = cidrError(m.cidrs[j]);
      if (e != null) add('$f.match.cidrs[$j]', e);
    }
    _ports(m.ports, '$f.match.ports', add);
    _domains(m.domains, '$f.match.domains', add);
  }

  for (final e in p.apps.entries) {
    final f = 'apps[${e.key}]';
    if (e.key.isEmpty) add(f, 'empty package name');
    for (final a in [e.value.wifi, e.value.cellular, e.value.roaming]) {
      if (a.isNotEmpty && !Verdicts.all.contains(a)) add(f, 'invalid action "$a"');
    }
  }

  final dns = p.dns;
  if (!['', 'nxdomain', 'zero'].contains(dns.blockResponse)) {
    add('dns.blockResponse', 'invalid value "${dns.blockResponse}"');
  }
  _domains(dns.allowDomains, 'dns.allowDomains', add);
  _domains(dns.blockDomains, 'dns.blockDomains', add);
  final listIds = <String>{};
  for (var i = 0; i < dns.blocklists.length; i++) {
    final b = dns.blocklists[i];
    final f = 'dns.blocklists[$i]';
    if (b.id.isEmpty) {
      add('$f.id', 'empty');
    } else if (!listIds.add(b.id)) {
      add('$f.id', 'duplicate blocklist id "${b.id}"');
    }
    _domains(b.domains, '$f.domains', add);
  }

  _domains(p.decideBlockDomains, 'decideBlockDomains', add);
  for (var i = 0; i < p.decideBlockCidrs.length; i++) {
    final e = cidrError(p.decideBlockCidrs[i]);
    if (e != null) add('decideBlockCidrs[$i]', e);
  }
  _domains(p.posture.remediationDomains, 'posture.remediationDomains', add);

  out.addAll(validatePrivateApps(p.privateApps));
  return out;
}

/// Checks the ZTNA apps of a tenant (ADR-0013).
List<PolicyIssue> validatePrivateApps(List<TenantPrivateApp> apps) {
  final out = <PolicyIssue>[];
  void add(String f, String m) => out.add(PolicyIssue(f, m));
  final ids = <String>{};
  for (var i = 0; i < apps.length; i++) {
    final a = apps[i];
    final f = 'privateApps[$i]';
    if (!validId(a.id)) {
      add('$f.id', a.id.isEmpty ? 'empty' : 'invalid identifier "${a.id}"');
    } else if (!ids.add(a.id)) {
      add('$f.id', 'duplicate app id "${a.id}"');
    }
    if (!['', 'compliant', 'noncompliant'].contains(a.posture)) {
      add('$f.posture', 'must be "compliant", "noncompliant" or empty');
    }
    if (a.domains.isEmpty) add('$f.domains', 'at least one domain is required');
    _domains(a.domains, '$f.domains', add);
    if (a.ports.isEmpty) add('$f.ports', 'at least one TCP port is required (empty means no access)');
    _ports(a.ports, '$f.ports', add);
    // An empty connectorGroup means "default" on the server.
    for (var j = 0; j < a.users.length; j++) {
      if (a.users[j].trim().isEmpty) add('$f.users[$j]', 'empty');
    }
  }
  return out;
}

void _domains(List<String> ds, String field, void Function(String, String) add) {
  for (var i = 0; i < ds.length; i++) {
    final e = domainError(ds[i]);
    if (e != null) add('$field[$i]', e);
  }
}

void _ports(List<PortRange> ps, String field, void Function(String, String) add) {
  for (var i = 0; i < ps.length; i++) {
    final p = ps[i];
    if (p.from < 0 || p.from > 65535 || p.to < 0 || p.to > 65535) {
      add('$field[$i]', 'port out of range');
    } else if (p.effectiveTo < p.from) {
      add('$field[$i]', 'to ${p.to} < from ${p.from}');
    }
  }
}
