import '../contracts/policy.dart';
import 'policy_logic.dart';

enum DraftField { cidrs, ports, domains, priority, empty }

/// Editable form state of a user rule; lists are typed as comma/space/newline separated text.
class RuleDraft {
  const RuleDraft({
    this.id,
    this.action = Verdict.block,
    this.description = '',
    this.protocols = const {},
    this.cidrs = '',
    this.ports = '',
    this.domains = '',
    this.networks = const {},
    this.apps = const [],
    this.log = false,
    this.priority = '',
  });

  final String? id;
  final Verdict action;
  final String description;
  final Set<String> protocols;
  final String cidrs;
  final String ports;
  final String domains;
  final Set<NetworkType> networks;
  final List<String> apps;
  final bool log;
  final String priority;

  static const allProtocols = ['tcp', 'udp', 'icmp'];
  static const allNetworks = [NetworkType.wifi, NetworkType.cellular, NetworkType.roaming, NetworkType.ethernet];

  static List<String> split(String s) =>
      s.split(RegExp(r'[,\s]+')).map((e) => e.trim()).where((e) => e.isNotEmpty).toList();

  Set<DraftField> validate() {
    final e = <DraftField>{};
    if (split(cidrs).any((c) => !PolicyLogic.isValidCidr(c))) e.add(DraftField.cidrs);
    if (split(ports).any((p) => PortRange.parse(p) == null)) e.add(DraftField.ports);
    if (split(domains).any((d) => PolicyLogic.normalizeDomain(d) == null)) e.add(DraftField.domains);
    if (priority.trim().isNotEmpty && int.tryParse(priority.trim()) == null) e.add(DraftField.priority);
    if (protocols.isEmpty &&
        split(cidrs).isEmpty &&
        split(ports).isEmpty &&
        split(domains).isEmpty &&
        networks.isEmpty &&
        apps.isEmpty) {
      e.add(DraftField.empty);
    }
    return e;
  }

  /// Builds the rule; call only when [validate] is empty.
  Rule toRule(String newId, int defaultPriority) => Rule(
    id: id ?? newId,
    source: RuleSource.user,
    priority: int.tryParse(priority.trim()) ?? defaultPriority,
    action: action,
    match: Match(
      apps: apps,
      networks: NetworkType.values.where(networks.contains).toList(),
      protocols: allProtocols.where(protocols.contains).toList(),
      cidrs: split(cidrs),
      ports: split(ports).map(PortRange.parse).whereType<PortRange>().toList(),
      domains: split(domains).map(PolicyLogic.normalizeDomain).whereType<String>().toList(),
    ),
    log: log,
    description: description.trim().isEmpty ? null : description.trim(),
  );

  factory RuleDraft.from(Rule r) => RuleDraft(
    id: r.id,
    action: r.action,
    description: r.description ?? '',
    protocols: r.match.protocols.toSet(),
    cidrs: r.match.cidrs.join(', '),
    ports: r.match.ports.join(', '),
    domains: r.match.domains.join(', '),
    networks: r.match.networks.toSet(),
    apps: r.match.apps,
    log: r.log,
    priority: '${r.priority}',
  );
}
