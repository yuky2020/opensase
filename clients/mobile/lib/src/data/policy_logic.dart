import '../contracts/api.dart';
import '../contracts/policy.dart';

/// The three per-app toggles shown in the UI. Ethernet is treated like Wi-Fi.
const appNetworks = [NetworkType.wifi, NetworkType.cellular, NetworkType.roaming];

/// Where the effective per-app verdict for one network comes from.
enum VerdictOrigin { tenantRule, tenantApp, userApp, defaultAction, lockdown }

class NetworkVerdict {
  const NetworkVerdict(this.network, this.action, this.origin, {required this.locked, this.ruleId = ''});

  final NetworkType network;
  final Verdict action;
  final VerdictOrigin origin;

  /// Locked entries are tenant-mandated and cannot be changed by the user.
  final bool locked;
  final String ruleId;

  bool get allowed => action != Verdict.block;
}

/// Pure policy helpers for the UI. They mirror the evaluation order in pkg/policy/types.go
/// (tenant rules > user rules > apps > default) only as far as the per-app view needs; the
/// real evaluation happens in the Go core.
class PolicyLogic {
  PolicyLogic._();

  static const userPriorityBase = 100;
  static const userPriorityStep = 10;

  /// A tenant rule that applies to the whole app (no protocol/IP/port/domain constraint).
  static bool _isWholeAppRule(Rule r, String pkg) =>
      r.source == RuleSource.tenant &&
      r.match.apps.contains(pkg) &&
      r.match.protocols.isEmpty &&
      r.match.cidrs.isEmpty &&
      r.match.ports.isEmpty &&
      r.match.domains.isEmpty;

  static List<NetworkVerdict> verdicts(
    String pkg,
    Snapshot? snapshot,
    UserRules user,
    Map<String, AppPolicy> tenantApps,
  ) {
    final fw = snapshot?.firewall;
    // No snapshot yet: nothing is known to be tenant-mandated; the cloud decides on save.
    final allowUser = fw?.allowUserRules ?? true;
    final tenant = tenantRules(snapshot);
    return appNetworks.map((net) {
      final rule = tenant.where(
        (r) =>
            _isWholeAppRule(r, pkg) &&
            r.action != Verdict.ask &&
            (r.match.networks.isEmpty || r.match.networks.contains(net)),
      );
      if (rule.isNotEmpty) {
        return NetworkVerdict(net, rule.first.action, VerdictOrigin.tenantRule, locked: true, ruleId: rule.first.id);
      }
      final u = user.apps[pkg]?.forNetwork(net);
      if (allowUser && u != null) return NetworkVerdict(net, u, VerdictOrigin.userApp, locked: false);
      final t = tenantApps[pkg]?.forNetwork(net);
      if (t != null) return NetworkVerdict(net, t, VerdictOrigin.tenantApp, locked: !allowUser);
      if (fw?.lockdown ?? false) return NetworkVerdict(net, Verdict.block, VerdictOrigin.lockdown, locked: !allowUser);
      return NetworkVerdict(net, fw?.defaultAction ?? Verdict.allow, VerdictOrigin.defaultAction, locked: !allowUser);
    }).toList();
  }

  static UserRules setAppNetwork(UserRules user, String pkg, NetworkType network, bool allowed) {
    final current = user.apps[pkg] ?? const AppPolicy();
    final updated = current.withNetwork(network, allowed ? Verdict.allow : Verdict.block);
    return user.copyWith(apps: {...user.apps, pkg: updated});
  }

  static UserRules setAppAll(UserRules user, String pkg, bool allowed) {
    final a = allowed ? Verdict.allow : Verdict.block;
    return user.copyWith(
      apps: {
        ...user.apps,
        pkg: AppPolicy(wifi: a, cellular: a, roaming: a),
      },
    );
  }

  static List<Rule> _bySource(Snapshot? s, RuleSource src) =>
      (s?.firewall.rules ?? const <Rule>[]).where((r) => r.source == src).toList()
        ..sort((a, b) => a.priority - b.priority);

  static List<Rule> userRules(Snapshot? s) => _bySource(s, RuleSource.user);
  static List<Rule> tenantRules(Snapshot? s) => _bySource(s, RuleSource.tenant);

  /// Assigns priorities 100, 110, ... in list order.
  static List<Rule> renumber(List<Rule> rules) => [
    for (var i = 0; i < rules.length; i++)
      rules[i].copyWith(priority: userPriorityBase + i * userPriorityStep, source: RuleSource.user),
  ];

  static List<Rule> sorted(List<Rule> rules) => [...rules]..sort((a, b) => a.priority - b.priority);

  static UserRules upsertRule(UserRules user, Rule rule) {
    final r = rule.copyWith(source: RuleSource.user);
    final list = [...user.rules];
    final idx = list.indexWhere((x) => x.id == r.id);
    if (idx >= 0) {
      list[idx] = r;
    } else {
      list.add(r);
    }
    return user.copyWith(rules: sorted(list));
  }

  static UserRules deleteRule(UserRules user, String id) =>
      user.copyWith(rules: user.rules.where((r) => r.id != id).toList());

  static UserRules moveRule(UserRules user, int from, int to) {
    final ordered = sorted(user.rules);
    if (from < 0 || from >= ordered.length || to < 0 || to >= ordered.length || from == to) return user;
    ordered.insert(to, ordered.removeAt(from));
    return user.copyWith(rules: renumber(ordered));
  }

  static int nextPriority(UserRules user) {
    if (user.rules.isEmpty) return userPriorityBase;
    return user.rules.map((r) => r.priority).reduce((a, b) => a > b ? a : b) + userPriorityStep;
  }

  static String newRuleId(Iterable<String> existing) {
    final ids = existing.toSet();
    var n = ids.length + 1;
    while (ids.contains('u-$n')) {
      n++;
    }
    return 'u-$n';
  }

  /// DNS custom entries are user rules that only match domains.
  static List<Rule> domainRules(UserRules user) => user.rules.where((r) => r.match.isDomainOnly).toList();

  static UserRules addDomainRule(UserRules user, String domain, Verdict action) {
    final d = normalizeDomain(domain);
    if (d == null) return user;
    final rule = Rule(
      id: newRuleId(user.rules.map((r) => r.id)),
      source: RuleSource.user,
      priority: nextPriority(user),
      action: action,
      match: Match(domains: [d]),
      log: true,
    );
    return user.copyWith(rules: [...user.rules, rule]);
  }

  static final _label = RegExp(r'^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$');

  /// Accepts "example.com" or "*.example.com"; lowercases and strips a trailing dot.
  static String? normalizeDomain(String input) {
    var d = input.trim().toLowerCase();
    while (d.endsWith('.')) {
      d = d.substring(0, d.length - 1);
    }
    final body = d.startsWith('*.') ? d.substring(2) : d;
    if (body.isEmpty || body.length > 253 || body.contains('*') || !body.contains('.')) return null;
    if (!body.split('.').every(_label.hasMatch)) return null;
    return d;
  }

  /// Validates "10.0.0.0/8", "192.168.1.1", "fd00::/8".
  static bool isValidCidr(String input) {
    final s = input.trim();
    final parts = s.split('/');
    if (parts.length > 2) return false;
    final addr = parts[0];
    final prefix = parts.length == 2 ? int.tryParse(parts[1]) : null;
    if (parts.length == 2 && prefix == null) return false;
    if (addr.contains(':')) {
      final colons = ':'.allMatches(addr).length;
      return (prefix == null || (prefix >= 0 && prefix <= 128)) &&
          RegExp(r'^[0-9a-fA-F:]+$').hasMatch(addr) &&
          colons >= 2 &&
          colons <= 7;
    }
    final octets = addr.split('.');
    return octets.length == 4 &&
        octets.every((o) => o.isNotEmpty && (int.tryParse(o) ?? -1) >= 0 && (int.tryParse(o) ?? 256) <= 255) &&
        (prefix == null || (prefix >= 0 && prefix <= 32));
  }
}
