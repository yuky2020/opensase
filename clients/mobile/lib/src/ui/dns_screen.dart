import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:material_ui/material_ui.dart';

import '../contracts/policy.dart';
import '../data/core_state.dart';
import '../data/policy_logic.dart';
import 'common.dart';

class DnsScreen extends ConsumerStatefulWidget {
  const DnsScreen({super.key});

  @override
  ConsumerState<DnsScreen> createState() => _DnsScreenState();
}

class _DnsScreenState extends ConsumerState<DnsScreen> {
  final _domain = TextEditingController();
  bool _invalid = false;

  @override
  void dispose() {
    _domain.dispose();
    super.dispose();
  }

  Future<void> _add(Verdict action) async {
    final text = _domain.text;
    if (PolicyLogic.normalizeDomain(text) == null) {
      setState(() => _invalid = true);
      return;
    }
    final r = await ref.read(coreProvider.notifier).updateUserLayer((u) => PolicyLogic.addDomainRule(u, text, action));
    if (!mounted) return;
    showSaveResult(context, r);
    if (r is SaveOk) _domain.clear();
  }

  static IconData _categoryIcon(String c) => switch (c) {
    'ads' => Icons.campaign,
    'trackers' => Icons.track_changes,
    'malware' => Icons.coronavirus,
    _ => Icons.block,
  };

  @override
  Widget build(BuildContext context) {
    final l = context.l10n;
    final s = ref.watch(coreProvider);
    final dns = s.policy.snapshot?.dns;
    final custom = PolicyLogic.domainRules(s.policy.user);
    final editable = s.policy.userLayerEditable;
    final t = Theme.of(context);
    return ListView(
      padding: const EdgeInsets.only(bottom: 24),
      children: [
        Padding(
          padding: const EdgeInsets.fromLTRB(16, 16, 16, 0),
          child: InfoBanner(l.dnsBlockedToday(s.counters.dnsBlocked), icon: Icons.shield_outlined),
        ),
        SectionHeader(l.dnsBlocklists, subtitle: l.dnsBlocklistsHint),
        if (dns == null || dns.blocklists.isEmpty) EmptyState(l.emptyNothingHere),
        for (final b in dns?.blocklists ?? const <Blocklist>[])
          Padding(
            padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 4),
            child: Card(
              child: ListTile(
                leading: Icon(_categoryIcon(b.category)),
                title: Text(b.name.isEmpty ? b.id : b.name),
                subtitle: Text('${l.dnsDomainCount(b.domains.length)} · ${b.category}'),
                trailing: Tooltip(message: l.companyPolicyLocked, child: const Icon(Icons.lock, size: 18)),
              ),
            ),
          ),
        if (dns != null)
          Padding(
            padding: const EdgeInsets.fromLTRB(16, 4, 16, 0),
            child: Text(l.dnsBlockResponse(dns.blockResponse), style: t.textTheme.bodySmall),
          ),
        if (dns != null && (dns.blockDomains.isNotEmpty || dns.allowDomains.isNotEmpty)) ...[
          SectionHeader(l.dnsTenantDomains),
          Padding(
            padding: const EdgeInsets.symmetric(horizontal: 16),
            child: Wrap(
              spacing: 8,
              runSpacing: 4,
              children: [
                for (final d in dns.blockDomains) Chip(avatar: const Icon(Icons.block, size: 16), label: Text(d)),
                for (final d in dns.allowDomains) Chip(avatar: const Icon(Icons.check, size: 16), label: Text(d)),
              ],
            ),
          ),
        ],
        SectionHeader(l.dnsCustom, subtitle: l.dnsCustomHint),
        if (!editable)
          Padding(
            padding: const EdgeInsets.symmetric(horizontal: 16),
            child: InfoBanner(l.rulesUserDisabled, warning: true),
          ),
        Padding(
          padding: const EdgeInsets.fromLTRB(16, 8, 16, 8),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: [
              TextField(
                key: const Key('dns_domain'),
                controller: _domain,
                enabled: editable,
                keyboardType: TextInputType.url,
                autocorrect: false,
                onChanged: (_) => setState(() => _invalid = false),
                decoration: InputDecoration(
                  hintText: l.dnsAddHint,
                  errorText: _invalid ? l.dnsInvalid : null,
                  border: const OutlineInputBorder(),
                  prefixIcon: const Icon(Icons.language),
                ),
              ),
              const SizedBox(height: 8),
              Row(
                children: [
                  Expanded(
                    child: FilledButton.tonalIcon(
                      key: const Key('dns_block'),
                      onPressed: editable ? () => _add(Verdict.block) : null,
                      icon: const Icon(Icons.block),
                      label: Text(l.dnsAddBlock),
                    ),
                  ),
                  const SizedBox(width: 8),
                  Expanded(
                    child: OutlinedButton.icon(
                      key: const Key('dns_allow'),
                      onPressed: editable ? () => _add(Verdict.allow) : null,
                      icon: const Icon(Icons.check),
                      label: Text(l.dnsAddAllow),
                    ),
                  ),
                ],
              ),
            ],
          ),
        ),
        if (custom.isEmpty) EmptyState(l.dnsEmpty),
        for (final r in custom)
          ListTile(
            leading: VerdictChip(r.action),
            title: Text(r.match.domains.join(', ')),
            subtitle: Text(r.id),
            trailing: IconButton(
              icon: const Icon(Icons.delete_outline),
              tooltip: l.actionDelete,
              onPressed: !editable
                  ? null
                  : () async {
                      final res = await ref
                          .read(coreProvider.notifier)
                          .updateUserLayer((u) => PolicyLogic.deleteRule(u, r.id));
                      if (context.mounted) showSaveResult(context, res);
                    },
            ),
          ),
      ],
    );
  }
}
