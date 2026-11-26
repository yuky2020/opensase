import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:material_ui/material_ui.dart' hide Flow;

import '../api/admin_api.dart';
import '../api/admin_models.dart';
import '../api/policy_models.dart';
import '../data/providers.dart';
import '../data/session.dart';
import 'common.dart';

class PolicyTestScreen extends ConsumerWidget {
  const PolicyTestScreen({super.key});

  @override
  Widget build(BuildContext context, WidgetRef ref) => TenantScoped(
    builder: (tenant) => _PolicyTestView(key: ValueKey('policy-test-$tenant'), tenant: tenant),
  );
}

class _PolicyTestView extends ConsumerStatefulWidget {
  const _PolicyTestView({super.key, required this.tenant});

  final String tenant;

  @override
  ConsumerState<_PolicyTestView> createState() => _PolicyTestViewState();
}

class _PolicyTestViewState extends ConsumerState<_PolicyTestView> {
  String? _selectedDeviceId;
  String _protocol = 'tcp';
  final _dstIpController = TextEditingController();
  final _dstPortController = TextEditingController();
  final _domainController = TextEditingController();
  final _appController = TextEditingController();
  String _network = '';
  bool _edge = false;
  bool _loading = false;

  String? _deviceError;
  String? _ipError;
  String? _portError;
  String? _serverError;
  PolicyTestResult? _result;

  @override
  void dispose() {
    _dstIpController.dispose();
    _dstPortController.dispose();
    _domainController.dispose();
    _appController.dispose();
    super.dispose();
  }

  static bool _isValidIp(String s) {
    final trimmed = s.trim();
    if (trimmed.isEmpty) return false;
    try {
      if (trimmed.contains(':')) {
        Uri.parseIPv6Address(trimmed);
      } else {
        Uri.parseIPv4Address(trimmed);
      }
      return true;
    } on FormatException {
      return false;
    }
  }

  static bool _isValidPort(String s) {
    final trimmed = s.trim();
    final p = int.tryParse(trimmed);
    return p != null && p >= 0 && p <= 65535;
  }

  Future<void> _test() async {
    final l = context.l10n;
    final ip = _dstIpController.text.trim();
    final portStr = _dstPortController.text.trim();

    String? devErr;
    String? ipErr;
    String? portErr;

    if (_selectedDeviceId == null || _selectedDeviceId!.isEmpty) {
      devErr = l.fieldRequired;
    }
    if (!_isValidIp(ip)) {
      ipErr = l.policyTestInvalidIp;
    }
    if (!_isValidPort(portStr)) {
      portErr = l.policyTestInvalidPort;
    }

    setState(() {
      _deviceError = devErr;
      _ipError = ipErr;
      _portError = portErr;
      _serverError = null;
    });

    if (devErr != null || ipErr != null || portErr != null) {
      return;
    }

    final port = int.parse(portStr);
    final domain = _domainController.text.trim();
    final app = _edge ? '' : _appController.text.trim();
    final network = _edge ? '' : _network;

    final req = PolicyTestRequest(
      deviceId: _selectedDeviceId!,
      flow: Flow(protocol: _protocol, dstIp: ip, dstPort: port, domain: domain, app: app, network: network),
      edge: _edge,
    );

    setState(() => _loading = true);
    try {
      final res = await ref.read(apiProvider).policyTest(widget.tenant, req);
      if (mounted) {
        setState(() {
          _result = res;
          _serverError = null;
        });
      }
    } on ApiException catch (e) {
      if (!mounted) return;
      if (e.status == 401) {
        showSnack(context, l.msgSessionExpired);
        ref.read(sessionProvider.notifier).logout();
      } else {
        setState(() {
          _serverError = e.toString();
          _result = null;
        });
        showSnack(context, l.msgError(e.toString()));
      }
    } on Object catch (e) {
      if (mounted) {
        setState(() {
          _serverError = '$e';
          _result = null;
        });
        showSnack(context, l.msgError('$e'));
      }
    } finally {
      if (mounted) setState(() => _loading = false);
    }
  }

  Widget _resultItem(String label, Widget content) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      mainAxisSize: MainAxisSize.min,
      children: [
        Text(
          label,
          style: Theme.of(context).textTheme.bodySmall?.copyWith(color: Theme.of(context).colorScheme.outline),
        ),
        const SizedBox(height: 4),
        content,
      ],
    );
  }

  @override
  Widget build(BuildContext context) {
    final l = context.l10n;
    final devicesAsync = ref.watch(devicesProvider(widget.tenant));
    final usersAsync = ref.watch(usersProvider(widget.tenant));

    final userMap = <String, String>{
      for (final u in usersAsync.value ?? const <AdminUser>[])
        u.id: (u.name.isNotEmpty ? u.name : (u.email.isNotEmpty ? u.email : u.id)),
    };

    final devices = devicesAsync.value ?? const <AdminDevice>[];

    return PageFrame(
      title: l.navPolicyTest,
      subtitle: l.policyTestSubtitle,
      actions: [
        IconButton(
          key: const ValueKey('policy_test_refresh'),
          tooltip: l.actionRefresh,
          icon: const Icon(Icons.refresh),
          onPressed: () {
            ref.invalidate(devicesProvider(widget.tenant));
            ref.invalidate(usersProvider(widget.tenant));
          },
        ),
      ],
      child: SingleChildScrollView(
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            SectionCard(
              title: l.navPolicyTest,
              children: [
                if (devicesAsync.isLoading)
                  const Padding(
                    padding: EdgeInsets.symmetric(vertical: 8),
                    child: Center(child: CircularProgressIndicator()),
                  )
                else if (devices.isEmpty)
                  Padding(
                    padding: const EdgeInsets.symmetric(vertical: 8),
                    child: Text(l.policyTestNoDevices, style: TextStyle(color: Theme.of(context).colorScheme.error)),
                  )
                else
                  DropdownButtonFormField<String>(
                    isExpanded: true,
                    key: const ValueKey('device_picker'),
                    initialValue: devices.any((d) => d.id == _selectedDeviceId) ? _selectedDeviceId : null,
                    decoration: InputDecoration(
                      labelText: l.policyTestDevice,
                      hintText: l.policyTestSelectDevice,
                      errorText: _deviceError,
                      border: const OutlineInputBorder(),
                    ),
                    items: [
                      for (final d in devices)
                        DropdownMenuItem(
                          value: d.id,
                          child: Text(
                            d.name.isNotEmpty
                                ? (userMap[d.userId] != null
                                      ? '${d.name} (${userMap[d.userId]})'
                                      : (d.userId.isNotEmpty ? '${d.name} (${d.userId})' : d.name))
                                : (userMap[d.userId] != null
                                      ? '${d.id} (${userMap[d.userId]})'
                                      : (d.userId.isNotEmpty ? '${d.id} (${d.userId})' : d.id)),
                          ),
                        ),
                    ],
                    onChanged: (v) => setState(() {
                      _selectedDeviceId = v;
                      _deviceError = null;
                    }),
                  ),
                const SizedBox(height: 16),
                Wrap(
                  spacing: 16,
                  runSpacing: 16,
                  children: [
                    SizedBox(
                      width: 140,
                      child: DropdownButtonFormField<String>(
                        isExpanded: true,
                        key: const ValueKey('protocol'),
                        initialValue: _protocol,
                        decoration: InputDecoration(
                          labelText: l.policyTestProtocol,
                          border: const OutlineInputBorder(),
                        ),
                        items: const [
                          DropdownMenuItem(value: 'tcp', child: Text('TCP')),
                          DropdownMenuItem(value: 'udp', child: Text('UDP')),
                          DropdownMenuItem(value: 'icmp', child: Text('ICMP')),
                        ],
                        onChanged: (v) {
                          if (v != null) setState(() => _protocol = v);
                        },
                      ),
                    ),
                    SizedBox(
                      width: 260,
                      child: TextField(
                        key: const ValueKey('dst_ip'),
                        controller: _dstIpController,
                        decoration: InputDecoration(
                          labelText: l.policyTestDstIp,
                          errorText: _ipError,
                          border: const OutlineInputBorder(),
                        ),
                        onChanged: (_) {
                          if (_ipError != null) setState(() => _ipError = null);
                        },
                      ),
                    ),
                    SizedBox(
                      width: 160,
                      child: TextField(
                        key: const ValueKey('dst_port'),
                        controller: _dstPortController,
                        keyboardType: TextInputType.number,
                        decoration: InputDecoration(
                          labelText: l.policyTestDstPort,
                          errorText: _portError,
                          border: const OutlineInputBorder(),
                        ),
                        onChanged: (_) {
                          if (_portError != null) setState(() => _portError = null);
                        },
                      ),
                    ),
                  ],
                ),
                const SizedBox(height: 16),
                Wrap(
                  spacing: 16,
                  runSpacing: 16,
                  children: [
                    SizedBox(
                      width: 260,
                      child: TextField(
                        key: const ValueKey('domain'),
                        controller: _domainController,
                        decoration: InputDecoration(labelText: l.policyTestDomain, border: const OutlineInputBorder()),
                      ),
                    ),
                    SizedBox(
                      width: 260,
                      child: TextField(
                        key: const ValueKey('app'),
                        controller: _appController,
                        enabled: !_edge,
                        decoration: InputDecoration(
                          labelText: l.policyTestApp,
                          helperText: _edge ? l.policyTestAppHelp : null,
                          border: const OutlineInputBorder(),
                        ),
                      ),
                    ),
                    SizedBox(
                      width: 200,
                      child: DropdownButtonFormField<String>(
                        isExpanded: true,
                        key: const ValueKey('network'),
                        initialValue: _network,
                        decoration: InputDecoration(labelText: l.policyTestNetwork, border: const OutlineInputBorder()),
                        items: [
                          DropdownMenuItem(value: '', child: Text(l.flowsAny)),
                          DropdownMenuItem(value: 'wifi', child: Text(networkLabel(context, 'wifi'))),
                          DropdownMenuItem(value: 'cellular', child: Text(networkLabel(context, 'cellular'))),
                          DropdownMenuItem(value: 'roaming', child: Text(networkLabel(context, 'roaming'))),
                          DropdownMenuItem(value: 'ethernet', child: Text(networkLabel(context, 'ethernet'))),
                          DropdownMenuItem(value: 'unknown', child: Text(networkLabel(context, 'unknown'))),
                        ],
                        onChanged: (v) => setState(() => _network = v ?? ''),
                      ),
                    ),
                  ],
                ),
                const SizedBox(height: 16),
                SwitchListTile(
                  key: const ValueKey('edge_switch'),
                  title: Text(l.policyTestEdge),
                  subtitle: Text(l.policyTestEdgeHelp),
                  value: _edge,
                  onChanged: (v) => setState(() => _edge = v),
                ),
                const SizedBox(height: 16),
                Align(
                  alignment: Alignment.centerLeft,
                  child: FilledButton.icon(
                    key: const ValueKey('test_button'),
                    onPressed: _loading ? null : _test,
                    icon: _loading
                        ? const SizedBox(width: 18, height: 18, child: CircularProgressIndicator(strokeWidth: 2))
                        : const Icon(Icons.play_arrow),
                    label: Text(_loading ? l.policyTestTesting : l.policyTestActionTest),
                  ),
                ),
              ],
            ),
            if (_serverError != null) ...[
              const SizedBox(height: 16),
              Container(
                key: const ValueKey('server_error'),
                padding: const EdgeInsets.all(12),
                decoration: BoxDecoration(
                  color: Theme.of(context).colorScheme.errorContainer,
                  borderRadius: BorderRadius.circular(8),
                ),
                child: Row(
                  children: [
                    Icon(Icons.error_outline, color: Theme.of(context).colorScheme.onErrorContainer),
                    const SizedBox(width: 8),
                    Expanded(
                      child: SelectableText(
                        _serverError!,
                        style: TextStyle(color: Theme.of(context).colorScheme.onErrorContainer),
                      ),
                    ),
                  ],
                ),
              ),
            ],
            if (_result != null) ...[
              const SizedBox(height: 16),
              SectionCard(
                key: const ValueKey('result_card'),
                title: l.policyTestResultTitle,
                children: [
                  Wrap(
                    spacing: 32,
                    runSpacing: 16,
                    crossAxisAlignment: WrapCrossAlignment.center,
                    children: [
                      _resultItem(
                        l.policyTestResultAction,
                        StatusChip(
                          key: const ValueKey('result_action'),
                          label: actionLabel(context, _result!.decision.action),
                          color: verdictColor(context, _result!.decision.action),
                        ),
                      ),
                      _resultItem(
                        l.policyTestResultLayer,
                        Text(
                          _result!.decision.layer,
                          key: const ValueKey('result_layer'),
                          style: const TextStyle(fontWeight: FontWeight.w600),
                        ),
                      ),
                      _resultItem(
                        l.policyTestResultRuleId,
                        Text(
                          _result!.decision.ruleId.isNotEmpty ? _result!.decision.ruleId : '-',
                          key: const ValueKey('result_rule_id'),
                          style: const TextStyle(fontFamily: 'monospace', fontWeight: FontWeight.w600),
                        ),
                      ),
                      if (_result!.decision.reason.isNotEmpty)
                        _resultItem(
                          l.policyTestResultReason,
                          Text(
                            _result!.decision.reason,
                            key: const ValueKey('result_reason'),
                            style: const TextStyle(fontWeight: FontWeight.w600),
                          ),
                        ),
                      _resultItem(
                        l.policyTestResultSnapshot,
                        Text(
                          '${_result!.snapshotVersion}',
                          key: const ValueKey('result_snapshot_version'),
                          style: const TextStyle(fontFamily: 'monospace', fontWeight: FontWeight.w600),
                        ),
                      ),
                    ],
                  ),
                ],
              ),
            ],
            const SizedBox(height: 24),
          ],
        ),
      ),
    );
  }
}
