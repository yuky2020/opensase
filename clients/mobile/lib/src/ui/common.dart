import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:intl/intl.dart';
import 'package:material_ui/material_ui.dart';

import '../contracts/policy.dart';
import '../data/core_state.dart';
import '../l10n/app_localizations.dart';
import 'theme.dart';

extension L10nX on BuildContext {
  AppLocalizations get l10n => AppLocalizations.of(this);
}

/// App icon from the native PNG bytes, or a letter avatar (fake engine, unknown app).
class AppIcon extends ConsumerWidget {
  const AppIcon(this.pkg, {super.key, this.size = 40});

  final String pkg;
  final double size;

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final app = ref.watch(appsByPackageProvider)[pkg];
    final icon = app?.icon;
    if (icon != null) {
      return ClipRRect(
        borderRadius: BorderRadius.circular(size / 4),
        child: Image.memory(
          icon,
          width: size,
          height: size,
          gaplessPlayback: true,
          filterQuality: FilterQuality.medium,
        ),
      );
    }
    final label = app?.label ?? (pkg.isEmpty ? '?' : pkg.split('.').last);
    final scheme = Theme.of(context).colorScheme;
    final hue = (pkg.hashCode % 360).abs().toDouble();
    final bg = HSLColor.fromAHSL(1, hue, 0.45, Theme.of(context).brightness == Brightness.dark ? 0.35 : 0.80).toColor();
    return Container(
      width: size,
      height: size,
      alignment: Alignment.center,
      decoration: BoxDecoration(
        color: pkg.isEmpty ? scheme.surfaceContainerHighest : bg,
        borderRadius: BorderRadius.circular(size / 4),
      ),
      child: Text(
        label.isEmpty ? '?' : label.characters.first.toUpperCase(),
        style: TextStyle(fontSize: size * 0.45, fontWeight: FontWeight.w600, color: scheme.onSurface),
      ),
    );
  }
}

/// Label for a package: the installed app name if known, else the package name.
String appLabel(WidgetRef ref, BuildContext context, String pkg) {
  if (pkg.isEmpty) return context.l10n.networkUnknown;
  return ref.watch(appsByPackageProvider)[pkg]?.label ?? pkg;
}

Color verdictColor(BuildContext context, Verdict v) {
  final c = context.verdicts;
  return switch (v) {
    Verdict.allow => c.allow,
    Verdict.block => c.block,
    Verdict.ask => c.ask,
  };
}

String verdictLabel(BuildContext context, Verdict v) {
  final l = context.l10n;
  return switch (v) {
    Verdict.allow => l.verdictAllow,
    Verdict.block => l.verdictBlock,
    Verdict.ask => l.verdictAsk,
  };
}

String actionLabel(BuildContext context, Verdict v) {
  final l = context.l10n;
  return switch (v) {
    Verdict.allow => l.actionAllow,
    Verdict.block => l.actionBlock,
    Verdict.ask => l.actionAsk,
  };
}

String networkLabel(BuildContext context, NetworkType n) {
  final l = context.l10n;
  return switch (n) {
    NetworkType.wifi => l.networkWifi,
    NetworkType.cellular => l.networkCellular,
    NetworkType.roaming => l.networkRoaming,
    NetworkType.ethernet => l.networkEthernet,
    NetworkType.unknown => l.networkUnknown,
  };
}

IconData networkIcon(NetworkType n, {bool blocked = false}) => switch (n) {
  NetworkType.wifi || NetworkType.ethernet || NetworkType.unknown => blocked ? Icons.wifi_off : Icons.wifi,
  NetworkType.cellular => blocked ? Icons.signal_cellular_off : Icons.signal_cellular_alt,
  NetworkType.roaming => blocked ? Icons.public_off : Icons.travel_explore,
};

String layerLabel(BuildContext context, String layer) {
  final l = context.l10n;
  return switch (layer) {
    'tenant' => l.layerTenant,
    'user' => l.layerUser,
    'app' => l.layerApp,
    'default' => l.layerDefault,
    'lockdown' => l.layerLockdown,
    'cloud' => l.layerCloud,
    'dns' => l.layerDns,
    _ => layer,
  };
}

/// Small coloured pill with the verdict.
class VerdictChip extends StatelessWidget {
  const VerdictChip(this.verdict, {super.key});
  final Verdict verdict;

  @override
  Widget build(BuildContext context) {
    final c = verdictColor(context, verdict);
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 2),
      decoration: BoxDecoration(color: c.withValues(alpha: 0.14), borderRadius: BorderRadius.circular(50)),
      child: Text(
        verdictLabel(context, verdict),
        style: Theme.of(context).textTheme.labelSmall?.copyWith(color: c, fontWeight: FontWeight.w600),
      ),
    );
  }
}

class SectionHeader extends StatelessWidget {
  const SectionHeader(this.title, {super.key, this.subtitle});
  final String title;
  final String? subtitle;

  @override
  Widget build(BuildContext context) {
    final t = Theme.of(context);
    return Padding(
      padding: const EdgeInsets.fromLTRB(16, 16, 16, 8),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(title, style: t.textTheme.titleMedium?.copyWith(color: t.colorScheme.primary)),
          if (subtitle != null)
            Text(subtitle!, style: t.textTheme.bodySmall?.copyWith(color: t.colorScheme.onSurfaceVariant)),
        ],
      ),
    );
  }
}

class EmptyState extends StatelessWidget {
  const EmptyState(this.text, {super.key});
  final String text;

  @override
  Widget build(BuildContext context) => Padding(
    padding: const EdgeInsets.all(32),
    child: Center(
      child: Text(
        text,
        textAlign: TextAlign.center,
        style: Theme.of(context).textTheme.bodyMedium?.copyWith(color: Theme.of(context).colorScheme.onSurfaceVariant),
      ),
    ),
  );
}

class InfoBanner extends StatelessWidget {
  const InfoBanner(this.text, {super.key, this.warning = false, this.icon});
  final String text;
  final bool warning;
  final IconData? icon;

  @override
  Widget build(BuildContext context) {
    final s = Theme.of(context).colorScheme;
    final bg = warning ? s.errorContainer : s.secondaryContainer;
    final fg = warning ? s.onErrorContainer : s.onSecondaryContainer;
    return Container(
      width: double.infinity,
      padding: const EdgeInsets.all(12),
      decoration: BoxDecoration(color: bg, borderRadius: BorderRadius.circular(12)),
      child: Row(
        children: [
          Icon(icon ?? (warning ? Icons.warning_amber_rounded : Icons.info_outline), color: fg, size: 20),
          const SizedBox(width: 8),
          Expanded(
            child: Text(text, style: TextStyle(color: fg)),
          ),
        ],
      ),
    );
  }
}

/// "Quantum-safe: X25519MLKEM768" badge. Show it only when status.pq is true.
class QuantumBadge extends StatelessWidget {
  const QuantumBadge(this.kex, {super.key});
  final String kex;

  @override
  Widget build(BuildContext context) {
    final c = context.verdicts.quantumSafe;
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 6),
      decoration: BoxDecoration(color: c.withValues(alpha: 0.14), borderRadius: BorderRadius.circular(50)),
      child: Row(
        mainAxisSize: MainAxisSize.min,
        children: [
          Icon(Icons.verified_user, size: 18, color: c),
          const SizedBox(width: 6),
          Flexible(
            child: Text(
              context.l10n.homeQuantumSafe(kex),
              overflow: TextOverflow.ellipsis,
              style: Theme.of(context).textTheme.labelLarge?.copyWith(color: c, fontWeight: FontWeight.w600),
            ),
          ),
        ],
      ),
    );
  }
}

/// Shows a snackbar with the outcome of a user-layer save.
void showSaveResult(BuildContext context, SaveResult r, {bool quietOk = false}) {
  final l = context.l10n;
  final text = switch (r) {
    SaveOk() => quietOk ? null : l.msgSaved,
    SaveForbidden() => l.msgForbidden,
    SaveFailed(:final message) => l.msgError(message),
  };
  if (text == null) return;
  ScaffoldMessenger.of(context)
    ..hideCurrentSnackBar()
    ..showSnackBar(SnackBar(content: Text(text)));
}

class Fmt {
  Fmt._();

  static String bytes(int n) {
    if (n < 1024) return '$n B';
    const units = ['KB', 'MB', 'GB', 'TB'];
    var v = n / 1024.0;
    var i = 0;
    while (v >= 1024 && i < units.length - 1) {
      v /= 1024;
      i++;
    }
    return '${v < 10 ? v.toStringAsFixed(1) : v.toStringAsFixed(0)} ${units[i]}';
  }

  static DateTime? _parse(String iso) {
    if (iso.isEmpty || iso.startsWith('0001-')) return null;
    return DateTime.tryParse(iso)?.toLocal();
  }

  static String time(String iso) {
    final d = _parse(iso);
    return d == null ? '' : DateFormat.Hms().format(d);
  }

  static String dateTime(String iso, String locale) {
    final d = _parse(iso);
    return d == null ? iso : DateFormat.MMMd(locale).add_Hm().format(d);
  }

  /// "1.2.3.4:443", or "[2001:db8::1]:443" for IPv6.
  static String endpoint(String ip, int port) => ip.contains(':') ? '[$ip]:$port' : '$ip:$port';
}
