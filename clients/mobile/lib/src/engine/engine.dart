import 'dart:typed_data';

/// The Client engine as seen from Dart.
///
/// Mirrors the gomobile `Engine` in mobile/api.go plus the VPN controls that only the
/// native side can perform. JSON payloads cross this boundary as raw strings (exactly what
/// the Go core produces) and are parsed in Dart by [EngineClient].
///
/// Implementations: [MethodChannelEngine] (native Android, MethodChannel
/// `eu.opensase/engine` + EventChannel `eu.opensase/events`) and [FakeEngine] (pure Dart).
abstract class Engine {
  /// Short name shown in Settings ("native", "fake").
  String get name;

  Future<bool> isEnrolled();
  Future<void> enroll(String controlUrl, String provisioningKey, String deviceName);
  Future<void> unenroll();

  /// Asks for VPN consent if needed (VpnService.prepare). Returns true if granted.
  Future<bool> prepareVpn();
  Future<void> connect();
  Future<void> disconnect();

  /// JSON EngineStatus.
  Future<String> status();

  /// JSON Snapshot, or "" when there is none yet.
  Future<String> snapshot();

  /// JSON api.UserRules. Throws [UserRulesForbiddenException] on HTTP 403.
  Future<void> setUserRules(String json);
  Future<void> setAppPolicy(String pkg, String wifi, String cellular, String roaming);

  /// JSON list of api.FlowRecord, newest first.
  Future<String> recentFlows(int limit);

  /// JSON list of AppStat.
  Future<String> appStats();

  Future<List<InstalledApp>> installedApps();

  /// Current VPN service state (also streamed as `vpn` events).
  Future<VpnStatus> vpnStatus();

  /// Opens the system VPN settings (always-on / lockdown live there).
  Future<void> openVpnSettings();

  /// Lets the user save [content] as a file named [fileName]. Returns false if cancelled.
  Future<bool> saveFile(String fileName, String content);

  /// Takes the pending `opensase://enroll?...` deep link that opened the app, if any.
  /// Links received while running arrive as [EngineEvent.enrollLink] events.
  Future<String?> takeEnrollLink();

  /// Reconnect after boot (only used when always-on VPN is off).
  Future<void> setConnectOnBoot(bool enabled);

  /// Core events (kind + JSON payload) and `vpn` state changes.
  Stream<EngineEvent> get events;
}

class EngineEvent {
  const EngineEvent(this.kind, this.payload);

  final String kind;
  final String payload;

  static const state = 'state';
  static const flow = 'flow';
  static const stats = 'stats';
  static const snapshot = 'snapshot';
  static const error = 'error';
  static const log = 'log';

  /// Emitted by the native VpnService (not by the Go core): payload is VpnStatus JSON.
  static const vpn = 'vpn';

  /// An `opensase://enroll` deep link (payload: the URI). Emitted by the native side.
  static const enrollLink = 'enrollLink';

  @override
  String toString() => 'EngineEvent($kind)';
}

class EngineException implements Exception {
  const EngineException(this.message);
  final String message;
  @override
  String toString() => message;
}

/// The tenant does not allow user rules (403 from PUT /v1/self/rules).
class UserRulesForbiddenException extends EngineException {
  const UserRulesForbiddenException(super.message);
}

enum VpnPhase { idle, connecting, running, failed }

class VpnStatus {
  const VpnStatus({this.phase = VpnPhase.idle, this.message = '', this.alwaysOn = false, this.lockdown = false});

  final VpnPhase phase;
  final String message;

  /// Last value of VpnService.isAlwaysOn / isLockdownEnabled seen by the service.
  final bool alwaysOn;
  final bool lockdown;

  bool get isOn => phase == VpnPhase.connecting || phase == VpnPhase.running;

  factory VpnStatus.fromJson(Map<String, dynamic> j) => VpnStatus(
    phase: VpnPhase.values.firstWhere((p) => p.name == j['phase'], orElse: () => VpnPhase.idle),
    message: (j['message'] as String?) ?? '',
    alwaysOn: (j['alwaysOn'] as bool?) ?? false,
    lockdown: (j['lockdown'] as bool?) ?? false,
  );

  Map<String, dynamic> toJson() => {
    'phase': phase.name,
    'message': message,
    'alwaysOn': alwaysOn,
    'lockdown': lockdown,
  };
}

class InstalledApp {
  const InstalledApp({
    required this.packageName,
    required this.label,
    this.uid = -1,
    this.isSystem = false,
    this.hasInternet = true,
    this.icon,
  });

  final String packageName;
  final String label;
  final int uid;
  final bool isSystem;
  final bool hasInternet;

  /// PNG bytes, or null (the UI then draws a letter avatar).
  final Uint8List? icon;

  factory InstalledApp.fromMap(Map<Object?, Object?> m) => InstalledApp(
    packageName: m['package'] as String,
    label: (m['label'] as String?) ?? (m['package'] as String),
    uid: (m['uid'] as int?) ?? -1,
    isSystem: (m['isSystem'] as bool?) ?? false,
    hasInternet: (m['hasInternetPermission'] as bool?) ?? false,
    icon: m['icon'] as Uint8List?,
  );
}
