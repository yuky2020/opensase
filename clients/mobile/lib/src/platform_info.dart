import 'dart:io' show Platform;

/// Override for testing desktop behavior on non-desktop platforms or vice-versa.
bool? isDesktopOverride;

/// Whether the current platform is desktop (Linux or Windows).
bool get isDesktop => isDesktopOverride ?? (Platform.isLinux || Platform.isWindows);
