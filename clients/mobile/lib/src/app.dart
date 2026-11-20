import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:go_router/go_router.dart';
import 'package:material_ui/material_ui.dart';

import 'data/core_state.dart';
import 'l10n/app_localizations.dart';
import 'ui/activity_screen.dart';
import 'ui/app_detail_screen.dart';
import 'ui/apps_screen.dart';
import 'ui/common.dart';
import 'ui/dns_screen.dart';
import 'ui/home_screen.dart';
import 'ui/onboarding_screen.dart';
import 'ui/rules_screen.dart';
import 'ui/settings_screen.dart';
import 'ui/stats_screen.dart';
import 'ui/theme.dart';

const appVersion = '0.1.0';

/// Bridges Riverpod's enrolled flag to go_router's refreshListenable.
class _EnrolledListenable extends ChangeNotifier {
  bool? enrolled;
  void set(bool? v) {
    if (v != enrolled) {
      enrolled = v;
      notifyListeners();
    }
  }
}

final _enrolledListenable = Provider<_EnrolledListenable>((ref) {
  final l = _EnrolledListenable();
  ref.listen(coreProvider.select((s) => s.enrolled), (_, v) => l.set(v), fireImmediately: true);
  ref.onDispose(l.dispose);
  return l;
});

final routerProvider = Provider<GoRouter>((ref) {
  final enrolled = ref.watch(_enrolledListenable);
  final router = GoRouter(
    initialLocation: '/splash',
    refreshListenable: enrolled,
    redirect: (context, state) {
      final loc = state.matchedLocation;
      return switch (enrolled.enrolled) {
        null => loc == '/splash' ? null : '/splash',
        false => loc == '/onboarding' ? null : '/onboarding',
        true => (loc == '/onboarding' || loc == '/splash') ? '/home' : null,
      };
    },
    routes: [
      GoRoute(
        path: '/splash',
        builder: (_, _) => const Scaffold(body: Center(child: CircularProgressIndicator())),
      ),
      GoRoute(path: '/onboarding', builder: (_, _) => const OnboardingScreen()),
      StatefulShellRoute.indexedStack(
        builder: (context, state, shell) => AppShell(shell: shell),
        branches: [
          StatefulShellBranch(
            routes: [
              GoRoute(
                path: '/home',
                builder: (context, _) => HomeScreen(onOpenApp: (p) => context.push('/app/$p')),
              ),
            ],
          ),
          StatefulShellBranch(
            routes: [
              GoRoute(
                path: '/apps',
                builder: (context, _) => AppsScreen(onOpen: (p) => context.push('/app/$p')),
              ),
            ],
          ),
          StatefulShellBranch(
            routes: [GoRoute(path: '/rules', builder: (_, _) => const RulesScreen())],
          ),
          StatefulShellBranch(
            routes: [GoRoute(path: '/dns', builder: (_, _) => const DnsScreen())],
          ),
          StatefulShellBranch(
            routes: [
              GoRoute(
                path: '/activity',
                builder: (context, _) => ActivityScreen(onOpenApp: (p) => context.push('/app/$p')),
              ),
            ],
          ),
        ],
      ),
      GoRoute(
        path: '/app/:pkg',
        builder: (_, state) => AppDetailScreen(pkg: state.pathParameters['pkg']!),
      ),
      GoRoute(
        path: '/stats',
        builder: (context, _) => _Page(
          title: context.l10n.navStats,
          child: StatsScreen(onOpenApp: (p) => context.push('/app/$p')),
        ),
      ),
      GoRoute(
        path: '/settings',
        builder: (context, _) => _Page(
          title: context.l10n.navSettings,
          child: const SettingsScreen(appVersion: appVersion),
        ),
      ),
    ],
  );
  ref.onDispose(router.dispose);
  return router;
});

class OpenSaseApp extends ConsumerWidget {
  const OpenSaseApp({super.key});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    return MaterialApp.router(
      onGenerateTitle: (_) => 'OpenSASE',
      theme: buildTheme(Brightness.light),
      darkTheme: buildTheme(Brightness.dark),
      routerConfig: ref.watch(routerProvider),
      localizationsDelegates: const [AppLocalizations.delegate, ...GlobalMaterialLocalizations.delegates],
      supportedLocales: AppLocalizations.supportedLocales,
      debugShowCheckedModeBanner: false,
    );
  }
}

/// Bottom navigation shell for the five main sections; Stats and Settings in the app bar.
class AppShell extends StatelessWidget {
  const AppShell({super.key, required this.shell});
  final StatefulNavigationShell shell;

  @override
  Widget build(BuildContext context) {
    final l = context.l10n;
    final titles = ['OpenSASE', l.navApps, l.navRules, l.navDns, l.navActivity];
    return Scaffold(
      appBar: AppBar(
        title: Text(titles[shell.currentIndex]),
        actions: [
          IconButton(icon: const Icon(Icons.insights), tooltip: l.navStats, onPressed: () => context.push('/stats')),
          IconButton(
            icon: const Icon(Icons.settings),
            tooltip: l.navSettings,
            onPressed: () => context.push('/settings'),
          ),
        ],
      ),
      body: shell,
      bottomNavigationBar: NavigationBar(
        selectedIndex: shell.currentIndex,
        onDestinationSelected: (i) => shell.goBranch(i, initialLocation: i == shell.currentIndex),
        destinations: [
          NavigationDestination(
            icon: const Icon(Icons.home_outlined),
            selectedIcon: const Icon(Icons.home),
            label: l.navHome,
          ),
          NavigationDestination(
            icon: const Icon(Icons.apps_outlined),
            selectedIcon: const Icon(Icons.apps),
            label: l.navApps,
          ),
          NavigationDestination(
            icon: const Icon(Icons.rule_outlined),
            selectedIcon: const Icon(Icons.rule),
            label: l.navRules,
          ),
          NavigationDestination(
            icon: const Icon(Icons.dns_outlined),
            selectedIcon: const Icon(Icons.dns),
            label: l.navDns,
          ),
          NavigationDestination(
            icon: const Icon(Icons.list_alt_outlined),
            selectedIcon: const Icon(Icons.list_alt),
            label: l.navActivity,
          ),
        ],
      ),
    );
  }
}

class _Page extends StatelessWidget {
  const _Page({required this.title, required this.child});
  final String title;
  final Widget child;

  @override
  Widget build(BuildContext context) => Scaffold(
    appBar: AppBar(title: Text(title)),
    body: child,
  );
}
