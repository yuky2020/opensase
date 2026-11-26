import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:go_router/go_router.dart';
import 'package:material_ui/material_ui.dart';

import 'data/providers.dart';
import 'data/session.dart';
import 'l10n/app_localizations.dart';
import 'ui/activity_screen.dart';
import 'ui/security_events_screen.dart';
import 'ui/common.dart';
import 'ui/infra_screens.dart';
import 'ui/login_screen.dart';
import 'ui/onboarding_screen.dart';
import 'ui/overview_screen.dart';
import 'ui/policy_screen.dart';
import 'ui/policy_test_screen.dart';
import 'ui/dns_screen.dart';
import 'ui/private_apps_screen.dart';
import 'ui/categories_screen.dart';
import 'ui/saas_screen.dart';
import 'ui/web_screen.dart';
import 'ui/settings_screen.dart';
import 'ui/admin_tokens_screen.dart';
import 'ui/sso_screen.dart';
import 'ui/oidc_signin_screen.dart';
import 'ui/audit_screen.dart';
import 'ui/status_screen.dart';
import 'ui/tenants_screen.dart';
import 'ui/theme.dart';
import 'ui/users_screen.dart';

class _Dest {
  const _Dest(
    this.path,
    this.icon,
    this.selectedIcon,
    this.label,
    this.builder, {
    this.perTenant = false,
    this.superOnly = false,
  });

  final String path;
  final IconData icon;
  final IconData selectedIcon;
  final String Function(BuildContext) label;
  final Widget Function() builder;
  final bool perTenant;

  /// Shown only to the super-admin (ST-03): a tenant admin cannot manage Edges.
  final bool superOnly;
}

final _dests = <_Dest>[
  _Dest('/overview', Icons.dashboard_outlined, Icons.dashboard, (c) => c.l10n.navOverview, OverviewScreen.new),
  _Dest(
    '/onboarding',
    Icons.flag_outlined,
    Icons.flag,
    (c) => c.l10n.navOnboarding,
    OnboardingScreen.new,
    perTenant: true,
  ),
  _Dest('/tenants', Icons.domain_outlined, Icons.domain, (c) => c.l10n.navTenants, TenantsScreen.new),
  _Dest('/users', Icons.people_outline, Icons.people, (c) => c.l10n.navUsers, UsersScreen.new, perTenant: true),
  _Dest('/policy', Icons.rule_outlined, Icons.rule, (c) => c.l10n.navPolicy, PolicyScreen.new, perTenant: true),
  _Dest(
    '/policy-test',
    Icons.fact_check_outlined,
    Icons.fact_check,
    (c) => c.l10n.navPolicyTest,
    PolicyTestScreen.new,
    perTenant: true,
  ),
  _Dest('/dns', Icons.dns_outlined, Icons.dns, (c) => c.l10n.navDns, DnsScreen.new, perTenant: true),
  _Dest(
    '/private-apps',
    Icons.lock_outline,
    Icons.lock,
    (c) => c.l10n.navPrivateApps,
    PrivateAppsScreen.new,
    perTenant: true,
  ),
  _Dest('/saas', Icons.apps_outlined, Icons.apps, (c) => c.l10n.navSaas, SaasScreen.new, perTenant: true),
  _Dest(
    '/categories',
    Icons.category_outlined,
    Icons.category,
    (c) => c.l10n.navCategories,
    CategoriesScreen.new,
    perTenant: true,
  ),
  _Dest(
    '/web',
    Icons.travel_explore_outlined,
    Icons.travel_explore,
    (c) => c.l10n.navWeb,
    WebScreen.new,
    perTenant: true,
  ),
  _Dest(
    '/connectors',
    Icons.hub_outlined,
    Icons.hub,
    (c) => c.l10n.navConnectors,
    ConnectorsScreen.new,
    perTenant: true,
  ),
  _Dest(
    '/devices',
    Icons.phone_android_outlined,
    Icons.phone_android,
    (c) => c.l10n.navDevices,
    DevicesScreen.new,
    perTenant: true,
  ),
  _Dest(
    '/admin-tokens',
    Icons.key_outlined,
    Icons.key,
    (c) => c.l10n.navAdminTokens,
    AdminTokensScreen.new,
    perTenant: true,
  ),
  _Dest('/sso', Icons.badge_outlined, Icons.badge, (c) => c.l10n.navSso, SsoScreen.new, perTenant: true),
  _Dest('/audit', Icons.history_outlined, Icons.history, (c) => c.l10n.navAudit, AuditScreen.new, perTenant: true),
  _Dest(
    '/edges',
    Icons.cell_tower_outlined,
    Icons.cell_tower,
    (c) => c.l10n.navEdges,
    EdgesScreen.new,
    superOnly: true,
  ),
  _Dest(
    '/status',
    Icons.monitor_heart_outlined,
    Icons.monitor_heart,
    (c) => c.l10n.navStatus,
    StatusScreen.new,
    superOnly: true,
  ),
  _Dest(
    '/activity',
    Icons.list_alt_outlined,
    Icons.list_alt,
    (c) => c.l10n.navActivity,
    ActivityScreen.new,
    perTenant: true,
  ),
  _Dest(
    '/security-events',
    Icons.shield_outlined,
    Icons.shield,
    (c) => c.l10n.navSecurityEvents,
    SecurityEventsScreen.new,
    perTenant: true,
  ),
  _Dest('/settings', Icons.settings_outlined, Icons.settings, (c) => c.l10n.navSettings, SettingsScreen.new),
];

/// Bridges the session token to go_router's refreshListenable.
class _SignedInListenable extends ChangeNotifier {
  bool signedIn = false;
  void set(bool v) {
    if (v != signedIn) {
      signedIn = v;
      notifyListeners();
    }
  }
}

final routerProvider = Provider<GoRouter>((ref) {
  final auth = _SignedInListenable();
  ref.listen(sessionProvider, (_, t) => auth.set(t != null), fireImmediately: true);
  final router = GoRouter(
    initialLocation: '/overview',
    refreshListenable: auth,
    redirect: (context, state) {
      final loc = state.matchedLocation;
      if (loc == '/oidc-signin') return null;
      final atLogin = loc == '/login';
      if (!auth.signedIn) return atLogin ? null : '/login';
      return atLogin ? '/overview' : null;
    },
    routes: [
      GoRoute(path: '/login', builder: (_, _) => const LoginScreen()),
      GoRoute(
        path: '/oidc-signin',
        builder: (context, state) => OidcSignInScreen(token: state.uri.queryParameters['token']),
      ),
      ShellRoute(
        builder: (context, state, child) => AdminShell(location: state.matchedLocation, child: child),
        routes: [
          for (final d in _dests)
            GoRoute(
              path: d.path,
              pageBuilder: (_, _) => NoTransitionPage(child: d.builder()),
            ),
          GoRoute(
            path: '/oidc',
            pageBuilder: (_, _) => const NoTransitionPage(child: SsoScreen()),
          ),
        ],
      ),
    ],
  );
  ref.onDispose(() {
    router.dispose();
    auth.dispose();
  });
  return router;
});

class AdminApp extends ConsumerWidget {
  const AdminApp({super.key});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    return MaterialApp.router(
      onGenerateTitle: (c) => c.l10n.appTitle,
      theme: buildTheme(Brightness.light),
      darkTheme: buildTheme(Brightness.dark),
      routerConfig: ref.watch(routerProvider),
      localizationsDelegates: const [AppLocalizations.delegate, ...GlobalMaterialLocalizations.delegates],
      supportedLocales: AppLocalizations.supportedLocales,
      debugShowCheckedModeBanner: false,
    );
  }
}

/// Responsive shell: a NavigationRail on wide screens, a Drawer on narrow ones.
class AdminShell extends ConsumerWidget {
  const AdminShell({super.key, required this.location, required this.child});

  final String location;
  final Widget child;

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final l = context.l10n;
    final width = MediaQuery.sizeOf(context).width;
    final wide = width >= 900;
    final isSuper = ref.watch(isSuperProvider);
    final dests = [
      for (final d in _dests)
        if (!d.superOnly || isSuper) d,
    ];
    final found = dests.indexWhere((d) => location.startsWith(d.path));
    final index = found < 0 ? 0 : found;
    final dest = dests[index];
    final appBar = AppBar(
      title: Text(l.appTitle),
      actions: [
        if (dest.perTenant || dest.path == '/overview') const _TenantPicker(),
        IconButton(
          key: const Key('logout'),
          tooltip: l.actionLogout,
          icon: const Icon(Icons.logout),
          onPressed: () => ref.read(sessionProvider.notifier).logout(),
        ),
        const SizedBox(width: 8),
      ],
    );
    void go(int i) => context.go(dests[i].path);
    if (!wide) {
      return Scaffold(
        appBar: appBar,
        drawer: NavigationDrawer(
          selectedIndex: index,
          onDestinationSelected: (i) {
            Navigator.pop(context);
            go(i);
          },
          children: [
            Padding(
              padding: const EdgeInsets.fromLTRB(28, 16, 16, 10),
              child: Text(l.appTitle, style: Theme.of(context).textTheme.titleSmall),
            ),
            for (final d in dests)
              NavigationDrawerDestination(
                icon: Icon(d.icon),
                selectedIcon: Icon(d.selectedIcon),
                label: Text(d.label(context)),
              ),
          ],
        ),
        body: child,
      );
    }
    return Scaffold(
      appBar: appBar,
      body: Row(
        children: [
          SingleChildScrollView(
            child: ConstrainedBox(
              constraints: BoxConstraints(minHeight: MediaQuery.sizeOf(context).height - kToolbarHeight),
              child: IntrinsicHeight(
                child: NavigationRail(
                  extended: width >= 1280,
                  labelType: width >= 1280 ? NavigationRailLabelType.none : NavigationRailLabelType.all,
                  selectedIndex: index,
                  onDestinationSelected: go,
                  destinations: [
                    for (final d in dests)
                      NavigationRailDestination(
                        icon: Icon(d.icon),
                        selectedIcon: Icon(d.selectedIcon),
                        label: Text(d.label(context)),
                      ),
                  ],
                ),
              ),
            ),
          ),
          const VerticalDivider(width: 1),
          Expanded(child: child),
        ],
      ),
    );
  }
}

class _TenantPicker extends ConsumerWidget {
  const _TenantPicker();

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final tenants = ref.watch(tenantsProvider).value ?? const [];
    final current = ref.watch(currentTenantProvider);
    if (tenants.isEmpty) return const SizedBox.shrink();
    return Padding(
      padding: const EdgeInsets.symmetric(horizontal: 8),
      child: DropdownButtonHideUnderline(
        child: DropdownButton<String>(
          key: const Key('tenant_picker'),
          value: tenants.any((t) => t.id == current) ? current : null,
          hint: Text(context.l10n.tenantPicker),
          icon: const Icon(Icons.arrow_drop_down),
          items: [
            for (final t in tenants)
              DropdownMenuItem(value: t.id, child: Text(t.name.isEmpty ? t.id : '${t.name} (${t.id})')),
          ],
          onChanged: (v) => ref.read(selectedTenantProvider.notifier).select(v),
        ),
      ),
    );
  }
}
