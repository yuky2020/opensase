import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:go_router/go_router.dart';
import 'package:material_ui/material_ui.dart';

import '../data/session.dart';

class OidcSignInScreen extends ConsumerStatefulWidget {
  const OidcSignInScreen({super.key, this.token});

  final String? token;

  @override
  ConsumerState<OidcSignInScreen> createState() => _OidcSignInScreenState();
}

class _OidcSignInScreenState extends ConsumerState<OidcSignInScreen> {
  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addPostFrameCallback((_) => _process());
  }

  Future<void> _process() async {
    final token = widget.token?.trim();
    if (token == null || token.isEmpty) {
      if (mounted) context.go('/login');
      return;
    }
    try {
      await ref.read(sessionProvider.notifier).login(token, rememberForTab: true);
      if (mounted) {
        context.replace('/overview');
      }
    } catch (_) {
      if (mounted) context.go('/login');
    }
  }

  @override
  Widget build(BuildContext context) {
    return const Scaffold(body: Center(child: CircularProgressIndicator()));
  }
}
