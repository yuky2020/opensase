import 'package:material_ui/material_ui.dart';

@immutable
class VerdictColors extends ThemeExtension<VerdictColors> {
  const VerdictColors({required this.allow, required this.block, required this.ask, required this.quantumSafe});

  final Color allow;
  final Color block;
  final Color ask;
  final Color quantumSafe;

  static const light = VerdictColors(
    allow: Color(0xFF1B6D2A),
    block: Color(0xFFBA1A1A),
    ask: Color(0xFF8C5300),
    quantumSafe: Color(0xFF6750A4),
  );

  static const dark = VerdictColors(
    allow: Color(0xFF79DC7F),
    block: Color(0xFFFFB4AB),
    ask: Color(0xFFFFB85C),
    quantumSafe: Color(0xFFCFBCFF),
  );

  @override
  VerdictColors copyWith({Color? allow, Color? block, Color? ask, Color? quantumSafe}) {
    return VerdictColors(
      allow: allow ?? this.allow,
      block: block ?? this.block,
      ask: ask ?? this.ask,
      quantumSafe: quantumSafe ?? this.quantumSafe,
    );
  }

  @override
  VerdictColors lerp(ThemeExtension<VerdictColors>? other, double t) {
    if (other is! VerdictColors) {
      return this;
    }
    return VerdictColors(
      allow: Color.lerp(allow, other.allow, t) ?? allow,
      block: Color.lerp(block, other.block, t) ?? block,
      ask: Color.lerp(ask, other.ask, t) ?? ask,
      quantumSafe: Color.lerp(quantumSafe, other.quantumSafe, t) ?? quantumSafe,
    );
  }
}

const ColorScheme lightScheme = ColorScheme(
  brightness: Brightness.light,
  primary: Color(0xFF00696B),
  onPrimary: Color(0xFFFFFFFF),
  primaryContainer: Color(0xFF6FF6F8),
  onPrimaryContainer: Color(0xFF002021),
  secondary: Color(0xFF4A6267),
  onSecondary: Color(0xFFFFFFFF),
  secondaryContainer: Color(0xFFCCE8ED),
  onSecondaryContainer: Color(0xFF051F23),
  tertiary: Color(0xFF795900),
  onTertiary: Color(0xFFFFFFFF),
  tertiaryContainer: Color(0xFFFFDEA3),
  onTertiaryContainer: Color(0xFF261900),
  error: Color(0xFFBA1A1A),
  onError: Color(0xFFFFFFFF),
  errorContainer: Color(0xFFFFDAD6),
  onErrorContainer: Color(0xFF410002),
  surface: Color(0xFFFAFDFB),
  onSurface: Color(0xFF191C1C),
  surfaceContainerLowest: Color(0xFFFFFFFF),
  surfaceContainerLow: Color(0xFFF4F7F6),
  surfaceContainer: Color(0xFFEEF1F0),
  surfaceContainerHigh: Color(0xFFE8ECEB),
  surfaceContainerHighest: Color(0xFFDAE5E4),
  onSurfaceVariant: Color(0xFF3F4948),
  outline: Color(0xFF6F7979),
  outlineVariant: Color(0xFFBEC9C8),
);

const ColorScheme darkScheme = ColorScheme(
  brightness: Brightness.dark,
  primary: Color(0xFF4CD9DB),
  onPrimary: Color(0xFF003738),
  primaryContainer: Color(0xFF004F51),
  onPrimaryContainer: Color(0xFF6FF6F8),
  secondary: Color(0xFFB0CCD1),
  onSecondary: Color(0xFF1C3438),
  secondaryContainer: Color(0xFF334B4F),
  onSecondaryContainer: Color(0xFFCCE8ED),
  tertiary: Color(0xFFF4BF48),
  onTertiary: Color(0xFF402D00),
  tertiaryContainer: Color(0xFF5C4200),
  onTertiaryContainer: Color(0xFFFFDEA3),
  error: Color(0xFFFFB4AB),
  onError: Color(0xFF690005),
  errorContainer: Color(0xFF93000A),
  onErrorContainer: Color(0xFFFFDAD6),
  surface: Color(0xFF191C1C),
  onSurface: Color(0xFFE0E3E2),
  surfaceContainerLowest: Color(0xFF0E1212),
  surfaceContainerLow: Color(0xFF1F2424),
  surfaceContainer: Color(0xFF232828),
  surfaceContainerHigh: Color(0xFF2D3232),
  surfaceContainerHighest: Color(0xFF3F4948),
  onSurfaceVariant: Color(0xFFBEC9C8),
  outline: Color(0xFF899392),
  outlineVariant: Color(0xFF3F4948),
);

ThemeData buildTheme(Brightness b) {
  final isDark = b == Brightness.dark;
  final colorScheme = isDark ? darkScheme : lightScheme;
  final verdictColors = isDark ? VerdictColors.dark : VerdictColors.light;
  final typography = Typography.material2021(platform: TargetPlatform.android);
  final baseTextTheme = (isDark ? typography.white : typography.black).apply();
  final textTheme = baseTextTheme.copyWith(
    headlineMedium: baseTextTheme.headlineMedium?.copyWith(fontWeight: FontWeight.w600),
    titleLarge: baseTextTheme.titleLarge?.copyWith(fontWeight: FontWeight.w600),
    displaySmall: baseTextTheme.displaySmall?.copyWith(fontWeight: FontWeight.w600),
  );

  return ThemeData(
    useMaterial3: true,
    colorScheme: colorScheme,
    extensions: <ThemeExtension<dynamic>>[verdictColors],
    cardTheme: CardThemeData(
      color: colorScheme.surfaceContainer,

      elevation: 0,
      margin: EdgeInsets.zero,
      shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(16)),
    ),
    appBarTheme: const AppBarTheme(centerTitle: false),
    textTheme: textTheme,
  );
}

extension VerdictColorsX on BuildContext {
  VerdictColors get verdicts => Theme.of(this).extension<VerdictColors>() ?? VerdictColors.light;
}
