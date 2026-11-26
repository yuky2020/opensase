import 'package:web/web.dart' as web;

void openUrl(String url) {
  web.window.location.href = url;
}

void openUrlInNewTab(String url) {
  web.window.open(url, '_blank', 'noopener');
}
