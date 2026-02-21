import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:webview_flutter/webview_flutter.dart';

import '../config.dart';
import '../widgets/loading_overlay.dart';

class WebAppScreen extends StatefulWidget {
  const WebAppScreen({super.key});

  @override
  State<WebAppScreen> createState() => _WebAppScreenState();
}

class _WebAppScreenState extends State<WebAppScreen> {
  late final WebViewController _controller;
  bool _isLoading = true;
  double _progress = 0;
  bool _pageLoaded = false;
  String? _apnsToken;
  bool _hasRequestedPermission = false;
  String? _lastUrl;

  @override
  void initState() {
    super.initState();

    _controller = WebViewController()
      ..setJavaScriptMode(JavaScriptMode.unrestricted)
      ..setBackgroundColor(Colors.white)
      ..setNavigationDelegate(
        NavigationDelegate(
          onPageStarted: (_) {
            setState(() {
              _isLoading = true;
              _progress = 0;
              _pageLoaded = false;
            });
          },
          onProgress: (progress) {
            setState(() {
              _progress = progress / 100.0;
            });
          },
          onPageFinished: (url) {
            setState(() {
              _isLoading = false;
              _progress = 1;
              _pageLoaded = true;
            });
            _lastUrl = url;
            _maybeRequestPermission();
            _sendTokenToWebView();
          },
          onWebResourceError: (error) {
            setState(() {
              _isLoading = false;
            });
          },
        ),
      )
      ..loadRequest(Uri.parse(AppConfig.baseUrl));
  }

  Future<void> _initApns() async {
    const channel = MethodChannel('apns');
    try {
      final token = await channel.invokeMethod<String>('requestToken');
      if (token != null && token.isNotEmpty) {
        _apnsToken = token;
        _sendTokenToWebView();
      }
    } catch (_) {
      // 권한 거부 등은 무시 (앱 사용은 가능)
    }
  }

  void _maybeRequestPermission() {
    if (_hasRequestedPermission) return;
    final url = _lastUrl ?? '';
    final shouldPrompt = url.contains('/dashboard') || url.contains('/setup') || url.contains('/history') || url.contains('/settings');
    if (!shouldPrompt) return;
    _hasRequestedPermission = true;
    _initApns();
  }

  Future<void> _sendTokenToWebView() async {
    if (!_pageLoaded || _apnsToken == null) return;
    final url = _lastUrl ?? '';
    final canSend = url.contains('/dashboard') || url.contains('/setup') || url.contains('/history') || url.contains('/settings');
    if (!canSend) return;
    final token = _apnsToken!;
    final js = '''
      (function() {
        try {
          if (window.__apnsTokenSent) return;
          fetch('/api/push/register', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            credentials: 'include',
            body: JSON.stringify({ token: '$token' })
          }).then(function(res) {
            if (res && res.ok) {
              window.__apnsTokenSent = true;
            }
          });
        } catch (e) {}
      })();
    ''';
    await _controller.runJavaScript(js);
  }

  Future<bool> _onWillPop() async {
    final canGoBack = await _controller.canGoBack();
    if (canGoBack) {
      await _controller.goBack();
      return false;
    }
    return true;
  }

  @override
  Widget build(BuildContext context) {
    return WillPopScope(
      onWillPop: _onWillPop,
      child: Scaffold(
        body: SafeArea(
          child: Stack(
            children: [
              WebViewWidget(controller: _controller),
              if (_isLoading)
                LoadingOverlay(progress: _progress),
            ],
          ),
        ),
      ),
    );
  }
}
