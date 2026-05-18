import 'dart:async';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:url_launcher/url_launcher.dart';
import 'package:webview_flutter/webview_flutter.dart';
import 'package:webview_flutter_android/webview_flutter_android.dart';

import '../config.dart';

class WebAppScreen extends StatefulWidget {
  const WebAppScreen({super.key});

  @override
  State<WebAppScreen> createState() => _WebAppScreenState();
}

class _WebAppScreenState extends State<WebAppScreen> {
  late final WebViewController _controller;
  bool _pageLoaded = false;
  String? _apnsToken;
  bool _hasRequestedPermission = false;
  String? _lastUrl;
  bool _recoveringFromCrash = false;
  int _crashRecoverAttempts = 0;
  DateTime? _lastCrashAt;

  @override
  void initState() {
    super.initState();

    _controller = WebViewController()
      ..setJavaScriptMode(JavaScriptMode.unrestricted)
      ..setBackgroundColor(const Color(0xFFFFF8E7))
      ..setNavigationDelegate(
        NavigationDelegate(
          onNavigationRequest: (NavigationRequest request) {
            final url = request.url;
            if (url.isEmpty) return NavigationDecision.navigate;
            // gom-hr.com 도메인은 항상 앱 내 WebView에서 처리 (콜라주, 대시보드 등)
            if (url.contains('gom-hr.com')) {
              return NavigationDecision.navigate;
            }
            final uri = Uri.tryParse(url);
            if (uri == null) return NavigationDecision.navigate;
            // 상대 경로 또는 같은 오리진
            if (uri.host.isEmpty || uri.host == 'gom-hr.com' || uri.host == 'www.gom-hr.com') {
              return NavigationDecision.navigate;
            }
            // tel:, mailto: 등은 외부 앱
            if (uri.scheme == 'tel' || uri.scheme == 'mailto') {
              launchUrl(uri, mode: LaunchMode.externalApplication);
              return NavigationDecision.prevent;
            }
            // 그 외 외부 도메인도 WebView에서 먼저 시도 (OAuth 콜백 등)
            return NavigationDecision.navigate;
          },
          onPageStarted: (_) {
            setState(() => _pageLoaded = false);
          },
          onPageFinished: (url) {
            setState(() => _pageLoaded = true);
            _lastUrl = url;
            _recoveringFromCrash = false;
            _crashRecoverAttempts = 0;
            _injectInAppNavigationGuards();
            _maybeRequestPermission();
            _sendTokenToWebView();
          },
          onWebResourceError: (error) {
            final desc = (error.description).toLowerCase();
            // "window terminated unexpectedly (code: 5)" 류의 웹 컨텐츠 프로세스 종료 복구
            if (desc.contains('terminated') || desc.contains('crashed') || desc.contains('code: 5')) {
              _recoverFromWebProcessCrash(error.description);
            }
          },
        ),
      )
      ..loadRequest(
        Uri.parse(AppConfig.baseUrl),
        headers: const {'X-Gomhour-App': '1'},
      );

    // Android: 카카오/애플 OAuth는 크로스 사이트 리다이렉트라 서드파티 쿠키 허용이 없으면 세션이 안 잡히는 경우가 있음
    WidgetsBinding.instance.addPostFrameCallback((_) {
      _enableAndroidThirdPartyCookies();
    });
  }

  Future<void> _injectInAppNavigationGuards() async {
    const js = '''
      (function() {
        try {
          if (window.__gomawoInAppNavGuardInstalled) return;
          window.__gomawoInAppNavGuardInstalled = true;

          var normalizeUrl = function(raw) {
            try {
              return new URL(raw, window.location.href).toString();
            } catch (_) {
              return raw || '';
            }
          };

          // target=_blank / window.open 요청을 모두 현재 WebView 내 이동으로 강제
          window.open = function(url) {
            var nextUrl = normalizeUrl(url);
            if (!nextUrl) return null;
            window.location.href = nextUrl;
            return null;
          };

          document.addEventListener('click', function(e) {
            var anchor = e.target && e.target.closest
              ? e.target.closest('a[target="_blank"], a[rel~="noopener"], a[rel~="noreferrer"]')
              : null;
            if (!anchor) return;

            var href = anchor.getAttribute('href');
            if (!href || href.indexOf('javascript:') === 0) return;

            e.preventDefault();
            e.stopPropagation();
            window.location.href = normalizeUrl(href);
          }, true);
        } catch (_) {}
      })();
    ''';
    await _controller.runJavaScript(js);
  }

  Future<void> _enableAndroidThirdPartyCookies() async {
    final platform = _controller.platform;
    if (platform is! AndroidWebViewController) return;
    final cookieManager = AndroidWebViewCookieManager(
      AndroidWebViewCookieManagerCreationParams.fromPlatformWebViewCookieManagerCreationParams(
        const PlatformWebViewCookieManagerCreationParams(),
      ),
    );
    await cookieManager.setAcceptThirdPartyCookies(platform, true);
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
    final shouldPrompt = url.contains('/dashboard') || url.contains('/setup') || url.contains('/history') || url.contains('/mypage') || url.contains('/settings') || url.contains('/collage');
    if (!shouldPrompt) return;
    _hasRequestedPermission = true;
    _initApns();
  }

  Future<void> _sendTokenToWebView() async {
    if (!_pageLoaded || _apnsToken == null) return;
    final url = _lastUrl ?? '';
    final canSend = url.contains('/dashboard') || url.contains('/setup') || url.contains('/history') || url.contains('/mypage') || url.contains('/settings') || url.contains('/collage');
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

  Future<void> _recoverFromWebProcessCrash(String reason) async {
    if (_recoveringFromCrash || !mounted) return;

    final now = DateTime.now();
    if (_lastCrashAt != null && now.difference(_lastCrashAt!).inSeconds < 3) {
      _crashRecoverAttempts += 1;
    } else {
      _crashRecoverAttempts = 1;
    }
    _lastCrashAt = now;
    if (_crashRecoverAttempts > 3) return;

    _recoveringFromCrash = true;
    setState(() => _pageLoaded = false);

    // 즉시 재시도 시 동일 상태로 실패하는 경우가 있어 아주 짧게 지연 후 복구
    await Future<void>.delayed(const Duration(milliseconds: 400));
    final fallback = _lastUrl ?? AppConfig.baseUrl;

    try {
      await _controller.loadRequest(
        Uri.parse(fallback),
        headers: const {'X-Gomhour-App': '1'},
      );
    } catch (_) {
      await _controller.loadRequest(
        Uri.parse(AppConfig.baseUrl),
        headers: const {'X-Gomhour-App': '1'},
      );
    } finally {
      _recoveringFromCrash = false;
    }
  }

  @override
  Widget build(BuildContext context) {
    final media = MediaQuery.of(context);
    const topSafeColor = Color(0xFFFFEED7); // 본문 배경색
    const bottomSafeColor = Color(0xFFFFD8A3); // 탭바 배경색

    return PopScope(
      canPop: false,
      onPopInvokedWithResult: (didPop, _) async {
        if (didPop) return;
        final canGoBack = await _controller.canGoBack();
        if (canGoBack) {
          await _controller.goBack();
        } else {
          if (!context.mounted) return;
          Navigator.of(context).maybePop();
        }
      },
      child: AnnotatedRegion<SystemUiOverlayStyle>(
        value: const SystemUiOverlayStyle(
          statusBarColor: topSafeColor,
          statusBarIconBrightness: Brightness.dark,
          statusBarBrightness: Brightness.light,
          systemNavigationBarColor: bottomSafeColor,
          systemNavigationBarIconBrightness: Brightness.dark,
        ),
        child: Scaffold(
          backgroundColor: bottomSafeColor,
          body: Stack(
            children: [
              const Positioned.fill(
                child: ColoredBox(color: bottomSafeColor),
              ),
              Positioned(
                top: 0,
                left: 0,
                right: 0,
                height: media.padding.top,
                child: const ColoredBox(color: topSafeColor),
              ),
              Positioned.fill(
                top: media.padding.top,
                bottom: media.padding.bottom,
                child: WebViewWidget(controller: _controller),
              ),
              Positioned(
                bottom: 0,
                left: 0,
                right: 0,
                height: media.padding.bottom,
                child: const ColoredBox(color: bottomSafeColor),
              ),
            ],
          ),
        ),
      ),
    );
  }
}
