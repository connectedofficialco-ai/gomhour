import 'dart:async';

import 'package:flutter/material.dart';

class LoadingOverlay extends StatefulWidget {
  const LoadingOverlay({super.key, required this.progress});

  final double progress;

  @override
  State<LoadingOverlay> createState() => _LoadingOverlayState();
}

class _LoadingOverlayState extends State<LoadingOverlay> {
  int _currentBearIndex = 0;
  Timer? _switchTimer;

  @override
  void initState() {
    super.initState();
    _switchTimer = Timer.periodic(const Duration(milliseconds: 800), (_) {
      if (mounted) {
        setState(() {
          _currentBearIndex = (_currentBearIndex + 1) % 2;
        });
      }
    });
  }

  @override
  void dispose() {
    _switchTimer?.cancel();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final bearAsset = _currentBearIndex == 0
        ? 'assets/loading_bear_1.png'
        : 'assets/loading_bear_2.png';

    return Container(
      color: const Color(0xFFFFF8E7),
      alignment: Alignment.center,
      child: Column(
        mainAxisSize: MainAxisSize.min,
        children: [
          AnimatedSwitcher(
            duration: const Duration(milliseconds: 300),
            child: Image.asset(
              bearAsset,
              key: ValueKey<int>(_currentBearIndex),
              width: 80,
              height: 80,
              fit: BoxFit.contain,
            ),
          ),
          const SizedBox(height: 16),
          Text(
            '곰아워',
            style: const TextStyle(
              fontSize: 20,
              fontWeight: FontWeight.bold,
              color: Color(0xFFB45309),
            ),
          ),
          const SizedBox(height: 24),
          SizedBox(
            width: 32,
            height: 32,
            child: CircularProgressIndicator(
              strokeWidth: 2.5,
              valueColor: AlwaysStoppedAnimation<Color>(
                Color(0xFFFFA500).withOpacity(0.8),
              ),
            ),
          ),
        ],
      ),
    );
  }
}
