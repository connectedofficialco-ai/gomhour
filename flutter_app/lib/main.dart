import 'package:flutter/material.dart';

import 'screens/web_app_screen.dart';

void main() {
  WidgetsFlutterBinding.ensureInitialized();
  runApp(const GomawoApp());
}

class GomawoApp extends StatelessWidget {
  const GomawoApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: '곰아워',
      debugShowCheckedModeBanner: false,
      theme: ThemeData(
        colorScheme: ColorScheme.fromSeed(seedColor: const Color(0xFFFFC107)),
        useMaterial3: true,
      ),
      home: const WebAppScreen(),
    );
  }
}
