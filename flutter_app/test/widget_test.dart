import 'package:flutter_test/flutter_test.dart';

import 'package:gomawo_app/main.dart';

void main() {
  testWidgets('App loads', (WidgetTester tester) async {
    await tester.pumpWidget(const GomawoApp());
    await tester.pumpAndSettle();
  });
}
