import 'package:code_buster/src/cli/hotspots_command.dart';
import 'package:code_buster/src/internal.dart';
import 'package:test/test.dart';

void main() {
  test('renders stable plain text and scan-friendly terminal colors', () {
    const Hotspot hotspot = Hotspot(
      path: 'lib/transfer.dart',
      commits: 3,
      added: 10,
      deleted: 2,
    );

    final String plain = renderHotspotsText(<Hotspot>[hotspot], color: false);
    final String colored = renderHotspotsText(<Hotspot>[hotspot], color: true);

    expect(
      plain,
      'Code Buster hotspots: 1\n'
      'lib/transfer.dart — risk 28.6, churn 12, commits 3 (+10/-2)\n',
    );
    expect(colored, contains('\u001b[1;36mCode Buster hotspots\u001b[0m'));
    expect(colored, contains('\u001b[36mlib/transfer.dart\u001b[0m'));
    expect(colored, contains('\u001b[33m28.6\u001b[0m'));
    expect(colored, contains('\u001b[32m+10\u001b[0m'));
    expect(colored, contains('\u001b[31m-2\u001b[0m'));
    expect(colored.replaceAll(RegExp(r'\x1B\[[0-9;]*m'), ''), plain);
  });
}
