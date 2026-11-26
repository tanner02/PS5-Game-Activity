from pathlib import Path
import sys

root = Path(__file__).resolve().parent.parent
output = Path(sys.argv[1])
for name, source, variable in [
    ('ca_bundle.hpp', 'vendor/ca-bundle.pem', 'PBSD_CA_BUNDLE'),
    ('activity_page.hpp', 'web/activity.html', 'activity_page'),
    ('activity_script.hpp', 'web/activity.js', 'activity_script'),
    ('activity_qr.hpp', 'web/qrcodegen.js', 'activity_qr'),
]:
    data = (root / source).read_bytes()
    (output / name).write_text(f'#pragma once\ninline constexpr char {variable}[] = {{{",".join(str(b if b < 128 else b - 256) for b in data)},0}};\n')
