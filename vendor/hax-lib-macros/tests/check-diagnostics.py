#!/usr/bin/env python3
"""Check the built cfg(hax) proc macro using real rustc success/error diagnostics."""
from pathlib import Path
import subprocess
import sys
import tempfile

library = Path(sys.argv[1]).resolve(strict=True)
rustc = sys.argv[2]
cases = [
    ('fn main() { hax_lib_macros::fstar_expr!("()"); }', None),
    ('fn main() { hax_lib_macros::coq_expr!("()"); }', None),
    ('#[hax_lib_macros::fstar_verification_status(bad)] fn f() {}',
     'Expected `lax` or `panic_free`'),
    ('#[hax_lib_macros::lemma] fn f() {}', 'A lemma is expected to return'),
    ('fn f() { hax_lib_macros::int!(1u8); }', 'The literal suffix'),
    ('#[hax_lib_macros::fstar_before(wrong, "()")] fn f() {}',
     'Expected `impl`, `both` or `interface`'),
    ('#[hax_lib_macros::refinement_type(|x| true)] struct S { x: u8 }',
     'Expected a newtype'),
    ('#[hax_lib_macros::refinement_type(|x| true)] struct S(u8, u8);',
     'got 2 fields'),
    ('#[hax_lib_macros::refinement_type(|x| true)] struct S(pub u8);',
     'This field was expected to be private'),
    ('#[hax_lib_macros::refinement_type(wrong, |x| true)] struct S(u8);',
     "Expected 'no_debug_runtime_check'"),
    ('#[hax_lib_macros::refinement_type(no_debug_runtime_check; |x| true)] struct S(u8);',
     'Expected a comma'),
    ('#[hax_lib_macros::fstar_options(42)] fn f() {}', 'expected string literal'),
]
with tempfile.TemporaryDirectory(prefix='hax-diagnostics-') as output:
    for source, diagnostic in cases:
        result = subprocess.run(
            [rustc, '--edition=2021', '--crate-type=lib', '--emit=metadata',
             '--out-dir', output, '--extern', f'hax_lib_macros={library}', '-'],
            input=source, text=True, capture_output=True,
        )
        if diagnostic is None:
            assert result.returncode == 0, result.stderr
        else:
            assert result.returncode != 0, source
            assert diagnostic in result.stderr, result.stderr
            assert 'proc macro panicked' not in result.stderr, result.stderr
            assert '--> <anon>:' in result.stderr, result.stderr
print(f'{len(cases)} cfg(hax) expansion/diagnostic checks passed')
