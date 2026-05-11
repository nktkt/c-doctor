// Layout-preserving preprocessor: replace comment bodies and string/char
// literal contents with spaces, keeping newlines and total length so reported
// line/col still match the original source.

pub fn preprocess(src: &str) -> String {
    let bytes = src.as_bytes();
    let n = bytes.len();
    let mut out = Vec::with_capacity(n);
    let mut i = 0usize;

    while i < n {
        let c = bytes[i];
        let next = if i + 1 < n { bytes[i + 1] } else { 0 };

        // line comment
        if c == b'/' && next == b'/' {
            out.push(b' ');
            out.push(b' ');
            i += 2;
            while i < n && bytes[i] != b'\n' {
                out.push(b' ');
                i += 1;
            }
            continue;
        }
        // block comment
        if c == b'/' && next == b'*' {
            out.push(b' ');
            out.push(b' ');
            i += 2;
            while i < n {
                if bytes[i] == b'*' && i + 1 < n && bytes[i + 1] == b'/' {
                    out.push(b' ');
                    out.push(b' ');
                    i += 2;
                    break;
                }
                out.push(if bytes[i] == b'\n' { b'\n' } else { b' ' });
                i += 1;
            }
            continue;
        }
        // string literal
        if c == b'"' {
            out.push(b'"');
            i += 1;
            while i < n && bytes[i] != b'"' {
                if bytes[i] == b'\\' && i + 1 < n {
                    out.push(b' ');
                    out.push(if bytes[i + 1] == b'\n' { b'\n' } else { b' ' });
                    i += 2;
                    continue;
                }
                out.push(if bytes[i] == b'\n' { b'\n' } else { b' ' });
                i += 1;
            }
            if i < n {
                out.push(b'"');
                i += 1;
            }
            continue;
        }
        // char literal
        if c == b'\'' {
            out.push(b'\'');
            i += 1;
            while i < n && bytes[i] != b'\'' {
                if bytes[i] == b'\\' && i + 1 < n {
                    out.push(b' ');
                    out.push(b' ');
                    i += 2;
                    continue;
                }
                out.push(b' ');
                i += 1;
            }
            if i < n {
                out.push(b'\'');
                i += 1;
            }
            continue;
        }
        out.push(c);
        i += 1;
    }

    // Safe: we only ever pushed ASCII spaces, newlines, quotes, or bytes that
    // were already part of valid UTF-8 input at identical positions.
    String::from_utf8(out).expect("preprocess preserves UTF-8")
}
