// Clean: the user-controlled value is reduced to its final path component with
// Path::file_name() before being read, stripping any `../` traversal, so this
// is safe. A correct scanner emits nothing; a TAINT-004 finding here is a false
// positive.
use std::env;
use std::fs;
use std::path::Path;

fn serve_file() -> Vec<u8> {
    let user_path = env::var("FILE").unwrap_or_default();
    // file_name() drops all directory components — ../ can no longer escape.
    let name = Path::new(&user_path).file_name().unwrap_or_default();
    let safe = Path::new("/srv/static").join(name);
    fs::read(safe).unwrap_or_default()
}
