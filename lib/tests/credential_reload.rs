use std::io::Write;
use tempfile::NamedTempFile;

#[allow(dead_code)]
mod common;

#[test]
fn test_credential_file_reload_simulation() {
    let mut credentials_file = NamedTempFile::new().unwrap();
    writeln!(
        credentials_file,
        r#"
[[client]]
username = "initial_user"
password = "initial_pass"
"#
    )
    .unwrap();
    credentials_file.flush().unwrap();

    let initial_clients =
        trusttunnel::settings::load_clients_from_file(credentials_file.path().to_str().unwrap())
            .unwrap();

    assert_eq!(initial_clients.len(), 1);
    assert_eq!(initial_clients[0].username, "initial_user");
    assert_eq!(initial_clients[0].password, "initial_pass");

    let file_path = credentials_file.path().to_str().unwrap().to_string();
    drop(credentials_file);

    let mut new_file = std::fs::File::create(&file_path).unwrap();
    writeln!(
        new_file,
        r#"
[[client]]
username = "new_user"
password = "new_pass"

[[client]]
username = "another_user"
password = "another_pass"
max_http2_conns = 10
max_http3_conns = 20
"#
    )
    .unwrap();
    new_file.flush().unwrap();
    drop(new_file);

    let new_clients = trusttunnel::settings::load_clients_from_file(&file_path).unwrap();

    assert_eq!(new_clients.len(), 2);
    assert_eq!(new_clients[0].username, "new_user");
    assert_eq!(new_clients[0].password, "new_pass");
    assert_eq!(new_clients[0].max_http2_conns, None);
    assert_eq!(new_clients[1].username, "another_user");
    assert_eq!(new_clients[1].password, "another_pass");
    assert_eq!(new_clients[1].max_http2_conns, Some(10));
    assert_eq!(new_clients[1].max_http3_conns, Some(20));
}
