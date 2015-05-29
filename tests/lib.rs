extern crate otpauth;
extern crate time;

#[test]
fn test_hotp() {
    let auth = otpauth::HOTP::new("python");
    let code = auth.generate(4);
    assert_eq!(true, auth.verify(code, 0, 100));
    assert_eq!(false, auth.verify(123456, 0, 100));
}

#[test]
fn test_totp() {
    let auth = otpauth::TOTP::new("python");
    let timestamp1 = time::now().to_timespec().sec as usize;
    let code = auth.generate(30usize, timestamp1);
    let timestamp2 = time::now().to_timespec().sec as usize;
    assert_eq!(true, auth.verify(code, 30usize, timestamp2));
    assert_eq!(false, auth.verify(123456, 30usize, timestamp2));
}

#[test]
fn test_to_uri_hotp() {
    let auth = otpauth::HOTP::new("python");
    let expect = "otpauth://hotp/python?secret=OB4XI2DPNY&issuer=python&counter=4";
    assert_eq!(expect, auth.to_uri("python", "python", 4));
}

#[test]
fn test_to_uri_totp() {
    let auth = otpauth::TOTP::new("python");
    let expect = "otpauth://totp/python?secret=OB4XI2DPNY&issuer=python";
    assert_eq!(expect, auth.to_uri("python", "python"));
}
