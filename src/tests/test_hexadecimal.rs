use crate::signer::hexadecimal;

#[test]
fn writes_lowercase_hexadecimal_with_two_digits_per_byte() {
    assert_eq!(hexadecimal(&[]), "");
    assert_eq!(
        hexadecimal(&[0x00, 0x0f, 0xf0, 0xff, 0xab, 0x19]),
        "000ff0ffab19"
    );
} // end fn writes_lowercase_hexadecimal_with_two_digits_per_byte
