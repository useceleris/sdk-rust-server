use crate::validation::channel_reference_rule;

#[test]
fn channel_references_permit_only_their_character_class() {
    assert_eq!(channel_reference_rule("azAZ09-_"), None);

    for character in ['`', '{', '@', '[', '/', ':', ' ', '.', 'é', '\u{0}'] {
        let reference = format!("a{character}b");

        assert!(
            channel_reference_rule(&reference).is_some(),
            "{character:?} accepted"
        );
    }
} // end fn channel_references_permit_only_their_character_class

#[test]
fn channel_references_measure_their_length_in_bytes() {
    assert_eq!(channel_reference_rule(&"x".repeat(255)), None);
    assert_eq!(
        channel_reference_rule(&"x".repeat(256)),
        Some("Must be at most 255 characters")
    );
} // end fn channel_references_measure_their_length_in_bytes
