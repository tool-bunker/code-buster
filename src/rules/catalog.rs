#[derive(Clone, Copy, Debug)]
pub struct RuleDescriptor {
    pub id: &'static str,
    pub language: &'static str,
    pub group: &'static str,
    pub title: &'static str,
    pub mvvm: bool,
}

#[allow(dead_code)]
#[derive(Clone, Copy, Debug)]
pub struct RuleMetadata {
    pub id: &'static str,
    pub default_severity: &'static str,
    pub legacy_group: &'static str,
    pub title: &'static str,
    pub why: &'static str,
    pub suggestion: &'static str,
    pub version: u32,
    pub semantic_maturity: &'static str,
    pub security_kind: &'static str,
    pub taxonomy: &'static [&'static str],
    pub requirements: &'static [&'static str],
    pub packs: &'static [&'static str],
    pub languages: &'static [&'static str],
    pub frameworks: &'static [&'static str],
    pub language_versions: &'static [(&'static str, &'static str)],
    pub limitations: &'static [&'static str],
}

include!(concat!(env!("OUT_DIR"), "/rule_catalog.rs"));

pub fn metadata(id: &str) -> Option<&'static RuleMetadata> {
    RULE_METADATA
        .binary_search_by_key(&id, |metadata| metadata.id)
        .ok()
        .map(|index| &RULE_METADATA[index])
}

pub fn descriptor(id: &str) -> Option<&'static RuleDescriptor> {
    RULE_DESCRIPTORS
        .binary_search_by_key(&id, |descriptor| descriptor.id)
        .ok()
        .map(|index| &RULE_DESCRIPTORS[index])
}

#[cfg(test)]
mod tests {
    use super::{RULE_DESCRIPTORS, RULE_METADATA, descriptor, metadata};

    #[test]
    fn generated_catalog_is_complete_sorted_and_binary_searchable() {
        assert!(!RULE_METADATA.is_empty());
        assert_eq!(RULE_DESCRIPTORS.len(), RULE_METADATA.len());

        for pair in RULE_METADATA.windows(2) {
            assert!(pair[0].id < pair[1].id, "metadata is not sorted");
        }
        for (descriptor_entry, metadata_entry) in RULE_DESCRIPTORS.iter().zip(RULE_METADATA.iter())
        {
            assert_eq!(descriptor_entry.id, metadata_entry.id);
            assert_eq!(
                descriptor(descriptor_entry.id).map(|entry| entry.id),
                Some(descriptor_entry.id)
            );
            assert_eq!(
                metadata(metadata_entry.id).map(|entry| entry.id),
                Some(metadata_entry.id)
            );
        }
    }
}
