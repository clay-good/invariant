//! Compile-time embedded library of bio profiles.
//!
//! Step 18 expands the library beyond the original BSL-2 stub to cover
//! peptide, chemical, BSL-3, BSL-4, and export-controlled installations.

use crate::models::profile::BioProfile;

/// One built-in profile entry: short name + raw JSON source.
struct Builtin {
    name: &'static str,
    json: &'static str,
}

const BUILTIN_PROFILES: &[Builtin] = &[
    Builtin {
        name: "university_bsl2_dna",
        json: include_str!("../../../profiles/biosynthesis/university_bsl2_dna.json"),
    },
    Builtin {
        name: "industry_peptide",
        json: include_str!("../../../profiles/biosynthesis/industry_peptide.json"),
    },
    Builtin {
        name: "industry_chemical",
        json: include_str!("../../../profiles/biosynthesis/industry_chemical.json"),
    },
    Builtin {
        name: "university_bsl3_dna",
        json: include_str!("../../../profiles/biosynthesis/university_bsl3_dna.json"),
    },
    Builtin {
        name: "government_bsl4_restricted",
        json: include_str!("../../../profiles/biosynthesis/government_bsl4_restricted.json"),
    },
    Builtin {
        name: "export_controlled_chemical",
        json: include_str!("../../../profiles/biosynthesis/export_controlled_chemical.json"),
    },
];

/// Load a built-in profile by name. Returns `None` if no profile matches.
pub fn load_builtin(name: &str) -> Option<BioProfile> {
    BUILTIN_PROFILES
        .iter()
        .find(|b| b.name == name)
        .and_then(|b| serde_json::from_str(b.json).ok())
}

/// Names of every built-in profile, in registration order.
pub fn builtin_names() -> Vec<&'static str> {
    BUILTIN_PROFILES.iter().map(|b| b.name).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::error::Validate;

    #[test]
    fn builtin_university_bsl2_dna_loads_and_validates() {
        let profile = load_builtin("university_bsl2_dna").expect("profile loads");
        assert_eq!(profile.name, "university_bsl2_dna");
        profile.validate().expect("stub profile is valid");
    }

    #[test]
    fn unknown_profile_returns_none() {
        assert!(load_builtin("nope").is_none());
    }

    #[test]
    fn every_builtin_profile_loads_round_trips_and_validates() {
        for name in builtin_names() {
            let profile =
                load_builtin(name).unwrap_or_else(|| panic!("profile {name} failed to load"));
            assert_eq!(profile.name, name, "name field mismatch in {name}");
            profile
                .validate()
                .unwrap_or_else(|e| panic!("profile {name} validation failed: {e}"));
            // Round-trip through JSON.
            let json = serde_json::to_string(&profile).unwrap();
            let back: BioProfile = serde_json::from_str(&json).unwrap();
            assert_eq!(back, profile, "round-trip mismatch for {name}");
        }
    }

    #[test]
    fn builtin_library_has_six_profiles() {
        assert_eq!(builtin_names().len(), 6);
    }

    #[test]
    fn bsl4_profile_is_export_controlled() {
        let p = load_builtin("government_bsl4_restricted").unwrap();
        assert_eq!(p.bsl_level, 4);
        assert!(p.export_controlled);
    }

    #[test]
    fn export_controlled_chemical_flag_set() {
        let p = load_builtin("export_controlled_chemical").unwrap();
        assert!(p.export_controlled);
        assert!(p.allowed_substrates.iter().any(|s| s == "chemical"));
    }

    #[test]
    fn dna_profiles_carry_protein_kmer_params() {
        let bsl2 = load_builtin("university_bsl2_dna").unwrap();
        let bsl3 = load_builtin("university_bsl3_dna").unwrap();
        let bsl4 = load_builtin("government_bsl4_restricted").unwrap();
        // All DNA profiles declare protein k-mer parameters.
        assert!(bsl2.protein_kmer_k.is_some());
        assert!(bsl3.protein_kmer_k.is_some());
        assert!(bsl4.protein_kmer_k.is_some());
        // Higher BSL => stricter (lower) threshold.
        let t2 = bsl2.protein_kmer_threshold.unwrap();
        let t3 = bsl3.protein_kmer_threshold.unwrap();
        let t4 = bsl4.protein_kmer_threshold.unwrap();
        assert!(t3 < t2, "BSL3 threshold should be stricter than BSL2");
        assert!(t4 < t3, "BSL4 threshold should be stricter than BSL3");
    }

    #[test]
    fn dna_profiles_declare_codon_usage_organism() {
        for name in &["university_bsl2_dna", "university_bsl3_dna", "government_bsl4_restricted"] {
            let p = load_builtin(name).unwrap();
            assert!(
                p.codon_usage_organism.is_some(),
                "DNA profile {name} should declare codon_usage_organism"
            );
        }
    }

    // ---- GAP-N2: explicit max_authority_chain_depth in all built-in profiles ----

    #[test]
    fn bsl4_profile_has_chain_depth_at_most_3() {
        let p = load_builtin("government_bsl4_restricted").unwrap();
        assert!(
            p.max_authority_chain_depth <= 3,
            "BSL-4 profile must have max_authority_chain_depth ≤ 3, got {}",
            p.max_authority_chain_depth
        );
    }

    #[test]
    fn all_builtin_profiles_have_explicit_chain_depth_in_json() {
        for name in builtin_names() {
            // Round-trip through JSON and confirm the field is present in the
            // serialised form. Because max_authority_chain_depth is always
            // serialised (no skip_serializing_if), the serialised JSON will
            // always contain it; the test checks the raw embedded JSON as well
            // to ensure the file is explicit (not relying on the default).
            let p = load_builtin(name)
                .unwrap_or_else(|| panic!("profile {name} failed to load"));
            let json = serde_json::to_string(&p).unwrap();
            assert!(
                json.contains("max_authority_chain_depth"),
                "serialised {name} must contain max_authority_chain_depth"
            );
            // Also verify the raw embedded JSON contains the field explicitly.
            let raw = BUILTIN_PROFILES
                .iter()
                .find(|b| b.name == name)
                .unwrap()
                .json;
            assert!(
                raw.contains("max_authority_chain_depth"),
                "raw JSON for {name} must declare max_authority_chain_depth explicitly"
            );
        }
    }

    #[test]
    fn chain_depth_is_stricter_at_higher_bsl() {
        let bsl2 = load_builtin("university_bsl2_dna").unwrap();
        let bsl3 = load_builtin("university_bsl3_dna").unwrap();
        let bsl4 = load_builtin("government_bsl4_restricted").unwrap();
        assert!(
            bsl3.max_authority_chain_depth <= bsl2.max_authority_chain_depth,
            "BSL-3 chain depth ({}) must be ≤ BSL-2 ({})",
            bsl3.max_authority_chain_depth,
            bsl2.max_authority_chain_depth
        );
        assert!(
            bsl4.max_authority_chain_depth <= bsl3.max_authority_chain_depth,
            "BSL-4 chain depth ({}) must be ≤ BSL-3 ({})",
            bsl4.max_authority_chain_depth,
            bsl3.max_authority_chain_depth
        );
    }
}
