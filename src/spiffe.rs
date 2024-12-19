use std::str::FromStr;

const SPIFFE_URI_SCHEME: &str = "spiffe://";

#[derive(Default)]
pub struct Builder {
    trust_domain: String,
    identifiers: Vec<String>,
}

#[derive(Debug, PartialEq)]
pub enum SPIFFEError {
    CannotParseError,
    InvalidScheme,
    InvalidIdentifier(usize),
    InvalidTrustDomainCharacter(usize, char),
    InvalidTrustDomainCharacters(Vec<usize>),
    MatcherError { message: String, attribute: String },
}

impl Builder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set_trust_domain(&mut self, trust_domain: &str) -> &mut Self {
        self.trust_domain = trust_domain.to_string();
        self
    }

    pub fn push_identifier(&mut self, identifier: &str) -> &mut Self {
        self.identifiers.push(identifier.to_string());
        self
    }

    pub fn append_identifiers(&mut self, identifiers: &mut Vec<String>) -> &mut Self {
        self.identifiers.append(identifiers);
        self
    }

    pub fn build(&self) -> Result<Identity, SPIFFEError> {
        validate_trustdomain(&self.trust_domain)?;

        for id in self.identifiers.iter() {
            validate_identifier(id)?
        }
        let mut identifier = String::from("/");
        identifier.push_str(&self.identifiers.join("/"));
        Ok(Identity {
            scheme: SPIFFE_URI_SCHEME.to_string(),
            trust_domain: self.trust_domain.clone(),
            parsed_identifiers: self.identifiers.clone(),
            identifier,
        })
    }
}

pub fn validate_trustdomain(td: &str) -> Result<(), SPIFFEError> {
    let invalid_offsets: Vec<usize> = td
        .chars()
        .enumerate()
        .filter_map(|(offset, c)| match c {
            'a'..='z' | '0'..='9' | '.' | '_' => None,
            _ => Some(offset),
        })
        .collect();
    if invalid_offsets.is_empty() {
        Ok(())
    } else {
        Err(SPIFFEError::InvalidTrustDomainCharacters(invalid_offsets))
    }
}

pub fn validate_identifier(identifier: &str) -> Result<(), SPIFFEError> {
    if identifier == "." || identifier == ".." || identifier.is_empty() {
        return Err(SPIFFEError::InvalidIdentifier(0));
    }
    for (offset, c) in identifier.chars().enumerate() {
        match c {
            'a'..='z' | 'A'..='Z' | '0'..='9' | '.' | '-' | '_' => continue,
            _ => return Err(SPIFFEError::InvalidIdentifier(offset)),
        }
    }
    Ok(())
}

pub trait Matcher {
    fn matches(&self, spiffe: &Identity) -> Result<(), SPIFFEError>;
}

pub struct TrustDomainMatcher {
    trust_domain: String,
}

impl TrustDomainMatcher {
    pub fn new(trust_domain: &str) -> Self {
        Self {
            trust_domain: trust_domain.to_lowercase(),
        }
    }
}

impl Matcher for TrustDomainMatcher {
    fn matches(&self, spiffe: &Identity) -> Result<(), SPIFFEError> {
        let trust_domain = spiffe.get_trust_domain().to_lowercase();
        match self.trust_domain == trust_domain {
            true => Ok(()),
            false => Err(SPIFFEError::MatcherError {
                message: String::from("trust domains do not match"),
                attribute: String::from("trust_domain"),
            }),
        }
    }
}

#[derive(Clone)]
pub enum IdentifierMatch {
    RequiredIdentifier(String),
    OptionalIdentifier(String),
    Any,
}

pub struct IdentityComponentsMatcher {
    components: Vec<IdentifierMatch>,
}

impl IdentityComponentsMatcher {
    pub fn new(components: Vec<IdentifierMatch>) -> Self {
        Self { components }
    }
}

#[derive(Default)]
pub struct IdentityComponentsMatcherBuilder {
    components: Vec<IdentifierMatch>,
}

impl IdentityComponentsMatcherBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn require_identifier(&mut self, identifier: &str) -> &mut Self {
        self.append_identifier(IdentifierMatch::RequiredIdentifier(identifier.to_string()))
    }

    pub fn allow_identifier(&mut self, identifier: &str) -> &mut Self {
        self.append_identifier(IdentifierMatch::OptionalIdentifier(identifier.to_string()))
    }

    pub fn append_identifier(&mut self, identifier: IdentifierMatch) -> &mut Self {
        self.components.push(identifier);
        self
    }

    pub fn build(&mut self) -> IdentityComponentsMatcher {
        IdentityComponentsMatcher::new(self.components.clone())
    }
}

impl Matcher for IdentityComponentsMatcher {
    fn matches(&self, spiffe: &Identity) -> Result<(), SPIFFEError> {
        let required_identifiers = self.components.iter().fold(0, |acc, v| match v {
            IdentifierMatch::RequiredIdentifier(_) | IdentifierMatch::Any => acc + 1,
            _ => acc,
        });
        let got_identifiers = spiffe.get_parsed_identifiers().len();
        if required_identifiers > got_identifiers {
            return Err(SPIFFEError::MatcherError {
                message: format!(
                    "expected at least {required_identifiers} identifiers, got {got_identifiers}"
                ),
                attribute: String::from("identifier"),
            });
        }
        for (index, (expected, got)) in self
            .components
            .iter()
            .zip(spiffe.get_parsed_identifiers())
            .enumerate()
        {
            match expected {
                IdentifierMatch::RequiredIdentifier(value)
                | IdentifierMatch::OptionalIdentifier(value) => {
                    if value != got {
                        return Err(SPIFFEError::MatcherError {
                            message: format!(
                                "identifier at index {} ({:?}) does not match expected identifier ({:?})",
                                index, got, value
                            ),
                            attribute: String::from("identifier"),
                        });
                    }
                }
                IdentifierMatch::Any => continue,
            }
        }
        Ok(())
    }
}

pub struct MultiMatcher {
    matchers: Vec<Box<dyn Matcher>>,
}

impl MultiMatcher {
    pub fn new(matchers: Vec<Box<dyn Matcher>>) -> Self {
        Self { matchers }
    }
}

impl Matcher for MultiMatcher {
    fn matches(&self, spiffe: &Identity) -> Result<(), SPIFFEError> {
        for matcher in self.matchers.iter() {
            matcher.matches(spiffe)?;
        }
        Ok(())
    }
}

#[derive(Debug, PartialEq)]
pub struct Identity {
    scheme: String,
    trust_domain: String,
    identifier: String,
    parsed_identifiers: Vec<String>,
}

impl Identity {
    pub fn get_scheme(&self) -> &str {
        &self.scheme
    }

    pub fn get_trust_domain(&self) -> &str {
        &self.trust_domain
    }

    pub fn get_identifier(&self) -> &str {
        &self.identifier
    }

    pub fn get_parsed_identifiers(&self) -> Vec<&str> {
        self.parsed_identifiers.iter().map(String::as_ref).collect()
    }

    pub fn matches(&self, matcher: &impl Matcher) -> Result<(), SPIFFEError> {
        matcher.matches(self)
    }
}

impl FromStr for Identity {
    type Err = SPIFFEError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.is_empty() {
            return Err(SPIFFEError::CannotParseError);
        }
        if !s.starts_with(SPIFFE_URI_SCHEME) {
            return Err(SPIFFEError::InvalidScheme);
        }
        let mut parsed = Identity {
            scheme: SPIFFE_URI_SCHEME.to_string(),
            trust_domain: String::new(),
            identifier: String::new(),
            parsed_identifiers: Vec::new(),
        };
        // Process trust domain
        let mut next_slice_start = 0;
        let mut original_index = SPIFFE_URI_SCHEME.len();
        let s = &s[original_index..];
        for (index, c) in s.chars().enumerate() {
            match c {
                'a'..='z' | '0'..='9' | '.' | '_' => parsed.trust_domain.push(c),
                'A'..='Z' => parsed.trust_domain.push(c.to_ascii_lowercase()),
                '/' => {
                    original_index += index - 1;
                    next_slice_start = index;
                    break;
                }
                _ => {
                    return Err(SPIFFEError::InvalidTrustDomainCharacter(
                        index + original_index,
                        c,
                    ))
                }
            }
        }
        // Process path
        let s = &s[next_slice_start..];
        let mut ends_with_slash = false;
        let mut current_identifier_index = 0;
        for (index, c) in s.chars().enumerate() {
            match c {
                'a'..='z' | 'A'..='Z' | '0'..='9' | '.' | '_' => {
                    parsed.identifier.push(c);
                    if parsed.parsed_identifiers.is_empty()
                        || current_identifier_index > parsed.parsed_identifiers.len() - 1
                    {
                        parsed.parsed_identifiers.push(String::new());
                    }
                    parsed.parsed_identifiers[current_identifier_index].push(c);
                    ends_with_slash = false;
                }
                '/' => {
                    parsed.identifier.push(c);
                    ends_with_slash = true;
                    if index == 0 {
                        continue;
                    }
                    current_identifier_index += 1;
                }
                _ => return Err(SPIFFEError::InvalidIdentifier(index + original_index)),
            }
        }
        if ends_with_slash {
            return Err(SPIFFEError::InvalidIdentifier(s.len() - 1 + original_index));
        }
        original_index += parsed.parsed_identifiers[..current_identifier_index]
            .iter()
            .map(|i| i.len() + 1) // +1 to account for `/` that separates the identifiers
            .sum::<usize>()
            + 1; // +1 accounts for the / between the last identifier and the current one
        let current_identifier = &parsed.parsed_identifiers[current_identifier_index];
        match validate_identifier(current_identifier) {
            Err(SPIFFEError::InvalidIdentifier(offset)) => {
                Err(SPIFFEError::InvalidIdentifier(original_index + offset))
            }
            _ => Ok(parsed),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_identity_accessors() {
        let id = Identity {
            scheme: SPIFFE_URI_SCHEME.to_string(),
            trust_domain: String::from("trust.domain.local"),
            identifier: String::from("/ns/namespace/sa/service"),
            parsed_identifiers: vec![
                String::from("ns"),
                String::from("namespace"),
                String::from("sa"),
                String::from("service"),
            ],
        };
        assert_eq!(SPIFFE_URI_SCHEME, id.get_scheme());
        assert_eq!("trust.domain.local", id.get_trust_domain());
        assert_eq!("/ns/namespace/sa/service", id.get_identifier());
        assert_eq!(
            vec!["ns", "namespace", "sa", "service"],
            id.get_parsed_identifiers()
        );
    }

    #[test]
    fn test_validate_identifier() {
        // let test_cases: [(String, Result<(), SPIFFEError>)
        let test_cases = [
            (String::from("kubernetes"), Ok(())),
            (String::from("k8s-api"), Ok(())),
            (String::from("k8s.api"), Ok(())),
            (String::from("k8s_api"), Ok(())),
            (String::from("authZ9"), Ok(())),
            (String::from("a=b"), Err(SPIFFEError::InvalidIdentifier(1))),
            (String::from("a/b"), Err(SPIFFEError::InvalidIdentifier(1))),
            (
                String::from("a%20b"),
                Err(SPIFFEError::InvalidIdentifier(1)),
            ),
            (
                String::from("ab%2F"),
                Err(SPIFFEError::InvalidIdentifier(2)),
            ),
            (String::from("."), Err(SPIFFEError::InvalidIdentifier(0))),
            (String::from(".."), Err(SPIFFEError::InvalidIdentifier(0))),
            (String::new(), Err(SPIFFEError::InvalidIdentifier(0))),
        ];

        for (input, expected) in test_cases {
            assert_eq!(validate_identifier(&input), expected);
        }
    }

    #[test]
    fn test_parses_spiffe() {
        let test_cases: &[(&str, Result<Identity, SPIFFEError>)] = &[
            (
                "spiffe://trust.domain.local/ns/namespace/sa/service_account",
                Ok(Identity {
                    scheme: String::from("spiffe://"),
                    trust_domain: String::from("trust.domain.local"),
                    identifier: String::from("/ns/namespace/sa/service_account"),
                    parsed_identifiers: vec![
                        String::from("ns"),
                        String::from("namespace"),
                        String::from("sa"),
                        String::from("service_account"),
                    ],
                }),
            ),
            (
                "spiffe://TRUST.DOMAIN.LOCAL/ns/namespace/sa/service_account",
                Ok(Identity {
                    scheme: String::from("spiffe://"),
                    trust_domain: String::from("trust.domain.local"),
                    identifier: String::from("/ns/namespace/sa/service_account"),
                    parsed_identifiers: vec![
                        String::from("ns"),
                        String::from("namespace"),
                        String::from("sa"),
                        String::from("service_account"),
                    ],
                }),
            ),
            ("", Err(SPIFFEError::CannotParseError)),
            ("https://example.com", Err(SPIFFEError::InvalidScheme)),
            (
                "spiffe://[::1]/id",
                Err(SPIFFEError::InvalidTrustDomainCharacter(9, '[')),
            ),
            (
                "spiffe://trust.domain.local/id=foo",
                Err(SPIFFEError::InvalidIdentifier(29)),
            ),
            (
                "spiffe://trust.domain.local/id=foo/bar",
                Err(SPIFFEError::InvalidIdentifier(29)),
            ),
            (
                "spiffe://trust.domain.local/id/foo/",
                Err(SPIFFEError::InvalidIdentifier(33)),
            ),
            (
                "spiffe://trust.domain.local/id/foo/.",
                Err(SPIFFEError::InvalidIdentifier(34)),
            ),
        ];
        for (input, expected) in test_cases {
            let got: Result<Identity, SPIFFEError> = input.parse();
            assert_eq!(&got, expected);
        }
    }

    #[test]
    fn test_builds_a_valid_spiffe() {
        let id = Builder::new()
            .set_trust_domain("trust.domain.local")
            .push_identifier("ns")
            .push_identifier("namespace")
            .append_identifiers(&mut vec![
                String::from("sa"),
                String::from("service_account"),
            ])
            .build();
        assert_eq!(
            id,
            Ok(Identity {
                scheme: SPIFFE_URI_SCHEME.to_string(),
                trust_domain: String::from("trust.domain.local"),
                identifier: String::from("/ns/namespace/sa/service_account"),
                parsed_identifiers: vec![
                    String::from("ns"),
                    String::from("namespace"),
                    String::from("sa"),
                    String::from("service_account")
                ]
            })
        );
    }

    #[test]
    fn test_fails_to_build_spiffe_with_invalid_identifier() {
        let invalid_identifiers: &[(usize, &str)] =
            &[(0, "."), (0, ".."), (3, "foo=bar"), (1, "f%20b")];
        for (expected_offset, identifier) in invalid_identifiers {
            let res = Builder::new()
                .set_trust_domain("trust.domain.local")
                .push_identifier(identifier)
                .build();
            assert_eq!(res, Err(SPIFFEError::InvalidIdentifier(*expected_offset)));
        }
    }

    #[test]
    fn test_fails_to_build_spiffe_with_invalid_trust_domain() {
        let invalid_trust_domains: &[(Vec<usize>, &str)] =
            &[(vec![0, 1, 2, 4], "[::1]"), (vec![4], "user@domain")];

        for (expected_offsets, td) in invalid_trust_domains {
            let res = Builder::new()
                .set_trust_domain(td)
                .push_identifier("ns")
                .build();
            assert_eq!(
                res,
                Err(SPIFFEError::InvalidTrustDomainCharacters(
                    expected_offsets.clone()
                )),
            );
        }
    }

    #[test]
    fn test_identity_components_matching_requires_identifiers() {
        let test_cases: &[(Vec<String>, Vec<String>, Result<(), SPIFFEError>)] = &[(
            vec![String::from("namespace")],
            vec![String::from("namespace")],
            Ok(()),
        ), (
            vec![String::from("ns"), String::from("namespace")],
            vec![String::from("namespace"), String::from("service")],
            Err(SPIFFEError::MatcherError{ message: String::from("identifier at index 0 (\"namespace\") does not match expected identifier (\"ns\")"), attribute: String::from("identifier") }), 
        ), (
            vec![String::from("ns"), String::from("namespace")],
            vec![String::from("namespace")],
            Err(SPIFFEError::MatcherError{ message: String::from("expected at least 2 identifiers, got 1"), attribute: String::from("identifier") }),
        )];
        for (required_components, components, expected_result) in test_cases {
            let mut matcher_builder = IdentityComponentsMatcherBuilder::new();
            for rc in required_components {
                matcher_builder.require_identifier(rc);
            }
            let matcher = matcher_builder.build();
            let test_id = Identity {
                scheme: SPIFFE_URI_SCHEME.to_string(),
                trust_domain: String::from("trust.domain.local"),
                identifier: String::from("/") + components.join("/").as_str(),
                parsed_identifiers: components.clone(),
            };
            let actual_result = test_id.matches(&matcher);
            assert_eq!(&actual_result, expected_result);
        }
    }

    #[test]
    fn test_optional_identity_component_matching() {
        let test_cases: &[(Vec<String>, Vec<String>, Vec<String>, Result<(), SPIFFEError>)] = &[(
            vec![String::from("namespace")],
            vec![String::from("service")],
            vec![String::from("namespace")],
            Ok(()),
        ), (
            vec![String::from("ns"), String::from("namespace")],
            vec![String::from("sa"), String::from("service")],
            vec![String::from("ns"), String::from("namespace"), String::from("service")],
            Err(SPIFFEError::MatcherError{ message: String::from("identifier at index 2 (\"service\") does not match expected identifier (\"sa\")"), attribute: String::from("identifier") }), 
        ), (
            vec![String::from("ns"), String::from("namespace")],
            vec![String::from("sa"), String::from("service")],
            vec![String::from("ns"), String::from("namespace"), String::from("sa"), String::from("service")],
            Ok(()),
        )];
        for (required_components, optional_components, components, expected_result) in test_cases {
            let mut matcher_builder = IdentityComponentsMatcherBuilder::new();
            for rc in required_components {
                matcher_builder.require_identifier(rc);
            }
            for oc in optional_components {
                matcher_builder.allow_identifier(oc);
            }
            let matcher = matcher_builder.build();
            let test_id = Identity {
                scheme: SPIFFE_URI_SCHEME.to_string(),
                trust_domain: String::from("trust.domain.local"),
                identifier: String::from("/") + components.join("/").as_str(),
                parsed_identifiers: components.clone(),
            };
            let actual_result = test_id.matches(&matcher);
            assert_eq!(&actual_result, expected_result);
        }
    }

    #[test]
    fn test_any_identity_component_matcher() -> Result<(), String> {
        let mut matcher_builder = IdentityComponentsMatcherBuilder::new();
        matcher_builder
            .append_identifier(IdentifierMatch::Any)
            .require_identifier("namespace");
        let matcher = matcher_builder.build();
        let id = Identity {
            scheme: SPIFFE_URI_SCHEME.to_string(),
            trust_domain: String::new(),
            identifier: String::new(),
            parsed_identifiers: vec![String::from("foo"), String::from("namespace")],
        };
        id.matches(&matcher).map_err(|e| format!("{e:?}"))
    }

    #[test]
    fn test_trust_domain_matcher() {
        let test_cases: &[(&str, &str, Result<(), SPIFFEError>)] = &[
            ("trust.acme.corp", "trust.acme.corp", Ok(())),
            ("trust.acme.corp", "TRUST.ACME.CORP", Ok(())),
            (
                "trust.acme.corp",
                "trust.acme0.corp",
                Err(SPIFFEError::MatcherError {
                    message: String::from("trust domains do not match"),
                    attribute: String::from("trust_domain"),
                }),
            ),
            ("TRUST.ACME.CORP", "TRUST.ACME.CORP", Ok(())),
        ];

        for (required_td, td, expected_result) in test_cases {
            let matcher = TrustDomainMatcher::new(required_td);
            let test_id = Identity {
                scheme: SPIFFE_URI_SCHEME.to_string(),
                trust_domain: td.to_string(),
                identifier: String::from("/"),
                parsed_identifiers: Vec::new(),
            };
            let actual_result = test_id.matches(&matcher);
            assert_eq!(&actual_result, expected_result);
        }
    }

    #[test]
    fn test_multi_matcher() {
        let test_cases: &[(&str, Vec<String>, Identity, Result<(), SPIFFEError>)] = &[
            (
                "trust.acme.corp",
                vec![String::from("ns"), String::from("default")],
                Identity {
                    scheme: SPIFFE_URI_SCHEME.to_string(),
                    trust_domain: String::from("trust.acme.corp"),
                    identifier: String::from("/ns/default"),
                    parsed_identifiers: vec![String::from("ns"), String::from("default")],
                },
                Ok(()),
            ),
            (
                "trust.acme.corp",
                vec![
                    String::from("ns"),
                    String::from("default"),
                    String::from("sa"),
                    String::from("svc"),
                ],
                Identity {
                    scheme: SPIFFE_URI_SCHEME.to_string(),
                    trust_domain: String::from("trust.acme.corp"),
                    identifier: String::from("/ns/default"),
                    parsed_identifiers: vec![String::from("ns"), String::from("default")],
                },
                Err(SPIFFEError::MatcherError {
                    message: String::from("expected at least 4 identifiers, got 2"),
                    attribute: String::from("identifier"),
                }),
            ),
        ];

        for (required_td, required_components, spiffe, expected_result) in test_cases {
            let mut id_matcher_builder = IdentityComponentsMatcherBuilder::new();
            for component in required_components {
                id_matcher_builder.require_identifier(component);
            }
            let id_matcher = id_matcher_builder.build();
            let td_matcher = TrustDomainMatcher::new(required_td);
            let multi_matcher = MultiMatcher::new(vec![Box::new(id_matcher), Box::new(td_matcher)]);
            let actual_result = spiffe.matches(&multi_matcher);
            assert_eq!(&actual_result, expected_result);
        }
    }
}
