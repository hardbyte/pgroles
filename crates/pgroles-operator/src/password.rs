//! Password generation and Kubernetes Secret management for operator-generated passwords.

use k8s_openapi::ByteString;
use k8s_openapi::api::core::v1::Secret;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::OwnerReference;
use kube::ResourceExt;
use kube::api::{Api, ObjectMeta, PostParams};
use rand::Rng;
use std::collections::BTreeMap;

use crate::crd::{GeneratePasswordSpec, PostgresPolicy};

/// Default password length when not specified in the CRD.
pub const DEFAULT_PASSWORD_LENGTH: u32 = 32;

/// Minimum allowed password length.
pub const MIN_PASSWORD_LENGTH: u32 = 16;

/// Maximum allowed password length.
pub const MAX_PASSWORD_LENGTH: u32 = 128;

/// Maximum length for a Kubernetes Secret name.
pub const MAX_SECRET_NAME_LENGTH: usize = 253;

/// Character set for generated passwords: alphanumeric + common symbols.
const CHARSET: &[u8] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*-_=+";

/// Generate a random password of the given length.
pub fn generate_password(length: u32) -> String {
    let length = length.clamp(MIN_PASSWORD_LENGTH, MAX_PASSWORD_LENGTH) as usize;
    let mut rng = rand::rng();
    (0..length)
        .map(|_| {
            let idx = rng.random_range(0..CHARSET.len());
            CHARSET[idx] as char
        })
        .collect()
}

/// Compute the Secret name for an operator-generated password.
pub fn generated_secret_name(
    policy_name: &str,
    role_name: &str,
    spec: &GeneratePasswordSpec,
) -> String {
    spec.secret_name
        .clone()
        .unwrap_or_else(|| default_generated_secret_name(policy_name, role_name))
}

/// Compute the Secret key for an operator-generated password.
pub fn generated_secret_key(spec: &GeneratePasswordSpec) -> String {
    spec.secret_key
        .clone()
        .unwrap_or_else(|| "password".to_string())
}

fn default_generated_secret_name(policy_name: &str, role_name: &str) -> String {
    let policy = sanitize_secret_name_segment(policy_name, "policy");
    let role = sanitize_secret_name_segment(role_name, "role");
    let mut name = format!("{policy}-pgr-{role}");
    if name.len() <= MAX_SECRET_NAME_LENGTH {
        return name;
    }

    name.truncate(MAX_SECRET_NAME_LENGTH);
    while matches!(name.as_bytes().last(), Some(b'-')) {
        name.pop();
    }
    if name.is_empty() {
        "pgroles-generated-password".to_string()
    } else {
        name
    }
}

fn sanitize_secret_name_segment(input: &str, fallback: &str) -> String {
    let mut result = String::new();
    let mut last_was_dash = false;

    for ch in input.chars() {
        let normalized = ch.to_ascii_lowercase();
        if normalized.is_ascii_lowercase() || normalized.is_ascii_digit() {
            result.push(normalized);
            last_was_dash = false;
        } else if !last_was_dash {
            result.push('-');
            last_was_dash = true;
        }
    }

    while matches!(result.as_bytes().first(), Some(b'-')) {
        result.remove(0);
    }
    while matches!(result.as_bytes().last(), Some(b'-')) {
        result.pop();
    }

    if result.is_empty() {
        fallback.to_string()
    } else {
        result
    }
}

fn secret_source_version(secret: &Secret, secret_name: &str, secret_key: &str) -> String {
    let resource_version = secret
        .metadata
        .resource_version
        .as_deref()
        .unwrap_or("unknown");
    format!("{secret_name}:{secret_key}:{resource_version}")
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GeneratedPasswordSecret {
    pub password: String,
    pub source_version: String,
}

/// Ensure a Kubernetes Secret exists for a generated password.
///
/// If the Secret already exists, returns the existing password.
/// If the Secret does not exist, generates a new password, creates the Secret
/// with `ownerReferences` back to the `PostgresPolicy` CR, and returns the
/// new password.
///
/// The generated Secret includes both the cleartext password (for application
/// consumption) and the SCRAM-SHA-256 verifier.
pub async fn ensure_generated_secret(
    client: kube::Client,
    namespace: &str,
    policy: &PostgresPolicy,
    role_name: &str,
    spec: &GeneratePasswordSpec,
) -> Result<GeneratedPasswordSecret, PasswordError> {
    let secrets_api: Api<Secret> = Api::namespaced(client.clone(), namespace);
    let secret_name = generated_secret_name(&policy.name_any(), role_name, spec);
    let secret_key = generated_secret_key(spec);

    // Try to read the existing Secret first.
    match secrets_api.get_opt(&secret_name).await {
        Ok(Some(existing)) => {
            // Secret exists — extract the password.
            let data = existing
                .data
                .as_ref()
                .ok_or_else(|| PasswordError::MissingKey {
                    secret: secret_name.clone(),
                    key: secret_key.clone(),
                })?;
            let value_bytes = data
                .get(&secret_key)
                .ok_or_else(|| PasswordError::MissingKey {
                    secret: secret_name.clone(),
                    key: secret_key.clone(),
                })?;
            let password = String::from_utf8(value_bytes.0.clone()).map_err(|_| {
                PasswordError::MissingKey {
                    secret: secret_name.clone(),
                    key: secret_key.clone(),
                }
            })?;
            if password.is_empty() {
                return Err(PasswordError::EmptyPassword {
                    secret: secret_name,
                    key: secret_key,
                });
            }
            tracing::debug!(
                secret = %secret_name,
                role = %role_name,
                "using existing generated password Secret"
            );
            Ok(GeneratedPasswordSecret {
                password,
                source_version: secret_source_version(&existing, &secret_name, &secret_key),
            })
        }
        Ok(None) => {
            // Secret doesn't exist — generate and create.
            let length = spec.length.unwrap_or(DEFAULT_PASSWORD_LENGTH);
            let password = generate_password(length);
            let verifier = pgroles_core::scram::compute_verifier(
                &password,
                pgroles_core::scram::DEFAULT_ITERATIONS,
            );

            let owner_ref = OwnerReference {
                api_version: "pgroles.io/v1alpha1".to_string(),
                kind: "PostgresPolicy".to_string(),
                name: policy.name_any(),
                uid: policy.uid().unwrap_or_default(),
                controller: Some(true),
                block_owner_deletion: Some(true),
            };

            let mut labels = BTreeMap::new();
            labels.insert(
                "app.kubernetes.io/managed-by".to_string(),
                "pgroles-operator".to_string(),
            );
            labels.insert("pgroles.io/policy".to_string(), policy.name_any());
            labels.insert("pgroles.io/role".to_string(), role_name.to_string());

            let mut annotations = BTreeMap::new();
            annotations.insert("pgroles.io/generated-at".to_string(), chrono_now_rfc3339());

            let mut data = BTreeMap::new();
            data.insert(secret_key.clone(), ByteString(password.as_bytes().to_vec()));
            data.insert(
                "verifier".to_string(),
                ByteString(verifier.as_bytes().to_vec()),
            );

            let secret = Secret {
                metadata: ObjectMeta {
                    name: Some(secret_name.clone()),
                    namespace: Some(namespace.to_string()),
                    owner_references: Some(vec![owner_ref]),
                    labels: Some(labels),
                    annotations: Some(annotations),
                    ..Default::default()
                },
                data: Some(data),
                ..Default::default()
            };

            match secrets_api.create(&PostParams::default(), &secret).await {
                Ok(created) => {
                    tracing::info!(
                        secret = %secret_name,
                        role = %role_name,
                        "created generated password Secret"
                    );
                    Ok(GeneratedPasswordSecret {
                        password,
                        source_version: secret_source_version(&created, &secret_name, &secret_key),
                    })
                }
                Err(kube::Error::Api(ref api_err)) if api_err.code == 409 => {
                    // 409 Conflict — another replica beat us. Read the Secret.
                    tracing::debug!(
                        secret = %secret_name,
                        "Secret creation conflict — reading existing"
                    );
                    let existing = secrets_api.get(&secret_name).await.map_err(|err| {
                        PasswordError::KubeApi {
                            secret: secret_name.clone(),
                            source: err,
                        }
                    })?;
                    let data = existing
                        .data
                        .as_ref()
                        .ok_or_else(|| PasswordError::MissingKey {
                            secret: secret_name.clone(),
                            key: secret_key.clone(),
                        })?;
                    let value_bytes =
                        data.get(&secret_key)
                            .ok_or_else(|| PasswordError::MissingKey {
                                secret: secret_name.clone(),
                                key: secret_key.clone(),
                            })?;
                    let password = String::from_utf8(value_bytes.0.clone()).map_err(|_| {
                        PasswordError::MissingKey {
                            secret: secret_name.clone(),
                            key: secret_key.clone(),
                        }
                    })?;
                    if password.is_empty() {
                        return Err(PasswordError::EmptyPassword {
                            secret: secret_name,
                            key: secret_key,
                        });
                    }
                    Ok(GeneratedPasswordSecret {
                        password,
                        source_version: secret_source_version(&existing, &secret_name, &secret_key),
                    })
                }
                Err(err) => Err(PasswordError::KubeApi {
                    secret: secret_name,
                    source: err,
                }),
            }
        }
        Err(err) => Err(PasswordError::KubeApi {
            secret: secret_name,
            source: err,
        }),
    }
}

/// Returns the current time as an RFC 3339 string.
///
/// Uses the same approach as the status module — no chrono dependency needed.
fn chrono_now_rfc3339() -> String {
    // Reuse the CRD helper which formats current time.
    crate::crd::now_rfc3339()
}

/// Errors from password generation and Secret management.
#[derive(Debug, thiserror::Error)]
pub enum PasswordError {
    #[error("generated Secret \"{secret}\" is missing key \"{key}\"")]
    MissingKey { secret: String, key: String },

    #[error("generated Secret \"{secret}\" has empty password at key \"{key}\"")]
    EmptyPassword { secret: String, key: String },

    #[error("Kubernetes API error for Secret \"{secret}\": {source}")]
    KubeApi { secret: String, source: kube::Error },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_password_default_length() {
        let pw = generate_password(DEFAULT_PASSWORD_LENGTH);
        assert_eq!(pw.len(), DEFAULT_PASSWORD_LENGTH as usize);
    }

    #[test]
    fn generate_password_custom_length() {
        let pw = generate_password(64);
        assert_eq!(pw.len(), 64);
    }

    #[test]
    fn generate_password_clamps_to_minimum() {
        let pw = generate_password(1);
        assert_eq!(pw.len(), MIN_PASSWORD_LENGTH as usize);
    }

    #[test]
    fn generate_password_clamps_to_maximum() {
        let pw = generate_password(999);
        assert_eq!(pw.len(), MAX_PASSWORD_LENGTH as usize);
    }

    #[test]
    fn generate_password_unique() {
        let p1 = generate_password(32);
        let p2 = generate_password(32);
        assert_ne!(p1, p2, "two generated passwords should differ");
    }

    #[test]
    fn generate_password_uses_expected_charset() {
        let pw = generate_password(128);
        for ch in pw.chars() {
            assert!(
                CHARSET.contains(&(ch as u8)),
                "unexpected character '{ch}' in generated password"
            );
        }
    }

    #[test]
    fn generated_secret_name_default() {
        let spec = GeneratePasswordSpec {
            length: None,
            secret_name: None,
            secret_key: None,
        };
        assert_eq!(
            generated_secret_name("my-policy", "app-user", &spec),
            "my-policy-pgr-app-user"
        );
    }

    #[test]
    fn generated_secret_name_sanitizes_invalid_default_segments() {
        let spec = GeneratePasswordSpec {
            length: None,
            secret_name: None,
            secret_key: None,
        };
        assert_eq!(
            generated_secret_name("My Policy", "app_user@prod", &spec),
            "my-policy-pgr-app-user-prod"
        );
    }

    #[test]
    fn generated_secret_name_custom() {
        let spec = GeneratePasswordSpec {
            length: None,
            secret_name: Some("custom-secret".to_string()),
            secret_key: None,
        };
        assert_eq!(
            generated_secret_name("my-policy", "app-user", &spec),
            "custom-secret"
        );
    }

    #[test]
    fn generated_secret_key_default() {
        let spec = GeneratePasswordSpec {
            length: None,
            secret_name: None,
            secret_key: None,
        };
        assert_eq!(generated_secret_key(&spec), "password");
    }

    #[test]
    fn generated_secret_key_custom() {
        let spec = GeneratePasswordSpec {
            length: None,
            secret_name: None,
            secret_key: Some("my-key".to_string()),
        };
        assert_eq!(generated_secret_key(&spec), "my-key");
    }
}
