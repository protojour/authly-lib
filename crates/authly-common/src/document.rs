//! Authly document type definitions.

use serde::Deserialize;
use toml::Spanned;
use uuid::Uuid;

use crate::{id::Eid, property::QualifiedAttributeName};

/// The deserialized representation of an authly document.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(missing_docs)]
pub struct Document {
    #[serde(rename = "authly-document")]
    pub authly_document: AuthlyDocument,

    #[serde(default)]
    pub entity: Vec<Entity>,

    #[serde(default, rename = "service-entity")]
    pub service_entity: Vec<Entity>,

    #[serde(default)]
    pub email: Vec<Email>,

    #[serde(default, rename = "password-hash")]
    pub password_hash: Vec<PasswordHash>,

    #[serde(default)]
    pub members: Vec<Members>,

    #[serde(default, rename = "entity-property")]
    pub entity_property: Vec<EntityProperty>,

    #[serde(default, rename = "resource-property")]
    pub resource_property: Vec<ResourceProperty>,

    #[serde(default)]
    pub policy: Vec<Policy>,

    #[serde(default, rename = "policy-binding")]
    pub policy_binding: Vec<PolicyBinding>,
}

/// The authly document header
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthlyDocument {
    /// The ID of this document as an Authly authority
    pub id: Spanned<Uuid>,
}

/// An entity definition
#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct Entity {
    /// The eid of this entity.
    pub eid: Spanned<Eid>,

    /// A label for the entity visible in the document namespace.
    #[serde(default)]
    pub label: Option<Spanned<String>>,

    /// Attributes bound to the entity.
    #[serde(default)]
    pub attributes: Vec<Spanned<QualifiedAttributeName>>,

    /// List of usernames.
    #[serde(default)]
    pub username: Option<Spanned<String>>,

    /// List of email addresses.
    #[serde(default)]
    pub email: Vec<Spanned<String>>,

    /// List of password hashes.
    #[serde(default, rename = "password-hash")]
    pub password_hash: Vec<String>,

    /// An optional kubernetes account.
    #[serde(default, rename = "kubernetes-account")]
    pub kubernetes_account: Option<KubernetesAccount>,
}

/// An email address assignment.
#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct Email {
    /// The label of the entity that is assigned this address.
    pub entity: Spanned<String>,

    /// The address itself.
    pub value: Spanned<String>,
}

/// An password hash assignment.
#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct PasswordHash {
    /// The label of the entity that is assigned this password hash.
    pub entity: Spanned<String>,

    /// The password hash itself.
    pub hash: String,
}

/// A members assignment.
///
/// In the authly model, any kind of entity may have members.
#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct Members {
    /// The label of the entity that members is assigned to.
    pub entity: Spanned<String>,

    /// Entity labels of the members.
    pub members: Vec<Spanned<String>>,
}

/// A definition of an entity property.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EntityProperty {
    /// The label of the service which defines this entity property.
    #[serde(default)]
    pub service: Option<Spanned<String>>,

    /// The property label.
    pub label: Spanned<String>,

    /// The list of attributes of the property.
    #[serde(default)]
    pub attributes: Vec<Spanned<String>>,
}

/// A kubernetes account definition.
#[derive(Default, Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct KubernetesAccount {
    /// The kubernetes namespace.
    pub namespace: String,

    /// The account name.
    pub name: String,
}

/// A definition of a resource property.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceProperty {
    /// The label of the service which defines this resource property.
    pub service: Spanned<String>,

    /// The property label.
    pub label: Spanned<String>,

    /// The list of attributes of the property.
    #[serde(default)]
    pub attributes: Vec<Spanned<String>>,
}

/// A policy definition.
///
/// A policy must contain either an `allow` or `deny` expression.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    /// The label of the service this policy belongs to.
    pub service: Spanned<String>,

    /// The policy label.
    pub label: Spanned<String>,

    /// An allow expression.
    #[serde(default)]
    pub allow: Option<Spanned<String>>,

    /// An deny expression.
    #[serde(default)]
    pub deny: Option<Spanned<String>>,
}

/// A policy binding.
#[derive(Deserialize)]
pub struct PolicyBinding {
    /// The label of the service the binding applies to.
    pub service: Spanned<String>,

    /// The attribute set which will trigger the policy set.
    pub attributes: Vec<Spanned<QualifiedAttributeName>>,

    /// A set of policies triggered.
    pub policies: Vec<Spanned<String>>,
}

impl Document {
    /// Deserialize document from `toml` format.
    pub fn from_toml(toml: &str) -> anyhow::Result<Self> {
        Ok(preprocess(toml::from_str(toml)?))
    }
}

fn preprocess(mut doc: Document) -> Document {
    for user in &mut doc.entity {
        let label = user
            .label
            .get_or_insert_with(|| Spanned::new(0..0, Uuid::new_v4().to_string()));

        for email in std::mem::take(&mut user.email) {
            doc.email.push(Email {
                entity: label.clone(),
                value: email,
            });
        }

        for pw_hash in std::mem::take(&mut user.password_hash) {
            doc.password_hash.push(PasswordHash {
                entity: label.clone(),
                hash: pw_hash,
            });
        }
    }

    doc
}
