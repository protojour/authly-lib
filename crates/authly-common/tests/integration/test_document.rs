use authly_common::document::Document;

const ENTITY: &str = r#"
[authly-document]
id = "d783648f-e6ac-4492-87f7-43d5e5805d60"

[[entity]]
eid = "7d8b18fa5836487592a43eacea830b47"
label = "me"
email = ["me@mail.com"]
username = "testuser"
password-hash = [
    "$argon2id$v=19$m=19456,t=2,p=1$/lj8Yj6ZTJLiqgpYb4Nn0g$z79FFMXstrkY8KmpC0vQWIDcne0lylBbctUAluIVqLk",
]
"#;

const SVC: &str = r#"
[authly-document]
id = "bc9ce588-50c3-47d1-94c1-f88b21eaf299"

[[service-entity]]
eid = "2671d2a0bc3545e69fc666130254f8e9"
label = "testservice"
attributes = ["authly:role:authenticate", "authly:role:get_access_token"]
kubernetes-account = { name = "testservice", namespace = "authly-test" }

[[entity-property]]
domain = "testservice"
label = "role"
attributes = ["ui/user", "ui/admin"]

[[entity-attribute-binding]]
eid = "7d8b18fa5836487592a43eacea830b47"
attributes = ["testservice:role:ui/user"]

[[resource-property]]
domain = "testservice"
label = "name"
attributes = ["ontology", "storage"]

[[resource-property]]
domain = "testservice"
label = "ontology/action"
attributes = ["read", "deploy", "stop"]

[[resource-property]]
domain = "testservice"
label = "buckets/action"
attributes = ["read"]

[[resource-property]]
domain = "testservice"
label = "bucket/action"
attributes = ["read", "create", "delete"]

[[resource-property]]
domain = "testservice"
label = "object/action"
attributes = ["read", "create", "delete"]

[[policy]]
label = "allow for main service"
allow = "Subject.entity == testservice"

[[policy]]
label = "allow for UI user"
allow = "Subject.testservice:role contains testservice:role:ui/user"

[[policy]]
label = "allow for UI admin"
allow = "Subject.testservice:role contains testservice:role:ui/admin"

[[policy-binding]]
attributes = ["testservice:ontology/action:read"]
policies = ["allow for main service", "allow for UI user"]

[[policy-binding]]
attributes = ["testservice:ontology/action:deploy"]
policies = ["allow for main service", "allow for UI admin"]
"#;

const SETTINGS: &str = r#"
[authly-document]
id = "d783648f-e6ac-4492-87f7-43d5e5805d60"

[local-settings]
KEY0 = "value0"
KEY1 = "value1"
"#;

#[test]
fn test_entity() {
    let toml = ENTITY;
    let document = Document::from_toml(toml).unwrap();

    assert_eq!(document.authly_document.id.span(), 24..62);
    // BUG: The span is off:
    assert_eq!(&toml[24..62], "\"d783648f-e6ac-4492-87f7-43d5e5805d60\"");

    assert_eq!(document.entity[0].eid.span(), 81..115);
    assert_eq!(&toml[81..115], "\"7d8b18fa5836487592a43eacea830b47\"");

    assert_eq!(document.entity.len(), 1);
}

#[test]
fn testservice_example() {
    let toml = SVC;
    Document::from_toml(toml).unwrap();
}

#[test]
fn settings_example() {
    let toml = SETTINGS;
    let document = Document::from_toml(toml).unwrap();
    let settings = document.local_settings.into_iter().next().unwrap();

    let (key0, value0) = settings.into_iter().next().unwrap();

    assert_eq!(&toml[key0.span()], "KEY0");
    assert_eq!(&toml[value0.span()], "\"value0\"");
}
