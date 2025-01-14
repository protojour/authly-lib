use authly_common::document::Document;

const ENTITY: &str = r#"
[authly-document]
id = "d783648f-e6ac-4492-87f7-43d5e5805d60"

[[entity]]
eid = "111111"
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
eid = "272878235402143010663560859986869906352"
label = "testservice"
attributes = ["authly:role/authenticate", "authly:role/get_access_token"]
kubernetes-account = { name = "testservice", namespace = "authly-test" }

[[entity-property]]
service = "testservice"
label = "role"
attributes = ["ui:user", "ui:admin"]

[[resource-property]]
service = "testservice"
label = "name"
attributes = ["ontology", "storage"]

[[resource-property]]
service = "testservice"
label = "ontology:action"
attributes = ["read", "deploy", "stop"]

[[resource-property]]
service = "testservice"
label = "buckets:action"
attributes = ["read"]

[[resource-property]]
service = "testservice"
label = "bucket:action"
attributes = ["read", "create", "delete"]

[[resource-property]]
service = "testservice"
label = "object:action"
attributes = ["read", "create", "delete"]

[[policy]]
service = "testservice"
label = "allow for main service"
allow = "Subject.entity == testservice"

[[policy]]
service = "testservice"
label = "allow for UI user"
allow = "Subject.role contains role/ui:user"

[[policy]]
service = "testservice"
label = "allow for UI admin"
allow = "Subject.role contains role/ui:admin"

[[policy-binding]]
service = "testservice"
attributes = ["ontology:action/read"]
policies = ["allow for main service", "allow for UI user"]

[[policy-binding]]
service = "testservice"
attributes = ["ontology:action/deploy"]
policies = ["allow for main service", "allow for UI admin"]
"#;

#[test]
fn test_entity() {
    let toml = ENTITY;
    let document = Document::from_toml(toml).unwrap();

    assert_eq!(document.authly_document.id.span(), 24..62);
    // BUG: The span is off:
    assert_eq!(&toml[24..62], "\"d783648f-e6ac-4492-87f7-43d5e5805d60\"");

    assert_eq!(document.entity[0].eid.span(), 81..89);
    assert_eq!(&toml[81..89], "\"111111\"");

    assert_eq!(document.entity.len(), 1);
}

#[test]
fn testservice_example() {
    let toml = SVC;
    Document::from_toml(toml).unwrap();
}
