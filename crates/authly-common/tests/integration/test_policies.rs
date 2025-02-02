use authly_common::{
    id::{AnyId, ObjId},
    policy::{
        code::{to_bytecode, OpCode, PolicyValue},
        engine::{AccessControlParams, NoOpPolicyTracer, PolicyEngine},
    },
};

const POL_DENY_FALSE0: ObjId = ObjId::from_uint(0);
const POL_DENY_FALSE1: ObjId = ObjId::from_uint(1);
const POL_DENY_TRUE0: ObjId = ObjId::from_uint(2);
const POL_DENY_TRUE1: ObjId = ObjId::from_uint(3);
const POL_ALLOW_FALSE0: ObjId = ObjId::from_uint(4);
const POL_ALLOW_FALSE1: ObjId = ObjId::from_uint(5);
const POL_ALLOW_TRUE0: ObjId = ObjId::from_uint(6);
const POL_ALLOW_TRUE1: ObjId = ObjId::from_uint(7);

const FOO: AnyId = AnyId::from_uint(0);
const BAR: AnyId = AnyId::from_uint(1);
const BAZ: AnyId = AnyId::from_uint(2);
const QUX: AnyId = AnyId::from_uint(3);
const BOG: AnyId = AnyId::from_uint(4);

fn true_policy() -> Vec<u8> {
    to_bytecode(&[
        OpCode::LoadConstId(0),
        OpCode::LoadConstId(0),
        OpCode::IsEq,
        OpCode::Return,
    ])
}

fn false_policy() -> Vec<u8> {
    to_bytecode(&[
        OpCode::LoadConstId(0),
        OpCode::LoadConstId(1),
        OpCode::IsEq,
        OpCode::Return,
    ])
}

fn test_engine_with_policies() -> PolicyEngine {
    let mut e = PolicyEngine::default();
    e.add_policy(POL_DENY_FALSE0, PolicyValue::Deny, false_policy());
    e.add_policy(POL_DENY_FALSE1, PolicyValue::Deny, false_policy());
    e.add_policy(POL_DENY_TRUE0, PolicyValue::Deny, true_policy());
    e.add_policy(POL_DENY_TRUE1, PolicyValue::Deny, true_policy());
    e.add_policy(POL_ALLOW_FALSE0, PolicyValue::Allow, false_policy());
    e.add_policy(POL_ALLOW_FALSE1, PolicyValue::Allow, false_policy());
    e.add_policy(POL_ALLOW_TRUE0, PolicyValue::Allow, true_policy());
    e.add_policy(POL_ALLOW_TRUE1, PolicyValue::Allow, true_policy());
    e
}

#[track_caller]
fn eval_attrs(engine: &PolicyEngine, attrs: impl IntoIterator<Item = AnyId>) -> &'static str {
    match engine.eval(
        &AccessControlParams {
            resource_attrs: attrs.into_iter().collect(),
            ..Default::default()
        },
        &mut NoOpPolicyTracer,
    ) {
        Ok(PolicyValue::Allow) => "allow",
        Ok(PolicyValue::Deny) => "deny",
        Err(err) => panic!("{err:?}"),
    }
}

#[test_log::test]
fn test_allow_class() {
    let mut e = test_engine_with_policies();
    e.add_trigger([FOO], [POL_ALLOW_FALSE0]);
    e.add_trigger([BAR], [POL_ALLOW_TRUE0]);
    e.add_trigger([BAZ, QUX], [POL_ALLOW_FALSE0, POL_ALLOW_TRUE0]);

    assert_eq!("deny", eval_attrs(&e, []));
    assert_eq!("deny", eval_attrs(&e, [FOO]));
    assert_eq!("deny", eval_attrs(&e, [BAZ]));
    assert_eq!("deny", eval_attrs(&e, [QUX]));
    assert_eq!("deny", eval_attrs(&e, [BOG]));
    assert_eq!("deny", eval_attrs(&e, [FOO, BAZ]));
    assert_eq!("deny", eval_attrs(&e, [FOO, QUX]));

    assert_eq!("allow", eval_attrs(&e, [BAR]));
    assert_eq!("allow", eval_attrs(&e, [BAZ, QUX]));
}

#[test_log::test]
fn test_deny_class() {
    let mut e = test_engine_with_policies();
    e.add_trigger([FOO], [POL_DENY_FALSE0]);
    e.add_trigger([BAR], [POL_DENY_TRUE0]);
    e.add_trigger([BAZ, QUX], [POL_DENY_FALSE0, POL_DENY_TRUE0]);
    e.add_trigger([QUX, BOG], [POL_DENY_FALSE0, POL_DENY_FALSE1]);

    assert_eq!("deny", eval_attrs(&e, []));
    assert_eq!("deny", eval_attrs(&e, [BAR]));
    assert_eq!("deny", eval_attrs(&e, [BAZ]));
    assert_eq!("deny", eval_attrs(&e, [QUX]));
    assert_eq!("deny", eval_attrs(&e, [BOG]));
    assert_eq!("deny", eval_attrs(&e, [BAZ, QUX]));
    assert_eq!("deny", eval_attrs(&e, [BAR, QUX]));
    assert_eq!("deny", eval_attrs(&e, [BAZ, BOG]));

    assert_eq!("allow", eval_attrs(&e, [FOO]));
    assert_eq!("allow", eval_attrs(&e, [FOO, BAZ]));
    assert_eq!("allow", eval_attrs(&e, [FOO, QUX]));
    assert_eq!("allow", eval_attrs(&e, [QUX, BOG]));
}

#[test_log::test]
fn test_allow_deny_classes() {
    let mut e = test_engine_with_policies();

    const NO: AnyId = AnyId::from_uint(100);
    const YES: AnyId = AnyId::from_uint(200);

    // "NO" triggers, results in deny
    e.add_trigger([NO, FOO], [POL_ALLOW_TRUE0, POL_DENY_TRUE0]);
    e.add_trigger(
        [NO, BAR],
        [POL_ALLOW_TRUE0, POL_DENY_FALSE0, POL_DENY_TRUE0],
    );
    e.add_trigger(
        [NO, BAZ],
        [
            POL_ALLOW_FALSE0,
            POL_ALLOW_TRUE0,
            POL_DENY_FALSE0,
            POL_DENY_TRUE0,
        ],
    );

    // "YES" triggers, results in allow
    e.add_trigger([YES, FOO], [POL_ALLOW_TRUE0, POL_DENY_FALSE0]);
    e.add_trigger(
        [YES, BAR],
        [
            POL_ALLOW_FALSE0,
            POL_ALLOW_TRUE0,
            POL_DENY_FALSE0,
            POL_DENY_FALSE1,
        ],
    );

    assert_eq!("deny", eval_attrs(&e, []));
    assert_eq!("deny", eval_attrs(&e, [FOO]));
    assert_eq!("deny", eval_attrs(&e, [NO, FOO]));
    assert_eq!("deny", eval_attrs(&e, [NO, BAR]));
    assert_eq!("deny", eval_attrs(&e, [NO, BAZ]));

    assert_eq!("allow", eval_attrs(&e, [YES, FOO]));
    assert_eq!("allow", eval_attrs(&e, [YES, BAR]));
}
