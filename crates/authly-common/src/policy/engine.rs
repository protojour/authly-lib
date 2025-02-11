//! Policy evaluation engine that implements a Policy Decision Point (PDP).

use std::collections::BTreeSet;

use byteorder::{BigEndian, ReadBytesExt};
use fnv::{FnvHashMap, FnvHashSet};
use tracing::error;

use crate::id::{kind::Kind, AttrId, EntityId, PolicyId, PropId};

use super::code::{Bytecode, PolicyValue};

/// Evaluation error.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum EvalError {
    /// Error in the program encoding
    Program,

    /// Type error
    Type,
}

/// The parameters to an policy-based access control evaluation.
///
/// The access control paramaters generall consists of attributes related to a `subject` and a `resource`.
///
/// The `subject` represents the entity or entities requesting access.
/// The `resource` is a representation of the abstract object being requested.
#[derive(Default, Debug)]
pub struct AccessControlParams {
    /// Entity IDs related to the `subject`.
    pub subject_eids: FnvHashMap<PropId, EntityId>,

    /// Attributes related to the `subject`.
    pub subject_attrs: FnvHashSet<AttrId>,

    /// Entity IDs related to the `resource`.
    pub resource_eids: FnvHashMap<PropId, EntityId>,

    /// Attributes related to the `resource`.
    pub resource_attrs: FnvHashSet<AttrId>,
}

/// The state of the policy engine.
///
/// Contains compiled policies and their triggers.
#[derive(Default, Debug)]
pub struct PolicyEngine {
    policies: FnvHashMap<PolicyId, Policy>,

    /// The triggers in this map are keyed by the one of the
    /// attributes that has to match the trigger.
    trigger_groups: FnvHashMap<AttrId, Vec<PolicyTrigger>>,
}

/// The policy trigger maps a set of attributes to a set of policies.
#[derive(Debug)]
struct PolicyTrigger {
    /// The set of attributes that has to match for this policy to trigger
    pub attr_matcher: BTreeSet<AttrId>,

    /// The policy which gets triggered by this attribute matcher
    pub policy_ids: BTreeSet<PolicyId>,
}

/// A tracer used to collect debugging information from the policy engine
#[allow(unused)]
pub trait PolicyTracer {
    /// Reports applicable policies of a specific class
    fn report_applicable(&mut self, class: PolicyValue, policies: impl Iterator<Item = PolicyId>) {}

    /// Report start of a policy evaluation
    fn report_policy_eval_start(&mut self, policy_id: PolicyId) {}

    /// Reports the value of policy after it has been evaluated
    fn report_policy_eval_end(&mut self, value: bool) {}
}

/// A [PolicyTracer] that does nothing.
pub struct NoOpPolicyTracer;

impl PolicyTracer for NoOpPolicyTracer {}

#[derive(Debug)]
struct Policy {
    class: PolicyValue,
    bytecode: Vec<u8>,
}

#[derive(PartialEq, Eq, Debug)]
enum StackItem<'a> {
    Uint(u64),
    AttrIdSet(&'a FnvHashSet<AttrId>),
    EntityId(EntityId),
    AttrId(AttrId),
}

#[derive(Debug)]
struct EvalCtx<'e> {
    applicable_allow: FnvHashMap<PolicyId, &'e Policy>,
    applicable_deny: FnvHashMap<PolicyId, &'e Policy>,
}

impl PolicyEngine {
    /// Adds a new policy to the engine.
    pub fn add_policy(&mut self, id: PolicyId, class: PolicyValue, bytecode: Vec<u8>) {
        self.policies.insert(id, Policy { class, bytecode });
    }

    /// Adds a new policy trigger to the engine.
    pub fn add_trigger(
        &mut self,
        attr_matcher: impl Into<BTreeSet<AttrId>>,
        policy_ids: impl Into<BTreeSet<PolicyId>>,
    ) {
        let attr_matcher = attr_matcher.into();
        let policy_ids = policy_ids.into();

        if let Some(first_attr) = attr_matcher.iter().next() {
            self.trigger_groups
                .entry(*first_attr)
                .or_default()
                .push(PolicyTrigger {
                    attr_matcher,
                    policy_ids,
                });
        }
    }

    /// Get the number of policies currently in the engine.
    pub fn get_policy_count(&self) -> usize {
        self.policies.len()
    }

    /// Get the number of policy triggers currently in the engine.
    pub fn get_trigger_count(&self) -> usize {
        self.trigger_groups.values().map(Vec::len).sum()
    }

    /// Perform an access control evalution of the given parameters within this engine.
    pub fn eval(
        &self,
        params: &AccessControlParams,
        tracer: &mut impl PolicyTracer,
    ) -> Result<PolicyValue, EvalError> {
        let mut eval_ctx = EvalCtx {
            applicable_allow: Default::default(),
            applicable_deny: Default::default(),
        };

        for attr in &params.subject_attrs {
            self.collect_applicable(*attr, params, &mut eval_ctx)?;
        }

        for attr in &params.resource_attrs {
            self.collect_applicable(*attr, params, &mut eval_ctx)?;
        }

        {
            tracer.report_applicable(PolicyValue::Deny, eval_ctx.applicable_deny.keys().copied());
            tracer.report_applicable(
                PolicyValue::Allow,
                eval_ctx.applicable_allow.keys().copied(),
            );
        }

        let has_allow = !eval_ctx.applicable_allow.is_empty();
        let has_deny = !eval_ctx.applicable_deny.is_empty();

        match (has_allow, has_deny) {
            (false, false) => {
                // idea: Fallback mode, no policies matched
                for subj_attr in &params.subject_attrs {
                    if params.resource_attrs.contains(subj_attr) {
                        return Ok(PolicyValue::Allow);
                    }
                }

                Ok(PolicyValue::Deny)
            }
            (true, false) => {
                // starts in Deny state, try to prove Allow
                let is_allow =
                    eval_policies_disjunctive(eval_ctx.applicable_allow, params, tracer)?;
                Ok(PolicyValue::from(is_allow))
            }
            (false, true) => {
                // starts in Allow state, try to prove Deny
                let is_deny = eval_policies_disjunctive(eval_ctx.applicable_deny, params, tracer)?;
                Ok(PolicyValue::from(!is_deny))
            }
            (true, true) => {
                // starts in Deny state, try to prove Allow
                let is_allow =
                    eval_policies_disjunctive(eval_ctx.applicable_allow, params, tracer)?;
                if !is_allow {
                    return Ok(PolicyValue::Deny);
                }

                // moved into in Allow state, try to prove Deny
                let is_deny = eval_policies_disjunctive(eval_ctx.applicable_deny, params, tracer)?;
                Ok(PolicyValue::from(!is_deny))
            }
        }
    }

    fn collect_applicable<'e>(
        &'e self,
        attr: AttrId,
        params: &AccessControlParams,
        eval_ctx: &mut EvalCtx<'e>,
    ) -> Result<(), EvalError> {
        // Find all potential triggers to investigate for this attribute
        let Some(policy_triggers) = self.trigger_groups.get(&attr) else {
            return Ok(());
        };

        for policy_trigger in policy_triggers {
            if policy_trigger.attr_matcher.len() > 1 {
                // a multi-attribute trigger: needs some post-processing
                // to figure out if it applies
                let mut matches: BTreeSet<AttrId> = Default::default();

                for attrs in [&params.subject_attrs, &params.resource_attrs] {
                    for attr in attrs {
                        if policy_trigger.attr_matcher.contains(attr) {
                            matches.insert(*attr);
                        }
                    }
                }

                if matches != policy_trigger.attr_matcher {
                    // not applicable
                    continue;
                }
            }

            // The trigger applies; register all its policies as applicable
            for policy_id in policy_trigger.policy_ids.iter().copied() {
                let Some(policy) = self.policies.get(&policy_id) else {
                    error!(?policy_id, "policy is missing");

                    // internal error, which is not exposed
                    continue;
                };

                match policy.class {
                    PolicyValue::Deny => {
                        eval_ctx.applicable_deny.insert(policy_id, policy);
                    }
                    PolicyValue::Allow => {
                        eval_ctx.applicable_allow.insert(policy_id, policy);
                    }
                }
            }
        }

        Ok(())
    }
}

/// Evaluate set of policies, map their outputs to a boolean value and return the OR function applied to those values.
fn eval_policies_disjunctive(
    map: FnvHashMap<PolicyId, &Policy>,
    params: &AccessControlParams,
    tracer: &mut impl PolicyTracer,
) -> Result<bool, EvalError> {
    for (policy_id, policy) in &map {
        tracer.report_policy_eval_start(*policy_id);

        let value = eval_policy(&policy.bytecode, params)?;

        tracer.report_policy_eval_end(value);

        if value {
            return Ok(true);
        }
    }

    Ok(false)
}

/// Evaluate one standalone policy on the given access control parameters
fn eval_policy(mut pc: &[u8], params: &AccessControlParams) -> Result<bool, EvalError> {
    let mut stack: Vec<StackItem> = Vec::with_capacity(16);

    while let Some(code) = pc.first() {
        pc = &pc[1..];

        let Ok(code) = Bytecode::try_from(*code) else {
            return Err(EvalError::Program);
        };

        match code {
            Bytecode::LoadSubjectId => {
                let prop_id = PropId::from_uint(pc.read_u128::<BigEndian>()?);
                let Some(id) = params.subject_eids.get(&prop_id) else {
                    return Err(EvalError::Type);
                };
                stack.push(StackItem::EntityId(*id));
            }
            Bytecode::LoadSubjectAttrs => {
                stack.push(StackItem::AttrIdSet(&params.subject_attrs));
            }
            Bytecode::LoadResourceId => {
                let prop_id = PropId::from_uint(pc.read_u128::<BigEndian>()?);
                let Some(id) = params.resource_eids.get(&prop_id) else {
                    return Err(EvalError::Type);
                };
                stack.push(StackItem::EntityId(*id));
            }
            Bytecode::LoadResourceAttrs => {
                stack.push(StackItem::AttrIdSet(&params.resource_attrs));
            }
            Bytecode::LoadConstEntityId => {
                let Ok(kind) = Kind::try_from(pc.read_u8()?) else {
                    return Err(EvalError::Type);
                };
                let uint = pc.read_u128::<BigEndian>()?;
                stack.push(StackItem::EntityId(EntityId::new(kind, uint.to_be_bytes())));
            }
            Bytecode::LoadConstAttrId => {
                let attr_id = AttrId::from_uint(pc.read_u128::<BigEndian>()?);
                stack.push(StackItem::AttrId(attr_id));
            }
            Bytecode::IsEq => {
                let Some(a) = stack.pop() else {
                    return Err(EvalError::Type);
                };
                let Some(b) = stack.pop() else {
                    return Err(EvalError::Type);
                };
                let is_eq = match (a, b) {
                    (StackItem::AttrId(a), StackItem::AttrId(b)) => a == b,
                    (StackItem::EntityId(a), StackItem::EntityId(b)) => a == b,
                    (StackItem::AttrIdSet(set), StackItem::AttrId(id)) => set.contains(&id),
                    (StackItem::AttrId(id), StackItem::AttrIdSet(set)) => set.contains(&id),
                    _ => false,
                };
                stack.push(StackItem::Uint(if is_eq { 1 } else { 0 }));
            }
            Bytecode::SupersetOf => {
                let Some(StackItem::AttrIdSet(a)) = stack.pop() else {
                    return Err(EvalError::Type);
                };
                let Some(StackItem::AttrIdSet(b)) = stack.pop() else {
                    return Err(EvalError::Type);
                };
                stack.push(StackItem::Uint(if a.is_superset(b) { 1 } else { 0 }));
            }
            Bytecode::IdSetContains => {
                let Some(a) = stack.pop() else {
                    return Err(EvalError::Type);
                };
                let Some(b) = stack.pop() else {
                    return Err(EvalError::Type);
                };

                match (a, b) {
                    (StackItem::AttrIdSet(a), StackItem::AttrId(b)) => {
                        // BUG: Does not support u128?
                        stack.push(StackItem::Uint(if a.contains(&b) { 1 } else { 0 }));
                    }
                    _ => {
                        return Err(EvalError::Type);
                    }
                }
            }
            Bytecode::And => {
                let Some(StackItem::Uint(rhs)) = stack.pop() else {
                    return Err(EvalError::Type);
                };
                let Some(StackItem::Uint(lhs)) = stack.pop() else {
                    return Err(EvalError::Type);
                };
                stack.push(StackItem::Uint(if rhs > 0 && lhs > 0 { 1 } else { 0 }));
            }
            Bytecode::Or => {
                let Some(StackItem::Uint(rhs)) = stack.pop() else {
                    return Err(EvalError::Type);
                };
                let Some(StackItem::Uint(lhs)) = stack.pop() else {
                    return Err(EvalError::Type);
                };
                stack.push(StackItem::Uint(if rhs > 0 || lhs > 0 { 1 } else { 0 }));
            }
            Bytecode::Not => {
                let Some(StackItem::Uint(val)) = stack.pop() else {
                    return Err(EvalError::Type);
                };
                stack.push(StackItem::Uint(if val > 0 { 0 } else { 1 }));
            }
            Bytecode::Return => {
                let Some(StackItem::Uint(u)) = stack.pop() else {
                    return Err(EvalError::Type);
                };
                return Ok(u > 0);
            }
        }
    }

    Err(EvalError::Program)
}

impl From<std::io::Error> for EvalError {
    fn from(_value: std::io::Error) -> Self {
        EvalError::Program
    }
}
