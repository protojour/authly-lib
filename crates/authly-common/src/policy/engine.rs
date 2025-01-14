//! Policy evaluation engine that implements a Policy Decision Point (PDP).

use std::collections::BTreeSet;

use fnv::{FnvHashMap, FnvHashSet};
use tracing::error;

use crate::id::{AnyId, ObjId};

use super::code::{Bytecode, Outcome};

/// Evaluation error.
#[derive(Debug)]
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
    pub subject_eids: FnvHashMap<AnyId, AnyId>,

    /// Attributes related to the `subject`.
    pub subject_attrs: FnvHashSet<AnyId>,

    /// Entity IDs related to the `resource`.
    pub resource_eids: FnvHashMap<AnyId, AnyId>,

    /// Attributes related to the `resource`.
    pub resource_attrs: FnvHashSet<AnyId>,
}

/// The state of the policy engine.
///
/// Contains compiled policies and their triggers.
#[derive(Default, Debug)]
pub struct PolicyEngine {
    policies: FnvHashMap<PolicyId, Policy>,

    /// Policy triggers: The hash map is keyed by the smallest attribute in the match set
    policy_triggers: FnvHashMap<AnyId, PolicyTrigger>,
}

/// The policy trigger maps a set of attributes to a policy.
#[derive(Debug)]
struct PolicyTrigger {
    /// The set of attributes that has to match for this policy to trigger
    pub attr_matcher: BTreeSet<AnyId>,

    /// The policy which gets triggered by this attribute matcher
    pub policy_id: PolicyId,
}

/// A placeholder for how to refer to a local policy
type PolicyId = AnyId;

#[derive(Debug)]
struct Policy {
    bytecode: Vec<u8>,
}

#[derive(PartialEq, Eq, Debug)]
enum StackItem<'a> {
    Uint(u64),
    IdSet(&'a FnvHashSet<AnyId>),
    Id(AnyId),
}

struct EvalCtx {
    outcomes: Vec<Outcome>,
    evaluated_policies: FnvHashSet<PolicyId>,
}

impl PolicyEngine {
    /// Adds a new policy to the engine.
    pub fn add_policy(&mut self, id: ObjId, policy_bytecode: Vec<u8>) {
        self.policies.insert(
            id.to_any(),
            Policy {
                bytecode: policy_bytecode,
            },
        );
    }

    /// Adds a new policy trigger to the engine.
    pub fn add_policy_trigger(&mut self, attr_matcher: BTreeSet<AnyId>, policy_id: ObjId) {
        if let Some(first_attr) = attr_matcher.iter().next() {
            self.policy_triggers.insert(
                first_attr.to_any(),
                PolicyTrigger {
                    attr_matcher,
                    policy_id: policy_id.to_any(),
                },
            );
        }
    }

    /// Get the number of policies currently in the engine.
    pub fn get_policy_count(&self) -> usize {
        self.policies.len()
    }

    /// Get the number of policy triggers currently in the engine.
    pub fn get_trigger_count(&self) -> usize {
        self.policy_triggers.len()
    }

    /// Perform an access control evalution of the given parameters within this engine.
    pub fn eval(&self, params: &AccessControlParams) -> Result<Outcome, EvalError> {
        let mut eval_ctx = EvalCtx {
            outcomes: vec![],
            evaluated_policies: Default::default(),
        };

        for attr in &params.subject_attrs {
            self.eval_triggers(*attr, params, &mut eval_ctx)?;
        }

        for attr in &params.resource_attrs {
            self.eval_triggers(*attr, params, &mut eval_ctx)?;
        }

        if eval_ctx.outcomes.is_empty() {
            // idea: Fallback mode, no policies matched
            for subj_attr in &params.subject_attrs {
                if params.resource_attrs.contains(subj_attr) {
                    return Ok(Outcome::Allow);
                }
            }

            Ok(Outcome::Deny)
        } else if eval_ctx
            .outcomes
            .iter()
            .any(|outcome| matches!(outcome, Outcome::Deny))
        {
            Ok(Outcome::Deny)
        } else {
            Ok(Outcome::Allow)
        }
    }

    fn eval_triggers(
        &self,
        attr: AnyId,
        params: &AccessControlParams,
        eval_ctx: &mut EvalCtx,
    ) -> Result<(), EvalError> {
        if let Some(policy_trigger) = self.policy_triggers.get(&attr) {
            if eval_ctx
                .evaluated_policies
                .contains(&policy_trigger.policy_id)
            {
                // already evaluated
                return Ok(());
            }

            let mut n_matches = 0;

            for attrs in [&params.subject_attrs, &params.resource_attrs] {
                for attr in attrs {
                    if policy_trigger.attr_matcher.contains(attr) {
                        n_matches += 1;
                    }
                }
            }

            if n_matches < policy_trigger.attr_matcher.len() {
                // not a match; no policy evaluated
                return Ok(());
            }

            let policy_id = policy_trigger.policy_id;

            let Some(policy) = self.policies.get(&policy_id) else {
                error!(?policy_id, "policy is missing");

                // internal error, which is not exposed
                return Ok(());
            };

            // register this policy as evaluated, to avoid re-triggering
            eval_ctx.evaluated_policies.insert(policy_trigger.policy_id);

            // evaluate policy outcome
            eval_ctx
                .outcomes
                .push(eval_policy(&policy.bytecode, params)?);
        }

        Ok(())
    }
}

fn eval_policy(mut pc: &[u8], params: &AccessControlParams) -> Result<Outcome, EvalError> {
    // println!("eval policy");

    let mut stack: Vec<StackItem> = Vec::with_capacity(16);

    while let Some(code) = pc.first() {
        // println!("    stack {stack:?}");

        pc = &pc[1..];

        let Ok(code) = Bytecode::try_from(*code) else {
            return Err(EvalError::Program);
        };

        // println!("  eval code {code:?}");

        match code {
            Bytecode::LoadSubjectId => {
                let (key, next) = decode_id(pc)?;
                let Some(id) = params.subject_eids.get(&key) else {
                    return Err(EvalError::Type);
                };
                stack.push(StackItem::Id(*id));
                pc = next;
            }
            Bytecode::LoadSubjectAttrs => {
                stack.push(StackItem::IdSet(&params.subject_attrs));
            }
            Bytecode::LoadResourceId => {
                let (key, next) = decode_id(pc)?;
                let Some(id) = params.resource_eids.get(&key) else {
                    return Err(EvalError::Type);
                };
                stack.push(StackItem::Id(*id));
                pc = next;
            }
            Bytecode::LoadResourceAttrs => {
                stack.push(StackItem::IdSet(&params.resource_attrs));
            }
            Bytecode::LoadConstId => {
                let (id, next) = decode_id(pc)?;
                stack.push(StackItem::Id(id));
                pc = next;
            }
            Bytecode::IsEq => {
                let Some(a) = stack.pop() else {
                    return Err(EvalError::Type);
                };
                let Some(b) = stack.pop() else {
                    return Err(EvalError::Type);
                };
                let is_eq = match (a, b) {
                    (StackItem::Id(a), StackItem::Id(b)) => a == b,
                    (StackItem::IdSet(set), StackItem::Id(id)) => set.contains(&id),
                    (StackItem::Id(id), StackItem::IdSet(set)) => set.contains(&id),
                    _ => false,
                };
                stack.push(StackItem::Uint(if is_eq { 1 } else { 0 }));
            }
            Bytecode::SupersetOf => {
                let Some(StackItem::IdSet(a)) = stack.pop() else {
                    return Err(EvalError::Type);
                };
                let Some(StackItem::IdSet(b)) = stack.pop() else {
                    return Err(EvalError::Type);
                };
                stack.push(StackItem::Uint(if a.is_superset(b) { 1 } else { 0 }));
            }
            Bytecode::IdSetContains => {
                let Some(StackItem::IdSet(set)) = stack.pop() else {
                    return Err(EvalError::Type);
                };
                let Some(StackItem::Id(arg)) = stack.pop() else {
                    return Err(EvalError::Type);
                };
                // BUG: Does not support u128
                stack.push(StackItem::Uint(if set.contains(&arg) { 1 } else { 0 }));
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
            Bytecode::TrueThenAllow => {
                let Some(StackItem::Uint(u)) = stack.pop() else {
                    return Err(EvalError::Type);
                };
                if u > 0 {
                    return Ok(Outcome::Allow);
                }
            }
            Bytecode::TrueThenDeny => {
                let Some(StackItem::Uint(u)) = stack.pop() else {
                    return Err(EvalError::Type);
                };
                if u > 0 {
                    return Ok(Outcome::Deny);
                }
            }
            Bytecode::FalseThenAllow => {
                let Some(StackItem::Uint(u)) = stack.pop() else {
                    return Err(EvalError::Type);
                };
                if u == 0 {
                    return Ok(Outcome::Allow);
                }
            }
            Bytecode::FalseThenDeny => {
                let Some(StackItem::Uint(u)) = stack.pop() else {
                    return Err(EvalError::Type);
                };
                if u == 0 {
                    return Ok(Outcome::Deny);
                }
            }
        }
    }

    Ok(Outcome::Deny)
}

fn decode_id(buf: &[u8]) -> Result<(AnyId, &[u8]), EvalError> {
    let (uint, next) = unsigned_varint::decode::u128(buf).map_err(|_| EvalError::Program)?;

    Ok((AnyId::from_uint(uint), next))
}
