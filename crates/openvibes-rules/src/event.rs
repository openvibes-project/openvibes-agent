//! The `event` binding and per-event evaluation of `process_event` rules
//! (protocol P14). Rules are parsed, type-checked and bounded in cost once
//! per verified bundle; each process start then only runs them.

use std::{collections::BTreeMap, fmt, time::Duration};

use cel::{
    IdedExpr,
    common::ast::{Expr, LiteralValue, operators as op},
};
use openvibes_core::{Identifier, ResourceLimits, Rule, RuleKind, RuleSet};

use crate::{
    EvaluationClock, EvaluationError as Error, VerifiedRuleSet,
    evaluation::Meter,
    subset::{self, Bindings, Type, Value, method_cost},
};

/// Value types of the `event` keys.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EventType {
    /// A string.
    String,
    /// A signed integer.
    Integer,
    /// A Boolean.
    Boolean,
    /// A sorted list of distinct strings.
    Strings,
}

/// The closed `event` key set (contract, "Process events and alarms"):
/// key, type, and the maximum bytes of a value (or of one list item).
pub const EVENT_KEYS: &[(&str, EventType, usize)] = &[
    ("process.exe", EventType::String, 4_096),
    ("process.name", EventType::String, 4_096),
    ("process.cmdline", EventType::String, 262_144),
    ("process.cmdline_truncated", EventType::Boolean, 1),
    ("process.cwd", EventType::String, 4_096),
    ("process.uid", EventType::Integer, 8),
    ("process.euid", EventType::Integer, 8),
    ("parent.exe", EventType::String, 4_096),
    ("parent.name", EventType::String, 4_096),
    ("parent.cmdline", EventType::String, 262_144),
    ("ancestors.names", EventType::Strings, 4_096),
    ("ancestors.exes", EventType::Strings, 4_096),
];

/// Items in an ancestors list.
pub const EVENT_LIST_ITEMS: usize = 5;

fn key_entry(key: &str) -> Option<&'static (&'static str, EventType, usize)> {
    EVENT_KEYS.iter().find(|(name, _, _)| *name == key)
}

fn event_type(ty: EventType) -> Type {
    match ty {
        EventType::String => Type::String,
        EventType::Integer => Type::Int,
        EventType::Boolean => Type::Bool,
        EventType::Strings => Type::Strings,
    }
}

/// One `event` value.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EventValue {
    /// A string.
    String(String),
    /// A signed integer.
    Integer(i64),
    /// A Boolean.
    Boolean(bool),
    /// A sorted list of distinct strings.
    Strings(Vec<String>),
}

/// Why an `event` value was refused.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EventError {
    /// The key is not in [`EVENT_KEYS`].
    UnknownKey,
    /// The value's type is not the key's.
    WrongType,
    /// A value, list item or list is over its bound.
    TooLarge,
    /// A list is not sorted by byte order without duplicates.
    NotSorted,
}

impl fmt::Display for EventError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "event value refused: {self:?}")
    }
}
impl std::error::Error for EventError {}

/// The values of one process start; a key left unset is missing.
#[derive(Clone, Debug, Default)]
pub struct ProcessEvent {
    values: BTreeMap<&'static str, EventValue>,
}

impl ProcessEvent {
    /// Sets one value, checked against the contract's key table.
    pub fn set(&mut self, key: &str, value: EventValue) -> Result<(), EventError> {
        let (name, ty, bound) = key_entry(key).ok_or(EventError::UnknownKey)?;
        match (ty, &value) {
            (EventType::String, EventValue::String(text)) => {
                if text.len() > *bound {
                    return Err(EventError::TooLarge);
                }
            }
            (EventType::Integer, EventValue::Integer(_))
            | (EventType::Boolean, EventValue::Boolean(_)) => {}
            (EventType::Strings, EventValue::Strings(items)) => {
                if items.len() > EVENT_LIST_ITEMS || items.iter().any(|item| item.len() > *bound) {
                    return Err(EventError::TooLarge);
                }
                if items.windows(2).any(|pair| pair[0] >= pair[1]) {
                    return Err(EventError::NotSorted);
                }
            }
            _ => return Err(EventError::WrongType),
        }
        self.values.insert(name, value);
        Ok(())
    }

    fn get(&self, key: &str) -> Option<&EventValue> {
        self.values.get(key)
    }
}

impl<'a> Bindings<'a> for &'a ProcessEvent {
    const NAME: &'static str = "event";

    fn type_of(&self, key: &str) -> Result<Type, Error> {
        key_entry(key)
            .map(|(_, ty, _)| event_type(*ty))
            .ok_or(Error::UnsupportedExpression)
    }

    fn value(&self, key: &str) -> Result<Value<'a>, Error> {
        Ok(match self.get(key).ok_or(Error::UnavailableFact)? {
            EventValue::String(text) => Value::String(text),
            EventValue::Integer(value) => Value::Int(*value),
            EventValue::Boolean(value) => Value::Bool(*value),
            EventValue::Strings(items) => Value::Strings(items),
        })
    }
}

/// The key table without values, for compiling.
struct Schema;

impl<'a> Bindings<'a> for Schema {
    const NAME: &'static str = "event";

    fn type_of(&self, key: &str) -> Result<Type, Error> {
        key_entry(key)
            .map(|(_, ty, _)| event_type(*ty))
            .ok_or(Error::UnsupportedExpression)
    }

    fn value(&self, _key: &str) -> Result<Value<'a>, Error> {
        Err(Error::UnsupportedExpression)
    }
}

/// A clock that stands still at the bundle's creation, for compiling.
struct CompileClock(i64);

impl EvaluationClock for CompileClock {
    fn elapsed(&self) -> Duration {
        Duration::ZERO
    }
    fn unix_ms(&self) -> i64 {
        self.0
    }
}

struct CompiledRule {
    rule_id: Identifier,
    ast: IdedExpr,
    programs: Option<Vec<String>>,
}

/// A bundle's `process_event` rules, compiled once.
pub struct CompiledEventRules {
    rules: Vec<CompiledRule>,
    limits: ResourceLimits,
    /// Rules refused at compile, with why; they never run.
    pub refused: Vec<(Identifier, Error)>,
}

/// The outcome of one rule on one event.
#[derive(Clone, Debug)]
pub struct EventOutcome {
    /// The rule that ran.
    pub rule_id: Identifier,
    /// It matched: an alarm.
    pub matched: bool,
    /// A value it needs is missing.
    pub unavailable: bool,
    /// It failed (budget, deadline, type); never an alarm.
    pub failure: Option<Error>,
}

/// Parses, type-checks and bounds the cost of every `process_event` rule of
/// `bundle`. A rule whose worst case exceeds the operation limit is refused
/// here, so no input can push an accepted rule over its budget.
#[must_use]
pub fn compile_event_rules(bundle: &VerifiedRuleSet, limits: ResourceLimits) -> CompiledEventRules {
    let clock = CompileClock(bundle.created_at_unix_ms());
    let mut compiled = CompiledEventRules {
        rules: Vec::new(),
        limits,
        refused: Vec::new(),
    };
    for rule in bundle
        .rules()
        .rules
        .iter()
        .filter(|rule| rule.kind == RuleKind::ProcessEvent)
    {
        let mut meter = Meter::new(&clock, bundle, limits);
        match compile(&rule.expression, &mut meter, limits) {
            Ok(ast) => compiled.rules.push(CompiledRule {
                rule_id: rule.id.clone(),
                ast,
                programs: rule.programs.clone(),
            }),
            Err(error) => compiled.refused.push((rule.id.clone(), error)),
        }
    }
    compiled
}

/// Parses, type-checks against the `event` keys and bounds the worst case.
fn compile<C: EvaluationClock>(
    expression: &str,
    meter: &mut Meter<'_, C>,
    limits: ResourceLimits,
) -> Result<IdedExpr, Error> {
    let ast = subset::parse(expression, "event", meter)?;
    let mut evidence = BTreeMap::new();
    let mut nodes = 0;
    if subset::check(&ast, &Schema, meter, 1, &mut nodes, &mut evidence)? != Type::Bool {
        return Err(Error::NonBoolean);
    }
    if worst_case(&ast)?.0 > limits.evaluation_operations {
        return Err(Error::OperationLimit);
    }
    Ok(ast)
}

/// The loader's static check (contract "Subset v2 (P14)"): every
/// `process_event` rule compiles, and every snapshot rule parses within the
/// subset with valid method calls. Fact types and missing facts are still
/// decided per rule at scan time (facts are dynamic).
pub(crate) fn check_rule_set(rules: &RuleSet, limits: ResourceLimits) -> Result<(), Error> {
    rules
        .rules
        .iter()
        .try_for_each(|rule| check_rule(rule, limits))
}

/// One rule's static check, with the exact error: what the loader refuses
/// (and so what no signing tool can produce).
pub fn check_rule(rule: &Rule, limits: ResourceLimits) -> Result<(), Error> {
    let clock = CompileClock(0);
    let mut meter = Meter::unbound(&clock, limits);
    match rule.kind {
        RuleKind::ProcessEvent => compile(&rule.expression, &mut meter, limits).map(drop),
        RuleKind::Snapshot => {
            let ast = subset::parse(&rule.expression, "facts", &mut meter)?;
            subset::check_method_shapes(&ast)
        }
    }
}

impl CompiledEventRules {
    /// Accepted rules.
    #[must_use]
    pub fn rules(&self) -> usize {
        self.rules.len()
    }

    /// Runs every accepted rule on `event`, skipping a rule whose `programs`
    /// name neither the event's `process.exe` nor its `process.name`.
    pub fn evaluate(
        &self,
        bundle: &VerifiedRuleSet,
        event: &ProcessEvent,
        clock: &impl EvaluationClock,
    ) -> Vec<EventOutcome> {
        let text = |key| match event.get(key) {
            Some(EventValue::String(text)) => Some(text.as_str()),
            _ => None,
        };
        let (exe, name) = (text("process.exe"), text("process.name"));
        let mut outcomes = Vec::new();
        for rule in &self.rules {
            if let Some(programs) = &rule.programs {
                let named = programs
                    .iter()
                    .any(|program| Some(program.as_str()) == exe || Some(program.as_str()) == name);
                if !named {
                    continue;
                }
            }
            let mut meter = Meter::new(clock, bundle, self.limits);
            let result = subset::run(&rule.ast, &event, &mut meter);
            let mut outcome = EventOutcome {
                rule_id: rule.rule_id.clone(),
                matched: false,
                unavailable: false,
                failure: None,
            };
            match result {
                Ok(Value::Bool(matched)) => outcome.matched = matched,
                Ok(_) => outcome.failure = Some(Error::NonBoolean),
                Err(Error::UnavailableFact) => outcome.unavailable = true,
                Err(error) => outcome.failure = Some(error),
            }
            outcomes.push(outcome);
        }
        outcomes
    }
}

/// `event['key']` → the key.
fn event_key(ast: &IdedExpr) -> Option<&str> {
    let Expr::Call(call) = &ast.expr else {
        return None;
    };
    match (
        call.func_name.as_str(),
        call.target.is_none(),
        call.args.as_slice(),
    ) {
        (
            op::INDEX,
            true,
            [
                IdedExpr {
                    expr: Expr::Ident(name),
                    ..
                },
                IdedExpr {
                    expr: Expr::Literal(LiteralValue::String(key)),
                    ..
                },
            ],
        ) if name == "event" => Some(key.inner()),
        _ => None,
    }
}

/// The largest total `subset::run` can charge for `ast`, and the largest
/// byte length its value can have; every branch counts, including those a
/// short circuit would skip. Mirrors each `meter.charge` in `run`.
fn worst_case(ast: &IdedExpr) -> Result<(u64, u64), Error> {
    if let Some(key) = event_key(ast) {
        let (_, _, bound) = key_entry(key).ok_or(Error::UnsupportedExpression)?;
        return Ok((1 + key.len() as u64 + 2, *bound as u64));
    }
    match &ast.expr {
        Expr::Literal(LiteralValue::String(value)) => Ok((1, value.inner().len() as u64)),
        Expr::Literal(_) => Ok((1, 0)),
        Expr::Call(call) if call.target.is_some() => {
            let target = call.target.as_deref().ok_or(Error::UnsupportedExpression)?;
            let (cost, length) = worst_case(target)?;
            Ok((1 + cost + method_cost(length as usize), 0))
        }
        Expr::Call(call) => match call.args.as_slice() {
            [value] => Ok((1 + worst_case(value)?.0, 0)),
            [left, right] => {
                let (left_cost, left_len) = worst_case(left)?;
                let (right_cost, right_len) = worst_case(right)?;
                let extra = match call.func_name.as_str() {
                    op::LOGICAL_AND | op::LOGICAL_OR => 0,
                    // At most 3 probes over at most 5 items, each charged
                    // 1 + needle + item.
                    op::IN => 3 * (1 + left_len + right_len),
                    _ => left_len + right_len,
                };
                Ok((1 + left_cost + right_cost + extra, 0))
            }
            _ => Err(Error::UnsupportedExpression),
        },
        _ => Err(Error::UnsupportedExpression),
    }
}
