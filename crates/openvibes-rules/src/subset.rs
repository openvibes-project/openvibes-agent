use std::{cmp::Ordering, collections::BTreeMap};

use cel::{
    IdedExpr,
    common::ast::{Expr, LiteralValue, operators as op},
    parser::PrattParser,
};
use openvibes_core::{FactValue, Identifier};

use crate::evaluation::{EvaluationClock, EvaluationError as Error, Facts, Meter};

/// Subset v2 (P14): string methods, each with one string literal argument.
pub(crate) const METHODS: [&str; 3] = ["startsWith", "endsWith", "contains"];
/// Longest literal argument of a subset v2 method, in UTF-8 bytes.
pub(crate) const LITERAL_BYTES: usize = 256;

/// A subset v2 method's charge: one operation per started 64 bytes of the
/// receiver (the search itself is linear: `str` uses Two-Way).
pub(crate) fn method_cost(receiver_len: usize) -> u64 {
    (receiver_len as u64).div_ceil(64).max(1)
}

/// The receiver and literal of a subset v2 method call, if `call` is one.
fn method_call(call: &cel::common::ast::CallExpr) -> Result<(&IdedExpr, &str), Error> {
    match (call.target.as_deref(), call.args.as_slice()) {
        (
            Some(target),
            [
                IdedExpr {
                    expr: Expr::Literal(LiteralValue::String(literal)),
                    ..
                },
            ],
        ) if METHODS.contains(&call.func_name.as_str())
            && literal.inner().len() <= LITERAL_BYTES =>
        {
            Ok((target, literal.inner()))
        }
        _ => Err(Error::UnsupportedExpression),
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub(crate) enum Type {
    Bool,
    Int,
    String,
    Strings,
}

#[derive(Clone, Copy)]
pub(crate) enum Value<'a> {
    Bool(bool),
    Int(i64),
    String(&'a str),
    Strings(&'a [String]),
}

/// What an expression may index: `facts` for snapshot rules, `event` for
/// `process_event` rules. Nothing else is reachable from CEL.
pub(crate) trait Bindings<'a> {
    /// The one identifier an expression may index.
    const NAME: &'static str;
    /// The key's type, `UnsupportedExpression` for a key that cannot exist,
    /// or `UnavailableFact` for a fact that is missing.
    fn type_of(&self, key: &str) -> Result<Type, Error>;
    /// The key's value, or `UnavailableFact` when it is missing.
    fn value(&self, key: &str) -> Result<Value<'a>, Error>;
    /// The evidence identifier a referenced key contributes (facts only).
    fn evidence(&self, _key: &str) -> Option<&'a Identifier> {
        None
    }
}

impl<'a> Bindings<'a> for Facts<'a> {
    const NAME: &'static str = "facts";

    fn type_of(&self, key: &str) -> Result<Type, Error> {
        Ok(match self.get(key)?.value {
            FactValue::Boolean(_) => Type::Bool,
            FactValue::Integer(_) => Type::Int,
            FactValue::String(_) => Type::String,
            FactValue::StringList(_) => Type::Strings,
        })
    }

    fn value(&self, key: &str) -> Result<Value<'a>, Error> {
        Ok(match &self.get(key)?.value {
            FactValue::Boolean(value) => Value::Bool(*value),
            FactValue::Integer(value) => Value::Int(*value),
            FactValue::String(value) => Value::String(value),
            FactValue::StringList(value) => Value::Strings(value),
        })
    }

    fn evidence(&self, key: &str) -> Option<&'a Identifier> {
        self.get(key).ok().map(|fact| &fact.key)
    }
}

/// Size-checks, preflights and parses `source`; `name` is the only
/// identifier it may index.
pub(crate) fn parse(
    source: &str,
    name: &str,
    meter: &mut Meter<'_, impl EvaluationClock>,
) -> Result<IdedExpr, Error> {
    if source.len() > meter.limits.expression_bytes {
        return Err(Error::ExpressionLimit);
    }
    meter.charge(source.len() as u64)?;
    preflight(source, name, meter)?;
    let ast = PrattParser::new()
        .max_recursion_depth(meter.limits.expression_depth as u16)
        .max_expression_node_count(meter.limits.expression_nodes)
        .error_recovery_limit(0)
        .error_reporting_limit(1)
        .parse(source)
        .map_err(|_| Error::InvalidExpression)?;
    meter.charge(0)?;
    Ok(ast)
}

pub(crate) fn evaluate(
    source: &str,
    facts: &Facts<'_>,
    meter: &mut Meter<'_, impl EvaluationClock>,
) -> Result<(bool, Vec<Identifier>), Error> {
    let ast = parse(source, "facts", meter)?;
    let mut evidence = BTreeMap::new();
    let mut nodes = 0;
    if check(&ast, facts, meter, 1, &mut nodes, &mut evidence)? != Type::Bool {
        return Err(Error::NonBoolean);
    }
    let result = run(&ast, facts, meter)?;
    meter.charge(0)?;
    match result {
        Value::Bool(value) => Ok((value, evidence.values().map(|id| (*id).clone()).collect())),
        _ => Err(Error::NonBoolean),
    }
}

// Reject macros/functions before handing input to the upstream parser. This
// bounds macro expansion as well as the source/AST token and nesting sizes.
fn preflight(
    source: &str,
    name: &str,
    meter: &mut Meter<'_, impl EvaluationClock>,
) -> Result<(), Error> {
    let bytes = source.as_bytes();
    let mut i = 0;
    let mut tokens = 0;
    let mut nesting = 0usize;
    while i < bytes.len() {
        meter.charge(0)?;
        let byte = bytes[i];
        if byte.is_ascii_whitespace() {
            i += 1;
            continue;
        }
        tokens += 1;
        if tokens > meter.limits.expression_nodes {
            return Err(Error::ExpressionLimit);
        }
        match byte {
            b'\'' | b'"' => {
                let quote = byte;
                if bytes.get(i..i + 3).is_some_and(|slice| slice == [quote; 3]) {
                    return Err(Error::UnsupportedExpression);
                }
                i += 1;
                let mut closed = false;
                while i < bytes.len() {
                    if i % 64 == 0 {
                        meter.charge(0)?;
                    }
                    if bytes[i] == quote {
                        i += 1;
                        closed = true;
                        break;
                    }
                    if bytes[i] == b'\\' {
                        i += 1;
                    }
                    i += 1;
                }
                if !closed {
                    return Err(Error::InvalidExpression);
                }
            }
            byte if byte.is_ascii_alphabetic() || byte == b'_' => {
                let start = i;
                while i < bytes.len() && (bytes[i].is_ascii_alphanumeric() || bytes[i] == b'_') {
                    i += 1;
                }
                let word = &source[start..i];
                if word != name
                    && !matches!(word, "in" | "true" | "false")
                    && !METHODS.contains(&word)
                {
                    return Err(Error::UnsupportedExpression);
                }
            }
            byte if byte.is_ascii_digit() => {
                while i < bytes.len() && bytes[i].is_ascii_digit() {
                    i += 1;
                }
            }
            b'(' | b'[' => {
                nesting += 1;
                if nesting > meter.limits.expression_depth {
                    return Err(Error::DepthLimit);
                }
                i += 1;
            }
            b')' | b']' => {
                nesting = nesting.checked_sub(1).ok_or(Error::InvalidExpression)?;
                i += 1;
            }
            b'!' | b'=' | b'<' | b'>' | b'&' | b'|' | b'-' | b'.' => i += 1,
            _ => return Err(Error::UnsupportedExpression),
        }
    }
    if nesting != 0 {
        return Err(Error::InvalidExpression);
    }
    Ok(())
}

/// `NAME['literal key']` → the key.
fn binding_key<'e>(ast: &'e IdedExpr, binding: &str) -> Option<&'e str> {
    let Expr::Call(call) = &ast.expr else {
        return None;
    };
    if call.func_name != op::INDEX || call.target.is_some() {
        return None;
    }
    match call.args.as_slice() {
        [
            IdedExpr {
                expr: Expr::Ident(name),
                ..
            },
            IdedExpr {
                expr: Expr::Literal(LiteralValue::String(key)),
                ..
            },
        ] if name == binding => Some(key.inner()),
        _ => None,
    }
}

pub(crate) fn check<'a, B: Bindings<'a>>(
    ast: &IdedExpr,
    facts: &B,
    meter: &mut Meter<'_, impl EvaluationClock>,
    depth: usize,
    nodes: &mut usize,
    evidence: &mut BTreeMap<&'a str, &'a Identifier>,
) -> Result<Type, Error> {
    meter.charge(1)?;
    *nodes += 1;
    if depth > meter.limits.expression_depth {
        return Err(Error::DepthLimit);
    }
    if *nodes > meter.limits.expression_nodes {
        return Err(Error::ExpressionLimit);
    }
    if let Some(key) = binding_key(ast, B::NAME) {
        *nodes += 2;
        if *nodes > meter.limits.expression_nodes {
            return Err(Error::ExpressionLimit);
        }
        if depth + 1 > meter.limits.expression_depth {
            return Err(Error::DepthLimit);
        }
        if key.len() > meter.limits.identifier_bytes || Identifier::new(key).is_err() {
            return Err(Error::UnsupportedExpression);
        }
        meter.charge(key.len() as u64 + 2)?;
        let ty = facts.type_of(key)?;
        if let Some(id) = facts.evidence(key) {
            evidence.insert(id.as_str(), id);
            if evidence.len() > meter.limits.evidence_per_finding {
                return Err(Error::EvidenceLimit);
            }
        }
        return Ok(ty);
    }
    match &ast.expr {
        Expr::Literal(LiteralValue::Boolean(_)) => Ok(Type::Bool),
        Expr::Literal(LiteralValue::Int(_)) => Ok(Type::Int),
        Expr::Literal(LiteralValue::String(value)) => {
            if value.len() > meter.limits.string_bytes {
                return Err(Error::ExpressionLimit);
            }
            Ok(Type::String)
        }
        Expr::Call(call) if call.target.is_some() => {
            let (target, _) = method_call(call)?;
            if check(target, facts, meter, depth + 1, nodes, evidence)? != Type::String {
                return Err(Error::TypeMismatch);
            }
            Ok(Type::Bool)
        }
        Expr::Call(call) if call.target.is_none() => {
            match (call.func_name.as_str(), call.args.as_slice()) {
                (op::LOGICAL_NOT | op::NEGATE, [value]) => {
                    let ty = check(value, facts, meter, depth + 1, nodes, evidence)?;
                    if call.func_name == op::LOGICAL_NOT && ty == Type::Bool {
                        Ok(Type::Bool)
                    } else if call.func_name == op::NEGATE && ty == Type::Int {
                        Ok(Type::Int)
                    } else {
                        Err(Error::TypeMismatch)
                    }
                }
                (name, [left, right])
                    if matches!(
                        name,
                        op::LOGICAL_AND
                            | op::LOGICAL_OR
                            | op::EQUALS
                            | op::NOT_EQUALS
                            | op::LESS
                            | op::LESS_EQUALS
                            | op::GREATER
                            | op::GREATER_EQUALS
                            | op::IN
                    ) =>
                {
                    let left = check(left, facts, meter, depth + 1, nodes, evidence)?;
                    let right = check(right, facts, meter, depth + 1, nodes, evidence)?;
                    let valid = match name {
                        op::LOGICAL_AND | op::LOGICAL_OR => {
                            left == Type::Bool && right == Type::Bool
                        }
                        op::IN => left == Type::String && right == Type::Strings,
                        op::EQUALS | op::NOT_EQUALS => left == right && left != Type::Strings,
                        _ => left == right && matches!(left, Type::Int | Type::String),
                    };
                    if valid {
                        Ok(Type::Bool)
                    } else {
                        Err(Error::TypeMismatch)
                    }
                }
                _ => Err(Error::UnsupportedExpression),
            }
        }
        _ => Err(Error::UnsupportedExpression),
    }
}

pub(crate) fn run<'a, B: Bindings<'a>>(
    ast: &'a IdedExpr,
    facts: &B,
    meter: &mut Meter<'_, impl EvaluationClock>,
) -> Result<Value<'a>, Error> {
    meter.charge(1)?;
    if let Some(key) = binding_key(ast, B::NAME) {
        meter.charge(key.len() as u64 + 2)?;
        return facts.value(key);
    }
    match &ast.expr {
        Expr::Literal(LiteralValue::Boolean(value)) => Ok(Value::Bool(*value.inner())),
        Expr::Literal(LiteralValue::Int(value)) => Ok(Value::Int(*value.inner())),
        Expr::Literal(LiteralValue::String(value)) => Ok(Value::String(value.inner())),
        Expr::Call(call) if call.target.is_some() => {
            let (target, literal) = method_call(call)?;
            let Value::String(receiver) = run(target, facts, meter)? else {
                return Err(Error::TypeMismatch);
            };
            meter.charge(method_cost(receiver.len()))?;
            Ok(Value::Bool(match call.func_name.as_str() {
                "startsWith" => receiver.starts_with(literal),
                "endsWith" => receiver.ends_with(literal),
                "contains" => receiver.contains(literal),
                _ => return Err(Error::UnsupportedExpression),
            }))
        }
        Expr::Call(call) if call.target.is_none() => {
            match (call.func_name.as_str(), call.args.as_slice()) {
                (op::LOGICAL_NOT, [value]) => match run(value, facts, meter)? {
                    Value::Bool(value) => Ok(Value::Bool(!value)),
                    _ => Err(Error::TypeMismatch),
                },
                (op::NEGATE, [value]) => match run(value, facts, meter)? {
                    Value::Int(value) => value
                        .checked_neg()
                        .map(Value::Int)
                        .ok_or(Error::TypeMismatch),
                    _ => Err(Error::TypeMismatch),
                },
                (name, [left, right]) => {
                    let left = run(left, facts, meter)?;
                    if name == op::LOGICAL_AND && matches!(left, Value::Bool(false)) {
                        return Ok(Value::Bool(false));
                    }
                    if name == op::LOGICAL_OR && matches!(left, Value::Bool(true)) {
                        return Ok(Value::Bool(true));
                    }
                    let right = run(right, facts, meter)?;
                    match name {
                        op::LOGICAL_AND | op::LOGICAL_OR => match (left, right) {
                            (Value::Bool(a), Value::Bool(b)) => {
                                Ok(Value::Bool(if name == op::LOGICAL_AND {
                                    a && b
                                } else {
                                    a || b
                                }))
                            }
                            _ => Err(Error::TypeMismatch),
                        },
                        op::IN => match (left, right) {
                            // Fact lists are sorted and unique (checked when
                            // the fact set is indexed), so this is a binary
                            // search charged per probe.
                            (Value::String(needle), Value::Strings(values)) => {
                                let (mut low, mut high) = (0, values.len());
                                while low < high {
                                    let middle = low + (high - low) / 2;
                                    let value = values[middle].as_str();
                                    meter.charge(1 + needle.len() as u64 + value.len() as u64)?;
                                    match value.cmp(needle) {
                                        std::cmp::Ordering::Less => low = middle + 1,
                                        std::cmp::Ordering::Greater => high = middle,
                                        std::cmp::Ordering::Equal => return Ok(Value::Bool(true)),
                                    }
                                }
                                Ok(Value::Bool(false))
                            }
                            _ => Err(Error::TypeMismatch),
                        },
                        _ => {
                            let order = match (left, right) {
                                (Value::Bool(a), Value::Bool(b)) => a.cmp(&b),
                                (Value::Int(a), Value::Int(b)) => a.cmp(&b),
                                (Value::String(a), Value::String(b)) => {
                                    meter.charge(a.len() as u64 + b.len() as u64)?;
                                    a.cmp(b)
                                }
                                _ => return Err(Error::TypeMismatch),
                            };
                            let value = match name {
                                op::EQUALS => order == Ordering::Equal,
                                op::NOT_EQUALS => order != Ordering::Equal,
                                op::LESS => order == Ordering::Less,
                                op::LESS_EQUALS => order != Ordering::Greater,
                                op::GREATER => order == Ordering::Greater,
                                op::GREATER_EQUALS => order != Ordering::Less,
                                _ => return Err(Error::UnsupportedExpression),
                            };
                            Ok(Value::Bool(value))
                        }
                    }
                }
                _ => Err(Error::UnsupportedExpression),
            }
        }
        _ => Err(Error::UnsupportedExpression),
    }
}
