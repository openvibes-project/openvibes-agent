use std::{cmp::Ordering, collections::BTreeMap};

use cel::{
    IdedExpr,
    common::ast::{Expr, LiteralValue, operators as op},
    parser::PrattParser,
};
use ovsvms_core::{FactValue, Identifier};

use crate::evaluation::{EvaluationClock, EvaluationError as Error, Facts, Meter};

#[derive(Clone, Copy, PartialEq)]
enum Type {
    Bool,
    Int,
    String,
    Strings,
}

#[derive(Clone, Copy)]
enum Value<'a> {
    Bool(bool),
    Int(i64),
    String(&'a str),
    Strings(&'a [String]),
}

pub(crate) fn evaluate(
    source: &str,
    facts: &Facts<'_>,
    meter: &mut Meter<'_, impl EvaluationClock>,
) -> Result<(bool, Vec<Identifier>), Error> {
    if source.len() > meter.limits.expression_bytes {
        return Err(Error::ExpressionLimit);
    }
    meter.charge(source.len() as u64)?;
    preflight(source, meter)?;
    let ast = PrattParser::new()
        .max_recursion_depth(meter.limits.expression_depth as u16)
        .max_expression_node_count(meter.limits.expression_nodes)
        .error_recovery_limit(0)
        .error_reporting_limit(1)
        .parse(source)
        .map_err(|_| Error::InvalidExpression)?;
    meter.charge(0)?;
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
fn preflight(source: &str, meter: &mut Meter<'_, impl EvaluationClock>) -> Result<(), Error> {
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
                if !matches!(&source[start..i], "facts" | "in" | "true" | "false") {
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
            b'!' | b'=' | b'<' | b'>' | b'&' | b'|' | b'-' => i += 1,
            _ => return Err(Error::UnsupportedExpression),
        }
    }
    if nesting != 0 {
        return Err(Error::InvalidExpression);
    }
    Ok(())
}

fn fact_key(ast: &IdedExpr) -> Option<&str> {
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
        ] if name == "facts" => Some(key.inner()),
        _ => None,
    }
}

fn check<'a>(
    ast: &IdedExpr,
    facts: &Facts<'a>,
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
    if let Some(key) = fact_key(ast) {
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
        let fact = facts.get(key)?;
        evidence.insert(fact.key.as_str(), &fact.key);
        if evidence.len() > meter.limits.evidence_per_finding {
            return Err(Error::EvidenceLimit);
        }
        return Ok(match fact.value {
            FactValue::Boolean(_) => Type::Bool,
            FactValue::Integer(_) => Type::Int,
            FactValue::String(_) => Type::String,
            FactValue::StringList(_) => Type::Strings,
        });
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

fn run<'a>(
    ast: &'a IdedExpr,
    facts: &Facts<'a>,
    meter: &mut Meter<'_, impl EvaluationClock>,
) -> Result<Value<'a>, Error> {
    meter.charge(1)?;
    if let Some(key) = fact_key(ast) {
        meter.charge(key.len() as u64 + 2)?;
        return Ok(match &facts.get(key)?.value {
            FactValue::Boolean(value) => Value::Bool(*value),
            FactValue::Integer(value) => Value::Int(*value),
            FactValue::String(value) => Value::String(value),
            FactValue::StringList(value) => Value::Strings(value),
        });
    }
    match &ast.expr {
        Expr::Literal(LiteralValue::Boolean(value)) => Ok(Value::Bool(*value.inner())),
        Expr::Literal(LiteralValue::Int(value)) => Ok(Value::Int(*value.inner())),
        Expr::Literal(LiteralValue::String(value)) => Ok(Value::String(value.inner())),
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
                            (Value::String(needle), Value::Strings(values)) => {
                                for value in values {
                                    meter.charge(1 + needle.len() as u64 + value.len() as u64)?;
                                    if needle == value {
                                        return Ok(Value::Bool(true));
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
