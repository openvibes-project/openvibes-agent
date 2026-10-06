//! A fixed-capacity trace of the original interpreter run. Values are
//! borrowed until a match is known; non-matches allocate no evidence.
use crate::{
    VerifiedRuleSet,
    subset::{Value, binding_key},
};
use cel::{
    IdedExpr,
    common::ast::{Expr, LiteralValue, operators as op},
};
use openvibes_core::{
    DETECTION_BYTES, Detection, DetectionInput, DetectionStatus as Status, DetectionStep,
    DetectionValue as Scalar, Identifier,
};

#[derive(Clone, Copy)]
enum Entry<'a> {
    Input(&'a str, Value<'a>),
    Step(&'a IdedExpr, bool),
}

pub(crate) struct Trace<'a> {
    entries: [Option<Entry<'a>>; 64],
    len: usize,
    truncated: bool,
}

impl<'a> Trace<'a> {
    pub(crate) fn new() -> Self {
        Self {
            entries: [None; 64],
            len: 0,
            truncated: false,
        }
    }
    fn push(&mut self, entry: Entry<'a>) {
        if self.len == self.entries.len() {
            self.truncated = true;
            return;
        }
        self.entries[self.len] = Some(entry);
        self.len += 1;
    }
    pub(crate) fn record(&mut self, ast: &'a IdedExpr, binding: &str, value: Value<'a>) {
        if let Some(key) = binding_key(ast, binding) {
            self.push(Entry::Input(key, value));
        } else if let Value::Bool(value) = value {
            self.push(Entry::Step(ast, value));
        }
    }
    pub(crate) fn finish(
        &self,
        bundle: &VerifiedRuleSet,
        binding: &str,
        mut budget: u64,
    ) -> Detection {
        let mut result = Detection {
            observed_at_unix_ms: 0,
            rule_set_version: bundle.accepted_version().version(),
            preimage_sha256: openvibes_core::hex(bundle.accepted_version().preimage_sha256()),
            inputs: Vec::new(),
            steps: Vec::new(),
            truncated: self.truncated,
        };
        let mut bytes = serde_json::to_vec(&result).map_or(DETECTION_BYTES, |v| v.len() + 20);
        for entry in self.entries[..self.len].iter().flatten() {
            // Bound assembly separately within the unused original operation
            // budget. Exhausting it only clips evidence, never changes a match.
            if budget < 1024 {
                result.truncated = true;
                break;
            }
            budget -= 1024;
            let added;
            match *entry {
                Entry::Input(key, value) => {
                    if result.inputs.iter().any(|input| input.key.as_str() == key) {
                        continue;
                    }
                    if result.inputs.len() == 32 {
                        result.truncated = true;
                        continue;
                    }
                    let Ok(id) = Identifier::new(key) else {
                        result.truncated = true;
                        continue;
                    };
                    let mut input = DetectionInput {
                        key: id,
                        status: Status::Complete,
                        value: None,
                        item_count: None,
                    };
                    if (binding == "event" && key.ends_with(".cmdline"))
                        || matches!(value, Value::String(s) if s.contains('\0'))
                    {
                        input.status = Status::Masked;
                    } else {
                        match value {
                            Value::Bool(value) => input.value = Some(Scalar::Boolean(value)),
                            Value::Int(value) => input.value = Some(Scalar::Integer(value)),
                            Value::String(value) => {
                                let text = clip(value, 256);
                                if text.len() != value.len() {
                                    input.status = Status::Truncated;
                                    result.truncated = true;
                                }
                                input.value = Some(Scalar::String(text.to_owned()));
                            }
                            Value::Strings(values) => {
                                input.status = Status::Summarized;
                                input.item_count = Some(values.len());
                            }
                        }
                    }
                    added = serde_json::to_vec(&input).map_or(DETECTION_BYTES, |v| v.len() + 1);
                    result.inputs.push(input);
                }
                Entry::Step(ast, value) => {
                    if result.steps.len() == 32 {
                        result.truncated = true;
                        continue;
                    }
                    let mut text = Text::default();
                    render(ast, &mut text);
                    if text.cut {
                        result.truncated = true;
                        text.text = format!("{}…", clip(&text.text, 509));
                    }
                    let step = DetectionStep {
                        expression: text.text,
                        result: value,
                    };
                    added = serde_json::to_vec(&step).map_or(DETECTION_BYTES, |v| v.len() + 1);
                    result.steps.push(step);
                }
            }
            bytes = bytes.saturating_add(added);
            if bytes > DETECTION_BYTES {
                match entry {
                    Entry::Input(..) => {
                        result.inputs.pop();
                    }
                    Entry::Step(..) => {
                        result.steps.pop();
                    }
                }
                result.truncated = true;
                break;
            }
        }
        result
    }
}

fn clip(value: &str, limit: usize) -> &str {
    let mut end = value.len().min(limit);
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    &value[..end]
}

#[derive(Default)]
struct Text {
    text: String,
    cut: bool,
}
impl Text {
    fn push(&mut self, value: &str) {
        let part = clip(value, 512 - self.text.len());
        self.text.push_str(part);
        self.cut |= part.len() != value.len();
    }
    fn string(&mut self, value: &str) {
        // Escape at most 512 source bytes, never an unbounded rule literal.
        let part = clip(value, 512);
        self.cut |= part.len() != value.len();
        self.push(&serde_json::to_string(part).unwrap_or_default());
    }
}
fn render(ast: &IdedExpr, out: &mut Text) {
    if out.cut {
        return;
    }
    match &ast.expr {
        Expr::Ident(name) => out.push(name),
        Expr::Literal(LiteralValue::String(value)) => out.string(value.inner()),
        Expr::Literal(LiteralValue::Boolean(value)) => {
            out.push(if *value.inner() { "true" } else { "false" })
        }
        Expr::Literal(LiteralValue::Int(value)) => out.push(&value.inner().to_string()),
        Expr::Call(call) => {
            if let Some(target) = &call.target {
                render(target, out);
                out.push(".");
                out.push(&call.func_name);
                out.push("(");
                if let Some(arg) = call.args.first() {
                    render(arg, out);
                }
                out.push(")");
            } else if call.func_name == op::INDEX && call.args.len() == 2 {
                render(&call.args[0], out);
                out.push("[");
                render(&call.args[1], out);
                out.push("]");
            } else {
                let symbol = match call.func_name.as_str() {
                    op::LOGICAL_NOT => "!",
                    op::NEGATE => "-",
                    op::LOGICAL_AND => "&&",
                    op::LOGICAL_OR => "||",
                    op::EQUALS => "==",
                    op::NOT_EQUALS => "!=",
                    op::LESS => "<",
                    op::LESS_EQUALS => "<=",
                    op::GREATER => ">",
                    op::GREATER_EQUALS => ">=",
                    op::IN => "in",
                    _ => "?",
                };
                out.push("(");
                if call.args.len() == 1 {
                    out.push(symbol);
                    render(&call.args[0], out);
                } else if call.args.len() == 2 {
                    render(&call.args[0], out);
                    out.push(" ");
                    out.push(symbol);
                    out.push(" ");
                    render(&call.args[1], out);
                }
                out.push(")");
            }
        }
        _ => out.push("?"),
    }
}
