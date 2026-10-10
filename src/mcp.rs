use crate::idempotency::RequestId;
use crate::locks::{AllowLocked, InputChoice, InputSet, LockAction};
use serde_json::{json, Value};

pub const PROTOCOL: &str = "2025-06-18";
const SUPPORTED: &[&str] = &["2025-06-18", "2025-03-26", "2024-11-05"];
const MAX_NOTE_CHARS: usize = 200;

#[derive(Clone, Debug, PartialEq)]
pub enum SendMode {
    DryRun,
    Broadcast { request_id: RequestId },
}

#[derive(Clone, Debug, PartialEq)]
pub enum ToolCall {
    Balance,
    Address {
        advance: bool,
    },
    History {
        limit: u32,
    },
    Utxos,
    EditLocks {
        action: LockAction,
        outpoints: InputSet,
        note: Option<String>,
    },
    FeeEstimates,
    Descriptor,
    Send {
        to: String,
        sats: u64,
        feerate: Option<u64>,
        inputs: InputChoice,
        mode: SendMode,
    },
    SignPsbt {
        psbt: String,
        broadcast: bool,
        allow_locked: AllowLocked,
        request_id: RequestId,
    },
    SignTx {
        tx_hex: String,
        broadcast: bool,
        allow_locked: AllowLocked,
        request_id: RequestId,
    },
    SpendLog {
        limit: u32,
    },
}

#[derive(Clone, Debug, PartialEq)]
pub enum Incoming {
    Notification,
    Reply { status: u16, body: Value },
    Call { id: Value, call: ToolCall },
}

pub fn incoming(body: &str, protocol_header: Option<&str>) -> Incoming {
    if let Some(header) = protocol_header {
        if !header.is_empty() && !SUPPORTED.contains(&header) {
            return Incoming::Reply {
                status: 400,
                body: json!({
                    "jsonrpc": "2.0",
                    "id": null,
                    "error": { "code": -32600, "message": "unsupported MCP-Protocol-Version" }
                }),
            };
        }
    }
    let value: Value = match serde_json::from_str(body) {
        Ok(value) => value,
        Err(_) => {
            return Incoming::Reply {
                status: 200,
                body: rpc_error(Value::Null, -32700, "parse error"),
            };
        }
    };
    if !value.is_object() {
        return Incoming::Reply {
            status: 200,
            body: rpc_error(Value::Null, -32600, "invalid request"),
        };
    }
    let id = value.get("id").cloned();
    let Some(method) = value.get("method").and_then(Value::as_str) else {
        return Incoming::Reply {
            status: 200,
            body: rpc_error(id.unwrap_or(Value::Null), -32600, "invalid request"),
        };
    };
    if !value
        .get("jsonrpc")
        .and_then(Value::as_str)
        .eq(&Some("2.0"))
    {
        return Incoming::Reply {
            status: 200,
            body: rpc_error(id.unwrap_or(Value::Null), -32600, "invalid request"),
        };
    }
    let Some(id) = id else {
        return Incoming::Notification;
    };
    match method {
        "initialize" => Incoming::Reply {
            status: 200,
            body: initialize_result(&id, value.get("params")),
        },
        "ping" => Incoming::Reply {
            status: 200,
            body: rpc_ok(&id, json!({})),
        },
        "tools/list" => Incoming::Reply {
            status: 200,
            body: rpc_ok(&id, json!({ "tools": tool_specs() })),
        },
        "tools/call" => match parse_call(value.get("params")) {
            Ok(call) => Incoming::Call { id, call },
            Err(message) => Incoming::Reply {
                status: 200,
                body: rpc_error(id, -32602, &message),
            },
        },
        _ => Incoming::Reply {
            status: 200,
            body: rpc_error(id, -32601, "method not found"),
        },
    }
}

fn initialize_result(id: &Value, params: Option<&Value>) -> Value {
    let requested = params
        .and_then(|params| params.get("protocolVersion"))
        .and_then(Value::as_str)
        .unwrap_or(PROTOCOL);
    let version = if SUPPORTED.contains(&requested) {
        requested
    } else {
        PROTOCOL
    };
    rpc_ok(
        id,
        json!({
            "protocolVersion": version,
            "capabilities": { "tools": {} },
            "serverInfo": { "name": "satchel", "title": "Satchel", "version": "0.1.0" },
            "instructions": "Satchel is a hot Bitcoin wallet. send defaults to an unsigned dry run and signs only when broadcast is true. sign_psbt and sign_tx always sign, even when broadcast is false, and the returned transaction can be broadcast elsewhere. Every call that signs needs a request_id. That is send with broadcast true, and every sign_psbt and sign_tx call. Use a new request_id for each new payment. To retry after an error or a lost reply, call again with the same arguments and the same request_id. Satchel then returns the stored result or rebroadcasts the same transaction, and it does not sign a second one. The same request_id with different arguments is an error. Amounts are satoshis. The sum of every input must be within MAX_TX_INPUT_SATS. Coins at or under AUTO_LOCK_SATS start locked, and lock and unlock change that. utxos shows which coins are locked. send without inputs skips locked coins. Listing coins in send inputs allows spending them even when locked. sign_psbt and sign_tx refuse to spend a locked output unless allow_locked is true."
        }),
    )
}

fn parse_call(params: Option<&Value>) -> Result<ToolCall, String> {
    let params = params.ok_or("tools/call needs params")?;
    let name = params
        .get("name")
        .and_then(Value::as_str)
        .ok_or("tools/call needs a name")?;
    let args = params
        .get("arguments")
        .cloned()
        .unwrap_or_else(|| json!({}));
    if !args.is_object() {
        return Err("tool arguments must be an object".into());
    }
    match name {
        "balance" => Ok(ToolCall::Balance),
        "address" => Ok(ToolCall::Address {
            advance: bool_arg(&args, "advance", false)?,
        }),
        "history" => Ok(ToolCall::History {
            limit: u32_arg(&args, "limit", 10, 1, 25)?,
        }),
        "utxos" => Ok(ToolCall::Utxos),
        "lock" => edit_locks(&args, LockAction::Lock),
        "unlock" => edit_locks(&args, LockAction::Unlock),
        "fee_estimates" => Ok(ToolCall::FeeEstimates),
        "descriptor" => Ok(ToolCall::Descriptor),
        "send" => Ok(ToolCall::Send {
            to: string_arg(&args, "to")?,
            sats: required_u64(&args, "sats")?,
            feerate: optional_feerate(&args)?,
            inputs: input_choice(&args)?,
            mode: send_mode(&args)?,
        }),
        "sign_psbt" => Ok(ToolCall::SignPsbt {
            psbt: string_arg(&args, "psbt")?,
            broadcast: bool_arg(&args, "broadcast", false)?,
            allow_locked: allow_locked_arg(&args)?,
            request_id: required_request_id(&args, "request_id is required for sign_psbt")?,
        }),
        "sign_tx" => Ok(ToolCall::SignTx {
            tx_hex: string_arg(&args, "tx_hex")?,
            broadcast: bool_arg(&args, "broadcast", false)?,
            allow_locked: allow_locked_arg(&args)?,
            request_id: required_request_id(&args, "request_id is required for sign_tx")?,
        }),
        "spend_log" => Ok(ToolCall::SpendLog {
            limit: u32_arg(&args, "limit", 50, 1, 200)?,
        }),
        _ => Err(format!("unknown tool {name}")),
    }
}

fn string_arg(args: &Value, name: &str) -> Result<String, String> {
    match args.get(name) {
        Some(Value::String(value)) if !value.trim().is_empty() => Ok(value.trim().to_string()),
        _ => Err(format!("{name} must be a non-empty string")),
    }
}

fn bool_arg(args: &Value, name: &str, default: bool) -> Result<bool, String> {
    match args.get(name) {
        None => Ok(default),
        Some(Value::Bool(value)) => Ok(*value),
        _ => Err(format!("{name} must be a boolean")),
    }
}

fn required_u64(args: &Value, name: &str) -> Result<u64, String> {
    match args.get(name) {
        Some(Value::Number(number)) => number
            .as_u64()
            .ok_or_else(|| format!("{name} must be a positive integer")),
        _ => Err(format!("{name} must be an integer")),
    }
    .and_then(|value| {
        if value == 0 {
            Err(format!("{name} must be greater than zero"))
        } else {
            Ok(value)
        }
    })
}

fn u32_arg(args: &Value, name: &str, default: u32, min: u32, max: u32) -> Result<u32, String> {
    match args.get(name) {
        None => Ok(default),
        Some(Value::Number(number)) => {
            let value = number
                .as_u64()
                .ok_or_else(|| format!("{name} must be an integer"))?;
            if value > u32::MAX as u64 {
                return Err(format!("{name} is too large"));
            }
            let value = value as u32;
            if value < min || value > max {
                return Err(format!("{name} must be between {min} and {max}"));
            }
            Ok(value)
        }
        _ => Err(format!("{name} must be an integer")),
    }
}

fn optional_feerate(args: &Value) -> Result<Option<u64>, String> {
    match args.get("feerate") {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Number(number)) => {
            let rate = number.as_f64().ok_or("feerate must be a number")?;
            if !rate.is_finite() || rate < 0.0 {
                return Err("feerate must be a non-negative number of sat/vB".into());
            }
            let ceil = rate.ceil();
            if ceil >= u64::MAX as f64 {
                return Err("feerate is too large".into());
            }
            Ok(Some(ceil as u64))
        }
        _ => Err("feerate must be a number of sat/vB".into()),
    }
}

fn edit_locks(args: &Value, action: LockAction) -> Result<ToolCall, String> {
    Ok(ToolCall::EditLocks {
        action,
        outpoints: outpoints_arg(args, "outpoints")?,
        note: note_arg(args)?,
    })
}

fn note_arg(args: &Value) -> Result<Option<String>, String> {
    match args.get("note") {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(note)) => {
            let note = note.trim();
            if note.chars().count() > MAX_NOTE_CHARS {
                return Err(format!("note must be at most {MAX_NOTE_CHARS} characters"));
            }
            Ok(Some(note.to_string()).filter(|note| !note.is_empty()))
        }
        _ => Err("note must be a string".into()),
    }
}

fn input_choice(args: &Value) -> Result<InputChoice, String> {
    match args.get("inputs") {
        None | Some(Value::Null) => Ok(InputChoice::Auto),
        Some(_) => outpoints_arg(args, "inputs").map(InputChoice::Exactly),
    }
}

fn outpoints_arg(args: &Value, name: &str) -> Result<InputSet, String> {
    let malformed = || format!("{name} must be a list of txid:vout strings");
    let Some(Value::Array(items)) = args.get(name) else {
        return Err(malformed());
    };
    let items = items
        .iter()
        .map(|item| item.as_str().ok_or_else(malformed))
        .collect::<Result<Vec<&str>, String>>()?;
    InputSet::parse(name, &items)
}

fn allow_locked_arg(args: &Value) -> Result<AllowLocked, String> {
    match args.get("allow_locked") {
        None | Some(Value::Bool(false)) => Ok(AllowLocked::No),
        Some(Value::Bool(true)) => Ok(AllowLocked::Yes),
        _ => Err("allow_locked must be a boolean".into()),
    }
}

fn send_mode(args: &Value) -> Result<SendMode, String> {
    if !bool_arg(args, "broadcast", false)? {
        optional_request_id(args)?;
        return Ok(SendMode::DryRun);
    }
    Ok(SendMode::Broadcast {
        request_id: required_request_id(args, "request_id is required when broadcast is true")?,
    })
}

fn required_request_id(args: &Value, missing: &str) -> Result<RequestId, String> {
    optional_request_id(args)?.ok_or_else(|| missing.to_string())
}

fn optional_request_id(args: &Value) -> Result<Option<RequestId>, String> {
    match args.get("request_id") {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(value)) if value.trim().is_empty() => Ok(None),
        Some(Value::String(value)) => RequestId::parse(value).map(Some),
        _ => Err("request_id must be a string".into()),
    }
}

pub fn tool_result(id: &Value, value: Value, is_error: bool) -> Value {
    rpc_ok(
        id,
        json!({
            "content": [{ "type": "text", "text": serde_json::to_string_pretty(&value).unwrap_or_else(|_| value.to_string()) }],
            "structuredContent": value,
            "isError": is_error
        }),
    )
}

pub fn rpc_ok(id: &Value, result: Value) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "result": result })
}

pub fn rpc_error(id: Value, code: i32, message: &str) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": { "code": code, "message": message }
    })
}

fn tool_specs() -> Vec<Value> {
    vec![
        tool("balance", "Confirmed and unconfirmed balance in satoshis.", json!({ "type": "object", "properties": {} })),
        tool("address", "Next unused receive address. Set advance true to skip it next time.", json!({
            "type": "object",
            "properties": { "advance": { "type": "boolean" } }
        })),
        tool("history", "Recent transactions that touch wallet addresses.", json!({
            "type": "object",
            "properties": { "limit": { "type": "integer", "minimum": 1, "maximum": 25 } }
        })),
        tool("utxos", "Unspent outputs known to the wallet, with lock state. A coin at or under AUTO_LOCK_SATS shows locked with lock_reason auto-small until unlock. A coin passed to lock shows lock_reason manual.", json!({ "type": "object", "properties": {} })),
        tool("lock", "Lock outpoints. send without inputs skips them, and sign_psbt and sign_tx refuse to spend them unless allow_locked is true. An outpoint does not need to be a wallet coin. Locking twice is the same as locking once. The reply shows only what lock stored. Auto-lock depends on a coin's value, which this tool does not look up, so check utxos for it.", json!({
            "type": "object",
            "required": ["outpoints"],
            "properties": {
                "outpoints": { "type": "array", "items": { "type": "string" }, "minItems": 1, "description": "txid:vout outpoints." },
                "note": { "type": "string", "maxLength": 200 }
            }
        })),
        tool("unlock", "Unlock outpoints, including coins auto-locked at or under AUTO_LOCK_SATS. They stay selectable until lock. Unlocking twice is the same as unlocking once. The reply shows only what unlock stored. Auto-lock depends on a coin's value, which this tool does not look up, so check utxos for it.", json!({
            "type": "object",
            "required": ["outpoints"],
            "properties": {
                "outpoints": { "type": "array", "items": { "type": "string" }, "minItems": 1, "description": "txid:vout outpoints." },
                "note": { "type": "string", "maxLength": 200 }
            }
        })),
        tool("fee_estimates", "Esplora fee estimates in sat/vB.", json!({ "type": "object", "properties": {} })),
        tool("descriptor", "Public account descriptors and the master fingerprint.", json!({ "type": "object", "properties": {} })),
        tool("send", "Build a payment. Dry-run unless broadcast is true. With broadcast true it signs and broadcasts, and request_id is required. Without inputs, coin selection skips locked coins. With inputs, only the listed coins are considered, they may be locked, and selection may leave a listed coin unspent. To retry, send the same arguments with the same request_id. Satchel returns the stored result or rebroadcasts the same transaction, and it does not sign a second one.", json!({
            "type": "object",
            "required": ["to", "sats"],
            "properties": {
                "to": { "type": "string" },
                "sats": { "type": "integer", "minimum": 1 },
                "feerate": { "type": "number" },
                "inputs": {
                    "type": "array",
                    "items": { "type": "string" },
                    "minItems": 1,
                    "description": "Optional txid:vout outpoints to choose from. Listing a locked coin allows spending it. To spend an exact set, build the transaction and call sign_tx."
                },
                "broadcast": { "type": "boolean" },
                "request_id": {
                    "type": "string",
                    "description": "Required when broadcast is true. Use one per payment, 1-80 letters, digits, or . _ : -. Reuse it only to retry the same arguments. Ignored on a dry run."
                }
            }
        })),
        tool("sign_psbt", "Sign a base64 PSBT. Every input must have a known value, and the input sum must be within MAX_TX_INPUT_SATS. It refuses to spend a locked output unless allow_locked is true. Broadcast only when broadcast is true. request_id is required. To retry, send the same PSBT, broadcast flag, and allow_locked with the same request_id. Satchel returns the stored result and does not sign again.", json!({
            "type": "object",
            "required": ["psbt", "request_id"],
            "properties": {
                "psbt": { "type": "string" },
                "broadcast": { "type": "boolean" },
                "allow_locked": {
                    "type": "boolean",
                    "description": "Set true to sign inputs that spend locked outputs. Default false."
                },
                "request_id": {
                    "type": "string",
                    "description": "Required. Use one per PSBT, 1-80 letters, digits, or . _ : -. Reuse it only to retry the same PSBT, broadcast flag, and allow_locked."
                }
            }
        })),
        tool("sign_tx", "Sign a consensus-hex transaction. It signs only inputs that spend this wallet's outputs, and leaves every other input and every output, including OP_RETURN, unchanged. It fetches the transaction behind every prevout to learn its value. The input sum must be within MAX_TX_INPUT_SATS. It refuses to spend a locked output unless allow_locked is true. Broadcast only when broadcast is true, and only when every input is signed. request_id is required. To retry, send the same hex, broadcast flag, and allow_locked with the same request_id. Satchel returns the stored transaction and does not sign again.", json!({
            "type": "object",
            "required": ["tx_hex", "request_id"],
            "properties": {
                "tx_hex": { "type": "string", "description": "Consensus-serialized transaction in hex." },
                "broadcast": { "type": "boolean" },
                "allow_locked": {
                    "type": "boolean",
                    "description": "Set true to sign inputs that spend locked outputs. Default false."
                },
                "request_id": {
                    "type": "string",
                    "description": "Required. Use one per transaction, 1-80 letters, digits, or . _ : -. Reuse it only to retry the same hex, broadcast flag, and allow_locked."
                }
            }
        })),
        tool("spend_log", "Recent signed transactions. No secrets.", json!({
            "type": "object",
            "properties": { "limit": { "type": "integer", "minimum": 1, "maximum": 200 } }
        })),
    ]
}

fn tool(name: &str, description: &str, schema: Value) -> Value {
    json!({
        "name": name,
        "description": description,
        "inputSchema": schema
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn initialize_and_tools_list_follow_json_rpc() {
        let init = incoming(
            r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"t","version":"0"}}}"#,
            None,
        );
        match init {
            Incoming::Reply { body, .. } => {
                assert_eq!(body["result"]["protocolVersion"], "2025-03-26");
                assert!(body["result"]["capabilities"]["tools"].is_object());
                assert_eq!(body["result"]["serverInfo"]["name"], "satchel");
                let instructions = body["result"]["instructions"].as_str().unwrap();
                assert!(instructions.contains("send defaults to an unsigned dry run"));
                assert!(instructions.contains("sign_psbt and sign_tx always sign"));
                assert!(instructions.contains("unless allow_locked is true"));
                assert!(!instructions.contains("sign_psbt default"));
            }
            other => panic!("expected reply, got {other:?}"),
        }
        let list = incoming(r#"{"jsonrpc":"2.0","id":2,"method":"tools/list"}"#, None);
        match list {
            Incoming::Reply { body, .. } => {
                let names: Vec<&str> = body["result"]["tools"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|tool| tool["name"].as_str().unwrap())
                    .collect();
                assert_eq!(
                    names,
                    vec![
                        "balance",
                        "address",
                        "history",
                        "utxos",
                        "lock",
                        "unlock",
                        "fee_estimates",
                        "descriptor",
                        "send",
                        "sign_psbt",
                        "sign_tx",
                        "spend_log"
                    ]
                );
            }
            other => panic!("expected reply, got {other:?}"),
        }
    }

    #[test]
    fn send_defaults_to_a_dry_run_and_bad_input_is_an_error() {
        let call = incoming(
            r#"{"jsonrpc":"2.0","id":"abc","method":"tools/call","params":{"name":"send","arguments":{"to":"bc1qtest","sats":1500}}}"#,
            Some("2025-06-18"),
        );
        match call {
            Incoming::Call { id, call } => {
                assert_eq!(id, json!("abc"));
                assert_eq!(
                    call,
                    ToolCall::Send {
                        to: "bc1qtest".into(),
                        sats: 1500,
                        feerate: None,
                        inputs: InputChoice::Auto,
                        mode: SendMode::DryRun,
                    }
                );
            }
            other => panic!("expected call, got {other:?}"),
        }
        let missing = incoming(
            r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"send","arguments":{"to":"bc1qtest"}}}"#,
            None,
        );
        assert!(matches!(missing, Incoming::Reply { body, .. } if body["error"]["code"] == -32602));
        let unknown = incoming(r#"{"jsonrpc":"2.0","id":4,"method":"nope"}"#, None);
        assert!(matches!(unknown, Incoming::Reply { body, .. } if body["error"]["code"] == -32601));
    }

    fn call(name: &str, arguments: Value) -> Incoming {
        let body = json!({
            "jsonrpc": "2.0",
            "id": 9,
            "method": "tools/call",
            "params": { "name": name, "arguments": arguments }
        });
        incoming(&body.to_string(), None)
    }

    fn invalid_params(reply: Incoming) -> String {
        match reply {
            Incoming::Reply { body, .. } => {
                assert_eq!(body["error"]["code"], -32602);
                body["error"]["message"].as_str().unwrap().to_string()
            }
            other => panic!("expected invalid params, got {other:?}"),
        }
    }

    #[test]
    fn signing_calls_require_a_request_id() {
        for request_id in [json!(null), json!("   ")] {
            assert_eq!(
                invalid_params(call(
                    "send",
                    json!({ "to": "bc1qtest", "sats": 1500, "broadcast": true, "request_id": request_id })
                )),
                "request_id is required when broadcast is true"
            );
        }
        assert_eq!(
            invalid_params(call(
                "send",
                json!({ "to": "bc1qtest", "sats": 1500, "broadcast": true })
            )),
            "request_id is required when broadcast is true"
        );
        assert_eq!(
            invalid_params(call("sign_psbt", json!({ "psbt": "cHNidP8=" }))),
            "request_id is required for sign_psbt"
        );
        assert_eq!(
            invalid_params(call(
                "sign_psbt",
                json!({ "psbt": "cHNidP8=", "broadcast": false, "request_id": "" })
            )),
            "request_id is required for sign_psbt"
        );
        assert_eq!(
            invalid_params(call(
                "sign_tx",
                json!({ "tx_hex": "0200", "broadcast": false })
            )),
            "request_id is required for sign_tx"
        );
        match call(
            "sign_tx",
            json!({ "tx_hex": " 0200 ", "allow_locked": true, "request_id": "join-4" }),
        ) {
            Incoming::Call { call, .. } => assert_eq!(
                call,
                ToolCall::SignTx {
                    tx_hex: "0200".into(),
                    broadcast: false,
                    allow_locked: AllowLocked::Yes,
                    request_id: RequestId::parse("join-4").unwrap(),
                }
            ),
            other => panic!("expected call, got {other:?}"),
        }
        match call(
            "send",
            json!({ "to": "bc1qtest", "sats": 1500, "broadcast": true, "request_id": " invoice-8841 " }),
        ) {
            Incoming::Call { call, .. } => assert_eq!(
                call,
                ToolCall::Send {
                    to: "bc1qtest".into(),
                    sats: 1500,
                    feerate: None,
                    inputs: InputChoice::Auto,
                    mode: SendMode::Broadcast {
                        request_id: RequestId::parse("invoice-8841").unwrap()
                    },
                }
            ),
            other => panic!("expected call, got {other:?}"),
        }
    }

    #[test]
    fn a_dry_run_checks_and_drops_the_request_id() {
        match call(
            "send",
            json!({ "to": "bc1qtest", "sats": 1500, "request_id": "invoice-8841" }),
        ) {
            Incoming::Call { call, .. } => assert_eq!(
                call,
                ToolCall::Send {
                    to: "bc1qtest".into(),
                    sats: 1500,
                    feerate: None,
                    inputs: InputChoice::Auto,
                    mode: SendMode::DryRun,
                }
            ),
            other => panic!("expected call, got {other:?}"),
        }
        assert_eq!(
            invalid_params(call(
                "send",
                json!({ "to": "bc1qtest", "sats": 1500, "request_id": "pay/1" })
            )),
            "request_id must be 1-80 characters of letters, digits, or . _ : -"
        );
    }

    #[test]
    fn send_inputs_are_a_non_empty_set_of_outpoints() {
        let first = format!("{}:1", "bb".repeat(32));
        let second = format!("{}:0", "aa".repeat(32));
        match call(
            "send",
            json!({ "to": "bc1qtest", "sats": 1500, "inputs": [first, second] }),
        ) {
            Incoming::Call { call, .. } => assert_eq!(
                call,
                ToolCall::Send {
                    to: "bc1qtest".into(),
                    sats: 1500,
                    feerate: None,
                    inputs: InputChoice::Exactly(
                        InputSet::parse("inputs", &[&second, &first]).unwrap()
                    ),
                    mode: SendMode::DryRun,
                }
            ),
            other => panic!("expected call, got {other:?}"),
        }
        match call(
            "send",
            json!({ "to": "bc1qtest", "sats": 1500, "inputs": null }),
        ) {
            Incoming::Call {
                call: ToolCall::Send { inputs, .. },
                ..
            } => assert_eq!(inputs, InputChoice::Auto),
            other => panic!("expected call, got {other:?}"),
        }
        let send_with = |inputs: Value| {
            invalid_params(call(
                "send",
                json!({ "to": "bc1qtest", "sats": 1500, "inputs": inputs }),
            ))
        };
        assert_eq!(
            send_with(json!([])),
            "inputs must list at least one outpoint"
        );
        assert_eq!(
            send_with(json!([first, first])),
            format!("inputs lists {first} more than once")
        );
        assert_eq!(
            send_with(json!(first)),
            "inputs must be a list of txid:vout strings"
        );
        assert_eq!(
            send_with(json!(["nope"])),
            "inputs entry nope is not a txid:vout outpoint"
        );
    }

    #[test]
    fn lock_and_unlock_take_outpoints_and_a_trimmed_note() {
        let outpoint = format!("{}:7", "cc".repeat(32));
        let set = InputSet::parse("outpoints", &[&outpoint]).unwrap();
        match call(
            "lock",
            json!({ "outpoints": [outpoint], "note": "  inscription  " }),
        ) {
            Incoming::Call { call, .. } => assert_eq!(
                call,
                ToolCall::EditLocks {
                    action: LockAction::Lock,
                    outpoints: set.clone(),
                    note: Some("inscription".into()),
                }
            ),
            other => panic!("expected call, got {other:?}"),
        }
        match call("unlock", json!({ "outpoints": [outpoint], "note": "   " })) {
            Incoming::Call { call, .. } => assert_eq!(
                call,
                ToolCall::EditLocks {
                    action: LockAction::Unlock,
                    outpoints: set,
                    note: None,
                }
            ),
            other => panic!("expected call, got {other:?}"),
        }
        assert_eq!(
            invalid_params(call("lock", json!({}))),
            "outpoints must be a list of txid:vout strings"
        );
        assert_eq!(
            invalid_params(call("lock", json!({ "outpoints": [] }))),
            "outpoints must list at least one outpoint"
        );
        assert_eq!(
            invalid_params(call(
                "lock",
                json!({ "outpoints": [outpoint], "note": "n".repeat(201) })
            )),
            "note must be at most 200 characters"
        );
    }

    #[test]
    fn allow_locked_defaults_to_no() {
        let sign = |extra: Value| {
            let mut arguments = json!({ "psbt": "cHNidP8=", "request_id": "psbt-1" });
            if let Value::Object(fields) = extra {
                arguments.as_object_mut().unwrap().extend(fields);
            }
            call("sign_psbt", arguments)
        };
        for (extra, expected) in [
            (json!({}), AllowLocked::No),
            (json!({ "allow_locked": false }), AllowLocked::No),
            (json!({ "allow_locked": true }), AllowLocked::Yes),
        ] {
            match sign(extra) {
                Incoming::Call {
                    call: ToolCall::SignPsbt { allow_locked, .. },
                    ..
                } => assert_eq!(allow_locked, expected),
                other => panic!("expected call, got {other:?}"),
            }
        }
        assert_eq!(
            invalid_params(sign(json!({ "allow_locked": "yes" }))),
            "allow_locked must be a boolean"
        );
    }

    #[test]
    fn notifications_parse_errors_and_protocol_header_are_distinct() {
        assert!(matches!(
            incoming(
                r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
                None
            ),
            Incoming::Notification
        ));
        assert!(matches!(
            incoming("not-json", None),
            Incoming::Reply { body, .. } if body["error"]["code"] == -32700
        ));
        assert!(matches!(
            incoming(
                r#"{"jsonrpc":"2.0","id":1,"method":"ping"}"#,
                Some("1999-01-01")
            ),
            Incoming::Reply { status: 400, .. }
        ));
        let ping = incoming(r#"{"jsonrpc":"2.0","id":1,"method":"ping"}"#, None);
        assert!(matches!(ping, Incoming::Reply { body, .. } if body["result"] == json!({})));
    }
}
