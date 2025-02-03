//! Authly protobuf types.

/// Tonic types for the `authly_connect` protobuf definition.
pub mod connect {
    tonic::include_proto!("authly.connect");
}

/// Tonic types for the `authly_mandate_submission` protobuf definition.
pub mod mandate_submission {
    tonic::include_proto!("authly.mandate_submission");
}

/// Tonic types for the `authly_service` protobuf definition.
pub mod service {
    tonic::include_proto!("authly.service");
}

/// Convert a protobuf Value to a JSON value.
pub fn proto_value_to_json(value: prost_types::Value) -> serde_json::Value {
    use prost_types::value::Kind;
    use serde_json::Value;

    match value.kind {
        Some(Kind::NullValue(_)) => Value::Null,
        Some(Kind::NumberValue(n)) => serde_json::Number::from_f64(n)
            .map(Value::Number)
            .unwrap_or(Value::Null),
        Some(Kind::StringValue(s)) => Value::String(s),
        Some(Kind::BoolValue(b)) => Value::Bool(b),
        Some(Kind::StructValue(s)) => Value::Object(proto_struct_to_json(s)),
        Some(Kind::ListValue(l)) => {
            Value::Array(l.values.into_iter().map(proto_value_to_json).collect())
        }
        None => serde_json::Value::Null,
    }
}

/// Convert a protobuf Struct to a JSON value.
pub fn proto_struct_to_json(
    proto: prost_types::Struct,
) -> serde_json::Map<String, serde_json::Value> {
    let mut map = serde_json::Map::default();

    for (key, value) in proto.fields {
        map.insert(key, proto_value_to_json(value));
    }

    map
}
