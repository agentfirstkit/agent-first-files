//! One contract source: the OpenAPI document and the standalone Schemas are
//! the same component definitions, so a field cannot be described one way in
//! one of them and another way in the other.

use std::collections::BTreeMap;

use serde_json::{Value, json};

use crate::{DEFAULT_MAX_READ_BYTES, DEFAULT_PAGE_LIMIT, MAX_PAGE_LIMIT};

const JSON_SCHEMA_DIALECT: &str = "https://json-schema.org/draft/2020-12/schema";

/// Stable `$id` base for the standalone Schemas. It names the contract, not a
/// build machine, and nothing is fetched from it at runtime: every generated
/// Schema is self-contained so the published package reads offline.
const SCHEMA_BASE: &str = "https://agentfirstkit.com/schemas/affiles/v1";

/// How many nested component expansions one Schema may need. This counts
/// `$ref` hops, not object nesting.
const MAX_INLINE_DEPTH: usize = 12;

/// The standalone Schemas, keyed by the filename they are served and exported
/// under.
pub fn standalone_schemas() -> BTreeMap<String, Value> {
    let components = schemas();
    let Some(components) = components.as_object() else {
        return BTreeMap::new();
    };
    components
        .iter()
        .map(|(component, schema)| {
            let filename = format!("{}.schema.json", schema_slug(component));
            let mut schema = inline_component_refs(schema, components, 0);
            if let Some(object) = schema.as_object_mut() {
                object.insert("$schema".to_string(), json!(JSON_SCHEMA_DIALECT));
                object.insert(
                    "$id".to_string(),
                    json!(format!("{SCHEMA_BASE}/{filename}")),
                );
                object.insert("title".to_string(), json!(component));
            }
            (filename, schema)
        })
        .collect()
}

/// The index a caller reads to discover the standalone Schemas.
pub fn schema_index() -> Value {
    let components = schemas();
    let entries = components
        .as_object()
        .map(|components| {
            components
                .keys()
                .map(|component| {
                    let slug = schema_slug(component);
                    json!({
                        "schema_name": slug,
                        "schema_url": format!("/schemas/{slug}.schema.json"),
                        "component_name": component,
                    })
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    json!({
        "schema_name": "affiles_schema_index",
        "schema_version": 1,
        "json_schema_dialect": JSON_SCHEMA_DIALECT,
        "count": entries.len(),
        "schemas": entries,
    })
}

/// `DirectoryResult` -> `directory-result`, so a filename is predictable from
/// the component name without a second hand-kept table.
fn schema_slug(component: &str) -> String {
    let mut slug = String::with_capacity(component.len() + 4);
    for (index, character) in component.char_indices() {
        if character.is_ascii_uppercase() {
            if index != 0 {
                slug.push('-');
            }
            slug.push(character.to_ascii_lowercase());
        } else {
            slug.push(character);
        }
    }
    slug
}

fn inline_component_refs(
    value: &Value,
    components: &serde_json::Map<String, Value>,
    depth: usize,
) -> Value {
    if depth > MAX_INLINE_DEPTH {
        return value.clone();
    }
    match value {
        Value::Object(object) => {
            if let Some(component) = object
                .get("$ref")
                .and_then(Value::as_str)
                .and_then(|reference| reference.strip_prefix("#/components/schemas/"))
                && let Some(target) = components.get(component)
            {
                return inline_component_refs(target, components, depth + 1);
            }
            Value::Object(
                object
                    .iter()
                    .map(|(key, nested)| {
                        (
                            key.clone(),
                            inline_component_refs(nested, components, depth),
                        )
                    })
                    .collect(),
            )
        }
        Value::Array(items) => Value::Array(
            items
                .iter()
                .map(|item| inline_component_refs(item, components, depth))
                .collect(),
        ),
        other => other.clone(),
    }
}

pub fn openapi_document() -> Value {
    json!({
        "openapi": "3.2.0",
        "$self": "/openapi.json",
        "jsonSchemaDialect": JSON_SCHEMA_DIALECT,
        "info": {
            "title": "Agent-First Files API",
            "version": env!("CARGO_PKG_VERSION"),
            "description": "A bearer-protected, read-only projection of one directory tree. Every path is relative to the root this process was started with; nothing outside it is reachable, and a path that is excluded or outside answers exactly as one that does not exist."
        },
        "servers": [{
            "url": "/",
            "description": "The affiles process that served this document"
        }],
        "tags": [
            {"name": "discovery"},
            {"name": "root"},
            {"name": "directories"},
            {"name": "files"}
        ],
        "security": [{"bearerAuth": []}],
        "paths": paths(),
        "components": {
            "securitySchemes": {
                "bearerAuth": {
                    "type": "http",
                    "scheme": "bearer",
                    "description": "Pass the API access token in Authorization. Query-string credentials are not accepted."
                }
            },
            "parameters": {
                "SchemaFile": {
                    "name": "schema_file",
                    "in": "path",
                    "required": true,
                    "description": "Standalone Schema filename from /schemas/index.json",
                    "schema": {
                        "type": "string",
                        "pattern": "^[a-z0-9-]+\\.schema\\.json$"
                    }
                },
                "EntryPath": {
                    "name": "path",
                    "in": "query",
                    "required": false,
                    "description": "Root-relative path. Empty or omitted is the root itself. Absolute paths and `..` are refused rather than resolved. A filesystem path is a query value here and never a URL path segment, so no name needs escaping to survive routing.",
                    "schema": relative_path_schema()
                },
                "PageLimit": {
                    "name": "limit",
                    "in": "query",
                    "required": false,
                    "description": "Entries per page",
                    "schema": {
                        "type": "integer",
                        "minimum": 1,
                        "maximum": MAX_PAGE_LIMIT,
                        "default": DEFAULT_PAGE_LIMIT
                    }
                },
                "PageCursor": {
                    "name": "cursor",
                    "in": "query",
                    "required": false,
                    "description": "Resume after this cursor, which is only ever one this API returned",
                    "schema": {"type": "string"}
                },
                "OffsetBytes": {
                    "name": "offset_bytes",
                    "in": "query",
                    "required": false,
                    "description": "Where in the file to start",
                    "schema": {"type": "integer", "minimum": 0, "default": 0}
                },
                "MaxBytes": {
                    "name": "max_bytes",
                    "in": "query",
                    "required": false,
                    "description": "How much to return, capped by the process-wide ceiling",
                    "schema": {
                        "type": "integer",
                        "minimum": 1,
                        "default": DEFAULT_MAX_READ_BYTES
                    }
                }
            },
            "schemas": schemas()
        }
    })
}

fn paths() -> Value {
    json!({
        "/health": {
            "get": {
                "operationId": "getHealth",
                "summary": "Check API process health",
                "description": "Public, and therefore carrying nothing about the projected root: the path this process is serving is a user value and lives behind the credential.",
                "tags": ["discovery"],
                "security": [],
                "responses": ok_response("HealthResult", "Process health")
            }
        },
        "/openapi.json": {
            "get": {
                "operationId": "getOpenApiDocument",
                "summary": "Read this OpenAPI document",
                "tags": ["discovery"],
                "security": [],
                "responses": {
                    "200": {
                        "description": "The OpenAPI document this process serves",
                        "content": {"application/json": {"schema": {"type": "object"}}}
                    }
                }
            }
        },
        "/schemas/index.json": {
            "get": {
                "operationId": "listJsonSchemas",
                "summary": "List the standalone JSON Schemas",
                "tags": ["discovery"],
                "security": [],
                "responses": {
                    "200": {
                        "description": "Standalone Schema index",
                        "content": {"application/json": {"schema": {"$ref": "#/components/schemas/SchemaIndex"}}}
                    }
                }
            }
        },
        "/schemas/{schema_file}": {
            "get": {
                "operationId": "getJsonSchema",
                "summary": "Read one standalone JSON Schema",
                "tags": ["discovery"],
                "security": [],
                "parameters": [{"$ref": "#/components/parameters/SchemaFile"}],
                "responses": {
                    "200": {
                        "description": "A self-contained JSON Schema",
                        "content": {"application/schema+json": {"schema": {"type": "object"}}}
                    },
                    "404": error_response("No such standalone Schema")
                }
            }
        },
        "/v1/root": {
            "get": {
                "operationId": "getRoot",
                "summary": "Describe the projected root",
                "description": "What this process is projecting and under what limits. The number of exclusion patterns is reported; the patterns themselves are not, because they describe what is being held back.",
                "tags": ["root"],
                "responses": with_auth(ok_response("RootResult", "The projected root"))
            }
        },
        "/v1/directories": {
            "get": {
                "operationId": "listDirectory",
                "summary": "List one directory",
                "description": "Sorted by name in byte order, which is the order paging depends on. Directories are not hoisted above files: that is a presentation choice and belongs to whatever draws the list.",
                "tags": ["directories"],
                "parameters": [
                    {"$ref": "#/components/parameters/EntryPath"},
                    {"$ref": "#/components/parameters/PageLimit"},
                    {"$ref": "#/components/parameters/PageCursor"}
                ],
                "responses": with_conflicts(
                    ok_response("DirectoryResult", "One page of a directory"),
                    "The path exists and is not a directory"
                )
            }
        },
        "/v1/entries": {
            "get": {
                "operationId": "getEntry",
                "summary": "Describe one entry",
                "tags": ["directories"],
                "parameters": [{"$ref": "#/components/parameters/EntryPath"}],
                "responses": with_auth(ok_response("EntryResult", "One entry"))
            }
        },
        "/v1/files/text": {
            "get": {
                "operationId": "readTextFile",
                "summary": "Read a slice of a file as text",
                "description": "Refuses NUL and invalid UTF-8 rather than returning replacement characters. When a truncated byte window ends inside a UTF-8 character, it omits only the final incomplete sequence, at most three bytes. byte_length counts the returned text bytes. The starting offset is not aligned automatically, and an incomplete sequence at the actual end of a file is still invalid. A slice that does not reach the end of the file is reported as truncated, which is not an error.",
                "tags": ["files"],
                "parameters": [
                    {"$ref": "#/components/parameters/EntryPath"},
                    {"$ref": "#/components/parameters/OffsetBytes"},
                    {"$ref": "#/components/parameters/MaxBytes"}
                ],
                "responses": with_conflicts(
                    ok_response("TextFileResult", "A slice of the file"),
                    "The path is a directory, or the file is not text"
                )
            }
        },
        "/v1/files/bytes": {
            "get": {
                "operationId": "readFileBytes",
                "summary": "Read a slice of a file as bytes",
                "description": "The one response that is not an AFDATA envelope, because a byte stream cannot be one. The media type is taken conservatively from the extension and never sniffed from content; anything unrecognised is application/octet-stream, and every response carries `Content-Disposition: attachment` and `X-Content-Type-Options: nosniff` so nothing here decides that a workspace file is something a browser should run.",
                "tags": ["files"],
                "parameters": [
                    {"$ref": "#/components/parameters/EntryPath"},
                    {"$ref": "#/components/parameters/OffsetBytes"},
                    {"$ref": "#/components/parameters/MaxBytes"}
                ],
                "responses": {
                    "200": {
                        "description": "A slice of the file, as itself",
                        "headers": {
                            "X-Total-Bytes": {
                                "description": "The whole file's size, so a caller knows what this slice left out",
                                "schema": {"type": "integer", "minimum": 0}
                            }
                        },
                        "content": {
                            "application/octet-stream": {
                                "schema": {"type": "string", "format": "binary"}
                            }
                        }
                    },
                    "400": error_response("The query or path is not one this projection accepts"),
                    "401": error_response("Missing or invalid bearer credential"),
                    "403": error_response("Permission to access this entry was denied"),
                    "500": error_response("The filesystem operation failed"),
                    "404": error_response("No such entry under this root"),
                    "409": error_response("The path is a directory")
                }
            }
        }
    })
}

fn ok_response(component: &str, description: &str) -> Value {
    json!({
        "200": {
            "description": description,
            "content": {
                "application/json": {
                    "schema": envelope_of(component)
                }
            }
        }
    })
}

fn with_auth(mut responses: Value) -> Value {
    if let Some(object) = responses.as_object_mut() {
        object.insert(
            "400".to_string(),
            error_response("The query or path is not one this projection accepts"),
        );
        object.insert(
            "401".to_string(),
            error_response("Missing or invalid bearer credential"),
        );
        object.insert(
            "403".to_string(),
            error_response("Permission to access this entry was denied"),
        );
        object.insert(
            "500".to_string(),
            error_response("The filesystem operation failed"),
        );
        object.insert(
            "404".to_string(),
            error_response("No such entry under this root"),
        );
    }
    responses
}

fn with_conflicts(responses: Value, conflict: &str) -> Value {
    let mut responses = with_auth(responses);
    if let Some(object) = responses.as_object_mut() {
        object.insert("409".to_string(), error_response(conflict));
    }
    responses
}

fn error_response(description: &str) -> Value {
    json!({
        "description": description,
        "content": {
            "application/json": {
                "schema": {"$ref": "#/components/schemas/ErrorEnvelope"}
            }
        }
    })
}

/// Every success is the AFDATA result envelope around one typed result, so no
/// operation declares a bare untyped envelope.
fn envelope_of(component: &str) -> Value {
    json!({
        "type": "object",
        "required": ["kind", "result"],
        "additionalProperties": false,
        "properties": {
            "kind": {"const": "result"},
            "result": {"$ref": format!("#/components/schemas/{component}")},
            "trace": {"$ref": "#/components/schemas/Trace"}
        }
    })
}

fn relative_path_schema() -> Value {
    json!({
        "type": "string",
        "description": "Root-relative path with `/` separators. Empty is the root.",
        "maxLength": 4096
    })
}

fn schemas() -> Value {
    json!({
        "Trace": {
            "type": "object",
            "additionalProperties": true,
            "properties": {
                "duration_ms": {"type": "integer", "minimum": 0}
            }
        },
        "ErrorEnvelope": {
            "type": "object",
            "required": ["kind", "error"],
            "additionalProperties": false,
            "properties": {
                "kind": {"const": "error"},
                "error": {
                    "type": "object",
                    "required": ["code", "message"],
                    "additionalProperties": true,
                    "properties": {
                        "code": {
                            "type": "string",
                            "description": "Stable failure code. `entry_not_found` is also what an excluded path and a path outside the root answer with, deliberately: a refusal a caller can tell apart from an absence is an oracle for what exists.",
                            "enum": [
                                "entry_not_found",
                                "not_a_directory",
                                "is_a_directory",
                                "not_text",
                                "invalid_path",
                                "invalid_query",
                                "invalid_cursor",
                                "permission_denied",
                                "files_io_error",
                                "authentication_required",
                                "schema_not_found",
                                "api_route_not_found",
                                "api_method_not_allowed",
                                "api_result_serialization_failed",
                                "api_error_envelope_failed"
                            ]
                        },
                        "message": {"type": "string"},
                        "retryable": {"type": "boolean"},
                        "hint": {"type": "string"}
                    }
                },
                "trace": {"$ref": "#/components/schemas/Trace"}
            }
        },
        "HealthResult": {
            "type": "object",
            "required": ["service", "version", "status"],
            "additionalProperties": false,
            "properties": {
                "service": {"const": "affiles"},
                "version": {"type": "string"},
                "status": {"type": "string"}
            }
        },
        "SchemaIndex": {
            "type": "object",
            "required": ["schema_name", "schema_version", "json_schema_dialect", "count", "schemas"],
            "additionalProperties": false,
            "properties": {
                "schema_name": {"const": "affiles_schema_index"},
                "schema_version": {"type": "integer"},
                "json_schema_dialect": {"type": "string"},
                "count": {"type": "integer", "minimum": 0},
                "schemas": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "required": ["schema_name", "schema_url", "component_name"],
                        "additionalProperties": false,
                        "properties": {
                            "schema_name": {"type": "string"},
                            "schema_url": {"type": "string"},
                            "component_name": {"type": "string"}
                        }
                    }
                }
            }
        },
        "RootResult": {
            "type": "object",
            "required": ["root_path", "name", "exclude_count", "symlinks", "max_read_bytes"],
            "additionalProperties": false,
            "properties": {
                "root_path": {"type": "string"},
                "name": {"type": "string"},
                "exclude_count": {"type": "integer", "minimum": 0},
                "symlinks": {
                    "type": "string",
                    "description": "within_root follows a link whose target is inside the root and refuses one whose target is not; never follows nothing at all.",
                    "enum": ["within_root", "never"]
                },
                "max_read_bytes": {"type": "integer", "minimum": 1}
            }
        },
        "EntryResult": entry_schema(),
        "DirectoryResult": {
            "type": "object",
            "required": ["path", "entries", "entry_count"],
            "additionalProperties": false,
            "properties": {
                "path": {"type": "string"},
                "entries": {"type": "array", "items": {"$ref": "#/components/schemas/EntryResult"}},
                "entry_count": {"type": "integer", "minimum": 0},
                "next_cursor": {
                    "type": "string",
                    "description": "Absent once the directory is exhausted"
                }
            }
        },
        "TextFileResult": {
            "type": "object",
            "required": ["path", "text", "byte_offset", "byte_length", "total_bytes", "truncated"],
            "additionalProperties": false,
            "properties": {
                "path": {"type": "string"},
                "text": {"type": "string"},
                "byte_offset": {"type": "integer", "minimum": 0},
                "byte_length": {
                    "type": "integer",
                    "minimum": 0,
                    "description": "The returned text length in bytes, excluding an incomplete UTF-8 tail omitted from a truncated window"
                },
                "total_bytes": {"type": "integer", "minimum": 0},
                "truncated": {"type": "boolean"}
            }
        }
    })
}

fn entry_schema() -> Value {
    json!({
        "type": "object",
        "required": ["path", "name", "kind", "size_bytes", "readable"],
        "additionalProperties": false,
        "properties": {
            "path": {"type": "string", "description": "Root-relative, and the key for every later call about this entry"},
            "name": {"type": "string"},
            "kind": {"type": "string", "enum": ["file", "directory", "symlink", "other"]},
            "size_bytes": {"type": "integer", "minimum": 0},
            "modified_rfc3339": {"type": "string"},
            "readable": {"type": "boolean"},
            "unsupported": {
                "type": "string",
                "description": "Why an entry that exists cannot be used the ordinary way. Present rather than implied, because `there is something here you cannot open` and `there is nothing here` are different facts.",
                "enum": ["non_utf8_name", "outside_root", "unsupported_kind"]
            },
            "symlink_target": {
                "type": "string",
                "description": "Where a link points, as written. Advisory: shown, never resolved on the caller's behalf."
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_file_operations_declare_permission_and_io_failures() {
        let document = openapi_document();
        for path in [
            "/v1/root",
            "/v1/directories",
            "/v1/entries",
            "/v1/files/text",
            "/v1/files/bytes",
        ] {
            let responses = &document["paths"][path]["get"]["responses"];
            for status in ["403", "500"] {
                assert!(responses[status].is_object(), "{path} lacks {status}");
                assert!(responses[status]["content"]["application/json"]["schema"].is_object());
            }
        }
    }

    #[test]
    fn every_operation_has_a_unique_id_and_a_typed_success() {
        let document = openapi_document();
        let paths = document["paths"].as_object().expect("paths");
        let mut ids = Vec::new();
        for (path, operations) in paths {
            for (method, operation) in operations.as_object().expect("operations") {
                let id = operation["operationId"]
                    .as_str()
                    .unwrap_or_else(|| panic!("{method} {path} has no operationId"));
                ids.push(id.to_owned());
                assert!(
                    operation["responses"]["200"].is_object(),
                    "{id} declares no success response"
                );
            }
        }
        let mut unique = ids.clone();
        unique.sort();
        unique.dedup();
        assert_eq!(
            unique.len(),
            ids.len(),
            "operationIds must be unique: {ids:?}"
        );
    }

    #[test]
    fn standalone_schemas_are_self_contained() {
        for (filename, schema) in standalone_schemas() {
            let rendered = serde_json::to_string(&schema).expect("schema renders");
            assert!(
                !rendered.contains("#/components/schemas/"),
                "{filename} still refers to a component it does not carry"
            );
            assert!(
                schema["$id"]
                    .as_str()
                    .is_some_and(|id| id.ends_with(&filename))
            );
            assert_eq!(schema["$schema"], JSON_SCHEMA_DIALECT);
        }
    }

    /// The index and the files have to agree, or a caller following the index
    /// asks for something that is not there.
    #[test]
    fn the_index_names_exactly_the_schemas_that_exist() {
        let schemas = standalone_schemas();
        let index = schema_index();
        let listed: Vec<String> = index["schemas"]
            .as_array()
            .expect("schemas")
            .iter()
            .filter_map(|entry| entry["schema_url"].as_str())
            .map(|url| url.trim_start_matches("/schemas/").to_owned())
            .collect();
        let mut expected: Vec<String> = schemas.keys().cloned().collect();
        expected.sort();
        let mut listed = listed;
        listed.sort();
        assert_eq!(listed, expected);
        assert_eq!(index["count"].as_u64(), Some(schemas.len() as u64));
    }

    /// Public discovery is public, and nothing else is.
    #[test]
    fn only_the_discovery_operations_opt_out_of_the_credential() {
        let document = openapi_document();
        for (path, operations) in document["paths"].as_object().expect("paths") {
            let public =
                path == "/health" || path.starts_with("/openapi") || path.starts_with("/schemas");
            for operation in operations.as_object().expect("operations").values() {
                let opted_out = operation["security"]
                    .as_array()
                    .is_some_and(|security| security.is_empty());
                assert_eq!(
                    opted_out,
                    public,
                    "{path} must {} the top-level security requirement",
                    if public { "opt out of" } else { "inherit" }
                );
            }
        }
    }
}
