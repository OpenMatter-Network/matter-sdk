//! The layout of every source a catalogue read decodes, rendered as text so two
//! runtimes can be compared.
//!
//! Read decoders are strict and positional, so a runtime that reorders a field,
//! widens an integer or adds an enum variant breaks the read that decodes it.
//! `testvectors/read_source_shapes.json` pins what the decoders were written
//! for; `live_chain.rs` recomputes it from a live runtime, so drift is reported
//! by the nightly job instead of by a user.

#![allow(dead_code)] // each test crate uses a different part

use std::collections::BTreeMap;

use scale_info::{PortableRegistry, TypeDef};
use serde_json::Value as Json;
use subxt::metadata::types::StorageEntryType;

/// Where the pinned shapes live, relative to this crate.
pub const SHAPES_FIXTURE: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../testvectors/read_source_shapes.json"
);

/// How a runtime API argument that is the runtime's own call type is rendered.
const RUNTIME_CALL: &str = "<the runtime's call>";

/// The read catalogue, as checked in.
pub fn read_catalogue() -> Json {
    serde_json::from_str(include_str!("../../../../testvectors/facade_reads.json"))
        .expect("testvectors/facade_reads.json is JSON")
}

/// The pinned shapes, as checked in: source name to rendered layout.
pub fn pinned_shapes() -> BTreeMap<String, String> {
    let fixture: Json = serde_json::from_str(include_str!(
        "../../../../testvectors/read_source_shapes.json"
    ))
    .expect("testvectors/read_source_shapes.json is JSON");
    serde_json::from_value(fixture["shapes"].clone()).expect("shapes is a map of strings")
}

/// A type's layout: field names, widths, enum variants with their indices, and
/// nothing else (type names and docs change without the bytes changing).
fn render(types: &PortableRegistry, id: u32, seen: &[u32]) -> String {
    if seen.contains(&id) {
        return format!("<recursive {id}>");
    }
    let seen = &[seen, &[id]].concat();
    let fields = |fields: &[scale_info::Field<scale_info::form::PortableForm>]| {
        fields
            .iter()
            .map(|field| {
                let ty = render(types, field.ty.id, seen);
                match &field.name {
                    Some(name) => format!("{name}:{ty}"),
                    None => ty,
                }
            })
            .collect::<Vec<_>>()
            .join(",")
    };
    let Some(ty) = types.resolve(id) else {
        return format!("<unknown {id}>");
    };
    match &ty.type_def {
        TypeDef::Primitive(primitive) => format!("{primitive:?}").to_lowercase(),
        TypeDef::Compact(compact) => {
            format!("compact<{}>", render(types, compact.type_param.id, seen))
        }
        TypeDef::Sequence(sequence) => {
            format!("vec<{}>", render(types, sequence.type_param.id, seen))
        }
        TypeDef::Array(array) => format!(
            "[{};{}]",
            render(types, array.type_param.id, seen),
            array.len
        ),
        TypeDef::Tuple(tuple) => format!(
            "({})",
            tuple
                .fields
                .iter()
                .map(|field| render(types, field.id, seen))
                .collect::<Vec<_>>()
                .join(",")
        ),
        TypeDef::Composite(composite) => format!("{{{}}}", fields(&composite.fields)),
        TypeDef::Variant(variant) => format!(
            "enum{{{}}}",
            variant
                .variants
                .iter()
                .map(|v| {
                    let payload = if v.fields.is_empty() {
                        String::new()
                    } else {
                        format!("({})", fields(&v.fields))
                    };
                    format!("{}={}{payload}", v.name, v.index)
                })
                .collect::<Vec<_>>()
                .join("|")
        ),
        TypeDef::BitSequence(_) => "bitsequence".to_string(),
    }
}

/// One source's layout in `metadata`, or `None` if the runtime does not have it.
/// JSON-RPC sources are the node's, not the runtime's, and have no layout here.
fn source_shape(metadata: &subxt::Metadata, kind: &str, name: &str) -> Option<String> {
    let types = metadata.types();
    match kind {
        "storage" => {
            let (pallet, entry) = name.split_once('.')?;
            let entry = metadata
                .pallet_by_name(pallet)?
                .storage()?
                .entry_by_name(entry)?;
            let layout = match entry.entry_type() {
                StorageEntryType::Plain(value) => render(types, *value, &[]),
                StorageEntryType::Map {
                    hashers,
                    key_ty,
                    value_ty,
                } => format!(
                    "{hashers:?} {} => {}",
                    render(types, *key_ty, &[]),
                    render(types, *value_ty, &[])
                ),
            };
            Some(format!("{:?} {layout}", entry.modifier()))
        }
        "constant" => {
            let (pallet, constant) = name.split_once('.')?;
            let constant = metadata
                .pallet_by_name(pallet)?
                .constant_by_name(constant)?;
            Some(render(types, constant.ty(), &[]))
        }
        "runtime_api" => {
            let (api, method) = name.split_once('_')?;
            let method = metadata
                .runtime_api_trait_by_name(api)?
                .method_by_name(method)?;
            // A read never decodes a call. Each binding encodes one from the
            // connected runtime's own metadata, and the type grows with every
            // call a runtime adds, so it is named here, not expanded.
            let call = metadata.outer_enums().call_enum_ty();
            let layout = |ty: u32| match ty == call {
                true => RUNTIME_CALL.to_string(),
                false => render(types, ty, &[]),
            };
            let inputs = method
                .inputs()
                .map(|input| format!("{}:{}", input.name, layout(input.ty)))
                .collect::<Vec<_>>()
                .join(",");
            Some(format!(
                "({inputs}) -> {}",
                render(types, method.output_ty(), &[])
            ))
        }
        _ => None,
    }
}

/// Every runtime source the catalogue names, with its layout in `metadata`. A
/// source the runtime lacks renders as `<absent>`, which never equals a pin.
pub fn source_shapes(metadata: &subxt::Metadata) -> BTreeMap<String, String> {
    read_catalogue()["reads"]
        .as_array()
        .expect("the catalogue lists reads")
        .iter()
        .flat_map(|row| row["sources"].as_array().expect("sources").clone())
        .filter(|source| source["kind"] != "rpc")
        .map(|source| {
            let kind = source["kind"].as_str().expect("a source has a kind");
            let name = source["name"].as_str().expect("a source has a name");
            let shape =
                source_shape(metadata, kind, name).unwrap_or_else(|| "<absent>".to_string());
            (name.to_string(), shape)
        })
        .collect()
}
