use std::fmt::{Display, Formatter};
use jsonrpsee_core::Serialize;
use serde_json::json;
use crate::api::method::get_validity_proof::InclusionProofInputs;

#[allow(non_snake_case)]
#[derive(Serialize)]
pub struct InclusionInputs {
    root: Vec<String>,
    leaf: Vec<String>,
    inPathIndices: Vec<u32>,
    inPathElements: Vec<Vec<String>>,
}

impl InclusionInputs {
    pub fn new(inputs: &[InclusionProofInputs]) -> Self {
        let mut roots = Vec::<String>::new();
        let mut leafs = Vec::<String>::new();
        let mut in_path_indices = Vec::<u32>::new();
        let mut in_path_elements = Vec::<Vec<String>>::new();

        for input in inputs {
            roots.push(input.root.to_string());
            leafs.push(input.leaf.to_string());
            in_path_indices.push(input.in_path_indices);
            in_path_elements.push(input.in_path_elements.iter().map(|h| h.to_string()).collect());
        }

        Self {
            root: roots,
            leaf: leafs,
            inPathIndices: in_path_indices,
            inPathElements: in_path_elements,
        }
    }

    fn to_pretty_json(&self) -> String {
        let json = json!(self);
        serde_json::to_string_pretty(&json)
            .expect("Failed to serialize to pretty json.")
    }
}

impl Display for InclusionInputs {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_pretty_json())
    }
}
