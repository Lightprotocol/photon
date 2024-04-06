use std::fmt::{Display, Formatter};
use jsonrpsee_core::Serialize;
use serde_json::json;
use crate::api::method::get_validity_proof::NonInclusionProofInputs;

#[allow(non_snake_case)]
#[derive(Serialize)]
pub struct NonInclusionInputs {
    root: Vec<String>,
    value: Vec<String>,
    inPathIndices: Vec<u32>,
    inPathElements: Vec<Vec<String>>,
    pub leafLowerRangeValue: Vec<String>,
    pub leafHigherRangeValue: Vec<String>,
    pub leafIndex: Vec<u32>,
}

impl NonInclusionInputs {
    fn new(inputs: &[NonInclusionProofInputs]) -> Self {
        let mut leaf_lower_range_values = Vec::<String>::new();
        let mut leaf_higher_range_values = Vec::<String>::new();
        let mut leaf_indices = Vec::<u32>::new();

        let mut roots = Vec::<String>::new();
        let mut values = Vec::<String>::new();
        let mut in_path_indices = Vec::<u32>::new();
        let mut in_path_elements = Vec::<Vec<String>>::new();

        for proof_input in inputs {
            leaf_lower_range_values.push(proof_input.leaf_lower_range_value.to_string());
            leaf_higher_range_values.push(proof_input.leaf_higher_range_value.to_string());
            leaf_indices.push(proof_input.leaf_index);
            roots.push(proof_input.root.to_string());
            values.push(proof_input.value.to_string());
            in_path_indices.push(proof_input.in_path_indices);
            in_path_elements.push(proof_input.in_path_elements.iter().map(|h| h.to_string()).collect());
        }

        Self {
            root: roots,
            value: values,
            inPathIndices: in_path_indices,
            inPathElements: in_path_elements,
            leafLowerRangeValue: leaf_lower_range_values,
            leafHigherRangeValue: leaf_higher_range_values,
            leafIndex: leaf_indices,
        }
    }

    fn to_pretty_json(&self) -> String {
        let json = json!(self);
        serde_json::to_string_pretty(&json)
            .expect("Failed to serialize to pretty json.")
    }
}

impl Display for NonInclusionInputs {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_pretty_json())
    }
}
