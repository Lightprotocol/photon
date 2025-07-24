use tokio::sync::mpsc;
use tracing::{error, warn};

#[derive(Debug, Clone)]
pub enum RewindCommand {
    Rewind { to_slot: u64, reason: String },
}

#[derive(Clone)]
pub struct RewindController {
    sender: mpsc::UnboundedSender<RewindCommand>,
}

impl RewindController {
    pub fn new() -> (Self, mpsc::UnboundedReceiver<RewindCommand>) {
        let (sender, receiver) = mpsc::unbounded_channel();
        (Self { sender }, receiver)
    }

    pub fn request_rewind(&self, to_slot: u64, reason: String) -> Result<(), String> {
        let command = RewindCommand::Rewind {
            to_slot,
            reason: reason.clone(),
        };

        error!("Requesting rewind to slot {}: {}", to_slot, reason);

        self.sender.send(command).map_err(|e| {
            error!("Failed to send rewind command: {}", e);
            format!("Failed to send rewind command: {}", e)
        })
    }
}

pub fn determine_rewind_slot(gaps: &[crate::ingester::parser::state_update::SequenceGap]) -> u64 {
    use crate::ingester::parser::tree_info::TreeInfo;

    // Find the earliest slot where we need to rewind to get the missing sequence
    let mut earliest_slot = u64::MAX;

    for gap in gaps {
        // Try to find the exact slot for the last known good sequence
        let target_seq = gap.expected_seq.saturating_sub(1);
        if let Some(slot) = TreeInfo::get_last_slot_for_seq(&gap.tree, target_seq) {
            // Rewind to just before this slot to ensure we reprocess
            earliest_slot = earliest_slot.min(slot.saturating_sub(1));
        } else {
            // Fallback: conservative approach if we can't find the exact slot
            // This handles the case where this is the first sequence for this tree
            earliest_slot = earliest_slot.min(gap.expected_seq.saturating_sub(10));
        }
    }

    // Ensure we don't rewind to slot 0 unless explicitly needed
    if earliest_slot == u64::MAX {
        // No valid slots found, use conservative fallback
        gaps.iter()
            .map(|gap| gap.expected_seq.saturating_sub(10))
            .min()
            .unwrap_or(0)
    } else {
        earliest_slot
    }
}
