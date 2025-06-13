use citrea_primitives::forks::get_tangerine_activation_height_non_zero;
use sov_db::ledger_db::SequencerLedgerOps;

/// Loads the next commitment index and starting height from the ledger database
///
/// # Arguments
/// * `db` - The ledger database interface
///
/// # Returns
/// A tuple containing:
/// * The next commitment index (u32)
/// * The starting height for the next commitment (u64)
pub(super) fn load_next_commitment_index_and_start_height<Db: SequencerLedgerOps>(
    db: &Db,
) -> (u32, u64) {
    let pending_commitments = db
        .get_pending_commitments()
        .expect("Failed to get pending commitments");
    let last_commitment = db
        .get_last_commitment()
        .expect("Failed to get last commitment");

    let max_commitment = pending_commitments
        .into_iter()
        .map(Some)
        .chain(std::iter::once(last_commitment))
        .flatten()
        .max();

    match max_commitment {
        Some(commitment) => (commitment.index + 1, commitment.l2_end_block_number + 1),
        None => (1, get_tangerine_activation_height_non_zero()),
    }
}
