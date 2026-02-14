use std::cmp::Reverse;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum ExecutionClass {
    Mcp,
    Legacy,
}

pub fn concat_batches_by_proposer_index<T>(
    proposer_batches: impl IntoIterator<Item = (u32, Vec<T>)>,
) -> Vec<T> {
    let mut batches: Vec<(u32, Vec<T>)> = proposer_batches.into_iter().collect();
    // Canonical proposer order for deterministic replay.
    batches.sort_by_key(|(proposer_index, _)| *proposer_index);

    let mut out = Vec::with_capacity(batches.iter().map(|(_, batch)| batch.len()).sum());
    for (_, batch) in batches {
        out.extend(batch);
    }
    out
}

pub fn order_batches_by_fee_desc<T>(
    proposer_batches: impl IntoIterator<Item = (u32, Vec<T>)>,
    mut ordering_fee_of: impl FnMut(&T) -> u64,
) -> Vec<T> {
    let mut concatenated = concat_batches_by_proposer_index(proposer_batches);
    // Stable sort keeps concatenation order for equal fees.
    concatenated.sort_by_cached_key(|tx| Reverse(ordering_fee_of(tx)));
    concatenated
}

pub fn order_batches_mcp_policy<T>(
    proposer_batches: impl IntoIterator<Item = (u32, Vec<T>)>,
    mut class_of: impl FnMut(&T) -> ExecutionClass,
    mut ordering_fee_of: impl FnMut(&T) -> u64,
    mut signature_of: impl FnMut(&T) -> [u8; 64],
) -> Vec<T> {
    let mut concatenated = concat_batches_by_proposer_index(proposer_batches);
    // Canonical ordering policy:
    // 1. MCP transactions first.
    // 2. Within class, higher ordering fee first.
    // 3. For fee ties, signature bytes ascending.
    // 4. Stable sort preserves concatenated order for fully equal keys.
    concatenated
        .sort_by_cached_key(|tx| (class_of(tx), Reverse(ordering_fee_of(tx)), signature_of(tx)));
    concatenated
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Clone, Debug, Eq, PartialEq)]
    struct Tx {
        id: &'static str,
        fee: u64,
        class: ExecutionClass,
        sig: [u8; 64],
    }

    #[test]
    fn test_concat_batches_by_proposer_index_is_deterministic() {
        let batches = vec![
            (
                5,
                vec![
                    Tx {
                        id: "p5-0",
                        fee: 5,
                        class: ExecutionClass::Mcp,
                        sig: [5u8; 64],
                    },
                    Tx {
                        id: "p5-1",
                        fee: 1,
                        class: ExecutionClass::Mcp,
                        sig: [6u8; 64],
                    },
                ],
            ),
            (
                2,
                vec![
                    Tx {
                        id: "p2-0",
                        fee: 9,
                        class: ExecutionClass::Mcp,
                        sig: [2u8; 64],
                    },
                    Tx {
                        id: "p2-1",
                        fee: 8,
                        class: ExecutionClass::Mcp,
                        sig: [3u8; 64],
                    },
                ],
            ),
            (
                3,
                vec![Tx {
                    id: "p3-0",
                    fee: 7,
                    class: ExecutionClass::Mcp,
                    sig: [4u8; 64],
                }],
            ),
        ];

        let ordered = concat_batches_by_proposer_index(batches);
        let ids: Vec<_> = ordered.into_iter().map(|tx| tx.id).collect();
        assert_eq!(ids, vec!["p2-0", "p2-1", "p3-0", "p5-0", "p5-1"]);
    }

    #[test]
    fn test_order_batches_by_fee_desc_highest_first() {
        let batches = vec![
            (
                1,
                vec![
                    Tx {
                        id: "a",
                        fee: 10,
                        class: ExecutionClass::Mcp,
                        sig: [1u8; 64],
                    },
                    Tx {
                        id: "b",
                        fee: 4,
                        class: ExecutionClass::Mcp,
                        sig: [2u8; 64],
                    },
                ],
            ),
            (
                0,
                vec![
                    Tx {
                        id: "c",
                        fee: 12,
                        class: ExecutionClass::Mcp,
                        sig: [3u8; 64],
                    },
                    Tx {
                        id: "d",
                        fee: 7,
                        class: ExecutionClass::Mcp,
                        sig: [4u8; 64],
                    },
                ],
            ),
            (
                2,
                vec![Tx {
                    id: "e",
                    fee: 11,
                    class: ExecutionClass::Mcp,
                    sig: [5u8; 64],
                }],
            ),
        ];

        let ordered = order_batches_by_fee_desc(batches, |tx| tx.fee);
        let ids: Vec<_> = ordered.into_iter().map(|tx| tx.id).collect();
        assert_eq!(ids, vec!["c", "e", "a", "d", "b"]);
    }

    #[test]
    fn test_fee_ties_keep_concatenated_position_order() {
        let batches = vec![
            (
                1,
                vec![
                    Tx {
                        id: "p1-0",
                        fee: 5,
                        class: ExecutionClass::Mcp,
                        sig: [10u8; 64],
                    },
                    Tx {
                        id: "p1-1",
                        fee: 5,
                        class: ExecutionClass::Mcp,
                        sig: [11u8; 64],
                    },
                ],
            ),
            (
                0,
                vec![
                    Tx {
                        id: "p0-0",
                        fee: 5,
                        class: ExecutionClass::Mcp,
                        sig: [12u8; 64],
                    },
                    Tx {
                        id: "p0-1",
                        fee: 5,
                        class: ExecutionClass::Mcp,
                        sig: [13u8; 64],
                    },
                ],
            ),
        ];

        // Concatenated order is p0 then p1; ties should preserve this order.
        let ordered = order_batches_by_fee_desc(batches, |tx| tx.fee);
        let ids: Vec<_> = ordered.into_iter().map(|tx| tx.id).collect();
        assert_eq!(ids, vec!["p0-0", "p0-1", "p1-0", "p1-1"]);
    }

    #[test]
    fn test_duplicate_proposer_indices_preserve_input_batch_order() {
        let batches = vec![
            (
                3,
                vec![Tx {
                    id: "first",
                    fee: 1,
                    class: ExecutionClass::Mcp,
                    sig: [1u8; 64],
                }],
            ),
            (
                3,
                vec![Tx {
                    id: "second",
                    fee: 1,
                    class: ExecutionClass::Mcp,
                    sig: [2u8; 64],
                }],
            ),
            (
                2,
                vec![Tx {
                    id: "p2",
                    fee: 1,
                    class: ExecutionClass::Mcp,
                    sig: [3u8; 64],
                }],
            ),
        ];

        let ordered = concat_batches_by_proposer_index(batches);
        let ids: Vec<_> = ordered.into_iter().map(|tx| tx.id).collect();
        assert_eq!(ids, vec!["p2", "first", "second"]);
    }

    #[test]
    fn test_concat_handles_empty_and_single_batches() {
        let ordered_empty: Vec<Tx> = concat_batches_by_proposer_index(Vec::new());
        assert!(ordered_empty.is_empty());

        let ordered_single = concat_batches_by_proposer_index(vec![(
            9,
            vec![Tx {
                id: "only",
                fee: 42,
                class: ExecutionClass::Mcp,
                sig: [9u8; 64],
            }],
        )]);
        let ids: Vec<_> = ordered_single.into_iter().map(|tx| tx.id).collect();
        assert_eq!(ids, vec!["only"]);
    }

    #[test]
    fn test_order_handles_empty_and_single_batches() {
        let empty_batches: Vec<(u32, Vec<Tx>)> = Vec::new();
        let ordered_empty: Vec<Tx> = order_batches_by_fee_desc(empty_batches, |tx| tx.fee);
        assert!(ordered_empty.is_empty());

        let ordered_single = order_batches_by_fee_desc(
            vec![(
                9,
                vec![Tx {
                    id: "only",
                    fee: 42,
                    class: ExecutionClass::Mcp,
                    sig: [9u8; 64],
                }],
            )],
            |tx| tx.fee,
        );
        let ids: Vec<_> = ordered_single.into_iter().map(|tx| tx.id).collect();
        assert_eq!(ids, vec!["only"]);
    }

    #[test]
    fn test_duplicate_transactions_are_not_deduplicated() {
        let batches = vec![
            (
                0,
                vec![Tx {
                    id: "dup",
                    fee: 10,
                    class: ExecutionClass::Mcp,
                    sig: [1u8; 64],
                }],
            ),
            (
                1,
                vec![Tx {
                    id: "dup",
                    fee: 10,
                    class: ExecutionClass::Mcp,
                    sig: [2u8; 64],
                }],
            ),
        ];

        let ordered = order_batches_by_fee_desc(batches, |tx| tx.fee);
        let ids: Vec<_> = ordered.into_iter().map(|tx| tx.id).collect();
        assert_eq!(ids, vec!["dup", "dup"]);
    }

    #[test]
    fn test_order_batches_mcp_policy_puts_legacy_last() {
        let batches = vec![
            (
                0,
                vec![Tx {
                    id: "legacy-high-fee",
                    fee: 100,
                    class: ExecutionClass::Legacy,
                    sig: [1u8; 64],
                }],
            ),
            (
                1,
                vec![Tx {
                    id: "mcp-low-fee",
                    fee: 1,
                    class: ExecutionClass::Mcp,
                    sig: [2u8; 64],
                }],
            ),
        ];

        let ordered = order_batches_mcp_policy(batches, |tx| tx.class, |tx| tx.fee, |tx| tx.sig);
        let ids: Vec<_> = ordered.into_iter().map(|tx| tx.id).collect();
        assert_eq!(ids, vec!["mcp-low-fee", "legacy-high-fee"]);
    }

    #[test]
    fn test_order_batches_mcp_policy_tie_breaks_by_signature() {
        let batches = vec![(
            0,
            vec![
                Tx {
                    id: "sig-ff",
                    fee: 7,
                    class: ExecutionClass::Mcp,
                    sig: [0xffu8; 64],
                },
                Tx {
                    id: "sig-00",
                    fee: 7,
                    class: ExecutionClass::Mcp,
                    sig: [0x00u8; 64],
                },
            ],
        )];

        let ordered = order_batches_mcp_policy(batches, |tx| tx.class, |tx| tx.fee, |tx| tx.sig);
        let ids: Vec<_> = ordered.into_iter().map(|tx| tx.id).collect();
        assert_eq!(ids, vec!["sig-00", "sig-ff"]);
    }
}
