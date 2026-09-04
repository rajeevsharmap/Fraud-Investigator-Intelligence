"""Detection rulebook - verbatim from Architecture.md section 16."""

SMURFING_RULES = {
    "SMF-001": {"name": "multiple_inbound_counterparties",
                "description": "Account receives funds from multiple distinct accounts within a short period.",
                "condition": {"unique_inbound_senders": ">= 3", "time_window_hours": "<= 24"}, "score": 15},
    "SMF-002": {"name": "fragmented_inbound_transactions",
                "description": "Multiple relatively smaller incoming transactions aggregate into a materially larger amount.",
                "condition": {"inbound_transaction_count": ">= 3", "aggregate_inbound_amount": "> account_baseline",
                              "amount_variance": "low_or_moderate"}, "score": 15},
    "SMF-003": {"name": "rapid_onward_transfer",
                "description": "Funds received by the account are transferred onward shortly after receipt.",
                "condition": {"incoming_to_outgoing_time_minutes": "<= 360",
                              "outgoing_amount_ratio_of_incoming": ">= 0.70"}, "score": 20},
    "SMF-004": {"name": "multiple_outbound_counterparties",
                "description": "Account distributes received funds to multiple beneficiaries or accounts.",
                "condition": {"unique_outbound_receivers": ">= 2", "time_window_hours": "<= 24"}, "score": 10},
    "SMF-005": {"name": "transaction_profile_deviation",
                "description": "Current transaction activity materially exceeds the customer's normal profile.",
                "condition": {"current_period_amount": "> 3 * avg_monthly_txn_amount"}, "score": 15},
    "SMF-006": {"name": "multi_hop_fund_flow",
                "description": "Funds can be followed through multiple connected accounts.",
                "condition": {"network_depth": ">= 2"}, "score": 15},
    "SMF-007": {"name": "fund_retention_anomaly",
                "description": "A large proportion of received funds leaves the account shortly after receipt.",
                "condition": {"outgoing_incoming_ratio": ">= 0.80", "outgoing_after_inbound_hours": "<= 6"}, "score": 20},
    "SMF-008": {"name": "new_beneficiary_after_inbound",
                "description": "Received funds are followed by a transfer to a newly added or first-time beneficiary.",
                "condition": {"is_first_time_beneficiary": True, "outgoing_after_inbound_hours": "<= 6"}, "score": 10},
}

REVERSE_SMURFING_RULES = {
    "RSMF-001": {"name": "multiple_outbound_counterparties",
                 "description": "One account distributes funds to multiple distinct receiving accounts.",
                 "condition": {"unique_outbound_receivers": ">= 3", "time_window_hours": "<= 24"}, "score": 20},
    "RSMF-002": {"name": "outbound_amount_fragmentation",
                 "description": "A source amount is divided into multiple smaller transfers.",
                 "condition": {"outbound_transaction_count": ">= 3", "individual_amounts": "relatively_similar"}, "score": 15},
    "RSMF-003": {"name": "rapid_distribution",
                 "description": "Funds are distributed to several accounts within a short period.",
                 "condition": {"distribution_window_minutes": "<= 360"}, "score": 15},
    "RSMF-004": {"name": "downstream_pass_through",
                 "description": "Recipients rapidly transfer received funds onward.",
                 "condition": {"recipient_onward_transfer_within_hours": "<= 6"}, "score": 20},
    "RSMF-005": {"name": "transaction_profile_deviation",
                 "description": "Distribution activity exceeds the source account's normal profile.",
                 "condition": {"current_amount": "> 3 * avg_monthly_txn_amount"}, "score": 15},
    "RSMF-006": {"name": "multi_hop_distribution_network",
                 "description": "Distributed funds continue through downstream accounts.",
                 "condition": {"network_depth": ">= 2"}, "score": 15},
    "RSMF-007": {"name": "downstream_fund_retention_anomaly",
                 "description": "Recipients transfer a substantial proportion of received funds onward shortly after receipt.",
                 "condition": {"recipient_outgoing_incoming_ratio": ">= 0.70",
                               "recipient_onward_transfer_within_hours": "<= 6"}, "score": 20},
}

ACCOUNT_SWAP_RULES = {
    "AS-001": {"name": "sim_change",
               "description": "SIM change detected near suspicious transaction activity.",
               "condition": {"sim_change_detected": True, "transaction_within_hours": "<= 24"}, "score": 25},
    "AS-002": {"name": "new_device",
               "description": "Transaction occurs from a previously unseen or untrusted device.",
               "condition": {"is_trusted_device": False}, "score": 15},
    "AS-003": {"name": "device_fingerprint_change",
               "description": "Device fingerprint changes around suspicious activity.",
               "condition": {"new_device_fingerprint": True}, "score": 15},
    "AS-004": {"name": "impossible_travel",
               "description": "Large geographic movement occurs within an implausibly short period.",
               "condition": {"distance_from_last_location_km": "> 500", "time_difference_hours": "<= 4"}, "score": 20},
    "AS-005": {"name": "vpn_or_proxy_signal",
               "description": "Transaction or authentication activity is associated with VPN or proxy usage.",
               "condition": {"is_vpn_or_proxy": True}, "score": 10},
    "AS-006": {"name": "registered_country_mismatch",
               "description": "Transaction-related location differs from the registered country.",
               "condition": {"registered_country_match": False}, "score": 10},
    "AS-007": {"name": "new_beneficiary",
               "description": "Large or unusual transfer is made to a newly added beneficiary.",
               "condition": {"is_first_time_beneficiary": True}, "score": 10},
    "AS-008": {"name": "transaction_amount_anomaly",
               "description": "Transaction amount significantly exceeds customer's normal activity.",
               "condition": {"transaction_amount": "> 3 * avg_monthly_txn_amount"}, "score": 15},
    "AS-009": {"name": "compound_account_takeover_signal",
               "description": "Multiple independent security and transaction anomalies occur together.",
               "condition": {"minimum_security_signals": ">= 2", "minimum_transaction_signals": ">= 1"}, "score": 20},
}

RULEBOOKS = {
    "smurfing": SMURFING_RULES,
    "reverse_smurfing": REVERSE_SMURFING_RULES,
    "account_swap": ACCOUNT_SWAP_RULES,
}

# Rule classes used for detection gating (Architecture.md section 17)
AS_SECURITY_RULES = {"AS-001", "AS-002", "AS-003", "AS-004", "AS-005", "AS-006"}
AS_TRANSACTION_RULES = {"AS-007", "AS-008"}
# A reverse-smurfing alert needs at least one distribution-side rule; the
# downstream rules (004/006/007) are corroborators, not a distribution.
RSMF_DISTRIBUTION_RULES = {"RSMF-001", "RSMF-002", "RSMF-003", "RSMF-005"}

# A smurfing alert needs >= 2 rules, at least one of them core (inbound-side,
# rapid-onward or profile evidence). 004/006/008 alone are corroborators.
SMF_CORE_RULES = {"SMF-001", "SMF-002", "SMF-003", "SMF-005", "SMF-007"}
