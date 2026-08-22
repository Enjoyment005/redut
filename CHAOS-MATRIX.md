# Reliability chaos matrix

This file maps every mandatory scenario in `RELIABILITY-PLAN.md` to deterministic,
offline evidence.  Selectors are relative to `panel/tests`; the sanitized public tree has
the same selectors under `agent/tests`.

Status legend: **PASS** is an automated regression; **COMPOSED** is an invariant covered by
several focused regressions; **BOUNDARY** is an intentional architecture limit documented by
the plan and not presented as a passed global guarantee.

## State and concurrency

| Scenario | Status | Automated evidence |
|---|---|---|
| AUTO/MANUAL × `reputation/balanced/speed` × OK/SUSPECT/ROTATING/EMERGENCY/FROZEN_NET | PASS | `test_chaos_matrix.TestModeStrategyStateCrossProduct.test_auto_manual_all_strategies_and_runtime_states_are_orthogonal` |
| kill/reboot before and after each apply mutation phase | PASS | `test_apply_saga.TestApplyRecovery.test_kill_before_live_mutation_is_terminalized_without_write`, `test_kill_after_replace_from_staged_is_committed`, `test_applied_with_before_means_rollback_already_won`, `test_verify_failure_restores_exact_before_checksum` |
| kill/reboot across rollback planned/probing/staged/applied/verifying | PASS | `test_apply_saga.TestApplyRecovery.test_explicit_rollback_kill_points_converge_by_actual_checksum`, `test_failed_explicit_rollback_recovery_compensates_to_before` |
| last strategy click survives reboot | PASS | `test_selection_revisions.TestSelectionRevisionState.test_pending_revision_survives_reopen`, `TestSelectionReconciler.test_panel_startup_requeues_pending_revision_after_reboot` |
| manual click while strategy worker is queued | PASS | `test_strategy_convergence.TestStrategyConvergence.test_manual_selected_after_queue_supersedes_worker` |
| manual click versus rotate/apply | COMPOSED | `states.rotate`, strategy convergence, provider switching, and explicit apply use the same `vpn-agent.lock`; `test_strategy_convergence.TestStrategyConvergence.test_manual_selected_after_queue_supersedes_worker` plus apply saga checksum tests prove stale work cannot commit |
| manual click versus update | PASS | `test_update.TestApplyOrchestration.test_agent_lock_busy_after_download_defers_install` |
| manual/strategy writes versus provider refresh | COMPOSED | `test_pool_db_reliability.TestPoolDBReliability.test_parallel_connections_do_not_lose_updates`, `test_selection_revisions.TestSelectionRevisionState.test_intent_and_event_roll_back_together`, `test_panel_api.TestStrategyPreview.test_concurrent_posts_serialize_intent_and_config` |
| remove provider key for reserve/current in AUTO/MANUAL | PASS | `test_pool.TestPurgeProvider`, `test_panel_api.TestKeyDelete.test_battle_channel_kept_and_switch_kicked`, `test_manual_selection.TestSelectionMode.test_removed_provider_key_does_not_bypass_manual_pin`, `test_switch_provider.TestSwitchFromProvider` |
| current pool row disappears while sing-box still uses it | PASS | `test_strategy_convergence.TestStrategyConvergence.test_live_current_missing_from_pool_is_probed_and_ranked_first`, `test_pool.TestRefreshActiveCleanup.test_orphan_battle_host_survives_as_gone` |
| read-only/disk-full/corrupt config and state DB | PASS | `test_manual_selection.TestSelectionMode.test_config_write_failure_does_not_block_failover_and_is_retried`, `test_selection_revisions.TestSelectionReconciler.test_read_only_config_cannot_be_acknowledged_as_applied`, `test_config_schema.TestConfigSchema.test_corrupt_json_does_not_crash_agent_or_panel_loader`, `test_pool_db_reliability.TestPoolDBReliability.test_error_classification`, `test_corrupt_init_is_classified_and_releases_file`, `test_cannot_open_is_storage_error` |

## Network and provider faults

| Scenario | Status | Automated evidence |
|---|---|---|
| server WAN outage freezes mutation | PASS | `test_states.TestDecideLadder.test_frozen_net_wins_over_everything`, `test_manual_selection.TestSelectionMode.test_server_network_failure_does_not_release_manual` |
| only proxy is dead; independent quorum confirms rotation | PASS | `test_health_quorum.TestHealthQuorum.test_two_independent_targets_confirm_real_failure`, `test_tcp_refusal_is_fast_path_without_quorum`, `test_manual_selection.TestSelectionMode.test_confirmed_proxy_failure_releases_to_speed_before_ranking` |
| Telegram-only outage never rotates | PASS | `test_failures.TestVerifyWhyKind.test_tg_only_dead`, `TestTgDegraded.test_degraded_not_rotating`, `test_health_quorum.TestHealthQuorum.test_one_external_site_is_not_a_proxy_fault` |
| HTTP alive/SOCKS dead and reverse | PASS | `test_probe_log.TestProbeNetworkChaos.test_http_alive_socks_dead_and_reverse_still_select_working_path` |
| DNS outage remains a separate signal | PASS | `test_health_quorum.TestQuorumRegressions.test_net_alive_preserves_dns_failure_as_separate_signal` |
| packet loss and latency jitter | PASS | `test_probe_log.TestProbeNetworkChaos.test_packet_loss_and_latency_jitter_use_median_of_successful_samples`, `test_strategy_convergence.TestSwitchDecision.test_latency_regression_and_invalid_config` |
| provider 401/429/500/timeout/bad JSON | PASS | `test_provider_contract.TestTypedProviderErrors.test_http_statuses_have_stable_kinds`, `test_transport.TestCurlParsing.test_http_429_reads_retry_after_header`, `test_http_500_is_typed_and_not_retried_as_network`, `test_bad_json_is_protocol_error`, `test_transport.TestUrlopenClassification.test_success_with_bad_json_is_typed_protocol_error`, `test_transport.TestTransport.test_mutating_read_timeout_never_retried` |
| IPv4/IPv6 normalization and geo mismatch | PASS | `test_normalize.TestNormProxy6.test_ipv4_auto`, `test_ipv6_host_vs_ip`, `test_country.TestRating.test_geo_mismatch_penalty`, `TestProbeIntegration.test_score_punishes_geo_mismatch` |

## Money faults

| Scenario | Status | Automated evidence |
|---|---|---|
| timeout known before send | PASS | `test_transport.TestTransport.test_mutating_unsent_may_retry_via_tun0`, `test_transport.TestUrlopenClassification.test_urlerror_is_unsent` |
| timeout after provider may have accepted buy | PASS | `test_transport.TestTransport.test_mutating_read_timeout_never_retried`, `test_money.TestIdempotency.test_recovered_by_descr_no_double_buy`, `test_unconfirmed_no_record_no_double` |
| parallel buy/prolong on one node | PASS | node-local cross-thread/process spend lock in `money.py`; `test_money.TestBuyGates.test_parallel_buy_is_serialized_before_daily_limit_check` |
| daily count/spend limits on one node | PASS | `test_money.TestBuyGates.test_daily_count_limit`, `test_daily_spend_limit` |
| daily count/spend limit shared by several independent nodes | BOUNDARY | The plan explicitly defers a shared control plane. Each node has its own `state.db`; the live provider balance reserve remains the cross-node safety belt. No global daily-limit claim is asserted. |
| invalid currency, price, balance, or semantic-corrupt ledger | PASS | `test_money.TestBuyGates.test_invalid_price_balance_and_currency_fail_closed`, `test_semantically_corrupt_ledger_blocks_before_remote_mutation`, `test_money.TestProlong.test_invalid_quote_denies_prolong_before_mutation` |
| buy succeeds but post-probe fails | PASS | `test_chaos_matrix.TestPostBuyFailureBoundary.test_successful_purchase_with_failed_postprobe_is_never_applied` |
| retry/reboot after ambiguous or committed-but-unreturned buy does not charge twice | PASS | durable `spend_operation`, stable `descr`, atomic ledger/result replay, and no blind mutation retry: `test_money.TestIdempotency.test_recovered_by_descr_no_double_buy`, `test_unconfirmed_no_record_no_double`, `test_kill_after_remote_acceptance_recovers_after_reopen_without_second_buy`, `test_kill_after_ledger_commit_replays_result_without_second_buy`, `test_empty_success_response_stays_unresolved_and_blocks_repeat` |
| retry/reboot after accepted prolong does not prolong twice | PASS | durable baseline and read-only `date_end` reconciliation: `test_money.TestProlong.test_kill_after_prolong_acceptance_recovers_after_reopen` |
| corrupt post-mutation response cannot bypass budget | PASS | quote-currency conservative accounting: `test_money.TestIdempotency.test_corrupt_post_mutation_response_uses_quote_currency_and_positive_price` |

## Installation, migration, and rollback

| Scenario | Status | Automated evidence |
|---|---|---|
| clean install and repeat install | PASS | `test_install_reinstall.TestCleanInstallAndReinstall.test_clean_install_then_reinstall_preserves_owner_state` |
| owner config, secrets, DB, clients, and ring survive reinstall | PASS | same isolated installer acceptance above |
| old config migration, backup, dry-run, idempotency | PASS | `test_config_schema.TestConfigSchema.test_migration_dry_run_backup_and_idempotency`, `test_future_and_invalid_migrations_never_rewrite_file` |
| old DB migration and pre-migration snapshot | PASS | `test_pool.TestRolesV2Migration.test_migrates_and_snapshots`, `test_pool_db_reliability.TestPoolDBReliability.test_roles_snapshot_contains_committed_wal_rows` |
| update failure rollback | PASS | `test_update.TestApplyOrchestration.test_verify_fail_rolls_back`, `test_setup_rc_nonzero_rolls_back`, `test_rollback_trusts_health_not_rc` |

The final release gate is one complete canonical suite, one complete sanitized-public suite,
secret/hygiene checks, and one independent end-to-end audit after implementation and docs are
finished.
