    #[tokio::test]
    async fn receipt_statement_retains_exact_available_condition_reason() {
        let path = database_path("receipt-available-reason");
        let request = request();
        let mut gateway = Gateway::open_for_test(&path).unwrap();
        gateway
            .submit_exact_for_test(&request, &authorization(&request))
            .unwrap();
        let mut adapter = failed_adapter(&path, &request);
        adapter.observation.updated_replicas = Some(1);
        adapter.observation.available_replicas = Some(1);
        adapter.observation.unavailable_replicas = Some(0);
        adapter.observation.rollout_condition_type = Some("Available".into());
        adapter.observation.rollout_condition_status = Some("True".into());
        adapter.observation.rollout_condition_reason = Some("DifferentObservedReason".into());
        gateway
            .run_once_with_adapter(&mut adapter, None)
            .await
            .unwrap();

        let statement = gateway
            .journal
            .receipt_statement(&request.operation_id)
            .unwrap()
            .unwrap();
        assert_eq!(statement.result(), OperationResult::Succeeded);
        assert_eq!(
            statement.rollout_condition_reason(),
            Some("DifferentObservedReason")
        );
        drop(gateway);
        fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }

    #[tokio::test]
    async fn receipt_inspection_reports_frozen_failed_receiver_facts() {
        let path = database_path("receipt-first-tracer");
        let request = request();
        let mut gateway = Gateway::open_for_test(&path).unwrap();
        gateway
            .submit_exact_for_test(&request, &authorization(&request))
            .unwrap();
        let mut adapter = failed_adapter(&path, &request);
        assert_eq!(
            gateway
                .run_once_with_adapter(&mut adapter, None)
                .await
                .unwrap(),
            Some(OperationState::ReceiverObserved)
        );

        let statement = gateway
            .journal
            .receipt_statement(&request.operation_id)
            .unwrap()
            .unwrap();
        assert_eq!(statement.operation_id, request.operation_id);
        assert_eq!(statement.authorization_id, "auth-001");
        assert_eq!(
            statement.authorization_signer_key_id(),
            "effect-gateway-authorization-test-key"
        );
        assert_eq!(statement.authorization_grant_digest().len(), 64);
        assert_eq!(statement.write_strategy(), WRITE_STRATEGY);
        assert_eq!(statement.target_uid(), "deployment-uid-1");
        assert_eq!(statement.target_resource_version(), "resource-version-0");
        assert_eq!(statement.receiver_uid(), Some("deployment-uid-1"));
        assert_eq!(
            statement.observed_image(),
            Some(request.immutable_image_digest.as_str())
        );
        assert_eq!(statement.observed_operation_marker(), Some("op-001"));
        assert_eq!(statement.current_generation(), Some(2));
        assert_eq!(statement.requested_generation(), Some(2));
        assert_eq!(statement.observed_generation(), Some(2));
        assert_eq!(statement.desired_replicas(), Some(1));
        assert_eq!(statement.updated_replicas(), Some(0));
        assert_eq!(statement.available_replicas(), Some(0));
        assert_eq!(statement.unavailable_replicas(), Some(1));
        assert_eq!(statement.result, OperationResult::Failed);
        assert_eq!(
            statement.rollout_condition_reason.as_deref(),
            Some("ProgressDeadlineExceeded")
        );

        let seed = [7_u8; 32];
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&seed);
        let trust = ReceiptTrust {
            key_id: "effect-gateway-test-key".into(),
            public_key: signing_key.verifying_key().to_bytes(),
            accepted_purpose: "kapsel.kap0038.kubernetes-effect-receipt.v2".into(),
            not_before_unix_s: 100,
            not_after_unix_s: 200,
        }
        .encode()
        .unwrap();
        let receipt = sign_statement(&statement, &seed, "effect-gateway-test-key").unwrap();
        let report = inspect_receipt(&receipt, &trust, 150, InspectionLimits::default());

        assert_eq!(report.status(), InspectionStatus::Inspected);
        assert_eq!(report.statement(), Some(&statement));
        assert_eq!(report.non_claims(), Some(statement.non_claims()));
        drop(gateway);
        fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }

    #[test]
    fn hostile_receipt_inputs_fail_closed_without_verified_vocabulary() {
        let statement = ReceiptStatement {
            approved_target: None,
            operation_id: "op-001".into(),
            authorization_id: "auth-001".into(),
            authorization_signer_key_id: "effect-gateway-authorization-test-key".into(),
            authorization_grant_digest: "0".repeat(64),
            namespace: "demo".into(),
            deployment: "agent-api".into(),
            container: "api".into(),
            immutable_image_digest: request().immutable_image_digest,
            write_strategy: WRITE_STRATEGY.into(),
            target_uid: "deployment-uid-1".into(),
            target_resource_version: "resource-version-0".into(),
            receiver_uid: Some("deployment-uid-1".into()),
            observed_image: Some(request().immutable_image_digest),
            observed_operation_marker: Some("op-001".into()),
            current_generation: Some(2),
            requested_generation: Some(2),
            observed_generation: Some(2),
            observed_resource_version: Some("resource-version-2".into()),
            desired_replicas: Some(1),
            updated_replicas: Some(0),
            available_replicas: Some(0),
            unavailable_replicas: Some(1),
            rollout_condition_type: Some("Progressing".into()),
            rollout_condition_status: Some("False".into()),
            rollout_condition_reason: Some("ProgressDeadlineExceeded".into()),
            result: OperationResult::Failed,
        };
        let seed = [8_u8; 32];
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&seed);
        let trust = ReceiptTrust {
            key_id: "effect-gateway-test-key".into(),
            public_key: signing_key.verifying_key().to_bytes(),
            accepted_purpose: "kapsel.kap0038.kubernetes-effect-receipt.v2".into(),
            not_before_unix_s: 100,
            not_after_unix_s: 200,
        }
        .encode()
        .unwrap();
        let receipt = sign_statement(&statement, &seed, "effect-gateway-test-key").unwrap();

        let mut malformed = receipt.clone();
        malformed[0] = b'X';
        assert_eq!(
            inspect_receipt(&malformed, &trust, 150, InspectionLimits::default()).status(),
            InspectionStatus::StructureRejected
        );

        let mut bad_signature = receipt.clone();
        let last = bad_signature.last_mut().unwrap();
        *last ^= 1;
        assert_eq!(
            inspect_receipt(&bad_signature, &trust, 150, InspectionLimits::default()).status(),
            InspectionStatus::SignatureRejected
        );

        assert_eq!(
            inspect_receipt(&receipt, &trust, 250, InspectionLimits::default()).status(),
            InspectionStatus::UntrustedSigner
        );
        assert!(!format!(
            "{:?}{:?}{:?}{:?}",
            InspectionStatus::StructureRejected,
            InspectionStatus::SignatureRejected,
            InspectionStatus::UntrustedSigner,
            InspectionStatus::Inspected
        )
        .contains("Verified"));
    }

    #[tokio::test]
    async fn receipt_written_reopens_and_finalizes_without_kubernetes() {
        let path = database_path("receipt-finalize-recovery");
        let output_directory = path.parent().unwrap().join("receipts");
        private_directory(&output_directory);
        let output_directory = fs::canonicalize(output_directory).unwrap();
        let seed = [11_u8; 32];
        let request = request();
        {
            let mut gateway = Gateway::open_for_test(&path).unwrap();
            gateway
                .submit_exact_for_test(&request, &authorization(&request))
                .unwrap();
            let mut adapter = failed_adapter(&path, &request);
            gateway
                .run_once_with_adapter(&mut adapter, None)
                .await
                .unwrap();
            let result = gateway.finalize_operation_receipt_once_with_fault(
                &request.operation_id,
                &ReceiptSettings {
                    signing_seed: &seed,
                    key_id: "effect-gateway-test-key",
                    output_directory: &output_directory,
                },
                Some(FaultPoint::ReceiptWrittenCommitted),
            );
            assert!(
                matches!(result, Err(GatewayError::InjectedFault)),
                "{result:?}"
            );
            assert_eq!(
                gateway.get(&request.operation_id).unwrap(),
                Some(OperationState::ReceiptWritten)
            );
        }
        let mut gateway = Gateway::open_for_test(&path).unwrap();
        assert_eq!(
            gateway
                .finalize_receipt_once(&ReceiptSettings {
                    signing_seed: &seed,
                    key_id: "effect-gateway-test-key",
                    output_directory: &output_directory,
                })
                .unwrap(),
            Some(OperationState::Finalized)
        );
        let reference = gateway
            .receipt_reference(&request.operation_id)
            .unwrap()
            .unwrap();
        assert!(reference.path.exists());
        assert_eq!(
            gateway.get(&request.operation_id).unwrap(),
            Some(OperationState::Finalized)
        );
        assert_eq!(
            gateway
                .run_once_with_adapter(&mut failed_adapter(&path, &request), None)
                .await
                .unwrap(),
            None
        );
        drop(gateway);
        fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }

    #[tokio::test]
    async fn receipt_access_directory_keeps_stable_reference_out_of_replacement() {
        let path = database_path("receipt-access-directory");
        let stable_directory = path.parent().unwrap().join("receipts");
        let access_directory = path.parent().unwrap().join("receipts-retained");
        private_directory(&stable_directory);
        private_directory(&access_directory);
        let stable_directory = fs::canonicalize(stable_directory).unwrap();
        let access_directory = fs::canonicalize(access_directory).unwrap();
        let request = request();
        let mut gateway = Gateway::open_for_test(&path).unwrap();
        gateway
            .submit_exact_for_test(&request, &authorization(&request))
            .unwrap();
        gateway
            .run_once_with_adapter(&mut failed_adapter(&path, &request), None)
            .await
            .unwrap();

        assert_eq!(
            gateway
                .finalize_operation_receipt_once(
                    &request.operation_id,
                    &ReceiptSettings {
                        signing_seed: &[11_u8; 32],
                        key_id: "effect-gateway-test-key",
                        output_directory: &stable_directory,
                    },
                    Some(&access_directory),
                )
                .unwrap(),
            Some(OperationState::Finalized)
        );

        let reference = gateway
            .receipt_reference(&request.operation_id)
            .unwrap()
            .unwrap();
        assert_eq!(reference.path.parent(), Some(stable_directory.as_path()));
        assert!(!reference.path.exists());
        let access_path = access_directory.join(reference.path.file_name().unwrap());
        assert!(access_path.is_file());
        assert_eq!(fs::read_dir(&stable_directory).unwrap().count(), 0);
        let signed_grant = sign_authorization_grant(
            &authorization(&request),
            &[7_u8; 32],
            "effect-gateway-authorization-test-key",
        )
        .unwrap();
        let loaded = gateway
            .authorized_operation(&request, &signed_grant)
            .unwrap()
            .unwrap();
        let (bytes, digest) = Gateway::read_loaded_receipt(
            loaded,
            &stable_directory,
            Some(&access_directory),
        )
        .unwrap();
        assert_eq!(publication::receipt_digest_hex(&bytes), digest);
        drop(gateway);
        fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }

    #[tokio::test]
    async fn receipt_preparation_is_durable_before_external_publication() {
        let path = database_path("receipt-prepared-recovery");
        let output_directory = path.parent().unwrap().join("receipts");
        private_directory(&output_directory);
        let output_directory = fs::canonicalize(output_directory).unwrap();
        let request = request();
        {
            let mut gateway = Gateway::open_for_test(&path).unwrap();
            gateway
                .submit_exact_for_test(&request, &authorization(&request))
                .unwrap();
            gateway
                .run_once_with_adapter(&mut failed_adapter(&path, &request), None)
                .await
                .unwrap();
            assert!(matches!(
                gateway.finalize_operation_receipt_once_with_fault(
                    &request.operation_id,
                    &ReceiptSettings {
                        signing_seed: &[13_u8; 32],
                        key_id: "effect-gateway-test-key",
                        output_directory: &output_directory,
                    },
                    Some(FaultPoint::ReceiptPreparedCommitted)
                ),
                Err(GatewayError::InjectedFault)
            ));
            assert_eq!(
                gateway.get(&request.operation_id).unwrap(),
                Some(OperationState::ReceiptPrepared)
            );
            assert_eq!(fs::read_dir(&output_directory).unwrap().count(), 0);
        }
        let gateway = Gateway::open_for_test(&path).unwrap();
        assert_eq!(
            gateway
                .finalize_receipt_once(&ReceiptSettings {
                    signing_seed: &[99_u8; 32],
                    key_id: "rotated-key",
                    output_directory: path.parent().unwrap(),
                })
                .unwrap(),
            Some(OperationState::Finalized)
        );
        let reference = gateway
            .receipt_reference(&request.operation_id)
            .unwrap()
            .unwrap();
        assert_eq!(reference.path.parent(), Some(output_directory.as_path()));
        assert!(reference.path.exists());
        drop(gateway);
        fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }

    #[tokio::test]
    async fn process_kill_after_receipt_publication_recovers_frozen_bytes_under_rotation() {
        let path = database_path("process-kill-receipt");
        let output_directory = path.parent().unwrap().join("receipts");
        private_directory(&output_directory);
        let output_directory = fs::canonicalize(output_directory).unwrap();
        let request = request();
        {
            let mut gateway = Gateway::open_for_test(&path).unwrap();
            gateway
                .submit_exact_for_test(&request, &authorization(&request))
                .unwrap();
            gateway
                .run_once_with_adapter(&mut failed_adapter(&path, &request), None)
                .await
                .unwrap();
        }
        let ready = path.parent().unwrap().join("receipt-ready");
        let mut child =
            spawn_process_child("receipt", &path, &ready, None, Some(&output_directory));
        wait_for_child_seam(&mut child, &ready);
        let published_path = fs::read_dir(&output_directory)
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .path();
        let published_bytes = fs::read(&published_path).unwrap();
        kill_child(&mut child);

        let rotated_directory = path.parent().unwrap().join("rotated-receipts");
        private_directory(&rotated_directory);
        let rotated_directory = fs::canonicalize(rotated_directory).unwrap();
        let gateway = Gateway::open_for_test(&path).unwrap();
        assert_eq!(
            gateway.get(&request.operation_id).unwrap(),
            Some(OperationState::ReceiptPrepared)
        );
        assert_eq!(
            gateway
                .finalize_receipt_once(&ReceiptSettings {
                    signing_seed: &[99_u8; 32],
                    key_id: "rotated-key",
                    output_directory: &rotated_directory,
                })
                .unwrap(),
            Some(OperationState::Finalized)
        );
        let reference = gateway
            .receipt_reference(&request.operation_id)
            .unwrap()
            .unwrap();
        assert_eq!(reference.path, published_path);
        assert_eq!(fs::read(&reference.path).unwrap(), published_bytes);
        assert_eq!(
            publication::receipt_digest_hex(&published_bytes),
            reference.digest
        );
        assert_eq!(fs::read_dir(&output_directory).unwrap().count(), 1);
        assert_eq!(fs::read_dir(&rotated_directory).unwrap().count(), 0);
        let frozen_key_id = gateway
            .journal
            .connection
            .query_row(
                "SELECT receipt_key_id FROM kubernetes_image_operations WHERE operation_id = ?1",
                [&request.operation_id],
                |row| row.get::<_, String>(0),
            )
            .unwrap();
        assert_eq!(frozen_key_id, "process-receipt-key");
        drop(gateway);
        fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }

    #[tokio::test]
    async fn receipt_publish_fault_recovers_with_existing_identical_bytes() {
        let path = database_path("receipt-published-recovery");
        let output_directory = path.parent().unwrap().join("receipts");
        private_directory(&output_directory);
        let output_directory = fs::canonicalize(output_directory).unwrap();
        let seed = [13_u8; 32];
        let request = request();
        {
            let mut gateway = Gateway::open_for_test(&path).unwrap();
            gateway
                .submit_exact_for_test(&request, &authorization(&request))
                .unwrap();
            let mut adapter = failed_adapter(&path, &request);
            gateway
                .run_once_with_adapter(&mut adapter, None)
                .await
                .unwrap();
            assert!(matches!(
                gateway.finalize_operation_receipt_once_with_fault(
                    &request.operation_id,
                    &ReceiptSettings {
                        signing_seed: &seed,
                        key_id: "effect-gateway-test-key",
                        output_directory: &output_directory,
                    },
                    Some(FaultPoint::ReceiptPublished)
                ),
                Err(GatewayError::InjectedFault)
            ));
            assert_eq!(
                gateway.get(&request.operation_id).unwrap(),
                Some(OperationState::ReceiptPrepared)
            );
        }
        let rotated_directory = path.parent().unwrap().join("rotated-receipts");
        private_directory(&rotated_directory);
        let rotated_directory = fs::canonicalize(rotated_directory).unwrap();
        let gateway = Gateway::open_for_test(&path).unwrap();
        assert_eq!(
            gateway
                .finalize_receipt_once(&ReceiptSettings {
                    signing_seed: &[99_u8; 32],
                    key_id: "rotated-key",
                    output_directory: &rotated_directory,
                })
                .unwrap(),
            Some(OperationState::Finalized)
        );
        let reference = gateway
            .receipt_reference(&request.operation_id)
            .unwrap()
            .unwrap();
        assert_eq!(reference.path.parent(), Some(output_directory.as_path()));
        assert_eq!(fs::read_dir(&output_directory).unwrap().count(), 1);
        assert_eq!(fs::read_dir(&rotated_directory).unwrap().count(), 0);
        drop(gateway);
        fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }

    #[tokio::test]
    async fn finalized_commit_is_terminal_after_reopen() {
        let path = database_path("receipt-finalized-terminal");
        let output_directory = path.parent().unwrap().join("receipts");
        private_directory(&output_directory);
        let output_directory = fs::canonicalize(output_directory).unwrap();
        let seed = [14_u8; 32];
        let request = request();
        {
            let mut gateway = Gateway::open_for_test(&path).unwrap();
            gateway
                .submit_exact_for_test(&request, &authorization(&request))
                .unwrap();
            let mut adapter = failed_adapter(&path, &request);
            gateway
                .run_once_with_adapter(&mut adapter, None)
                .await
                .unwrap();
            assert!(matches!(
                gateway.finalize_operation_receipt_once_with_fault(
                    &request.operation_id,
                    &ReceiptSettings {
                        signing_seed: &seed,
                        key_id: "effect-gateway-test-key",
                        output_directory: &output_directory,
                    },
                    Some(FaultPoint::FinalizedCommitted)
                ),
                Err(GatewayError::InjectedFault)
            ));
        }
        let gateway = Gateway::open_for_test(&path).unwrap();
        assert_eq!(
            gateway.get(&request.operation_id).unwrap(),
            Some(OperationState::Finalized)
        );
        assert_eq!(
            gateway
                .finalize_receipt_once(&ReceiptSettings {
                    signing_seed: &seed,
                    key_id: "effect-gateway-test-key",
                    output_directory: &output_directory,
                })
                .unwrap(),
            None
        );
        drop(gateway);
        fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }

    #[tokio::test]
    async fn receipt_publication_collision_does_not_finalize() {
        let path = database_path("receipt-collision");
        let output_directory = path.parent().unwrap().join("receipts");
        let seed = [12_u8; 32];
        let request = request();
        let mut gateway = Gateway::open_for_test(&path).unwrap();
        gateway
            .submit_exact_for_test(&request, &authorization(&request))
            .unwrap();
        let mut adapter = failed_adapter(&path, &request);
        gateway
            .run_once_with_adapter(&mut adapter, None)
            .await
            .unwrap();
        let statement = gateway
            .journal
            .receipt_statement(&request.operation_id)
            .unwrap()
            .unwrap();
        let receipt = sign_statement(&statement, &seed, "effect-gateway-test-key").unwrap();
        let digest = publication::receipt_digest_hex(&receipt);
        private_directory(&output_directory);
        let output_directory = fs::canonicalize(output_directory).unwrap();
        fs::write(
            output_directory.join(publication::receipt_filename(
                &request.operation_id,
                &digest,
            )),
            b"different",
        )
        .unwrap();

        assert!(matches!(
            gateway.finalize_receipt_once(&ReceiptSettings {
                signing_seed: &seed,
                key_id: "effect-gateway-test-key",
                output_directory: &output_directory,
            }),
            Err(GatewayError::ReceiptPublication)
        ));
        assert_eq!(
            gateway.get(&request.operation_id).unwrap(),
            Some(OperationState::ReceiptPrepared)
        );
        drop(gateway);
        fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }

    #[tokio::test]
    async fn finalizer_contender_changes_no_durable_or_public_fact() {
        let path = database_path("receipt-finalizer-lock");
        let output_directory = path.parent().unwrap().join("receipts");
        private_directory(&output_directory);
        let output_directory = fs::canonicalize(output_directory).unwrap();
        let seed = [21_u8; 32];
        let request = request();
        let mut first = Gateway::open_for_test(&path).unwrap();
        first
            .submit_exact_for_test(&request, &authorization(&request))
            .unwrap();
        first
            .run_once_with_adapter(&mut failed_adapter(&path, &request), None)
            .await
            .unwrap();
        let worker_lock = first.journal.try_lock_worker().unwrap().unwrap();
        let contender = Gateway::open_for_test(&path).unwrap();

        assert_eq!(
            contender
                .finalize_receipt_once(&ReceiptSettings {
                    signing_seed: &seed,
                    key_id: "effect-gateway-test-key",
                    output_directory: &output_directory,
                })
                .unwrap(),
            None
        );
        assert_eq!(
            contender.get(&request.operation_id).unwrap(),
            Some(OperationState::ReceiverObserved)
        );
        assert_eq!(fs::read_dir(&output_directory).unwrap().count(), 0);

        drop(worker_lock);
        assert_eq!(
            contender
                .finalize_receipt_once(&ReceiptSettings {
                    signing_seed: &seed,
                    key_id: "effect-gateway-test-key",
                    output_directory: &output_directory,
                })
                .unwrap(),
            Some(OperationState::Finalized)
        );
        drop(contender);
        drop(first);
        fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }
