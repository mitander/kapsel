fn snapshot_authorization(request: &SetDeploymentImageRequest) -> ExactAuthorization {
    let mut grant = authorization(request);
    grant.approved_target = Some(ApprovedTarget {
        uid: "deployment-uid-1".into(),
        resource_version: "resource-version-0".into(),
    });
    grant
}

#[tokio::test]
async fn stale_snapshot_is_durable_status_only_without_patch_or_receipt() {
    let stale = [
        ("drifted-version", "deployment-uid-1", "different"),
        ("recreated-object", "recreated", "resource-version-0"),
    ];
    for (case, uid, version) in stale {
        let path = database_path(case);
        let request = request();
        let mut approval = snapshot_authorization(&request);
        approval.approved_target = Some(ApprovedTarget {
            uid: uid.into(),
            resource_version: version.into(),
        });
        let mut gateway = Gateway::open_for_test(&path).unwrap();
        gateway.submit_exact_for_test(&request, &approval).unwrap();
        let mut adapter = failed_adapter(&path, &request);
        assert_eq!(
            gateway.run_once_with_adapter(&mut adapter, None).await.unwrap(),
            Some(OperationState::NotAttempted)
        );
        assert_eq!((adapter.apply_calls, adapter.observe_calls), (0, 0));
        drop(gateway);
        let mut gateway = Gateway::open_for_test(&path).unwrap();
        let row = gateway.journal.operation(&request.operation_id).unwrap().unwrap();
        assert_eq!(row.target_rejection(), Some(TargetRejection::StaleApproval));
        assert_eq!(row.targets().approved_target, approval.approved_target);
        assert_eq!(
            row.targets().observed_target.unwrap().uid.as_deref(),
            Some("deployment-uid-1")
        );
        assert!(row.targets().attempt_target.is_none());
        assert!(row.result().is_none());
        assert!(row.frozen_receipt().is_none());
        assert_eq!(
            gateway.run_once_with_adapter(&mut adapter, None).await.unwrap(),
            None
        );
        assert_eq!((adapter.apply_calls, adapter.observe_calls), (0, 0));
    }
}

#[tokio::test]
async fn matching_snapshot_freezes_distinct_approved_observed_and_attempt_targets() {
    let path = database_path("matching-snapshot-targets");
    let request = request();
    let approval = snapshot_authorization(&request);
    let mut gateway = Gateway::open_for_test(&path).unwrap();
    gateway.submit_exact_for_test(&request, &approval).unwrap();
    let mut adapter = failed_adapter(&path, &request);

    assert_eq!(
        gateway.run_once_with_adapter(&mut adapter, None).await.unwrap(),
        Some(OperationState::ReceiverObserved)
    );
    assert_eq!(adapter.apply_calls, 1);
    assert_eq!(
        adapter
            .applied_target
            .as_ref()
            .map(|target| (&target.deployment_uid, &target.resource_version)),
        approval
            .approved_target
            .as_ref()
            .map(|target| (&target.uid, &target.resource_version))
    );
    let row = gateway.journal.operation(&request.operation_id).unwrap().unwrap();
    let targets = row.targets();
    assert_eq!(targets.approved_target, approval.approved_target);
    assert_eq!(targets.attempt_target, approval.approved_target);
    assert_eq!(
        targets.observed_target,
        Some(ObservedTarget {
            uid: Some("deployment-uid-1".into()),
            resource_version: Some("resource-version-2".into()),
        })
    );
    let statement = gateway.journal.receipt_statement(&request.operation_id).unwrap().unwrap();
    assert_eq!(statement.approved_target(), approval.approved_target.as_ref());
    assert_eq!(statement.target_uid(), "deployment-uid-1");
    assert_eq!(statement.target_resource_version(), "resource-version-0");
    assert_eq!(statement.receiver_uid(), Some("deployment-uid-1"));
    assert_eq!(statement.observed_resource_version(), Some("resource-version-2"));
}

#[tokio::test]
async fn snapshot_apply_failure_after_marker_is_attempted_and_recovery_only_observes() {
    let path = database_path("snapshot-patch-conflict");
    let request = request();
    let approval = snapshot_authorization(&request);
    let mut gateway = Gateway::open_for_test(&path).unwrap();
    gateway.submit_exact_for_test(&request, &approval).unwrap();
    let mut conflict = failed_adapter(&path, &request);
    conflict.apply_failure = true;

    assert!(matches!(
        gateway.run_once_with_adapter(&mut conflict, None).await,
        Err(GatewayError::KubernetesApply)
    ));
    assert_eq!(gateway.get(&request.operation_id).unwrap(), Some(OperationState::ApplyStarted));
    assert_eq!(conflict.apply_calls, 1);
    assert_eq!(
        conflict
            .applied_target
            .as_ref()
            .map(|target| (&target.deployment_uid, &target.resource_version)),
        approval
            .approved_target
            .as_ref()
            .map(|target| (&target.uid, &target.resource_version))
    );
    let row = gateway.journal.operation(&request.operation_id).unwrap().unwrap();
    assert_eq!(row.targets().approved_target, approval.approved_target);
    assert_eq!(row.targets().attempt_target, approval.approved_target);
    assert_eq!(
        row.targets().observed_target,
        Some(ObservedTarget {
            uid: Some("deployment-uid-1".into()),
            resource_version: Some("resource-version-0".into()),
        })
    );
    assert!(row.result().is_none());
    drop(gateway);

    let mut gateway = Gateway::open_for_test(&path).unwrap();
    let mut recovery = failed_adapter(&path, &request);
    assert_eq!(
        gateway.run_once_with_adapter(&mut recovery, None).await.unwrap(),
        Some(OperationState::ReceiverObserved)
    );
    assert_eq!((recovery.identify_calls, recovery.apply_calls, recovery.observe_calls), (0, 0, 1));
    drop(gateway);
    std::fs::remove_dir_all(path.parent().unwrap()).unwrap();
}

#[tokio::test]
async fn restart_before_attempt_revalidates_the_original_snapshot_without_refreshing_it() {
    let path = database_path("snapshot-restart-before-attempt");
    let request = request();
    let approval = snapshot_authorization(&request);
    let gateway = Gateway::open_for_test(&path).unwrap();
    assert!(matches!(
        gateway.submit_exact_with_fault_for_test(
            &request,
            &approval,
            Some(FaultPoint::AuthorizedCommitted)
        ),
        Err(GatewayError::InjectedFault)
    ));
    drop(gateway);

    let mut gateway = Gateway::open_for_test(&path).unwrap();
    let mut adapter = failed_adapter(&path, &request);
    adapter.identified_target.resource_version = "intervening-write".into();
    assert_eq!(
        gateway.run_once_with_adapter(&mut adapter, None).await.unwrap(),
        Some(OperationState::NotAttempted)
    );
    assert_eq!((adapter.identify_calls, adapter.apply_calls, adapter.observe_calls), (1, 0, 0));
    let row = gateway.journal.operation(&request.operation_id).unwrap().unwrap();
    assert_eq!(row.target_rejection(), Some(TargetRejection::StaleApproval));
    assert_eq!(row.targets().approved_target, approval.approved_target);
    assert!(row.targets().attempt_target.is_none());
    drop(gateway);
    std::fs::remove_dir_all(path.parent().unwrap()).unwrap();
}

#[tokio::test]
async fn snapshot_restart_retains_authority_and_marker_recovery_never_resends() {
    for seam in [
        FaultPoint::RequestedCommitted,
        FaultPoint::AuthorizedCommitted,
        FaultPoint::ApplyStartedCommitted,
    ] {
        let path = database_path(&format!("snapshot-{seam:?}"));
        let request = request();
        let approval = snapshot_authorization(&request);
        let mut gateway = Gateway::open_for_test(&path).unwrap();
        if seam == FaultPoint::ApplyStartedCommitted {
            gateway.submit_exact_for_test(&request, &approval).unwrap();
            let mut adapter = failed_adapter(&path, &request);
            let attempt = gateway
                .run_operation_once_with_adapter_and_fault(
                    &request.operation_id,
                    &mut adapter,
                    Some(seam),
                )
                .await;
            assert!(matches!(attempt, Err(GatewayError::InjectedFault)));
            assert_eq!(adapter.apply_calls, 0);
        } else {
            let fault = gateway
                .submit_exact_with_fault_for_test(&request, &approval, Some(seam));
            assert!(matches!(fault, Err(GatewayError::InjectedFault)));
        }
        drop(gateway);
        let mut gateway = Gateway::open_for_test(&path).unwrap();
        let mut replacement = approval.clone();
        replacement.approved_target.as_mut().unwrap().resource_version = "replacement".into();
        let replaced = gateway.submit_exact_for_test(&request, &replacement);
        assert!(matches!(replaced, Err(GatewayError::OperationIdentityConflict)));
        let legacy = gateway.submit_exact_for_test(&request, &authorization(&request));
        assert!(matches!(legacy, Err(GatewayError::OperationIdentityConflict)));
        gateway.submit_exact_for_test(&request, &approval).unwrap();
        let mut adapter = failed_adapter(&path, &request);
        gateway.run_once_with_adapter(&mut adapter, None).await.unwrap();
        assert_eq!(
            adapter.apply_calls,
            usize::from(seam != FaultPoint::ApplyStartedCommitted)
        );
        let statement = gateway.journal.receipt_statement(&request.operation_id).unwrap().unwrap();
        assert_eq!(statement.approved_target(), approval.approved_target.as_ref());
        let bytes = sign_statement(&statement, &[9_u8; 32], "receipt-key").unwrap();
        let trust = ReceiptTrust {
            key_id: "receipt-key".into(),
            public_key: ed25519_dalek::SigningKey::from_bytes(&[9_u8; 32])
                .verifying_key()
                .to_bytes(),
            accepted_purpose: "kapsel.kap0038.kubernetes-effect-receipt.v3".into(),
            not_before_unix_s: 0,
            not_after_unix_s: 10,
        }
        .encode()
        .unwrap();
        let report = inspect_receipt(&bytes, &trust, 1, InspectionLimits::default());
        assert_eq!(report.status(), InspectionStatus::Inspected);
        assert_eq!(
            report.statement().unwrap().approved_target(),
            approval.approved_target.as_ref()
        );
    }
}
