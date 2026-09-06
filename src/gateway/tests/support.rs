    use std::{
        fs,
        os::unix::fs::PermissionsExt,
        path::{Path, PathBuf},
        process::{Child, Command, Stdio},
        time::{Duration, Instant},
    };

    use rusqlite::{params, Connection};

    use super::*;
    use super::journal;

    fn database_path(name: &str) -> PathBuf {
        let directory = std::env::temp_dir().join(format!(
            "kapsel-effect-gateway-{}-{}-{name}",
            std::process::id(),
            std::thread::current().name().unwrap_or("test")
        ));
        let _ = fs::remove_dir_all(&directory);
        fs::create_dir(&directory).unwrap();
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
        directory.join("journal.sqlite3")
    }

    fn private_directory(path: &Path) {
        fs::create_dir(path).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
    }

    fn request() -> SetDeploymentImageRequest {
        SetDeploymentImageRequest {
            operation_id: "op-001".into(),
            namespace: "demo".into(),
            deployment: "agent-api".into(),
            container: "api".into(),
            immutable_image_digest: concat!(
                "registry.example/example/agent-api@sha256:",
                "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
            )
            .into(),
        }
    }

    fn authorization(request: &SetDeploymentImageRequest) -> ExactAuthorization {
        ExactAuthorization {
            approved_target: None,
            authorization_id: "auth-001".into(),
            operation_id: request.operation_id.clone(),
            namespace: request.namespace.clone(),
            deployment: request.deployment.clone(),
            container: request.container.clone(),
            immutable_image_digest: request.immutable_image_digest.clone(),
        }
    }

    fn unknown_observation(request: &SetDeploymentImageRequest) -> ReceiverObservation {
        ReceiverObservation {
            deployment_uid: Some("deployment-uid-1".into()),
            resource_version: Some("resource-version-2".into()),
            current_generation: Some(2),
            observed_generation: Some(2),
            image: Some(request.immutable_image_digest.clone()),
            operation_marker: Some(request.operation_id.clone()),
            desired_replicas: Some(1),
            updated_replicas: Some(0),
            available_replicas: Some(0),
            unavailable_replicas: Some(1),
            rollout_condition_type: None,
            rollout_condition_status: None,
            rollout_condition_reason: None,
        }
    }

    struct FakeAdapter {
        database_path: PathBuf,
        identify_calls: usize,
        apply_calls: usize,
        observe_calls: usize,
        apply_started_seen: bool,
        outcome: ApplyOutcome,
        observation: ReceiverObservation,
    }

    fn failed_adapter(path: &Path, request: &SetDeploymentImageRequest) -> FakeAdapter {
        FakeAdapter {
            database_path: path.to_path_buf(),
            identify_calls: 0,
            apply_calls: 0,
            observe_calls: 0,
            apply_started_seen: false,
            outcome: ApplyOutcome {
                accepted: true,
                requested_generation: Some(2),
                deployment_uid: Some("deployment-uid-1".into()),
                resource_version: Some("resource-version-1".into()),
            },
            observation: {
                let mut observation = unknown_observation(request);
                observation.rollout_condition_type = Some("Progressing".into());
                observation.rollout_condition_status = Some("False".into());
                observation.rollout_condition_reason = Some("ProgressDeadlineExceeded".into());
                observation
            },
        }
    }

    #[allow(
        clippy::unused_async_trait_impl,
        reason = "the fake mirrors the production async provider seam"
    )]
    impl DeploymentImageAdapter for FakeAdapter {
        async fn identify(
            &mut self,
            _: &SetDeploymentImageRequest,
        ) -> Result<TargetIdentity, TargetReadError> {
            self.identify_calls += 1;
            Ok(TargetIdentity {
                deployment_uid: "deployment-uid-1".into(),
                resource_version: "resource-version-0".into(),
            })
        }

        async fn apply(
            &mut self,
            request: &SetDeploymentImageRequest,
            _: &TargetIdentity,
        ) -> Result<ApplyOutcome, ()> {
            self.apply_calls += 1;
            let connection = Connection::open(&self.database_path).map_err(|_| ())?;
            let persisted: (String, i64, String) = connection
                .query_row(
                    "SELECT state, apply_attempted, write_strategy
                     FROM kubernetes_image_operations
                     WHERE operation_id = ?1",
                    [&request.operation_id],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                )
                .map_err(|_| ())?;
            self.apply_started_seen =
                persisted == ("apply_started".into(), 1, WRITE_STRATEGY.into());
            Ok(self.outcome.clone())
        }

        async fn observe(
            &mut self,
            _: &SetDeploymentImageRequest,
            _: &ApplyOutcome,
        ) -> Result<ReceiverObservation, ()> {
            self.observe_calls += 1;
            Ok(self.observation.clone())
        }
    }

    struct TargetRoutingAdapter {
        permanent: Option<(String, TargetRejection)>,
        transient_once: Option<String>,
        transient_returned: bool,
        identify_order: Vec<String>,
        apply_order: Vec<String>,
        observe_order: Vec<String>,
    }

    impl TargetRoutingAdapter {
        fn permanent(operation_id: &str, rejection: TargetRejection) -> Self {
            Self {
                permanent: Some((operation_id.into(), rejection)),
                transient_once: None,
                transient_returned: false,
                identify_order: Vec::new(),
                apply_order: Vec::new(),
                observe_order: Vec::new(),
            }
        }

        fn transient_once(operation_id: &str) -> Self {
            Self {
                permanent: None,
                transient_once: Some(operation_id.into()),
                transient_returned: false,
                identify_order: Vec::new(),
                apply_order: Vec::new(),
                observe_order: Vec::new(),
            }
        }
    }

    #[allow(
        clippy::unused_async_trait_impl,
        reason = "the fake mirrors the production async provider seam"
    )]
    impl DeploymentImageAdapter for TargetRoutingAdapter {
        async fn identify(
            &mut self,
            request: &SetDeploymentImageRequest,
        ) -> Result<TargetIdentity, TargetReadError> {
            self.identify_order.push(request.operation_id.clone());
            if let Some((operation_id, rejection)) = &self.permanent {
                if operation_id == &request.operation_id {
                    return Err(TargetReadError::Permanent(*rejection));
                }
            }
            if self.transient_once.as_deref() == Some(request.operation_id.as_str())
                && !self.transient_returned
            {
                self.transient_returned = true;
                return Err(TargetReadError::Transient);
            }
            Ok(TargetIdentity {
                deployment_uid: "deployment-uid-1".into(),
                resource_version: "resource-version-0".into(),
            })
        }

        async fn apply(
            &mut self,
            request: &SetDeploymentImageRequest,
            _: &TargetIdentity,
        ) -> Result<ApplyOutcome, ()> {
            self.apply_order.push(request.operation_id.clone());
            Ok(ApplyOutcome {
                accepted: true,
                requested_generation: Some(2),
                deployment_uid: Some("deployment-uid-1".into()),
                resource_version: Some("resource-version-1".into()),
            })
        }

        async fn observe(
            &mut self,
            request: &SetDeploymentImageRequest,
            _: &ApplyOutcome,
        ) -> Result<ReceiverObservation, ()> {
            self.observe_order.push(request.operation_id.clone());
            let mut observation = unknown_observation(request);
            observation.rollout_condition_type = Some("Progressing".into());
            observation.rollout_condition_status = Some("False".into());
            observation.rollout_condition_reason = Some("ProgressDeadlineExceeded".into());
            Ok(observation)
        }
    }

    struct ProcessMutationAdapter {
        ready_path: PathBuf,
        patch_count_path: PathBuf,
    }

    #[allow(
        clippy::unused_async_trait_impl,
        reason = "the fake mirrors the production async provider seam"
    )]
    impl DeploymentImageAdapter for ProcessMutationAdapter {
        async fn identify(
            &mut self,
            _: &SetDeploymentImageRequest,
        ) -> Result<TargetIdentity, TargetReadError> {
            Ok(TargetIdentity {
                deployment_uid: "deployment-uid-1".into(),
                resource_version: "resource-version-0".into(),
            })
        }

        async fn apply(
            &mut self,
            _: &SetDeploymentImageRequest,
            _: &TargetIdentity,
        ) -> Result<ApplyOutcome, ()> {
            let count = fs::read_to_string(&self.patch_count_path)
                .ok()
                .and_then(|value| value.parse::<usize>().ok())
                .unwrap_or(0)
                + 1;
            fs::write(&self.patch_count_path, count.to_string()).map_err(|_| ())?;
            fs::write(&self.ready_path, b"provider-side-effect-complete").map_err(|_| ())?;
            std::future::pending::<Result<ApplyOutcome, ()>>().await
        }

        async fn observe(
            &mut self,
            _: &SetDeploymentImageRequest,
            _: &ApplyOutcome,
        ) -> Result<ReceiverObservation, ()> {
            Err(())
        }
    }

    fn spawn_process_child(
        scenario: &str,
        database: &Path,
        ready: &Path,
        patch_count: Option<&Path>,
        output: Option<&Path>,
    ) -> Child {
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .args([
                "--ignored",
                "--exact",
                "gateway::tests::recovery::process_kill_child",
                "--nocapture",
                "--test-threads=1",
            ])
            .env("KAPSEL_PROCESS_CHILD_SCENARIO", scenario)
            .env("KAPSEL_PROCESS_DATABASE", database)
            .env("KAPSEL_PROCESS_READY", ready)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::inherit());
        if let Some(path) = patch_count {
            command.env("KAPSEL_PROCESS_PATCH_COUNT", path);
        }
        if let Some(path) = output {
            command.env("KAPSEL_PROCESS_OUTPUT", path);
        }
        command.spawn().unwrap()
    }

    fn wait_for_child_seam(child: &mut Child, ready: &Path) {
        let deadline = Instant::now() + Duration::from_secs(10);
        while Instant::now() < deadline {
            if ready.exists() {
                return;
            }
            let status = child.try_wait().unwrap();
            assert!(status.is_none(), "process-kill child exited before seam");
            std::thread::sleep(Duration::from_millis(10));
        }
        let _ = child.kill();
        let _ = child.wait();
        assert!(ready.exists(), "process-kill child did not reach seam");
    }

    fn kill_child(child: &mut Child) {
        child.kill().unwrap();
        let status = child.wait().unwrap();
        assert!(!status.success());
    }
