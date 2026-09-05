//! Deterministic comparison of ambiguous-action continuation policies.
//!
//! This is an independent receiver model. It does not call the gateway classifier or production
//! recovery path. The Temporal policy projects the documented behavior of one Activity with an
//! explicit maximum of two attempts; it does not execute Temporal.

const OPERATION_ID_ONE: &str = "kap30-op-001";
const OPERATION_ID_TWO: &str = "kap30-op-002";
const DEPLOYMENT_UID: &str = "deployment-uid-1";
const RESOURCE_VERSION: &str = "resource-version-1";
const IMAGE: &str = concat!(
    "registry.example/kapsel/demo@sha256:",
    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
);
const STRATEGY: &str = "conditional-strategic-merge-patch";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FrozenPatch {
    operation_id: &'static str,
    deployment_uid: &'static str,
    resource_version: &'static str,
    image: &'static str,
    strategy: &'static str,
}

const PATCH_ONE: FrozenPatch = FrozenPatch {
    operation_id: OPERATION_ID_ONE,
    deployment_uid: DEPLOYMENT_UID,
    resource_version: RESOURCE_VERSION,
    image: IMAGE,
    strategy: STRATEGY,
};
const PATCH_TWO: FrozenPatch = FrozenPatch {
    operation_id: OPERATION_ID_TWO,
    ..PATCH_ONE
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Policy {
    ObserveOnly,
    ExactReplayOnce,
    TemporalActivityMaximumAttemptsTwo,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Scenario {
    DeathBeforeSend,
    AcceptedMutationLostResponse,
    ConcurrentInvocations,
    InterveningWriter,
    DeleteAndRecreate,
    LaterTemplateChangeRetainingMarker,
    AdmissionSideEffect,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CallerConclusion {
    SucceededFromObservedState,
    Unknown,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Evidence {
    caller_invocations: usize,
    http_patch_requests: usize,
    mutating_admission_invocations: usize,
    admission_out_of_band_effects: usize,
    persisted_deployment_changes: usize,
    controller_effects: usize,
    abandoned_authorized_actions: usize,
    conclusions: Vec<CallerConclusion>,
    sent_patches: Vec<FrozenPatch>,
    later_generation_attributed_to_original: bool,
}

#[derive(Clone, Copy)]
struct Observation {
    uid: &'static str,
    image: &'static str,
    operation_marker: Option<&'static str>,
    current_generation: i64,
    observed_generation: i64,
    desired_replicas: i32,
    updated_replicas: i32,
    available_replicas: i32,
    unavailable_replicas: i32,
    available_condition: bool,
}

struct Receiver {
    observation: Observation,
    resource_version: &'static str,
    response_generation_one: Option<i64>,
    response_generation_two: Option<i64>,
    attempted_one: bool,
    attempted_two: bool,
    http_patch_requests: usize,
    mutating_admission_invocations: usize,
    admission_out_of_band_effects: usize,
    persisted_deployment_changes: usize,
    controller_effects: usize,
    sent_patches: Vec<FrozenPatch>,
    later_template_change: bool,
}

impl Receiver {
    fn initial() -> Self {
        Self {
            observation: Observation {
                uid: DEPLOYMENT_UID,
                image: "registry.example/kapsel/demo:before",
                operation_marker: None,
                current_generation: 1,
                observed_generation: 1,
                desired_replicas: 1,
                updated_replicas: 1,
                available_replicas: 1,
                unavailable_replicas: 0,
                available_condition: true,
            },
            resource_version: RESOURCE_VERSION,
            response_generation_one: None,
            response_generation_two: None,
            attempted_one: false,
            attempted_two: false,
            http_patch_requests: 0,
            mutating_admission_invocations: 0,
            admission_out_of_band_effects: 0,
            persisted_deployment_changes: 0,
            controller_effects: 0,
            sent_patches: Vec::new(),
            later_template_change: false,
        }
    }

    fn patch(&mut self, patch: FrozenPatch, response_delivered: bool, has_side_effect: bool) {
        self.http_patch_requests += 1;
        self.mutating_admission_invocations += 1;
        self.admission_out_of_band_effects += usize::from(has_side_effect);
        self.sent_patches.push(patch);
        if patch.operation_id == OPERATION_ID_ONE {
            self.attempted_one = true;
        } else if patch.operation_id == OPERATION_ID_TWO {
            self.attempted_two = true;
        }

        // The live v1.33.12 proof qualifies admission before stale UID/resourceVersion rejection.
        // These frozen receiver preconditions, not admission, decide whether persistence occurs.
        if patch.deployment_uid != self.observation.uid
            || patch.resource_version != self.resource_version
        {
            return;
        }
        self.observation.image = patch.image;
        self.observation.operation_marker = Some(patch.operation_id);
        self.observation.current_generation += 1;
        self.observation.observed_generation = self.observation.current_generation;
        self.resource_version = "resource-version-2";
        self.persisted_deployment_changes += 1;
        self.controller_effects += 1;
        if response_delivered {
            if patch.operation_id == OPERATION_ID_ONE {
                self.response_generation_one = Some(self.observation.current_generation);
            } else {
                self.response_generation_two = Some(self.observation.current_generation);
            }
        }
    }

    fn intervening_writer(&mut self) {
        self.observation.image = "registry.example/kapsel/demo:intervening";
        self.observation.operation_marker = None;
        self.observation.current_generation += 1;
        self.observation.observed_generation = self.observation.current_generation;
        self.resource_version = "resource-version-writer";
        self.persisted_deployment_changes += 1;
        self.controller_effects += 1;
    }

    fn delete_and_recreate(&mut self) {
        self.observation.uid = "deployment-uid-replacement";
        self.observation.image = "registry.example/kapsel/demo:replacement";
        self.observation.operation_marker = None;
        self.observation.current_generation = 1;
        self.observation.observed_generation = 1;
        self.resource_version = "resource-version-replacement";
        self.persisted_deployment_changes += 1;
        self.controller_effects += 1;
    }

    fn later_template_change_retaining_marker(&mut self) {
        self.observation.current_generation += 1;
        self.observation.observed_generation = self.observation.current_generation;
        self.resource_version = "resource-version-later-template";
        self.persisted_deployment_changes += 1;
        self.controller_effects += 1;
        self.later_template_change = true;
    }

    fn conclusion(&self, operation_id: &str) -> CallerConclusion {
        let operation_matches = self.observation.uid == DEPLOYMENT_UID
            && self.observation.image == IMAGE
            && self.observation.operation_marker == Some(operation_id);
        let response_generation = if operation_id == OPERATION_ID_ONE {
            self.response_generation_one
        } else {
            self.response_generation_two
        };
        let requested_generation = response_generation.or(if operation_matches {
            Some(self.observation.current_generation)
        } else {
            None
        });
        let generation_matches = requested_generation == Some(self.observation.current_generation)
            && self.observation.observed_generation >= self.observation.current_generation;
        let replicas_available = self.observation.updated_replicas
            == self.observation.desired_replicas
            && self.observation.available_replicas == self.observation.desired_replicas
            && self.observation.unavailable_replicas == 0
            && self.observation.available_condition;
        if operation_matches && generation_matches && replicas_available {
            CallerConclusion::SucceededFromObservedState
        } else {
            CallerConclusion::Unknown
        }
    }
}

fn compare(policy: Policy, scenario: Scenario) -> Evidence {
    let mut receiver = Receiver::initial();
    let concurrent = scenario == Scenario::ConcurrentInvocations;
    let side_effecting_admission = scenario == Scenario::AdmissionSideEffect;
    let ambiguous_operation = match scenario {
        Scenario::DeathBeforeSend => Some(PATCH_ONE),
        Scenario::AcceptedMutationLostResponse | Scenario::AdmissionSideEffect => {
            receiver.patch(PATCH_ONE, false, side_effecting_admission);
            Some(PATCH_ONE)
        },
        Scenario::ConcurrentInvocations => {
            receiver.patch(PATCH_ONE, true, false);
            receiver.patch(PATCH_TWO, true, false);
            None
        },
        Scenario::InterveningWriter => {
            receiver.intervening_writer();
            Some(PATCH_ONE)
        },
        Scenario::DeleteAndRecreate => {
            receiver.delete_and_recreate();
            Some(PATCH_ONE)
        },
        Scenario::LaterTemplateChangeRetainingMarker => {
            receiver.patch(PATCH_ONE, false, false);
            receiver.later_template_change_retaining_marker();
            Some(PATCH_ONE)
        },
    };

    if policy != Policy::ObserveOnly {
        if let Some(patch) = ambiguous_operation {
            // Both replay policies send one bounded recovery attempt using only the frozen payload.
            receiver.patch(patch, true, side_effecting_admission);
        }
    }

    let conclusions = if concurrent {
        vec![
            receiver.conclusion(OPERATION_ID_ONE),
            receiver.conclusion(OPERATION_ID_TWO),
        ]
    } else {
        vec![receiver.conclusion(OPERATION_ID_ONE)]
    };
    let abandoned_authorized_actions = if concurrent {
        usize::from(!receiver.attempted_one) + usize::from(!receiver.attempted_two)
    } else {
        usize::from(!receiver.attempted_one)
    };
    let later_generation_attributed_to_original = receiver.later_template_change
        && receiver.conclusion(OPERATION_ID_ONE) == CallerConclusion::SucceededFromObservedState;
    Evidence {
        caller_invocations: usize::from(concurrent) + 1,
        http_patch_requests: receiver.http_patch_requests,
        mutating_admission_invocations: receiver.mutating_admission_invocations,
        admission_out_of_band_effects: receiver.admission_out_of_band_effects,
        persisted_deployment_changes: receiver.persisted_deployment_changes,
        controller_effects: receiver.controller_effects,
        abandoned_authorized_actions,
        conclusions,
        sent_patches: receiver.sent_patches,
        later_generation_attributed_to_original,
    }
}

struct Expected {
    policy: Policy,
    scenario: Scenario,
    counts: [usize; 7],
    conclusions: &'static [CallerConclusion],
    sent_patches: &'static [FrozenPatch],
    later_generation_attributed_to_original: bool,
}

const SUCCEEDED: &[CallerConclusion] = &[CallerConclusion::SucceededFromObservedState];
const UNKNOWN: &[CallerConclusion] = &[CallerConclusion::Unknown];
const CONCURRENT: &[CallerConclusion] = &[
    CallerConclusion::SucceededFromObservedState,
    CallerConclusion::Unknown,
];
const NO_PATCHES: &[FrozenPatch] = &[];
const ONE_PATCH: &[FrozenPatch] = &[PATCH_ONE];
const TWO_PATCHES: &[FrozenPatch] = &[PATCH_ONE, PATCH_ONE];
const CONCURRENT_PATCHES: &[FrozenPatch] = &[PATCH_ONE, PATCH_TWO];

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "the complete 21-cell evidence matrix stays inline so every expected cell is visible"
)]
fn frozen_recovery_policy_matrix_separates_requests_admission_and_effects() {
    use Policy::{ExactReplayOnce, ObserveOnly, TemporalActivityMaximumAttemptsTwo as Temporal};
    use Scenario::{
        AcceptedMutationLostResponse as Lost, AdmissionSideEffect as SideEffect,
        ConcurrentInvocations as ConcurrentScenario, DeathBeforeSend as BeforeSend,
        DeleteAndRecreate as Recreate, InterveningWriter as Writer,
        LaterTemplateChangeRetainingMarker as Later,
    };

    // Counts are callers, PATCHes, admission invocations, out-of-band admission effects,
    // persisted Deployment changes, controller effects, and abandoned unsent actions.
    let expected = [
        Expected {
            policy: ObserveOnly,
            scenario: BeforeSend,
            counts: [1, 0, 0, 0, 0, 0, 1],
            conclusions: UNKNOWN,
            sent_patches: NO_PATCHES,
            later_generation_attributed_to_original: false,
        },
        Expected {
            policy: ObserveOnly,
            scenario: Lost,
            counts: [1, 1, 1, 0, 1, 1, 0],
            conclusions: SUCCEEDED,
            sent_patches: ONE_PATCH,
            later_generation_attributed_to_original: false,
        },
        Expected {
            policy: ObserveOnly,
            scenario: ConcurrentScenario,
            counts: [2, 2, 2, 0, 1, 1, 0],
            conclusions: CONCURRENT,
            sent_patches: CONCURRENT_PATCHES,
            later_generation_attributed_to_original: false,
        },
        Expected {
            policy: ObserveOnly,
            scenario: Writer,
            counts: [1, 0, 0, 0, 1, 1, 1],
            conclusions: UNKNOWN,
            sent_patches: NO_PATCHES,
            later_generation_attributed_to_original: false,
        },
        Expected {
            policy: ObserveOnly,
            scenario: Recreate,
            counts: [1, 0, 0, 0, 1, 1, 1],
            conclusions: UNKNOWN,
            sent_patches: NO_PATCHES,
            later_generation_attributed_to_original: false,
        },
        Expected {
            policy: ObserveOnly,
            scenario: Later,
            counts: [1, 1, 1, 0, 2, 2, 0],
            conclusions: SUCCEEDED,
            sent_patches: ONE_PATCH,
            later_generation_attributed_to_original: true,
        },
        Expected {
            policy: ObserveOnly,
            scenario: SideEffect,
            counts: [1, 1, 1, 1, 1, 1, 0],
            conclusions: SUCCEEDED,
            sent_patches: ONE_PATCH,
            later_generation_attributed_to_original: false,
        },
        Expected {
            policy: ExactReplayOnce,
            scenario: BeforeSend,
            counts: [1, 1, 1, 0, 1, 1, 0],
            conclusions: SUCCEEDED,
            sent_patches: ONE_PATCH,
            later_generation_attributed_to_original: false,
        },
        Expected {
            policy: ExactReplayOnce,
            scenario: Lost,
            counts: [1, 2, 2, 0, 1, 1, 0],
            conclusions: SUCCEEDED,
            sent_patches: TWO_PATCHES,
            later_generation_attributed_to_original: false,
        },
        Expected {
            policy: ExactReplayOnce,
            scenario: ConcurrentScenario,
            counts: [2, 2, 2, 0, 1, 1, 0],
            conclusions: CONCURRENT,
            sent_patches: CONCURRENT_PATCHES,
            later_generation_attributed_to_original: false,
        },
        Expected {
            policy: ExactReplayOnce,
            scenario: Writer,
            counts: [1, 1, 1, 0, 1, 1, 0],
            conclusions: UNKNOWN,
            sent_patches: ONE_PATCH,
            later_generation_attributed_to_original: false,
        },
        Expected {
            policy: ExactReplayOnce,
            scenario: Recreate,
            counts: [1, 1, 1, 0, 1, 1, 0],
            conclusions: UNKNOWN,
            sent_patches: ONE_PATCH,
            later_generation_attributed_to_original: false,
        },
        Expected {
            policy: ExactReplayOnce,
            scenario: Later,
            counts: [1, 2, 2, 0, 2, 2, 0],
            conclusions: SUCCEEDED,
            sent_patches: TWO_PATCHES,
            later_generation_attributed_to_original: true,
        },
        Expected {
            policy: ExactReplayOnce,
            scenario: SideEffect,
            counts: [1, 2, 2, 2, 1, 1, 0],
            conclusions: SUCCEEDED,
            sent_patches: TWO_PATCHES,
            later_generation_attributed_to_original: false,
        },
        Expected {
            policy: Temporal,
            scenario: BeforeSend,
            counts: [1, 1, 1, 0, 1, 1, 0],
            conclusions: SUCCEEDED,
            sent_patches: ONE_PATCH,
            later_generation_attributed_to_original: false,
        },
        Expected {
            policy: Temporal,
            scenario: Lost,
            counts: [1, 2, 2, 0, 1, 1, 0],
            conclusions: SUCCEEDED,
            sent_patches: TWO_PATCHES,
            later_generation_attributed_to_original: false,
        },
        Expected {
            policy: Temporal,
            scenario: ConcurrentScenario,
            counts: [2, 2, 2, 0, 1, 1, 0],
            conclusions: CONCURRENT,
            sent_patches: CONCURRENT_PATCHES,
            later_generation_attributed_to_original: false,
        },
        Expected {
            policy: Temporal,
            scenario: Writer,
            counts: [1, 1, 1, 0, 1, 1, 0],
            conclusions: UNKNOWN,
            sent_patches: ONE_PATCH,
            later_generation_attributed_to_original: false,
        },
        Expected {
            policy: Temporal,
            scenario: Recreate,
            counts: [1, 1, 1, 0, 1, 1, 0],
            conclusions: UNKNOWN,
            sent_patches: ONE_PATCH,
            later_generation_attributed_to_original: false,
        },
        Expected {
            policy: Temporal,
            scenario: Later,
            counts: [1, 2, 2, 0, 2, 2, 0],
            conclusions: SUCCEEDED,
            sent_patches: TWO_PATCHES,
            later_generation_attributed_to_original: true,
        },
        Expected {
            policy: Temporal,
            scenario: SideEffect,
            counts: [1, 2, 2, 2, 1, 1, 0],
            conclusions: SUCCEEDED,
            sent_patches: TWO_PATCHES,
            later_generation_attributed_to_original: false,
        },
    ];

    for row in expected {
        let actual = compare(row.policy, row.scenario);
        assert_eq!(
            [
                actual.caller_invocations,
                actual.http_patch_requests,
                actual.mutating_admission_invocations,
                actual.admission_out_of_band_effects,
                actual.persisted_deployment_changes,
                actual.controller_effects,
                actual.abandoned_authorized_actions,
            ],
            row.counts,
            "count drift for {:?} / {:?}",
            row.policy,
            row.scenario
        );
        assert_eq!(
            actual.conclusions, row.conclusions,
            "conclusion drift for {:?} / {:?}",
            row.policy, row.scenario
        );
        assert_eq!(
            actual.sent_patches, row.sent_patches,
            "frozen authority drift for {:?} / {:?}",
            row.policy, row.scenario
        );
        assert_eq!(
            actual.later_generation_attributed_to_original,
            row.later_generation_attributed_to_original,
            "attribution drift for {:?} / {:?}",
            row.policy,
            row.scenario
        );
    }
}
