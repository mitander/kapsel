include!("support.rs");

mod validation {
    use super::*;

    include!("validation.rs");
}

mod lifecycle {
    use super::*;

    include!("lifecycle.rs");
}

mod recovery {
    use super::*;

    include!("recovery.rs");
}

mod receipt_behavior {
    use super::*;

    include!("receipt.rs");
}

mod publication_behavior {
    use super::*;

    include!("publication.rs");
}

mod migration {
    use super::*;

    include!("migration.rs");
}

mod qualification {
    use super::*;

    include!("qualification.rs");
}

mod v011_upgrade {
    use super::*;

    include!("v011_upgrade.rs");
}

mod snapshot_approval {
    use super::*;
    include!("snapshot.rs");
}
