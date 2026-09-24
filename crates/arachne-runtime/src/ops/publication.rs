//! Protected publication: stage an outgoing object, then adopt it (which
//! sends it). The staging body still lives in `protected.rs` and moves here
//! with the publication group; the workspace check is typed already.

use arachne_api::ApiError;

use crate::Session;
use crate::errors;

/// B5: a publication names the session workspace, checked before anything
/// is staged so the session stays usable.
pub(crate) fn check_workspace(session: &Session, workspace: Option<[u8; 32]>) -> Result<(), ApiError> {
    let owner = session
        .workspace
        .as_ref()
        .ok_or_else(errors::no_workspace)?;
    if workspace.is_some_and(|workspace| workspace != owner.id()) {
        return Err(ApiError::invalid_input(
            "workspace",
            "invalid publication workspace for this session",
        ));
    }
    Ok(())
}
