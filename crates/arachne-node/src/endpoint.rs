//! The Iroh endpoint key as the workspace endpoint signer (ADR A2 step 6).
//!
//! The Iroh endpoint id is an Ed25519 public key. The security crate asks
//! the endpoint key to sign the binding between a workspace member and this
//! endpoint; the signature is plain Ed25519 over the raw message.

/// Signs endpoint bindings with an Iroh secret key.
pub struct IrohEndpointSigner<'a>(pub &'a iroh::SecretKey);

impl arachne_security::EndpointSigner for IrohEndpointSigner<'_> {
    fn endpoint(&self) -> [u8; 32] {
        *self.0.public().as_bytes()
    }
    fn sign_endpoint(&self, message: &[u8]) -> Result<[u8; 64], &'static str> {
        Ok(self.0.sign(message).to_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use arachne_security::{EndpointSigner, JoinProof, Workspace, checkpoint_digest};

    #[test]
    fn the_iroh_key_signs_a_binding_every_member_verifies() {
        let secret = iroh::SecretKey::from_bytes(&[7; 32]);
        let signer = IrohEndpointSigner(&secret);
        assert_eq!(signer.endpoint(), *secret.public().as_bytes());
        let owner = Workspace::create(&signer, "Iroh endpoint").unwrap();
        assert_eq!(owner.endpoint(), *secret.public().as_bytes());
        // A checkpoint verifies the endpoint binding of every leaf.
        let checkpoint = owner.join_checkpoint().unwrap();
        JoinProof::from_trusted_checkpoint(
            owner.id(),
            checkpoint_digest(&checkpoint).unwrap(),
            &checkpoint,
        )
        .unwrap();
    }
}
