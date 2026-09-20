//! Self-authored workspace presentation; never an authorization source.
use super::{MemberProfile, SUITE, Workspace, bootstrap};
use openmls_traits::{OpenMlsProvider, crypto::OpenMlsCrypto, signatures::Signer};

const HEADER: &[u8; 5] = b"DFMP\x01";
const SERVICE_HEADER: &[u8; 5] = b"DFMP\x02";
pub const MAX_MEMBER_PROFILE: usize = 5 + 32 + 32 + 1 + 256 + 64;

#[derive(Clone, Debug)]
pub struct MemberIdentity {
    pub id: [u8; 32],
    pub endpoint: [u8; 32],
    pub administrator: bool,
}

impl Workspace {
    pub fn member_roster(&self) -> Result<Vec<MemberIdentity>, &'static str> {
        let admins = bootstrap::authority(self.group.extensions())?;
        self.group
            .members()
            .map(|m| {
                let (id, endpoint) = bootstrap::binding(&m.credential)?;
                Ok(MemberIdentity {
                    id,
                    endpoint,
                    administrator: admins.contains(&m.signature_key),
                })
            })
            .collect()
    }

    /// A stable chosen name, shareable only within this workspace. Rename ordering
    /// is not implemented; a valid signature alone would not prove the latest name.
    pub fn sign_member_profile(&self) -> Result<Vec<u8>, &'static str> {
        self.sign_profile(false)
    }

    pub fn sign_service_profile(&self) -> Result<Vec<u8>, &'static str> {
        self.sign_profile(true)
    }

    fn sign_profile(&self, service: bool) -> Result<Vec<u8>, &'static str> {
        let member = self.member().ok_or("member profile required")?;
        let mut bytes = if service {
            SERVICE_HEADER.to_vec()
        } else {
            HEADER.to_vec()
        };
        bytes.extend(self.id());
        bytes.extend(member.id());
        if service {
            bytes.push(1);
        }
        bytes.extend(member.display_name().as_bytes());
        let signature = self
            ._signer
            .sign(&bytes)
            .map_err(|_| "profile signing failed")?;
        bytes.extend(signature);
        Ok(bytes)
    }

    pub fn verify_member_profile(&self, bytes: &[u8]) -> Result<MemberProfile, &'static str> {
        let (name_start, service) = if bytes.starts_with(HEADER) {
            (69, false)
        } else if bytes.starts_with(SERVICE_HEADER) && bytes.get(69) == Some(&1) {
            (70, true)
        } else {
            return Err("invalid member profile scope or size");
        };
        if bytes.len() < name_start + 1 + 64
            || bytes.len() > MAX_MEMBER_PROFILE
            || bytes[5..37] != self.id()
        {
            return Err("invalid member profile scope or size");
        }
        let id: [u8; 32] = bytes[37..69].try_into().unwrap();
        let end = bytes.len() - 64;
        let name =
            std::str::from_utf8(&bytes[name_start..end]).map_err(|_| "invalid profile text")?;
        let profile = MemberProfile::new_kind(id, name, service)?;
        if profile.display_name() != name {
            return Err("noncanonical member profile");
        }
        let member = self
            .group
            .members()
            .find(|m| bootstrap::binding(&m.credential).is_ok_and(|(bound, _)| bound == id))
            .ok_or("profile author is not a current member")?;
        self.provider
            .crypto()
            .verify_signature(
                SUITE.signature_algorithm(),
                &bytes[..end],
                &member.signature_key,
                &bytes[end..],
            )
            .map_err(|_| "invalid member profile signature")?;
        Ok(profile)
    }
}

#[test]
fn profiles_bind_names_to_current_workspace_members() {
    let mut admin = Workspace::create([91; 32], "Alex Morgan").unwrap();
    let outsider = Workspace::create([92; 32], "Alex Morgan").unwrap();
    let signed = admin.sign_member_profile().unwrap();
    assert_eq!(
        admin.verify_member_profile(&signed).unwrap(),
        admin.member().unwrap().clone()
    );
    assert!(outsider.verify_member_profile(&signed).is_err());
    for cut in 0..signed.len() {
        assert!(admin.verify_member_profile(&signed[..cut]).is_err());
    }
    for i in 0..signed.len() {
        let mut bad = signed.clone();
        bad[i] ^= 1;
        assert!(admin.verify_member_profile(&bad).is_err());
    }
    let (invitation, checkpoint) = admin.issue_invitation().unwrap();
    let pending =
        super::PendingJoin::from_invitation(&invitation, &checkpoint, [93; 32], "Alex Morgan")
            .unwrap();
    let request = pending.admission_request().unwrap();
    let prepared = admin.prepare_admission([93; 32], request).unwrap();
    admin = prepared.workspace;
    let reply = admin
        .retained_admission([93; 32], request)
        .unwrap()
        .unwrap();
    let mut proof = pending.join_proof().unwrap();
    proof
        .apply_add(&reply.authorization, &reply.commit)
        .unwrap();
    let member = pending.prepare_workspace(&proof, &reply.welcome).unwrap();
    let second = member.sign_member_profile().unwrap();
    let profile = admin.verify_member_profile(&second).unwrap();
    let mut forged = second[..second.len() - 64].to_vec();
    forged.extend(admin._signer.sign(&forged).unwrap());
    assert!(admin.verify_member_profile(&forged).is_err());
    let mut invalid_name = signed[..69].to_vec();
    invalid_name.extend("Alex\u{202e}Morgan".as_bytes());
    invalid_name.extend(admin._signer.sign(&invalid_name).unwrap());
    assert!(admin.verify_member_profile(&invalid_name).is_err());

    assert_eq!(profile.display_name(), "Alex Morgan");
    assert_ne!(profile.id(), admin.member().unwrap().id());
    assert_eq!(
        admin
            .member_roster()
            .unwrap()
            .iter()
            .filter(|m| m.administrator)
            .count(),
        1
    );
    admin = admin
        .prepare_management(super::ManagementAction::Promote(profile.id()))
        .unwrap()
        .workspace;
    assert_eq!(
        admin
            .member_roster()
            .unwrap()
            .iter()
            .filter(|m| m.administrator)
            .count(),
        2
    );
    admin = admin
        .prepare_management(super::ManagementAction::Remove(profile.id()))
        .unwrap()
        .workspace;
    assert!(admin.verify_member_profile(&second).is_err());
}
