use anyhow::Result;
use fission_core::capabilities::did::Did;
use rs_ucan::{semantics::ability::Ability, ucan::Ucan};
use std::fmt::Debug;

#[tracing::instrument(skip(ucans))]
pub(crate) fn find_delegation_chain(
    subject_did: &Did,
    ability: &(impl Ability + ?Sized + Debug),
    target_did: &str,
    ucans: &[Ucan],
) -> Option<Vec<Ucan>> {
    // This kinda fakes it for now
    // Would make a lot more sense in UCAN v1.0
    // We don't really follow the `prf`s
    // We don't support ucan/*
    // We're not checking caveats
    let mut current_target = target_did;
    let mut chain = Vec::new();
    loop {
        if current_target == subject_did.as_ref() {
            return Some(chain); // no proofs needed
        }

        tracing::debug!(audience = %current_target, "Looking for UCANs with particular audience.");

        // Find a UCAN that 'proves' the corrent subject
        let Some(ucan) = ucans.iter().find(|ucan| {
            if ucan.audience() == current_target {
                tracing::debug!(
                    ucan = ucan.encode().unwrap(),
                    "Found UCAN proof chain candidate"
                );

                ucan.capabilities().any(|cap| {
                    let valid_attenuation = ability.is_valid_attenuation(cap.ability());
                    let matching_resource = cap
                        .resource()
                        .downcast_ref::<Did>()
                        .map_or(false, |did| did == subject_did);

                    tracing::debug!(
                        valid_attenuation,
                        matching_resource,
                        "Checking capability attenuation"
                    );

                    valid_attenuation && matching_resource
                    // Not handling caveats yet
                })
            } else {
                false
            }
        }) else {
            tracing::debug!("Couldn't prove this step, aborting");
            return None;
        };

        tracing::debug!("Chain link proven");

        current_target = ucan.issuer();

        chain.push(ucan.clone());

        if current_target == subject_did.as_ref() {
            tracing::debug!("Finished chain");
            return Some(chain);
        }
    }
}

pub(crate) fn encode_ucan_header(proofs: &[Ucan]) -> Result<String> {
    Ok(proofs
        .iter()
        .map(|ucan| Ok(ucan.encode()?))
        .collect::<Result<Vec<_>>>()?
        .join(", "))
}
