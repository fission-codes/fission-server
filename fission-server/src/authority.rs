use fission_common::capabilities::delegation;
use ucan::{capability::Capability, chain::ProofChain, crypto::KeyMaterial};

///////////
// TYPES //
///////////

pub struct Authority {
    proof: ProofChain,
}

/////////////////////
// IMPLEMENTATIONS //
/////////////////////

impl Authority {
    // pub fn try_authorize(
    //     &self,
    //     capability: &Capability<delegation::Resource, delegation::Ability>,
    // ) -> Result<(), StatusCode> {
    //     let capability_infos = self.proof.reduce_capabilities(&delegation::SEMANTICS);

    //     for capability_info in capability_infos {
    //         trace!("Checking capability: {:?}", capability_info.capability);
    //         if capability_info
    //             .originators
    //             .contains()
    //             && capability_info.capability.enables(capability)
    //         {
    //             debug!("Authorized!");
    //             return Ok(());
    //         }
    //     }

    //     Err(StatusCode::UNAUTHORIZED)
    // }

    // TODO:
    // Implement authority checking.
    // Different functions for different capabilities, or somehow merge them?
}
