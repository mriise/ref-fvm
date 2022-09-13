use fvm_shared::randomness::RANDOMNESS_LENGTH;

use super::*;
use crate::kernel::{Result, RandomnessOps};

struct Rand;

impl Rand {
    /// Gets 32 bytes of randomness from the ticket chain.
    /// The supplied output buffer must have at least 32 bytes of capacity.
    /// If this syscall succeeds, exactly 32 bytes will be written starting at the
    /// supplied offset.
    pub fn get_chain_randomness(
        context: Context<'_, impl RandomnessOps>,
        pers: i64,  // DomainSeparationTag
        round: i64, // ChainEpoch
        entropy_off: u32,
        entropy_len: u32,
    ) -> Result<[u8; RANDOMNESS_LENGTH]> {
        let entropy = context.memory.try_slice(entropy_off, entropy_len)?;
        context
            .kernel
            .get_randomness_from_tickets(pers, round, entropy)
    }

    /// Gets 32 bytes of randomness from the beacon system (currently Drand).
    /// The supplied output buffer must have at least 32 bytes of capacity.
    /// If this syscall succeeds, exactly 32 bytes will be written starting at the
    /// supplied offset.
    pub fn get_beacon_randomness(
        context: Context<'_, impl RandomnessOps>,
        pers: i64,  // DomainSeparationTag
        round: i64, // ChainEpoch
        entropy_off: u32,
        entropy_len: u32,
    ) -> Result<[u8; RANDOMNESS_LENGTH]> {
        let entropy = context.memory.try_slice(entropy_off, entropy_len)?;
        context
            .kernel
            .get_randomness_from_beacon(pers, round, entropy)
    }
}

impl<K: BaseKernel + RandomnessOps> Bind<K, Rand> for K {
    fn bind_syscalls(linker: &mut Linker<InvocationData<K>>) -> anyhow::Result<()> {
        linker.bind("rand", "get_chain_randomness", Rand::get_chain_randomness)?;
        linker.bind("rand", "get_beacon_randomness", Rand::get_beacon_randomness)?;
        Ok(())
    }
}
