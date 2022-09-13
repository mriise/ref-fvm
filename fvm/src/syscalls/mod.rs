use std::mem;

use anyhow::{anyhow, Context as _};
use wasmtime::{AsContextMut, Global, Linker, Memory, Val, Func, Caller};

use crate::call_manager::backtrace;
use crate::gas::Gas;
use crate::{Kernel, CheckedKernel};
use crate::kernel::{BaseKernel, ValidateKernel, DebugOps, SendOps, IpldBlockOps};

pub(crate) mod error;

mod actor;
mod bind;
mod context;
mod crypto;
mod debug;
mod gas;
mod ipld;
mod network;
mod rand;
mod send;
mod sself;
mod vm;

use crate::syscalls::ipld::IpldFunctions;

pub(self) use context::Context;

/// Invocation data attached to a wasm "store" and available to the syscall binding.
pub struct InvocationData<K> {
    /// The kernel on which this actor is being executed.
    pub kernel: K,

    /// The last-seen syscall error. This error is considered the abort "cause" if an actor aborts
    /// after receiving this error without calling any other syscalls.
    pub last_error: Option<backtrace::Cause>,

    /// The global containing remaining available gas.
    pub avail_gas_global: Global,

    /// The last-set milligas limit. When `charge_for_exec` is called, we charge for the
    /// _difference_ between the current gas available (the wasm global) and the
    /// `last_milligas_available`.
    pub last_milligas_available: i64,

    /// The invocation's imported "memory".
    pub memory: Memory,
}

pub fn update_gas_available(
    ctx: &mut impl AsContextMut<Data = InvocationData<impl BaseKernel>>,
) -> Result<(), Abort> {
    let mut ctx = ctx.as_context_mut();
    let avail_milligas = ctx.data_mut().kernel.gas_available().as_milligas();

    let gas_global = ctx.data_mut().avail_gas_global;
    gas_global
        .set(&mut ctx, Val::I64(avail_milligas))
        .map_err(|e| Abort::Fatal(anyhow!("failed to set available gas global: {}", e)))?;

    ctx.data_mut().last_milligas_available = avail_milligas;
    Ok(())
}

/// Updates the FVM-side gas tracker with newly accrued execution gas charges.
pub fn charge_for_exec(
    ctx: &mut impl AsContextMut<Data = InvocationData<impl BaseKernel>>,
) -> Result<(), Abort> {
    let mut ctx = ctx.as_context_mut();
    let global = ctx.data_mut().avail_gas_global;

    let milligas_available = global
        .get(&mut ctx)
        .i64()
        .context("failed to get wasm gas")
        .map_err(Abort::Fatal)?;

    // Determine milligas used, and update the gas tracker.
    let milligas_used = {
        let data = ctx.data_mut();
        let last_milligas = mem::replace(&mut data.last_milligas_available, milligas_available);
        // This should never be negative, but we might as well check.
        last_milligas.saturating_sub(milligas_available)
    };

    ctx.data_mut()
        .kernel
        .charge_gas("wasm_exec", Gas::from_milligas(milligas_used))
        .map_err(Abort::from_error_as_fatal)?;

    Ok(())
}

use self::bind::{BindSyscall, BindCheckedSyscall};
use self::error::Abort;



// Binds the syscall handlers so they can handle invocations
// from the actor code.
pub fn bind_invoke_syscalls<K: Kernel>(
    linker: &mut Linker<InvocationData<K>>,
) -> anyhow::Result<()> {
    <K as Bind<K, debug::Debug>>::bind_syscalls(linker)?;
    <K as Bind<K, send::Send>>::bind_syscalls(linker)?;
    <K as Bind<K, vm::VmAbort>>::bind_syscalls(linker)?;
    <K as Bind<K, vm::InvokeContext>>::bind_syscalls(linker)?;    


    linker.bind("network", "base_fee", network::base_fee)?;
    linker.bind(
        "network",
        "total_fil_circ_supply",
        network::total_fil_circ_supply,
    )?;

    linker.bind("ipld", "block_open", ipld::block_open)?;
    linker.bind("ipld", "block_create", ipld::block_create)?;
    linker.bind("ipld", "block_read", ipld::block_read)?;
    linker.bind("ipld", "block_stat", ipld::block_stat)?;
    linker.bind("ipld", "block_link", ipld::block_link)?;

    <K as Bind<K, sself::Sself>>::bind_syscalls(linker)?;

    linker.bind("actor", "resolve_address", actor::resolve_address)?;
    linker.bind("actor", "get_actor_code_cid", actor::get_actor_code_cid)?;
    linker.bind("actor", "new_actor_address", actor::new_actor_address)?;
    linker.bind("actor", "create_actor", actor::create_actor)?;
    linker.bind(
        "actor",
        "get_builtin_actor_type",
        actor::get_builtin_actor_type,
    )?;
    linker.bind(
        "actor",
        "get_code_cid_for_type",
        actor::get_code_cid_for_type,
    )?;

    // Only wire this syscall when M2 native is enabled.
    #[cfg(feature = "m2-native")]
    linker.bind("actor", "install_actor", actor::install_actor)?;

    linker.bind("crypto", "verify_signature", crypto::verify_signature)?;
    linker.bind(
        "crypto",
        "recover_secp_public_key",
        crypto::recover_secp_public_key,
    )?;
    linker.bind("crypto", "hash", crypto::hash)?;
    linker.bind("crypto", "verify_seal", crypto::verify_seal)?;
    linker.bind("crypto", "verify_post", crypto::verify_post)?;
    linker.bind(
        "crypto",
        "compute_unsealed_sector_cid",
        crypto::compute_unsealed_sector_cid,
    )?;
    linker.bind(
        "crypto",
        "verify_consensus_fault",
        crypto::verify_consensus_fault,
    )?;
    linker.bind(
        "crypto",
        "verify_aggregate_seals",
        crypto::verify_aggregate_seals,
    )?;
    linker.bind(
        "crypto",
        "verify_replica_update",
        crypto::verify_replica_update,
    )?;
    linker.bind("crypto", "batch_verify_seals", crypto::batch_verify_seals)?;


    linker.bind("gas", "charge", gas::charge_gas)?;

    Ok(())
}

pub(crate) trait Bind<K, BT> {
    fn bind_syscalls(linker: &mut Linker<InvocationData<K>>) -> anyhow::Result<()>;
}



pub fn bind_validate_syscalls<K: ValidateKernel>(
    linker: &mut Linker<InvocationData<K>>,
) -> anyhow::Result<()> {
    todo!()
}

