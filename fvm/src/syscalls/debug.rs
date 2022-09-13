use wasmtime::Linker;

use crate::BaseKernel;
use crate::kernel::{ClassifyResult, Result, DebugOps};
use crate::syscalls::context::Context;

use super::bind::BindSyscall;
use super::{Bind, InvocationData};

pub(crate) struct Debug;

impl Debug {
    pub fn log(context: Context<'_, impl DebugOps>, msg_off: u32, msg_len: u32) -> Result<()> {
        // No-op if disabled.
        if !context.kernel.debug_enabled() {
            return Ok(());
        }
    
        let msg = context.memory.try_slice(msg_off, msg_len)?;
        let msg = String::from_utf8(msg.to_owned()).or_illegal_argument()?;
        context.kernel.log(msg);
        Ok(())
    }
    
    pub fn enabled(context: Context<'_, impl DebugOps>) -> Result<i32> {
        Ok(if context.kernel.debug_enabled() {
            0
        } else {
            -1
        })
    }
    
    pub fn store_artifact(
        context: Context<'_, impl DebugOps>,
        name_off: u32,
        name_len: u32,
        data_off: u32,
        data_len: u32,
    ) -> Result<()> {
        // No-op if disabled.
        if !context.kernel.debug_enabled() {
            return Ok(());
        }
    
        let data = context.memory.try_slice(data_off, data_len)?;
        let name = context.memory.try_slice(name_off, name_len)?;
        let name =
            std::str::from_utf8(name).or_error(fvm_shared::error::ErrorNumber::IllegalArgument)?;
    
        context.kernel.store_artifact(name, data)?;
    
        Ok(())
    }
    
}


impl<K: BaseKernel + DebugOps> Bind<K, Debug> for K {
    fn bind_syscalls(linker: &mut Linker<InvocationData<K>>) -> anyhow::Result<()> {
        linker.bind("debug", "log", Debug::log)?;
        linker.bind("debug", "enabled", Debug::enabled)?;
        linker.bind("debug", "store_artifact", Debug::store_artifact)?;
        Ok(())
    }
}