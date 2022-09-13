use fvm_shared::address::Address;
use fvm_shared::econ::TokenAmount;
use fvm_shared::error::ExitCode;
use fvm_shared::sys;
use wasmtime::Linker;

use super::bind::BindSyscall;
use super::{Context, Bind, InvocationData};
use crate::kernel::{Result, SendResult, SendOps};
use crate::{Kernel, BaseKernel};

pub(crate) struct Send;

impl Send {
    /// Send a message to another actor. The result is placed as a CBOR-encoded
    /// receipt in the block registry, and can be retrieved by the returned BlockId.
    pub fn send(
        context: Context<'_, impl SendOps>,
        recipient_off: u32,
        recipient_len: u32,
        method: u64,
        params_id: u32,
        value_hi: u64,
        value_lo: u64,
    ) -> Result<sys::out::send::Send> {
        let recipient: Address = context.memory.read_address(recipient_off, recipient_len)?;
        let value = TokenAmount::from_atto((value_hi as u128) << 64 | value_lo as u128);
        // An execution error here means that something went wrong in the FVM.
        // Actor errors are communicated in the receipt.
        Ok(
            match context.kernel.send(&recipient, method, params_id, &value)? {
                SendResult::Return(id, stat) => sys::out::send::Send {
                    exit_code: ExitCode::OK.value(),
                    return_id: id,
                    return_codec: stat.codec,
                    return_size: stat.size,
                },
                SendResult::Abort(code) => sys::out::send::Send {
                    exit_code: code.value(),
                    return_id: 0,
                    return_codec: 0,
                    return_size: 0,
                },
            },
        )
    }

}

impl<K: BaseKernel + SendOps> Bind<K, Send> for K {
    fn bind_syscalls(linker: &mut Linker<InvocationData<K>>) -> anyhow::Result<()> {
        linker.bind("send", "send", Send::send)?;
        Ok(())
    }
}
