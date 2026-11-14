// Copyright (C) 2026 xbmc4lyfe
// SPDX-License-Identifier: RPL-1.5
//
// Unless explicitly acquired and licensed from Licensor under another license,
// the contents of this file are subject to the Reciprocal Public License
// ("RPL") Version 1.5, or subsequent versions as allowed by the RPL, and You
// may not copy or use this file in either source code or executable form,
// except in compliance with the terms and conditions of the RPL.
//
// All software distributed under the RPL is provided strictly on an "AS IS"
// basis, WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESS OR IMPLIED, AND LICENSOR
// HEREBY DISCLAIMS ALL SUCH WARRANTIES, INCLUDING WITHOUT LIMITATION, ANY
// WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, QUIET
// ENJOYMENT, OR NON-INFRINGEMENT. See the RPL for specific language governing
// rights and limitations under the RPL.

//! One final completion, prepared before selected payload work.
use super::super::projected::ActionAuxiliary;
use super::*;
use crate::extract::Mode;
use crate::zip::EntryId;

/// A one-shot final diagnostic capability. Prepare it before any payload work.
/// It borrows immutable options, but does not borrow the owner/context across a read.
///
/// ```compile_fail
/// use zipfast::zip::{EncryptedReadContext, ProjectedReadSession, ZipDirectDiagnostics};
/// fn twice(session: &mut ProjectedReadSession, token: ZipDirectDiagnostics<'_>,
///          context: &mut EncryptedReadContext, out: &mut std::fs::File) {
///     let _first = session.emit_diagnostic(token, context, Ok(()), out, |_, _, _| Ok(()));
///     let _second = session.emit_diagnostic(token, context, Ok(()), out, |_, _, _| Ok(()));
/// }
/// ```
#[must_use]
pub struct ZipDirectDiagnostics<'options> {
    options: &'options Options,
    cancel: Cancellation,
    action: LedgerIdentity,
}

/// A lossless final operation receipt and its checked completion diagnostic.
///
/// Always inspect both values returned by `into_parts`. `Some(value)` means the
/// operation succeeded or legitimately skipped, even if a later diagnostic failed.
/// `None` means the operation failed; its original error includes new diagnostic
/// evidence. This carrier never implies rollback of accepted/published output.
#[must_use]
pub struct ZipDiagnosticCompletion<T> {
    operation_value: Option<T>,
    error: Option<ZipReadError>,
    usage: ZipDiagnosticUsage,
}
impl<T> ZipDiagnosticCompletion<T> {
    pub fn into_parts(self) -> (Option<T>, Option<ZipReadError>, ZipDiagnosticUsage) {
        (self.operation_value, self.error, self.usage)
    }
    pub(crate) fn refused(
        token: ZipDirectDiagnostics<'_>,
        context: &mut EncryptedReadContext,
        operation: ZipReadResult<T>,
        error: ZipReadError,
    ) -> Self {
        // Only this token's context may retire its stored state. A foreign
        // context retains its own capability and metadata unchanged.
        let same_context = token.action == context.ledger.identity();
        let compact = if same_context {
            context.action.as_mut().and_then(|action| {
                if !matches!(action.auxiliary, ActionAuxiliary::DirectDiagnostics(_)) {
                    return None;
                }
                let ActionAuxiliary::DirectDiagnostics(state) =
                    std::mem::replace(&mut action.auxiliary, ActionAuxiliary::Empty)
                else {
                    unreachable!()
                };
                Some(state)
            })
        } else {
            None
        };
        let (usage, error) = match compact {
            Some(mut state) => (state.usage, finish_cwd(state.cwd.take(), context, Some(error))),
            None => (ZipDiagnosticUsage::default(), Some(error)),
        };
        let mut completed = Self::complete(operation, Evidence::default(), error, usage);
        if same_context && let Some(error) = completed.error.take() {
            completed.error = Some(error.with_usage(context.usage(), context.run_usage()));
        }
        completed
    }
    fn complete(
        operation: ZipReadResult<T>,
        evidence: Evidence,
        refusal: Option<ZipReadError>,
        usage: ZipDiagnosticUsage,
    ) -> Self {
        match operation {
            Ok(value) => {
                let error = if evidence.failed() {
                    Some(evidence.merge(refusal.unwrap_or_else(ZipReadError::diagnostic_only)))
                } else {
                    refusal
                };
                Self {
                    operation_value: Some(value),
                    error: error.map(|e| e.with_publication(PublicationState::Unknown, 0)),
                    usage,
                }
            }
            Err(error) => {
                // Refusals are capability errors; merge them as diagnostic evidence
                // without erasing any actual original operation/publication fields.
                let error = match refusal {
                    Some(fault) => error.merge_source_boundary(fault),
                    None => error,
                };
                Self { operation_value: None, error: Some(evidence.merge(error)), usage }
            }
        }
    }
}

fn entry_action(context: &EncryptedReadContext, identity: u64, expected: Option<usize>) -> Result<usize, ReadFault> {
    if !context.has_action_plan() || context.ledger.with_state(|s| s.poisoned) {
        return Err(ReadFault::InvalidPlan);
    }
    context.verify_identity(identity)?;
    let action = context.action.as_ref().ok_or(ReadFault::InvalidPlan)?;
    let ProjectedReadScope::Entry(ordinal) = action.scope else {
        return Err(ReadFault::InvalidPlan);
    };
    if action.run_bound || expected.is_some_and(|i| i != ordinal) {
        return Err(ReadFault::InvalidPlan);
    }
    Ok(ordinal)
}
fn original<'a>(source: &'a SourceParts<'_>) -> Result<(&'a File, &'a SourceBinding), ReadFault> {
    match source {
        SourceParts::Held { file, binding } => Ok((file, binding.as_ref().map_err(|_| ReadFault::InvalidPlan)?)),
        SourceParts::Retained { file, binding } => Ok((file, binding)),
        SourceParts::Retired(_) => Err(ReadFault::InvalidPlan),
    }
}
#[allow(clippy::too_many_arguments)]
fn scope<'a>(
    source: SourceParts<'a>,
    entries: DiagnosticEntries<'a>,
    options: &'a Options,
    context: &'a mut EncryptedReadContext,
    state: &'a mut DiagnosticState,
    cancel: &'a Cancellation,
    ordinal: usize,
    emission_allowed: bool,
) -> ZipDiagnosticScope<'a> {
    let token = Token { action: Some(context.ledger.identity()), serial: 1 };
    ZipDiagnosticScope {
        inner: ScopeInner::Bound(BoundScope {
            source,
            entries,
            options,
            context,
            state,
            cancel,
            ordinal: Some(ordinal),
            evidence: Evidence::default(),
            token,
            emission_allowed,
            emitted: false,
        }),
    }
}
fn finish_state(
    state: &mut DiagnosticState,
    context: &EncryptedReadContext,
    error: Option<ZipReadError>,
) -> Option<ZipReadError> {
    finish_cwd(state.cwd.take(), context, error)
}
fn finish_cwd(
    cwd: Option<policy::OwnedMetadata<u8>>,
    context: &EncryptedReadContext,
    error: Option<ZipReadError>,
) -> Option<ZipReadError> {
    let Some(cwd) = cwd else {
        return error;
    };
    match cwd.finish(&context.ledger) {
        Ok(()) => error,
        Err((_, fault)) => {
            context.ledger.with_state(|s| s.poisoned = true);
            let fault = ZipReadError::from(fault).owned_boundary_error(OwnedObject::PolicyPath, ReadIoOperation::Stat);
            Some(match error {
                Some(error) => error.merge_cleanup_only(fault),
                None => fault,
            })
        }
    }
}
#[allow(clippy::too_many_arguments, clippy::result_large_err)]
fn prepare<'o>(
    source: SourceParts<'_>,
    entries: DiagnosticEntries<'_>,
    identity: u64,
    ordinal: usize,
    options: &'o Options,
    cancel: &Cancellation,
    context: &mut EncryptedReadContext,
    which: ZipDiagnosticSink,
    sink: &dyn AsFd,
) -> ZipReadResult<ZipDirectDiagnostics<'o>> {
    entry_action(context, identity, Some(ordinal))?;
    let action = context.action.as_ref().ok_or(ReadFault::InvalidPlan)?;
    if ordinal >= entries.len()
        || action.consumed
        || action.completed
        || action.controlled_output
        || action.raw_output
        || !matches!(action.auxiliary, ActionAuxiliary::Empty)
        || action.policy.is_some()
    {
        return Err(ReadFault::InvalidPlan.into());
    }
    let staged = action.output == budget::PlannedOutput::StagedFiles;
    if staged {
        if options.mode != Mode::Extract
            || action.destination.as_ref().is_none_or(|p| p.as_os_str() != options.dest.as_os_str())
        {
            return Err(ReadFault::InvalidPlan.into());
        }
    } else if options.mode != Mode::Test {
        return Err(ReadFault::InvalidPlan.into());
    }
    let (file, binding) = original(&source)?;
    context.ledger.with_state(|s| s.verify_source(binding.stamp))?;
    let ceiling = action.attempt_ceiling;
    let cwd = options.mode == Mode::Test && options.protected_paths.iter().any(|p| p.is_relative());
    context.options.limits.io_attempts = context
        .ledger
        .with_state(|s| s.bind_direct_diagnostics(options.protected_paths.len() as u128, cwd, ceiling))?;
    if staged {
        let policy =
            policy::FrozenPolicy::bind(&context.ledger, options, &binding.path, file, binding.stamp, ceiling, cancel)?;
        context.options.limits.io_attempts = context.ledger.with_state(|s| s.encrypted.limits.io_attempts);
        context.action.as_mut().ok_or(ReadFault::InvalidPlan)?.policy = Some(policy);
    }
    let mut state = DiagnosticState::default();
    let mut prepared = scope(source, entries, options, context, &mut state, cancel, ordinal, false);
    let admitted = match which {
        ZipDiagnosticSink::Stdout => prepared.admit_sinks(Some(sink), None),
        ZipDiagnosticSink::Stderr => prepared.admit_sinks(None, Some(sink)),
    };
    let evidence = prepared.finish(admitted.map_err(ZipObserverFault::from));
    if evidence.failed() {
        let error = evidence.merge(ZipReadError::diagnostic_only());
        return Err(finish_state(&mut state, context, Some(error))
            .unwrap()
            .with_usage(context.usage(), context.run_usage()));
    }
    let compact = match DirectDiagnosticState::pack(&mut state, which) {
        Ok(compact) => compact,
        Err(fault) => return Err(finish_state(&mut state, context, Some(fault.into())).unwrap()),
    };
    context.action.as_mut().ok_or(ReadFault::InvalidPlan)?.auxiliary = ActionAuxiliary::DirectDiagnostics(compact);
    Ok(ZipDirectDiagnostics { options, cancel: cancel.clone(), action: context.ledger.identity() })
}
#[allow(clippy::too_many_arguments)]
fn emit<T, W: Write + AsFd, F>(
    source: SourceParts<'_>,
    entries: DiagnosticEntries<'_>,
    identity: u64,
    expected: Option<usize>,
    token: ZipDirectDiagnostics<'_>,
    context: &mut EncryptedReadContext,
    operation: ZipReadResult<T>,
    out: &mut W,
    render: F,
) -> ZipDiagnosticCompletion<T>
where
    F: FnOnce(&ZipReadResult<T>, ZipDiagnosticStatus<'_>, &mut ZipDiagnosticWriter<'_, W>) -> ZipDiagnosticResult<()>,
{
    let ordinal = match entry_action(context, identity, expected) {
        Ok(i) if token.action == context.ledger.identity() && i < entries.len() => i,
        _ => return ZipDiagnosticCompletion::refused(token, context, operation, ReadFault::InvalidPlan.into()),
    };
    let auxiliary = &mut context.action.as_mut().unwrap().auxiliary;
    if !matches!(auxiliary, ActionAuxiliary::DirectDiagnostics(_)) {
        return ZipDiagnosticCompletion::refused(token, context, operation, ReadFault::InvalidPlan.into());
    }
    let ActionAuxiliary::DirectDiagnostics(compact) = std::mem::replace(auxiliary, ActionAuxiliary::Empty) else {
        unreachable!()
    };
    let which = compact.which;
    let mut state = compact.expand();
    let mut emitting = scope(source, entries, token.options, context, &mut state, &token.cancel, ordinal, true);
    let result = emitting.emit(which, out, |status, writer| render(&operation, status, writer));
    let evidence = emitting.finish(result.map(|_| ()).map_err(ZipObserverFault::from));
    let cleanup = finish_state(&mut state, context, None);
    let mut completed = ZipDiagnosticCompletion::complete(operation, evidence, cleanup, state.usage);
    if let Some(error) = completed.error.take() {
        completed.error = Some(error.with_usage(context.usage(), context.run_usage()));
    }
    completed
}

#[allow(clippy::result_large_err)]
impl projected::ProjectedOwner {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn prepare_diagnostics<'o>(
        &mut self,
        ordinal: usize,
        options: &'o Options,
        cancel: &Cancellation,
        context: &mut EncryptedReadContext,
        which: ZipDiagnosticSink,
        sink: &dyn AsFd,
    ) -> ZipReadResult<ZipDirectDiagnostics<'o>> {
        prepare(
            SourceParts::Held { file: &self.file, binding: &mut self.source },
            DiagnosticEntries::Projected(&self.entries),
            self.identity,
            ordinal,
            options,
            cancel,
            context,
            which,
            sink,
        )
    }
    pub(crate) fn emit_diagnostic<T, W: Write + AsFd, F>(
        &mut self,
        expected: Option<usize>,
        token: ZipDirectDiagnostics<'_>,
        context: &mut EncryptedReadContext,
        operation: ZipReadResult<T>,
        out: &mut W,
        render: F,
    ) -> ZipDiagnosticCompletion<T>
    where
        F: FnOnce(
            &ZipReadResult<T>,
            ZipDiagnosticStatus<'_>,
            &mut ZipDiagnosticWriter<'_, W>,
        ) -> ZipDiagnosticResult<()>,
    {
        emit(
            SourceParts::Held { file: &self.file, binding: &mut self.source },
            DiagnosticEntries::Projected(&self.entries),
            self.identity,
            expected,
            token,
            context,
            operation,
            out,
            render,
        )
    }
}
#[allow(clippy::result_large_err)]
impl ProjectedReadSession {
    /// Prepares one final completion diagnostic before payload FD admission or reads.
    #[allow(clippy::too_many_arguments)]
    pub fn prepare_diagnostics<'o>(
        &mut self,
        ordinal: usize,
        options: &'o Options,
        cancel: &Cancellation,
        context: &mut EncryptedReadContext,
        which: ZipDiagnosticSink,
        sink: &dyn AsFd,
    ) -> ZipReadResult<ZipDirectDiagnostics<'o>> {
        self.owner.prepare_diagnostics(ordinal, options, cancel, context, which, sink)
    }
    /// Consumes the prepared capability while this original owner remains held.
    pub fn emit_diagnostic<T, W: Write + AsFd, F>(
        &mut self,
        token: ZipDirectDiagnostics<'_>,
        context: &mut EncryptedReadContext,
        operation: ZipReadResult<T>,
        out: &mut W,
        render: F,
    ) -> ZipDiagnosticCompletion<T>
    where
        F: FnOnce(
            &ZipReadResult<T>,
            ZipDiagnosticStatus<'_>,
            &mut ZipDiagnosticWriter<'_, W>,
        ) -> ZipDiagnosticResult<()>,
    {
        self.owner.emit_diagnostic(None, token, context, operation, out, render)
    }
}
#[allow(clippy::result_large_err)]
impl crate::zip::ReadSession {
    /// Prepares one final completion using an ID from this original retained catalogue.
    #[allow(clippy::too_many_arguments)]
    pub fn prepare_diagnostics<'o>(
        &mut self,
        id: &EntryId,
        options: &'o Options,
        cancel: &Cancellation,
        context: &mut EncryptedReadContext,
        which: ZipDiagnosticSink,
        sink: &dyn AsFd,
    ) -> ZipReadResult<ZipDirectDiagnostics<'o>> {
        let ordinal = self.metadata.ordinal(id).map_err(|_| ReadFault::InvalidPlan)?;
        prepare(
            SourceParts::Retained { file: &self.file, binding: &mut self.source },
            DiagnosticEntries::Retained(&self.metadata),
            self.checked_identity,
            ordinal,
            options,
            cancel,
            context,
            which,
            sink,
        )
    }
    /// Preserves the actual operation receipt and merges checked completion faults.
    pub fn emit_diagnostic<T, W: Write + AsFd, F>(
        &mut self,
        token: ZipDirectDiagnostics<'_>,
        context: &mut EncryptedReadContext,
        operation: ZipReadResult<T>,
        out: &mut W,
        render: F,
    ) -> ZipDiagnosticCompletion<T>
    where
        F: FnOnce(
            &ZipReadResult<T>,
            ZipDiagnosticStatus<'_>,
            &mut ZipDiagnosticWriter<'_, W>,
        ) -> ZipDiagnosticResult<()>,
    {
        emit(
            SourceParts::Retained { file: &self.file, binding: &mut self.source },
            DiagnosticEntries::Retained(&self.metadata),
            self.checked_identity,
            None,
            token,
            context,
            operation,
            out,
            render,
        )
    }
}
