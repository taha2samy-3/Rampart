import type { FindingState } from '@/api/types';

/**
 * The moves the server allows (internal/domain/enums.go CanTransitionTo). The server decides; this only keeps
 * the dialog from offering a move that would be refused. `risk_accepted` is not offered: a risk is accepted
 * through a risk acceptance with an owner and an expiry (docs/16 D38), which has its own flow.
 */
const NEXT: Record<FindingState, FindingState[]> = {
  open: ['under_investigation', 'affected', 'not_affected', 'out_of_scope', 'duplicate', 'fixed'],
  under_investigation: ['affected', 'not_affected', 'out_of_scope', 'duplicate', 'fixed'],
  affected: ['under_investigation', 'not_affected', 'fixed'],
  not_affected: ['under_investigation', 'affected'],
  fixed: ['open', 'under_investigation'],
  risk_accepted: ['open', 'under_investigation', 'affected', 'fixed'],
  out_of_scope: ['open', 'under_investigation'],
  duplicate: ['open', 'under_investigation'],
};
export const nextStates = (s: FindingState): FindingState[] => NEXT[s] ?? [];

/** The five OpenVEX justifications a not_affected decision must give one of. */
export const JUSTIFICATIONS = [
  'component_not_present',
  'vulnerable_code_not_present',
  'vulnerable_code_not_in_execute_path',
  'vulnerable_code_cannot_be_controlled_by_adversary',
  'inline_mitigations_already_exist',
] as const;
