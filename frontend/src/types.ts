export type Role = 'JUNIOR' | 'SENIOR'
export type RecordValue = string | number | boolean | null | undefined
export type DataRecord = Record<string, unknown>

export interface CaseListResponse { role: Role; count: number; cases: DataRecord[] }
export interface CaseDetailResponse { case: DataRecord; alerts: DataRecord[] }
export interface NetworkResponse { elements?: DataRecord[] | { nodes?: DataRecord[]; edges?: DataRecord[] }; [key: string]: unknown }
export interface AuditResponse { case_id: string; events: DataRecord[] }
export interface ReferenceResponse { role: Role; count: number; reference_cases: DataRecord[] }
export interface InvestigationResponse { llm_safe_evidence: DataRecord; agents: DataRecord }
export interface ApiErrorShape { detail?: string }
