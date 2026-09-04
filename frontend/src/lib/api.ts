import type { AuditResponse, CaseDetailResponse, CaseListResponse, DataRecord, InvestigationResponse, NetworkResponse, ReferenceResponse, Role } from '../types'

const API_URL = (import.meta.env.VITE_API_URL || '/api').replace(/\/$/, '')

export class ApiError extends Error {
  status: number
  constructor(status: number, message: string) { super(message); this.status = status }
}

let activeRole: Role | null = null
export function setApiRole(role: Role | null) { activeRole = role }

async function request<T>(path: string, options: RequestInit = {}, responseType: 'json' | 'blob' = 'json'): Promise<T> {
  const headers = new Headers(options.headers)
  if (activeRole && path !== '/health') headers.set('X-Investigator-Role', activeRole)
  if (options.body && !headers.has('Content-Type')) headers.set('Content-Type', 'application/json')
  let response: Response
  try { response = await fetch(`${API_URL}${path}`, { ...options, headers }) }
  catch (error) {
    console.error(`[SENTINEL API] ${options.method || 'GET'} ${path} failed`, error)
    throw new ApiError(0, 'Backend service is unavailable.')
  }
  if (!response.ok) {
    let message = `Request failed (${response.status})`
    try { const payload = await response.json() as { detail?: string }; message = payload.detail || message } catch { /* non-JSON error */ }
    const apiError = new ApiError(response.status, message)
    console.error(`[SENTINEL API] ${options.method || 'GET'} ${path} returned ${response.status}`, { message, response })
    throw apiError
  }
  return (responseType === 'blob' ? response.blob() : response.json()) as Promise<T>
}

export const api = {
  listCases: () => request<CaseListResponse>('/cases'),
  getCase: (id: string) => request<CaseDetailResponse>(`/cases/${encodeURIComponent(id)}`),
  getNetwork: (id: string) => request<NetworkResponse>(`/cases/${encodeURIComponent(id)}/network`),
  investigate: (id: string) => request<InvestigationResponse>(`/cases/${encodeURIComponent(id)}/investigate`, { method: 'POST' }),
  resolveContradiction: (id: string) => request<DataRecord>(`/cases/${encodeURIComponent(id)}/resolve-contradiction`, { method: 'POST' }),
  getEvidence: (id: string) => request<DataRecord>(`/cases/${encodeURIComponent(id)}/evidence`),
  runAnalysis: (id: string) => request<DataRecord>(`/cases/${encodeURIComponent(id)}/analysis`, { method: 'POST' }),
  getAnalysis: (id: string) => request<DataRecord>(`/cases/${encodeURIComponent(id)}/analysis`),
  getAudit: (id: string) => request<AuditResponse>(`/cases/${encodeURIComponent(id)}/audit-trail`),
  escalate: (id: string, reason: string) => request<DataRecord>(`/cases/${encodeURIComponent(id)}/escalate`, { method: 'POST', body: JSON.stringify({ reason }) }),
  sar: (id: string) => request<Blob>(`/cases/${encodeURIComponent(id)}/sar-report`, { method: 'POST' }, 'blob'),
  addReference: (id: string, notes: string) => request<DataRecord>(`/cases/${encodeURIComponent(id)}/reference`, { method: 'POST', body: JSON.stringify({ notes }) }),
  listReferences: () => request<ReferenceResponse>('/reference-cases'),
  revealAgents: (id: string) => request<DataRecord>(`/cases/${encodeURIComponent(id)}/agents/reveal`, { method: 'POST' }),
}
