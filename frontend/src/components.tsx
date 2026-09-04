import {
  AlertTriangle,
  ArrowRight,
  CheckCircle2,
  CircleDashed,
  Clock3,
  Database,
  FileText,
  GitBranch,
  Inbox,
  LockKeyhole,
  RefreshCw,
  Search,
  Shield,
  Users,
  XCircle,
} from "lucide-react";
import type { DataRecord } from "./types";

export const value = (
  record: DataRecord | undefined,
  keys: string[],
  fallback = "—",
) => {
  if (!record) return fallback;
  for (const key of keys) {
    const item = record[key];
    if (item !== undefined && item !== null && item !== "") return String(item);
  }
  return fallback;
};
export const prettyKey = (key: string) =>
  key.replace(/_/g, " ").replace(/\b\w/g, (letter) => letter.toUpperCase());
export const formatValue = (item: unknown) =>
  typeof item === "object" && item !== null
    ? JSON.stringify(item)
    : String(item ?? "—");

export function StatusBadge({ status }: { status: string }) {
  const normalized = status.toUpperCase();
  const tone =
    normalized.includes("SENIOR") || normalized.includes("ESCALAT")
      ? "amber"
      : normalized.includes("SAR")
        ? "green"
        : "blue";
  return (
    <span className={`status-badge ${tone}`}>
      <span className="status-dot" />
      {status.replace(/_/g, " ")}
    </span>
  );
}
export function LoadingState({
  label = "Loading intelligence",
}: {
  label?: string;
}) {
  return (
    <div className="state">
      <RefreshCw className="spin" size={20} />
      <span>{label}</span>
    </div>
  );
}
export function ErrorState({
  message,
  retry,
}: {
  message: string;
  retry?: () => void;
}) {
  return (
    <div className="state error-state">
      <XCircle size={22} />
      <div>
        <strong>Unable to load this view</strong>
        <p>{message}</p>
        {retry && (
          <button className="button secondary" onClick={retry}>
            <RefreshCw size={15} />
            Retry
          </button>
        )}
      </div>
    </div>
  );
}
export function EmptyState({
  title,
  detail,
  icon: Icon = Inbox,
}: {
  title: string;
  detail: string;
  icon?: typeof Inbox;
}) {
  return (
    <div className="state empty-state">
      <Icon size={28} />
      <strong>{title}</strong>
      <p>{detail}</p>
    </div>
  );
}

export function Metric({
  label,
  value: metric,
  icon: Icon = Database,
}: {
  label: string;
  value: string;
  icon?: typeof Database;
}) {
  return (
    <div className="metric">
      <Icon size={16} />
      <span>{label}</span>
      <strong>{metric}</strong>
    </div>
  );
}
export function JsonBlock({ data }: { data: unknown }) {
  return <pre className="json-block">{JSON.stringify(data, null, 2)}</pre>;
}
export function RecordGrid({ record }: { record: DataRecord }) {
  return (
    <div className="record-grid">
      {Object.entries(record).map(([key, item]) => (
        <div className="record-item" key={key}>
          <span>{prettyKey(key)}</span>
          <strong>{formatValue(item)}</strong>
        </div>
      ))}
    </div>
  );
}
export function Workflow({ agents }: { agents: DataRecord | null }) {
  const labels = [
    "Detection Agent",
    "Genuine Hypothesis",
    "Fraud / Scam Hypothesis",
    "Contradiction Agent",
    "Investigator Agent",
    "Next-Best Action",
  ];
  return (
    <div className="workflow">
      {labels.map((label, index) => {
        const key = [
          "detection",
          "legitimate_hypothesis",
          "scammer_hypothesis",
          "contradiction",
          "investigator",
          "next_best_action",
        ][index];
        const result = agents?.[key];
        return (
          <div className="workflow-step" key={label}>
            <div className={`workflow-icon ${result ? "done" : ""}`}>
              {result ? <CheckCircle2 size={16} /> : <CircleDashed size={16} />}
            </div>
            <div>
              <strong>{label}</strong>
              <span>
                {result ? "Backend result available" : "Pending backend result"}
              </span>
            </div>
            {index < labels.length - 1 && (
              <ArrowRight className="workflow-arrow" size={14} />
            )}
          </div>
        );
      })}
    </div>
  );
}
export const icons = {
  alerts: AlertTriangle,
  escalated: Users,
  audit: Shield,
  saved: FileText,
  graph: GitBranch,
  clock: Clock3,
  search: Search,
  lock: LockKeyhole,
};
