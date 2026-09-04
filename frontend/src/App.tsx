import { useEffect, useRef, useState } from "react";
import {
  AlertTriangle,
  ArrowLeft,
  ArrowRight,
  Check,
  CheckCircle2,
  ChevronRight,
  CircleDashed,
  Download,
  Eye,
  EyeOff,
  FileText,
  GitBranch,
  LockKeyhole,
  LogOut,
  Menu,
  PanelLeft,
  Play,
  Save,
  Search,
  Shield,
  Sparkles,
  Users,
  X,
} from "lucide-react";
import cytoscape from "cytoscape";
import {
  Link,
  Navigate,
  NavLink,
  Route,
  Routes,
  useNavigate,
  useParams,
  useSearchParams,
} from "react-router-dom";
import { ApiError, api } from "./lib/api";
import { useRole } from "./role";
import type { DataRecord, Role } from "./types";
import {
  EmptyState,
  ErrorState,
  JsonBlock,
  LoadingState,
  Metric,
  RecordGrid,
  StatusBadge,
  Workflow,
  formatValue,
  icons,
  prettyKey,
  value,
} from "./components";

// Local index of case ids this browser session has opened. The backend's
// bulk /cases response is pre-filtered per role (JUNIOR only ever sees
// status == JUNIOR), so a case a Junior worked that later becomes SAR_READY
// disappears from their list view. Remembering the ids client-side lets the
// Audit-Ready queue re-fetch those cases individually - the backend still
// authorizes every single-case fetch (JUNIOR is allowed JUNIOR or SAR_READY).
const KNOWN_CASES_KEY = "sentinel-known-cases";

function readKnownCases(): string[] {
  try {
    const parsed = JSON.parse(localStorage.getItem(KNOWN_CASES_KEY) || "[]");
    return Array.isArray(parsed)
      ? parsed.filter((id): id is string => typeof id === "string" && !!id)
      : [];
  } catch {
    return [];
  }
}

function rememberKnownCase(caseId: string) {
  if (!caseId) return;
  const known = readKnownCases();
  if (!known.includes(caseId)) {
    localStorage.setItem(KNOWN_CASES_KEY, JSON.stringify([...known, caseId]));
  }
}

function userFacingError(error: unknown, fallback: string) {
  if (!(error instanceof ApiError)) return fallback;
  if (error.status === 0)
    return "Unable to connect to the investigation service. Please check that the backend service is running.";
  if (error.status === 401)
    return "Your investigator session is not authorized. Please select your investigator role again.";
  if (error.status === 403) return "You are not authorized to access this case.";
  if (error.status === 404) return "This case could not be found.";
  if (error.status >= 500)
    return "The requested investigation action could not be completed at this time. Please try again.";
  return "Something went wrong. Please try again.";
}

function riskBand(record: DataRecord) {
  const explicitRisk = value(record, ["risk", "risk_level", "severity"], "").toLowerCase();
  if (["low", "medium", "high"].includes(explicitRisk)) return explicitRisk;
  const score = Number(value(record, ["risk_score", "alert_score", "score"], "").match(/\d+(?:\.\d+)?/)?.[0] || value(record, ["bundle_reason"], "").match(/total_score=(\d+(?:\.\d+)?)/)?.[1] || NaN);
  if (!Number.isFinite(score)) return "unknown";
  return score >= 45 ? "high" : score >= 30 ? "medium" : "low";
}

function AccessState({ message }: { message: string }) {
  return (
    <div className="access-state">
      <Shield size={28} />
      <h2>Access unavailable</h2>
      <p>{message}</p>
      <Link className="button secondary" to="/alerts">
        <ArrowLeft size={15} />
        Return to suspected alerts
      </Link>
    </div>
  );
}

function RoleScreen() {
  const { selectRole } = useRole();
  const [choice, setChoice] = useState<Role>("JUNIOR");
  const [investigatorName, setInvestigatorName] = useState(
    () => sessionStorage.getItem("sentinel-investigator-name") || "",
  );
  const [password, setPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [validationError, setValidationError] = useState("");
  const enterWorkspace = () => {
    const name = investigatorName.trim();
    if (!name) {
      setValidationError("Please enter your investigator name.");
      return;
    }
    if (!password) {
      setValidationError("Please enter your password.");
      return;
    }
    if (password !== "Argus@123") {
      setValidationError("Invalid investigator credentials.");
      return;
    }
    setValidationError("");
    if (name) sessionStorage.setItem("sentinel-investigator-name", name);
    else sessionStorage.removeItem("sentinel-investigator-name");
    selectRole(choice);
  };
  return (
    <main className="role-screen">
      <div className="role-panel">
        <div className="brand-mark">
          <Shield size={23} />
          <span>ARGUS</span>
        </div>
        <div className="eyebrow">Financial intelligence / secure operations</div>
        <h1>
          Financial Crime
          <br />
          <em>Investigation</em>
        </h1>
        <p className="lede">
          ARGUS is an investigation workspace for reviewing suspicious
          financial activity, following evidence, and taking accountable action.
        </p>
      </div>
      <div className="role-aside">
        <div className="access-card">
          <div className="access-card-head">
            <div>
              <div className="eyebrow">Secure workspace</div>
              <h2>Investigator Access</h2>
              <p>Sign in to enter the secure investigation workspace.</p>
            </div>
            <div className="access-lock"><LockKeyhole size={18} /></div>
          </div>
          <div className="access-form">
            <label className="access-label" htmlFor="access-name">Investigator Name</label>
            <input
              className="access-input"
              id="access-name"
              value={investigatorName}
              onChange={(event) => setInvestigatorName(event.target.value)}
              placeholder="Enter your name"
              autoComplete="name"
            />
            <label className="access-label" htmlFor="access-password">Password</label>
            <div className="password-field">
              <input
                className="access-input"
                id="access-password"
                type={showPassword ? "text" : "password"}
                value={password}
                onChange={(event) => setPassword(event.target.value)}
                placeholder="Enter your password"
                autoComplete="current-password"
              />
              <button className="password-toggle" type="button" aria-label={showPassword ? "Hide password" : "Show password"} onClick={() => setShowPassword((visible) => !visible)}>
                {showPassword ? <EyeOff size={16} /> : <Eye size={16} />}
              </button>
            </div>
            <div className="role-select-label">Select investigator role</div>
            <div className="role-options">
              {(["JUNIOR", "SENIOR"] as Role[]).map((role) => (
                <button
                  className={`role-option ${choice === role ? "selected" : ""}`}
                  key={role}
                  type="button"
                  onClick={() => setChoice(role)}
                >
                  <span className="role-radio">{choice === role && <span />}</span>
                  <span>
                    <strong>{role === "JUNIOR" ? "Junior Investigator" : "Senior Investigator"}</strong>
                    <small>{role === "JUNIOR" ? "Review new queue cases and escalate findings" : "Access senior queue and authorized case intelligence"}</small>
                  </span>
                  <ChevronRight size={18} />
                </button>
              ))}
            </div>
            {validationError && <p className="access-error" role="alert">{validationError}</p>}
            <button className="button primary enter-button" onClick={enterWorkspace}>
              Sign In <ChevronRight size={17} />
            </button>
          </div>
          <div className="access-card-foot"><span><span className="live-dot" /> Secure investigator workspace</span><span>DEMO ACCESS</span></div>
        </div>
      </div>
    </main>
  );
}

function Shell({ children }: { children: React.ReactNode }) {
  const { role, clearRole } = useRole();
  const navigate = useNavigate();
  const [menu, setMenu] = useState(false);
  const navigation = [
    { to: "/alerts", label: "Suspected Alerts", icon: AlertTriangle },
    ...(role === "SENIOR" ? [{ to: "/escalated", label: "Escalated Cases", icon: Users }] : []),
    { to: "/audit", label: "Audit-Ready Cases", icon: Shield },
    { to: "/saved", label: "Reference Cases", icon: FileText },
  ];
  return (
    <div className="app-shell">
      <aside className={`sidebar ${menu ? "open" : ""}`}>
        <div className="sidebar-head">
          <Link to="/alerts" className="brand-mark">
            <Shield size={21} />
            <span>ARGUS</span>
          </Link>
          <button
            className="icon-button mobile-close"
            onClick={() => setMenu(false)}
          >
            <X size={18} />
          </button>
        </div>
        <div className="workspace-label">INVESTIGATION DESK</div>
        <nav>
          {navigation.map((item) => (
            <NavLink key={item.to} to={item.to} onClick={() => setMenu(false)}>
              <item.icon size={17} />
              <span>{item.label}</span>
            </NavLink>
          ))}
        </nav>
        <div className="sidebar-bottom">
          <div className="connection">
            <span className="live-dot" />
            <div>
              <strong>Service connected</strong>
              <small>127.0.0.1:8000</small>
            </div>
          </div>
          <button
            className="role-chip"
            onClick={() => {
              clearRole();
              navigate("/");
            }}
          >
            <span className="avatar">{role?.[0]}</span>
            <span>
              <strong>
                {role === "JUNIOR" ? "Junior" : "Senior"} Investigator
              </strong>
              <small>Change role</small>
            </span>
            <LogOut size={15} />
          </button>
        </div>
      </aside>
      <div className="main-area">
        <header className="topbar">
          <button
            className="icon-button menu-button"
            onClick={() => setMenu(true)}
          >
            <Menu size={20} />
          </button>
          <div className="breadcrumb">
            <span>Argus</span>
            <ChevronRight size={14} />
            <strong>Investigation desk</strong>
          </div>
          <div className="top-actions">
            <div className="role-top">
              <span className="live-dot" />
              {role}
            </div>
            <button className="icon-button">
              <PanelLeft size={18} />
            </button>
          </div>
        </header>
        <main className="content">{children}</main>
      </div>
    </div>
  );
}

function useCases() {
  const [data, setData] = useState<DataRecord[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const load = () => {
    setLoading(true);
    setError("");
    api
      .listCases()
      .then((result) => setData(result.cases))
      .catch((error) => setError(userFacingError(error, "Unable to load case queue.")))
      .finally(() => setLoading(false));
  };
  useEffect(() => {
    load();
    const refresh = () => load();
    window.addEventListener("sentinel:cases-changed", refresh);
    return () => window.removeEventListener("sentinel:cases-changed", refresh);
  }, []);
  return { data, loading, error, reload: load };
}
function CaseQueue({
  mode = "alerts",
}: {
  mode?: "alerts" | "escalated" | "audit";
}) {
  const { data, loading, error, reload } = useCases();
  const { role } = useRole();
  const [query, setQuery] = useState("");
  const [riskFilter, setRiskFilter] = useState("all");
  const [triggerFilter, setTriggerFilter] = useState("all");
  // Cases this investigator opened that later left the bulk /cases response
  // (e.g. became SAR_READY). Re-fetched individually; the backend still 403s
  // anything this role is not allowed to open.
  const [reopenedCases, setReopenedCases] = useState<DataRecord[]>([]);
  // Local receipts for cases this Junior escalated (no case re-fetch: the
  // backend 403s a Junior on SENIOR-status cases, by design).
  const [escalationReceipts, setEscalationReceipts] = useState<DataRecord[]>([]);
  const juniorEscalatedView = mode === "escalated" && role === "JUNIOR";

  useEffect(() => {
    if (mode !== "audit" || role !== "JUNIOR") return;
    let cancelled = false;
    const loadReopened = () => {
      const ids = readKnownCases();
      if (!ids.length) {
        setReopenedCases([]);
        return;
      }
      Promise.all(
        ids.map((id) =>
          api
            .getCase(id)
            .then((result) => result.case)
            .catch(() => null),
        ),
      ).then((results) => {
        if (cancelled) return;
        setReopenedCases(
          results.filter(
            (item): item is DataRecord =>
              !!item &&
              value(item, ["status"], "").toUpperCase() === "SAR_READY",
          ),
        );
      });
    };
    loadReopened();
    window.addEventListener("sentinel:cases-changed", loadReopened);
    return () => {
      cancelled = true;
      window.removeEventListener("sentinel:cases-changed", loadReopened);
    };
  }, [mode, role]);

  useEffect(() => {
    if (!juniorEscalatedView) return;
    const loadReceipts = () => {
      setEscalationReceipts(
        Object.keys(sessionStorage)
          .filter((key) => key.startsWith("sentinel-escalation-"))
          .map((key) => {
            try {
              return {
                case_id: key.slice("sentinel-escalation-".length),
                ...JSON.parse(sessionStorage.getItem(key) || "{}"),
              } as DataRecord;
            } catch {
              return null;
            }
          })
          .filter((item): item is DataRecord => !!item),
      );
    };
    loadReceipts();
    window.addEventListener("sentinel:cases-changed", loadReceipts);
    return () =>
      window.removeEventListener("sentinel:cases-changed", loadReceipts);
  }, [juniorEscalatedView]);

  const seenIds = new Set(data.map((item) => value(item, ["case_id"])));
  const cases =
    mode === "audit" && role === "JUNIOR"
      ? [
          ...data,
          ...reopenedCases.filter(
            (item) => !seenIds.has(value(item, ["case_id"])),
          ),
        ]
      : data;
  const filtered = cases
    .filter((item) => {
      const status = value(item, ["status"], "").toUpperCase();
      const locallyEscalated =
        sessionStorage.getItem(
          `sentinel-escalated-${value(item, ["case_id"])}`,
        ) === "true";
      const matchesMode =
        mode === "alerts"
          ? !(role === "JUNIOR" && locallyEscalated)
          : mode === "escalated"
            ? status.includes("SENIOR") || status.includes("ESCALAT")
            : status.includes("SAR");
      const matchesRisk = riskFilter === "all" || riskBand(item) === riskFilter;
      const matchesTrigger =
        triggerFilter === "all" ||
        value(item, ["primary_trigger"], "").toLowerCase() === triggerFilter;
      return (
        matchesMode &&
        matchesRisk &&
        matchesTrigger &&
        JSON.stringify(item).toLowerCase().includes(query.toLowerCase())
      );
    });
  const title =
    mode === "alerts"
      ? "Suspected alerts"
      : mode === "escalated"
        ? "Escalated cases"
        : "Audit-ready cases";
  const subtitle =
    mode === "alerts"
      ? "Cases currently visible in your investigator queue."
      : mode === "escalated"
        ? juniorEscalatedView
          ? "Local record of cases you escalated from this browser. Senior-queue case data stays restricted to the Senior role."
          : "Cases legitimately identified as moved to senior review."
        : "Finalized cases available for audit follow-through.";
  return (
    <section>
      <div className="page-heading">
        <div>
          <div className="eyebrow">Operations / {mode}</div>
          <h1>{title}</h1>
          <p>{subtitle}</p>
        </div>
        <div className="heading-meta">
          <span className="count-label">
            {loading
              ? "—"
              : juniorEscalatedView
                ? escalationReceipts.length
                : filtered.length}{" "}
            records
          </span>
          <button className="button secondary" onClick={reload}>
            <icons.clock size={15} />
            Refresh
          </button>
        </div>
      </div>
      {juniorEscalatedView ? (
        loading ? (
          <LoadingState label="Loading escalation receipts" />
        ) : error ? (
          <ErrorState message={error} retry={reload} />
        ) : escalationReceipts.length === 0 ? (
          <EmptyState
            title="No locally escalated cases"
            detail="Cases you escalate from this browser are recorded here locally. The backend does not expose senior-queue cases to the Junior role."
          />
        ) : (
          <div className="reference-grid">
            {escalationReceipts.map((receipt, index) => (
              <div
                className="reference-card"
                key={value(receipt, ["case_id"], String(index))}
              >
                <div className="card-kicker">
                  {value(receipt, ["escalation_id"], "ESCALATED")}
                </div>
                <h3>{value(receipt, ["case_id"])}</h3>
                <RecordGrid record={receipt} />
              </div>
            ))}
          </div>
        )
      ) : (
        <>
          <div className="toolbar">
        <div className="search-field">
          <Search size={17} />
          <input
            value={query}
            onChange={(event) => setQuery(event.target.value)}
            placeholder="Search case records..."
          />
        </div>
        <label className="select-label">
          Filter by Risk{" "}
          <select
            value={riskFilter}
            onChange={(event) => setRiskFilter(event.target.value)}
          >
            <option value="all">All</option>
            <option value="low">Low</option>
            <option value="medium">Medium</option>
            <option value="high">High</option>
          </select>
        </label>
        <label className="select-label">
          Filter by Primary Trigger{" "}
          <select
            value={triggerFilter}
            onChange={(event) => setTriggerFilter(event.target.value)}
          >
            <option value="all">All</option>
            <option value="smurfing">smurfing</option>
            <option value="reverse_smurfing">reverse_smurfing</option>
            <option value="account_swap">account_swap</option>
          </select>
        </label>
      </div>
      {loading ? (
        <LoadingState label="Loading authorized case queue" />
      ) : error ? (
        <ErrorState message={error} retry={reload} />
      ) : filtered.length === 0 ? (
        <EmptyState
          title={
            mode === "alerts"
              ? "No authorized cases"
              : `No ${mode} cases available`
          }
          detail="The backend returned no records matching this view. Nothing has been fabricated for this queue."
        />
      ) : (
        <div className="case-table">
          <div className="table-head">
            <span>Case</span>
            <span>Primary trigger</span>
            <span>Evidence signals</span>
            <span>Status</span>
            <span />
          </div>
          {filtered.map((item) => (
            <Link
              className="case-row"
              to={`/cases/${encodeURIComponent(value(item, ["case_id"], ""))}`}
              key={value(item, ["case_id"])}
            >
              <div>
                <strong>{value(item, ["case_id"])}</strong>
                <small>
                  {value(item, ["account_id", "created_at", "detected_at"])}
                </small>
              </div>
              <span>
                {value(item, ["primary_trigger", "reason", "alert_reason"])}
              </span>
              <span>{value(item, ["evidence_signals", "typologies"])}</span>
              <StatusBadge status={value(item, ["status"])} />
              <ChevronRight size={17} />
            </Link>
          ))}
        </div>
      )}
        </>
      )}
    </section>
  );
}

function References() {
  const [items, setItems] = useState<DataRecord[]>([]);
  const [state, setState] = useState<"loading" | "ready" | "error">("loading");
  useEffect(() => {
    api
      .listReferences()
      .then((result) => {
        setItems(result.reference_cases);
        setState("ready");
      })
      .catch(() => setState("error"));
  }, []);
  return (
    <section>
      <div className="page-heading">
        <div>
          <div className="eyebrow">Knowledge / retained intelligence</div>
          <h1>Reference cases</h1>
          <p>Explicitly retained case memory from the backend.</p>
        </div>
      </div>
      {state === "loading" ? (
        <LoadingState />
      ) : state === "error" ? (
        <ErrorState message="Reference cases could not be loaded." />
      ) : items.length === 0 ? (
        <EmptyState
          title="No reference cases"
          detail="Reference memory is empty. Retention happens explicitly from an authorized case workspace."
          icon={FileText}
        />
      ) : (
        <div className="reference-grid">
          {items.map((item, index) => (
            <div
              className="reference-card"
              key={value(item, ["reference_id", "case_id"], String(index))}
            >
              <div className="card-kicker">
                {value(item, ["reference_id"], "REFERENCE")}
              </div>
              <h3>{value(item, ["case_id", "title"])}</h3>
              <RecordGrid record={item} />
            </div>
          ))}
        </div>
      )}
    </section>
  );
}

function CaseWorkspace() {
  const { caseId = "" } = useParams();
  const [tab, setTab] = useSearchParams();
  const { role } = useRole();
  const activeTab = tab.get("tab") || "overview";
  const [detail, setDetail] = useState<{
    case: DataRecord;
    alerts: DataRecord[];
  } | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [accessDenied, setAccessDenied] = useState(false);
  const load = () => {
    setLoading(true);
    setError("");
    setAccessDenied(false);
    api
      .getCase(caseId)
      .then((result) => {
        setDetail(result);
        rememberKnownCase(caseId);
      })
      .catch((error) => {
        setAccessDenied(error instanceof ApiError && error.status === 403);
        setError(userFacingError(error, "Unable to load case"));
      })
      .finally(() => setLoading(false));
  };
  useEffect(load, [caseId]);
  if (loading) return <LoadingState label="Loading case workspace" />;
  if (accessDenied)
    return (
      <AccessState message="This case has moved to Senior review and is no longer available to Junior investigators." />
    );
  if (error || !detail)
    return (
      <ErrorState
        message={error || "Case record was not returned."}
        retry={load}
      />
    );
  const tabs = [
    ["overview", "Overview"],
    ["graph", "Graph"],
    ["evidence", "Evidence"],
    ["sar", "SAR / Audits"],
  ];
  return (
    <section className="case-workspace">
      <Link to="/alerts" className="back-link">
        <ArrowLeft size={15} />
        Back to queue
      </Link>
      <div className="case-header">
        <div>
          <div className="eyebrow">Case workspace</div>
          <h1>{value(detail.case, ["case_id"])}</h1>
          <p>
            {value(
              detail.case,
              ["primary_trigger", "reason", "typologies"],
              "Investigation record",
            )}
          </p>
        </div>
        <div className="case-header-side">
          <StatusBadge status={value(detail.case, ["status"])} />
          <span>Role: {role}</span>
        </div>
      </div>
      <div className="case-meta">
        <Metric label="Account" value={value(detail.case, ["account_id"])} />
        <Metric
          label="Risk / score"
          value={value(detail.case, ["risk_score", "score", "alert_score"])}
          icon={AlertTriangle}
        />
        <Metric
          label="Signals"
          value={value(detail.case, ["evidence_signals", "typologies"])}
          icon={GitBranch}
        />
        <Metric
          label="Detected"
          value={value(detail.case, ["detected_at", "created_at", "timestamp"])}
        />
      </div>
      <div className="tabs">
        {tabs.map(([key, label]) => (
          <button
            className={activeTab === key ? "active" : ""}
            key={key}
            onClick={() => setTab({ tab: key })}
          >
            {label}
          </button>
        ))}
      </div>
      {activeTab === "overview" && (
        <Overview detail={detail} caseId={caseId} onRefresh={load} />
      )}
      {activeTab === "graph" && <Graph caseId={caseId} />}
      {activeTab === "evidence" && <Evidence caseId={caseId} />}
      {activeTab === "sar" && <SarAudits caseId={caseId} detail={detail} />}
    </section>
  );
}

function Overview({
  detail,
  caseId,
  onRefresh,
}: {
  detail: { case: DataRecord; alerts: DataRecord[] };
  caseId: string;
  onRefresh: () => void;
}) {
  const { role } = useRole();
  const [investigating, setInvestigating] = useState(false);
  const [investigation, setInvestigation] = useState<DataRecord | null>(null);
  const [analysis, setAnalysis] = useState<DataRecord | null>(null);
  const [analysisLoading, setAnalysisLoading] = useState(false);
  const [reason, setReason] = useState("");
  const [message, setMessage] = useState("");
  const [actionError, setActionError] = useState("");
  const [escalated, setEscalated] = useState(
    () => sessionStorage.getItem(`sentinel-escalated-${caseId}`) === "true",
  );
  const investigate = async () => {
    setInvestigating(true);
    setActionError("");
    try {
      const result = await api.investigate(caseId);
      setInvestigation(result as unknown as DataRecord);
    } catch (error) {
      setActionError(
        userFacingError(
          error,
          "The investigation could not be completed. Please check the backend response.",
        ),
      );
      console.error("[SENTINEL] investigation failed", error);
    } finally {
      setInvestigating(false);
    }
  };
  const runAnalysis = async () => {
    setAnalysisLoading(true);
    setActionError("");
    try {
      setAnalysis(await api.runAnalysis(caseId));
    } catch (error) {
      setActionError(
        userFacingError(error, "Analysis could not be completed."),
      );
    } finally {
      setAnalysisLoading(false);
    }
  };
  const escalate = async () => {
    if (!reason.trim()) return;
    try {
      const result = await api.escalate(caseId, reason);
      setMessage(`Escalation ${value(result, ["escalation_id"])} recorded.`);
      setReason("");
      setEscalated(true);
      sessionStorage.setItem(`sentinel-escalated-${caseId}`, "true");
      sessionStorage.setItem(
        `sentinel-escalation-${caseId}`,
        JSON.stringify({
          escalation_id: value(result, ["escalation_id"], ""),
          reason,
          escalated_at: new Date().toISOString(),
        }),
      );
      window.dispatchEvent(new Event("sentinel:cases-changed"));
      onRefresh();
    } catch (error) {
      setActionError(
        userFacingError(error, "Escalation could not be completed."),
      );
    }
  };
  return (
    <div className="workspace-grid ">
      <div className="workspace-main">
        <div className="section-title">
          <div>
            <div className="eyebrow">Primary record</div>
            <h2>Investigation overview</h2>
          </div>
          <button
            className="button primary"
            disabled={investigating || escalated}
            onClick={investigate}
          >
            {escalated ? (
              "Case escalated to Senior review"
            ) : investigating ? (
              "Investigation running"
            ) : (
              <>
                <Play size={15} />
                Start investigation
              </>
            )}
          </button>
        </div>
        {actionError && (
          <div className="inline-error">
            <X size={16} />
            {actionError}
          </div>
        )}
        {message && (
          <div className="inline-success">
            <Check size={16} />
            {message}
          </div>
        )}
        <div className="panel">
          <h3>Case metadata</h3>
          <RecordGrid record={detail.case} />
        </div>
        <div className="panel">
          <h3>Alerts ({detail.alerts.length})</h3>
          {detail.alerts.length ? (
            detail.alerts.map((alert, index) => (
              <div className="alert-line" key={String(alert.alert_id || index)}>
                <AlertTriangle size={16} />
                <RecordGrid record={alert} />
              </div>
            ))
          ) : (
            <EmptyState
              title="No alert records"
              detail="The backend returned no linked alerts for this case."
            />
          )}
        </div>
        {investigation && (
          <div className="panel">
            <h3>Investigation response</h3>
            <Workflow agents={investigation.agents as DataRecord} />
            <HypothesisResults agents={investigation.agents as DataRecord} />
            <JsonBlock data={investigation.llm_safe_evidence} />
          </div>
        )}
        <div className="panel">
          <div className="section-title compact">
            <div>
              <h3>Analysis workflow</h3>
              <p>Only persisted backend results are shown.</p>
            </div>
            <button
              className="button secondary"
              disabled={analysisLoading}
              onClick={runAnalysis}
            >
              {analysisLoading ? "Running..." : "Run analysis"}
            </button>
          </div>
          <Workflow agents={analysis?.agents as DataRecord} />
          {analysis && <JsonBlock data={analysis} />}
        </div>
      </div>
      <aside className="workspace-side">
        <div className="panel action-panel">
          <div className="panel-icon">
            <Users size={18} />
          </div>
          <h3>Escalation action</h3>
          <p>
            Escalation to Senior review. The backend authorizes this action by
            investigator role.
          </p>
          {role === "JUNIOR" && !escalated ? (
            <>
              <label className="field-label" htmlFor="investigator-name">
                Investigator name <span>UI only</span>
              </label>
              <input
                id="investigator-name"
                placeholder="Your name"
                aria-label="Investigator name, UI only"
              />
              <p className="field-note">
                This is not sent to the backend. The selected role is the
                authorization mechanism.
              </p>
              <label className="field-label" htmlFor="escalation-reason">
                Reason for escalation
              </label>
              <textarea
                id="escalation-reason"
                value={reason}
                onChange={(event) => setReason(event.target.value)}
                placeholder="Reason for escalation"
              />
              <button
                className="button warning"
                disabled={!reason.trim()}
                onClick={escalate}
              >
                <ArrowRight size={15} />
                Escalate to Senior
              </button>
            </>
          ) : escalated ? (
            <>
              <div className="inline-success">
                <Check size={16} />
                <span>
                  Case escalated to Senior review.
                  <small className="success-detail">
                    This case is no longer available in the Junior
                    investigation queue.
                  </small>
                </span>
              </div>
              <Link className="button secondary return-button" to="/alerts">
                <ArrowLeft size={15} />
                Return to suspected alerts
              </Link>
            </>
          ) : (
            <div className="restricted">
              <Shield size={16} />
              Senior role cannot initiate escalation.
            </div>
          )}
        </div>
      </aside>
    </div>
  );
}

// Account-swap cases can have zero internal fund-flow edges (every
// counterparty external), so the Graph tab falls back to this builder: an
// "external exposure" graph from the sanitized evidence package showing
// external money movement plus the device / geo-login security surface.
function buildSwapGraph(evidence: DataRecord): {
  elements: unknown[];
  summary: { peers: number; outbound: number; devices: number; locations: number };
} {
  const account = (evidence.account || {}) as DataRecord;
  const accountId = String(
    value(account, ["account_id"], String(evidence.case_id || "case-account")),
  );
  const elements: unknown[] = [
    {
      data: {
        id: accountId,
        label: `Case account ${accountId}`,
        is_case_account: true,
        depth: 0,
      },
    },
  ];

  const peers = new Map<
    string,
    { inbound: number; outbound: number; count: number; channels: Set<string>; last: string }
  >();
  for (const txn of (evidence.transactions || []) as DataRecord[]) {
    const peer = value(txn, ["counterparty", "beneficiary_id", "dest_acct"], "");
    if (!peer || peer === accountId) continue;
    const entry =
      peers.get(peer) ||
      { inbound: 0, outbound: 0, count: 0, channels: new Set<string>(), last: "" };
    const amount = Number(value(txn, ["amount"], "0")) || 0;
    if (value(txn, ["direction"], "OUT") === "IN") entry.inbound += amount;
    else entry.outbound += amount;
    entry.count += 1;
    entry.channels.add(value(txn, ["channel"], ""));
    entry.last = value(txn, ["timestamp"], entry.last);
    peers.set(peer, entry);
  }
  let outboundTotal = 0;
  peers.forEach((entry, peer) => {
    outboundTotal += entry.outbound;
    elements.push({
      data: {
        id: peer,
        label: peer,
        depth: 1,
        total_in: Math.round(entry.inbound) || undefined,
        total_out: Math.round(entry.outbound) || undefined,
        transactions: entry.count,
        channels: [...entry.channels].filter(Boolean).join(", "),
        last_activity: entry.last,
      },
      classes: peer.startsWith("EXT") ? "swap-external" : "",
    });
    if (entry.outbound > 0) {
      elements.push({
        data: {
          id: `flow-out-${peer}`,
          source: accountId,
          target: peer,
          amount: Math.round(entry.outbound),
          transactions: entry.count,
          channel: "outbound",
          timestamp: entry.last,
        },
        classes: "swap-edge-money",
      });
    }
    if (entry.inbound > 0) {
      elements.push({
        data: {
          id: `flow-in-${peer}`,
          source: peer,
          target: accountId,
          amount: Math.round(entry.inbound),
          transactions: entry.count,
          channel: "inbound",
          timestamp: entry.last,
        },
        classes: "swap-edge-money",
      });
    }
  });

  for (const device of (evidence.devices || []) as DataRecord[]) {
    const id = value(device, ["device_id"], "");
    if (!id) continue;
    const risky =
      value(device, ["sim_change_detected"], "FALSE") === "TRUE" ||
      value(device, ["jailbroken_rooted"], "FALSE") === "TRUE" ||
      value(device, ["is_trusted_device"], "TRUE") !== "TRUE";
    elements.push({
      data: {
        id,
        label: `${value(device, ["device_type"], "Device")} - ${id}`,
        os: value(device, ["os"], ""),
        trusted: value(device, ["is_trusted_device"], ""),
        sim_change: value(device, ["sim_change_detected"], ""),
        jailbroken: value(device, ["jailbroken_rooted"], ""),
        status: value(device, ["device_status"], ""),
      },
      classes: risky ? "swap-device swap-risky" : "swap-device",
    });
    elements.push({
      data: { id: `uses-${id}`, source: accountId, target: id, relation: "device access" },
      classes: "swap-edge-device",
    });
  }

  const cities = new Map<string, { events: number; vpn: boolean; country: string; last: string }>();
  for (const geo of (evidence.geo_events || []) as DataRecord[]) {
    const city = value(geo, ["city"], "");
    if (!city) continue;
    const entry =
      cities.get(city) || { events: 0, vpn: false, country: value(geo, ["country"], ""), last: "" };
    entry.events += 1;
    if (value(geo, ["is_vpn_or_proxy"], "FALSE") === "TRUE") entry.vpn = true;
    entry.last = value(geo, ["timestamp"], entry.last);
    cities.set(city, entry);
  }
  cities.forEach((entry, city) => {
    elements.push({
      data: {
        id: `geo-${city}`,
        label: city,
        events: entry.events,
        country: entry.country,
        vpn: entry.vpn ? "YES" : "NO",
        last: entry.last,
      },
      classes: entry.vpn ? "swap-geo swap-risky" : "swap-geo",
    });
    elements.push({
      data: {
        id: `geo-from-${city}`,
        source: accountId,
        target: `geo-${city}`,
        relation: "login / auth",
        events: entry.events,
      },
      classes: "swap-edge-geo",
    });
  });

  return {
    elements,
    summary: {
      peers: peers.size,
      outbound: Math.round(outboundTotal),
      devices: ((evidence.devices || []) as DataRecord[]).length,
      locations: cities.size,
    },
  };
}

type SwapLayer = "all" | "money" | "devices" | "geo";

function Graph({ caseId }: { caseId: string }) {
  const [container, setContainer] = useState<HTMLDivElement | null>(null);
  const [network, setNetwork] = useState<DataRecord | null>(null);
  const [selected, setSelected] = useState<DataRecord | null>(null);
  const [hovered, setHovered] = useState<{ data: DataRecord; x: number; y: number } | null>(null);
  const [depthLimit, setDepthLimit] = useState<number | null>(null);
  const [swap, setSwap] = useState<ReturnType<typeof buildSwapGraph> | null>(null);
  const [swapLoading, setSwapLoading] = useState(false);
  const [layer, setLayer] = useState<SwapLayer>("all");
  const graphRef = useRef<cytoscape.Core | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  useEffect(() => {
    setLoading(true);
    setError("");
    setNetwork(null);
    setSelected(null);
    setHovered(null);
    setDepthLimit(null);
    setSwap(null);
    setSwapLoading(false);
    setLayer("all");
    api
      .getNetwork(caseId)
      .then((result) => {
        setNetwork(result as DataRecord);
        const els = (result as DataRecord).elements;
        if (Array.isArray(els) && els.length === 0) {
          setSwapLoading(true);
          return api
            .getEvidence(caseId)
            .then((evidence) => setSwap(buildSwapGraph(evidence)))
            .catch(() => undefined)   // not investigated yet -> normal empty state
            .finally(() => setSwapLoading(false));
        }
      })
      .catch((error) => setError(userFacingError(error, "The case network could not be loaded.")))
      .finally(() => setLoading(false));
  }, [caseId]);
  useEffect(() => {
    if (!container || !network) return;
    const rawElements: DataRecord[] = swap
      ? (swap.elements as unknown as DataRecord[])
      : Array.isArray(network.elements)
        ? (network.elements as DataRecord[])
        : [];
    const elements = rawElements.map((element) => {
      const data = (element.data || {}) as DataRecord;
      const depth = Number(data.depth);
      const base = data.is_case_account === true
        ? "case-account"
        : Number.isFinite(depth) && depth >= 1 && depth <= 3
          ? `depth-${depth}`
          : "";
      const extra = typeof element.classes === "string" ? element.classes : "";
      const classes = [base, extra].filter(Boolean).join(" ");
      return { ...element, classes };
    });
    if (!elements.length) return;
    const graph = cytoscape({
      container,
      elements: elements as cytoscape.ElementDefinition[],
      style: [
        {
          selector: "node",
          style: {
            label: "data(label)",
            color: "#e9f1f7",
            "background-color": "#3f7185",
            "border-width": 1.5,
            "border-color": "#6dabb8",
            "font-size": 11,
            "text-outline-color": "#0d171f",
            "text-outline-width": 2,
            "min-zoomed-font-size": 8,
          },
        },
        { selector: ".case-account", style: { "background-color": "#c77b43", "border-color": "#f1c18b", "border-width": 3, width: 42, height: 42 } },
        { selector: ".depth-1", style: { "background-color": "#3f91b2" } },
        { selector: ".depth-2", style: { "background-color": "#579477" } },
        { selector: ".depth-3", style: { "background-color": "#8b8fb2" } },
        { selector: ".hovered", style: { "border-color": "#d9f3f3", "border-width": 2, opacity: 1 } },
        {
          selector: "edge",
          style: {
            width: 1.5,
            color: "#8aa0ae",
            "line-color": "#355665",
            "target-arrow-color": "#64c5dd",
            "target-arrow-shape": "triangle",
            "font-size": 9,
            "curve-style": "bezier",
          },
        },
        { selector: ".context-muted", style: { opacity: 0.16 } },
        { selector: ".context-active", style: { opacity: 1, "line-color": "#78d6df", "target-arrow-color": "#78d6df", width: 3 } },
        { selector: ":selected", style: { "border-color": "#f0d18a", "border-width": 3, "line-color": "#f0d18a", "target-arrow-color": "#f0d18a" } },
        { selector: ".swap-external", style: { "background-color": "#7d4634", "border-color": "#d9a75b", "border-width": 2, "border-style": "dashed", width: 30, height: 30 } },
        { selector: ".swap-device", style: { "background-color": "#35566b", "border-color": "#6dabb8", shape: "round-rectangle", width: 26, height: 26 } },
        { selector: ".swap-geo", style: { "background-color": "#3d6b52", "border-color": "#7fc39a", shape: "round-rectangle", width: 26, height: 26 } },
        { selector: ".swap-risky", style: { "background-color": "#8f3540", "border-color": "#e08a8a", "border-width": 3 } },
        { selector: ".layer-hidden", style: { display: "none" } },
      ],
    });
    // The layout is created explicitly (makeLayout + run, identical to the
    // constructor's `layout` option behaviour) so the cleanup holds a handle:
    // a running layout keeps its own animation frame, and letting it tick
    // against a destroyed core throws the "notify" / "isHeadless" errors on
    // every interaction after unmount.
    // Swap mode is a hub-and-spoke (one account, dozens of peers) - cose
    // scatters it, concentric rings read better and settle deterministically.
    const runningLayout = graph.makeLayout(
      swap
        ? {
            name: "concentric",
            concentric: (node: cytoscape.NodeSingular) =>
              node.data("is_case_account") === true
                ? 2
                : node.hasClass("swap-device") || node.hasClass("swap-geo")
                  ? 0
                  : 1,
            levelWidth: () => 1,
            minNodeSpacing: 26,
            animate: true,
            animationDuration: 700,
            fit: true,
            padding: 45,
          }
        : {
            name: "cose",
            animate: true,
            animationDuration: 850,
            animationEasing: "ease-out-cubic",
            refresh: 30,
            fit: true,
            padding: 45,
            nodeRepulsion: 450000,
            idealEdgeLength: 105,
            gravity: 0.35,
          },
    );
    runningLayout.run();
    graphRef.current = graph;
    let physicsFrame = 0;
    let draggedNode: cytoscape.NodeSingular | null = null;
    let localNodes: cytoscape.NodeSingular[] = [];
    let localVelocities = new Map<string, { x: number; y: number }>();
    let pointerPosition: cytoscape.Position | null = null;
    let simulationStartedAt = 0;

    const stopLocalPhysics = () => {
      if (physicsFrame) cancelAnimationFrame(physicsFrame);
      physicsFrame = 0;
    };

    const nearbyNodes = (node: cytoscape.NodeSingular) => {
      const direct = node.connectedEdges().connectedNodes();
      const secondLevel = direct.connectedEdges().connectedNodes();
      return node.union(direct).union(secondLevel).nodes().toArray();
    };

    const runLocalPhysics = (mode: "dragging" | "settling") => {
      stopLocalPhysics();
      const affected = localNodes.filter((node) => node.id() !== draggedNode?.id());
      simulationStartedAt = performance.now();
      affected.forEach((node) => {
        if (!localVelocities.has(node.id())) localVelocities.set(node.id(), { x: 0, y: 0 });
      });
      const tick = (now: number) => {
        if (mode === "dragging" && (!draggedNode || !pointerPosition)) {
          physicsFrame = 0;
          return;
        }
        const elapsed = now - simulationStartedAt;
        const damping = mode === "dragging" ? 0.88 : elapsed < 360 ? 0.86 : 0.76;
        affected.forEach((node) => {
          const velocity = localVelocities.get(node.id());
          if (!velocity) return;
          let forceX = 0;
          let forceY = 0;
          node.connectedEdges().forEach((edge) => {
            const other = edge.source().id() === node.id() ? edge.target() : edge.source();
            const otherPosition = other.position();
            const position = node.position();
            const dx = otherPosition.x - position.x;
            const dy = otherPosition.y - position.y;
            const distance = Math.max(1, Math.sqrt(dx * dx + dy * dy));
            const spring = (distance - 105) * 0.0021;
            forceX += (dx / distance) * spring;
            forceY += (dy / distance) * spring;
          });
          affected.forEach((other) => {
            if (other.id() === node.id()) return;
            const position = node.position();
            const otherPosition = other.position();
            const dx = position.x - otherPosition.x;
            const dy = position.y - otherPosition.y;
            const distance = Math.max(1, Math.sqrt(dx * dx + dy * dy));
            if (distance >= 78) return;
            const repulsion = (78 - distance) * 0.0026;
            forceX += (dx / distance) * repulsion;
            forceY += (dy / distance) * repulsion;
          });
          if (draggedNode) {
            const anchor = draggedNode.position();
            const position = node.position();
            const dx = anchor.x - position.x;
            const dy = anchor.y - position.y;
            const distance = Math.max(1, Math.sqrt(dx * dx + dy * dy));
            const influence = draggedNode.connectedEdges().connectedNodes().contains(node) ? 0.003 : 0.0008;
            forceX += (dx / distance) * Math.min(24, distance) * influence;
            forceY += (dy / distance) * Math.min(24, distance) * influence;
          }
          velocity.x = Math.max(-4, Math.min(4, (velocity.x + forceX) * damping));
          velocity.y = Math.max(-4, Math.min(4, (velocity.y + forceY) * damping));
          const position = node.position();
          node.position({ x: position.x + velocity.x, y: position.y + velocity.y });
        });
        if (mode === "dragging" || elapsed < 720) physicsFrame = requestAnimationFrame(tick);
        else {
          physicsFrame = 0;
        }
      };
      physicsFrame = requestAnimationFrame(tick);
    };

    graph.on("grab", "node", (event) => {
      stopLocalPhysics();
      const node = event.target as cytoscape.NodeSingular;
      draggedNode = node;
      pointerPosition = node.position();
      localNodes = nearbyNodes(node);
      localVelocities = new Map(localNodes.map((localNode) => [localNode.id(), { x: 0, y: 0 }]));
      runLocalPhysics("dragging");
    });
    graph.on("drag", "node", (event) => {
      const activeNode = draggedNode;
      if (!activeNode) return;
      pointerPosition = event.target.position();
    });
    graph.on("dragfree", "node", () => {
      if (!draggedNode) return;
      runLocalPhysics("settling");
      draggedNode = null;
      pointerPosition = null;
      localNodes = [];
      localVelocities.clear();
    });
    graph.on("mouseover", "node, edge", (event) => {
      const position = event.renderedPosition || { x: 0, y: 0 };
      setHovered({ data: event.target.data() as DataRecord, x: position.x + 12, y: position.y + 12 });
      event.target.addClass("hovered");
    });
    graph.on("mouseout", "node, edge", (event) => {
      setHovered(null);
      event.target.removeClass("hovered");
    });
    graph.on("tap", "node, edge", (event) => {
      const target = event.target;
      setSelected(target.data() as DataRecord);
      graph.elements().addClass("context-muted");
      target.removeClass("context-muted").addClass("context-active");
      target.connectedEdges().removeClass("context-muted").addClass("context-active");
      target.connectedNodes().removeClass("context-muted");
    });
    graph.on("tap", (event) => {
      if (event.target === graph) {
        graph.elements().removeClass("context-muted context-active");
        setSelected(null);
      }
    });
    return () => {
      stopLocalPhysics();
      draggedNode = null;
      pointerPosition = null;
      graphRef.current = null;
      try {
        runningLayout.stop();
      } catch {
        /* layout already ended */
      }
      graph.destroy();
    };
  }, [container, network, swap]);
  useEffect(() => {
    const graph = graphRef.current;
    if (!graph || !swap) return;
    const nodeVisible = (node: cytoscape.NodeSingular) => {
      if (layer === "all") return true;
      if (layer === "money")
        return !node.hasClass("swap-device") && !node.hasClass("swap-geo");
      if (layer === "devices")
        return node.hasClass("swap-device") || node.data("is_case_account") === true;
      return node.hasClass("swap-geo") || node.data("is_case_account") === true;
    };
    graph.nodes().forEach((node) => {
      node.toggleClass("layer-hidden", !nodeVisible(node));
    });
    graph.edges().forEach((edge) => {
      const edgeLayer = edge.hasClass("swap-edge-device")
        ? "devices"
        : edge.hasClass("swap-edge-geo")
          ? "geo"
          : "money";
      edge.toggleClass("layer-hidden", !(layer === "all" || layer === edgeLayer));
    });
  }, [layer, swap]);
  useEffect(() => {
    const graph = graphRef.current;
    if (!graph) return;
    graph.nodes().forEach((node) => {
      const depth = Number(node.data("depth"));
      const visible = depthLimit === null || (Number.isFinite(depth) && depth <= depthLimit);
      node.toggleClass("depth-hidden", !visible);
    });
    graph.edges().forEach((edge) => {
      edge.toggleClass("depth-hidden", edge.source().hasClass("depth-hidden") || edge.target().hasClass("depth-hidden"));
    });
    graph.elements().removeClass("context-muted context-active");
    graph.fit(undefined, 35);
  }, [depthLimit]);
  if (loading || (swapLoading && !swap))
    return (
      <LoadingState
        label={swapLoading ? "Building external exposure map" : "Building case network"}
      />
    );
  if (error) return <ErrorState message="Unable to load network data. Please try again." />;
  const swapMode = !!swap;
  const elements = swap
    ? (swap.elements as DataRecord[])
    : Array.isArray(network?.elements)
      ? (network.elements as DataRecord[])
      : [];
  const nodes = elements.filter((element) => element.group === "nodes");
  const edges = elements.filter((element) => element.group === "edges");
  const depths = nodes.map((element) => Number((element.data as DataRecord | undefined)?.depth)).filter((depth) => Number.isFinite(depth) && depth >= 1 && depth <= 3);
  const stats = (network?.stats || {}) as DataRecord;
  const caseAccount = value(network || {}, ["case_account"], "");
  return (
    <div className="graph-view">
      <div className="graph-toolbar">
        <div><span className="eyebrow">Network intelligence</span><h2>{swapMode ? "External exposure & security map" : "Fund-flow network"}</h2><p>{swapMode ? "No internal fund-flow trail exists for this case (account-swap pattern): external counterparties, devices and login locations from the sanitized evidence." : caseAccount ? `Case account ${caseAccount}` : "Backend network for this case"}</p></div>
        <div className="graph-actions">
          <button className="button secondary" onClick={() => graphRef.current?.zoom((graphRef.current?.zoom() || 1) + .2)}>Zoom in</button>
          <button className="button secondary" onClick={() => graphRef.current?.zoom(Math.max(.2, (graphRef.current?.zoom() || 1) - .2))}>Zoom out</button>
          <button className="button secondary" onClick={() => graphRef.current?.fit(undefined, 35)}>Fit network</button>
          {caseAccount && !swapMode && <button className="button secondary" onClick={() => { const node = graphRef.current?.getElementById(caseAccount); if (node?.length) graphRef.current?.animate({ center: { eles: node }, zoom: 1.25 }, { duration: 220 }); }}>Focus case account</button>}
          {swapMode && (
            <div className="depth-controls">
              <span>Layers</span>
              {([["all", "All"], ["money", "Money flow"], ["devices", "Devices"], ["geo", "Geo logins"]] as [SwapLayer, string][]).map(([key, label]) => (
                <button key={key} className={layer === key ? "active" : ""} onClick={() => setLayer(key)}>{label}</button>
              ))}
            </div>
          )}
        </div>
      </div>
      {!elements.length ? (
        <EmptyState
          title="No network data available for this case."
          detail="The backend returned no network elements for this case."
          icon={GitBranch}
        />
      ) : <div className="graph-layout">
        <div className="graph-panel panel">
          <div className="graph-canvas" ref={setContainer}>
            {hovered && <div className="graph-tooltip" style={{ left: hovered.x, top: hovered.y }}><strong>{hovered.data.source ? "Transaction" : hovered.data.os ? "Device" : hovered.data.events !== undefined && String(hovered.data.id || "").startsWith("geo-") ? "Login location" : "Account"}</strong><span>{value(hovered.data, ["label", "id", "transaction_id"])}</span>{hovered.data.depth !== undefined && <span>Depth {formatValue(hovered.data.depth)}</span>}</div>}
          </div>
          {swapMode ? (
            <div className="graph-legend"><span><i className="legend-dot case" />Case account</span><span><i className="legend-dot d3" />External counterparty</span><span><i className="legend-dot d1" />Device</span><span><i className="legend-dot d2" />Login location</span><span><i className="legend-dot" style={{ background: "#8f3540" }} />Flagged (VPN / risky device)</span></div>
          ) : (
            <div className="graph-legend"><span><i className="legend-dot case" />Case account</span><span><i className="legend-dot d1" />Depth 1</span><span><i className="legend-dot d2" />Depth 2</span><span><i className="legend-dot d3" />Depth 3</span><span><i className="legend-line" />Transaction / fund transfer</span></div>
          )}
        </div>
        <aside className="graph-context panel"><div className="eyebrow">Network context</div><h3>{selected ? (selected.source ? (selected.relation ? "Security relation" : "Transaction detail") : selected.os ? "Device detail" : String(selected.id || "").startsWith("geo-") ? "Login location" : "Selected account") : "Select an element"}</h3>{selected ? <RecordGrid record={selected} /> : <p className="muted">Click a node or edge to inspect backend-provided details.</p>}</aside>
      </div>}
      <div className="graph-summary">{swapMode ? (
        <>
          <Metric label="External counterparties" value={String(swap!.summary.peers)} icon={Users} />
          <Metric label="Outbound volume" value={String(swap!.summary.outbound)} icon={ArrowRight} />
          <Metric label="Devices" value={String(swap!.summary.devices)} icon={Shield} />
          <Metric label="Login locations" value={String(swap!.summary.locations)} icon={GitBranch} />
        </>
      ) : (
        <>
          <Metric label="Nodes" value={value(stats, ["nodes"], String(nodes.length))} icon={Users} /><Metric label="Transactions" value={value(stats, ["edges"], String(edges.length))} icon={GitBranch} /><Metric label="Maximum depth" value={value(stats, ["max_reached_depth"], depths.length ? String(Math.max(...depths)) : "—")} icon={GitBranch} />{depths.length > 0 && <div className="depth-controls"><span>Depth view</span><button className={depthLimit === null ? "active" : ""} onClick={() => setDepthLimit(null)}>All</button>{[1, 2, 3].filter((depth) => depths.includes(depth)).map((depth) => <button className={depthLimit === depth ? "active" : ""} key={depth} onClick={() => setDepthLimit(depth)}>Depth {depth}</button>)}</div>}
        </>
      )}</div>
    </div>
  );
}

function Evidence({ caseId }: { caseId: string }) {
  const [data, setData] = useState<DataRecord | null>(null);
  const [state, setState] = useState<"loading" | "ready" | "error">("loading");
  const load = () => {
    setState("loading");
    api
      .getEvidence(caseId)
      .then((result) => {
        setData(result);
        setState("ready");
      })
      .catch(() => setState("error"));
  };
  useEffect(load, [caseId]);
  if (state === "loading")
    return <LoadingState label="Loading sanitized evidence" />;
  if (state === "error")
    return (
      <ErrorState
        message="No evidence package is available yet, or this role is not authorized."
        retry={load}
      />
    );
  return (
    <div className="panel evidence-panel">
      <div className="section-title compact">
        <div>
          <h2>Sanitized evidence</h2>
          <p>Displayed exactly from the authorized backend response.</p>
        </div>
        <span className="safe-label">
          <Shield size={14} />
          Sanitized
        </span>
      </div>
      <EvidenceSections data={data || {}} />
    </div>
  );
}

function EvidenceSections({ data }: { data: DataRecord }) {
  const entries = Object.entries(data);
  if (!entries.length)
    return (
      <EmptyState
        title="Evidence package is empty"
        detail="The backend returned an empty sanitized evidence package."
      />
    );
  return (
    <div className="evidence-sections">
      {entries.map(([key, item]) => {
        const title = prettyKey(key);
        if (Array.isArray(item))
          return (
            <div className="evidence-section" key={key}>
              <h3>
                {title} <span>{item.length}</span>
              </h3>
              {item.length ? (
                <div className="evidence-list">
                  {item.map((entry, index) =>
                    typeof entry === "object" && entry !== null ? (
                      <div className="evidence-record" key={`${key}-${index}`}>
                        <RecordGrid record={entry as DataRecord} />
                      </div>
                    ) : (
                      <div className="evidence-value" key={`${key}-${index}`}>
                        {formatValue(entry)}
                      </div>
                    ),
                  )}
                </div>
              ) : (
                <p className="muted">No records returned.</p>
              )}
            </div>
          );
        if (typeof item === "object" && item !== null)
          return (
            <div className="evidence-section" key={key}>
              <h3>{title}</h3>
              <RecordGrid record={item as DataRecord} />
            </div>
          );
        return (
          <div className="evidence-section evidence-value" key={key}>
            <span>{title}</span>
            <strong>{formatValue(item)}</strong>
          </div>
        );
      })}
    </div>
  );
}

// Step tracker for the backend investigation contract:
// POST /investigate (evidence + agents) -> POST /analysis -> POST /sar-report.
function PipelineSteps({ steps }: { steps: { label: string; done: boolean }[] }) {
  return (
    <div className="workflow">
      {steps.map((step, index) => (
        <div className="workflow-step" key={step.label}>
          <div className={`workflow-icon ${step.done ? "done" : ""}`}>
            {step.done ? <CheckCircle2 size={16} /> : <CircleDashed size={16} />}
          </div>
          <div>
            <strong>{step.label}</strong>
            <span>{step.done ? "Complete" : "Pending"}</span>
          </div>
          {index < steps.length - 1 && (
            <ArrowRight className="workflow-arrow" size={14} />
          )}
        </div>
      ))}
    </div>
  );
}

// The three Grok hypothesis agents (Checkpoint 4), rendered from stored
// backend responses only.
function HypothesisResults({ agents }: { agents: DataRecord | null }) {
  if (!agents) return null;
  const sections: [string, unknown][] = [
    ["Fraud / scam hypothesis", agents.scammer_hypothesis],
    ["Legitimate hypothesis", agents.legitimate_hypothesis],
    ["Contradiction", agents.contradiction],
  ];
  return (
    <>
      {sections.map(([title, result]) => (
        <div className="evidence-section" key={title}>
          <h3>{title}</h3>
          {result && typeof result === "object" ? (
            <RecordGrid record={result as DataRecord} />
          ) : (
            <p className="muted">{formatValue(result)}</p>
          )}
        </div>
      ))}
    </>
  );
}

function SarAudits({
  caseId,
  detail,
}: {
  caseId: string;
  detail: { case: DataRecord; alerts: DataRecord[] };
}) {
  const [audit, setAudit] = useState<DataRecord[]>([]);
  const [auditError, setAuditError] = useState("");
  // Pipeline gates per the backend contract: POST /sar-report only accepts a
  // case that already has BOTH an evidence package and a stored analysis
  // (POST /investigate -> POST /analysis -> POST /sar-report).
  const [evidenceState, setEvidenceState] = useState<
    "loading" | "ready" | "missing"
  >("loading");
  const [analysisState, setAnalysisState] = useState<
    "loading" | "ready" | "notrun"
  >("loading");
  const [analysis, setAnalysis] = useState<DataRecord | null>(null);
  const [agents, setAgents] = useState<DataRecord | null>(null);
  const [investigating, setInvestigating] = useState(false);
  const [analyzing, setAnalyzing] = useState(false);
  const [sarLoading, setSarLoading] = useState(false);
  const [sarDone, setSarDone] = useState(false);
  const [sarError, setSarError] = useState("");
  const [progress, setProgress] = useState("");
  const [saved, setSaved] = useState(false);
  const [reveal, setReveal] = useState<DataRecord | null>(null);
  const { role } = useRole();
  const loadAudit = () => {
    api
      .getAudit(caseId)
      .then((result) => setAudit(result.events))
      .catch((error) =>
        setAuditError(userFacingError(error, "The audit trail could not be loaded.")),
      );
  };
  useEffect(() => {
    loadAudit();
  }, [caseId]);
  useEffect(() => {
    setEvidenceState("loading");
    api
      .getEvidence(caseId)
      .then(() => setEvidenceState("ready"))
      .catch(() => setEvidenceState("missing"));
  }, [caseId]);
  useEffect(() => {
    setAnalysisState("loading");
    setAnalysis(null);
    setAgents(null);
    setSarDone(false);
    setProgress("");
    setSarError("");
    api
      .getAnalysis(caseId)
      .then((result) => {
        setAnalysis(result);
        setAgents((result.agents || null) as DataRecord | null);
        setAnalysisState("ready");
      })
      .catch((error) => {
        if (error instanceof ApiError && error.status !== 404)
          console.error("[SENTINEL] stored analysis could not be loaded", error);
        setAnalysisState("notrun");
      });
  }, [caseId]);
  const startInvestigation = async () => {
    setInvestigating(true);
    setSarError("");
    setProgress("");
    try {
      const result = await api.investigate(caseId);
      setAgents((result.agents || null) as DataRecord | null);
      setEvidenceState("ready");
      setProgress(
        "Evidence bundle sanitized and sent to the three hypothesis agents (scammer, legitimate, contradiction). Run the analysis to score the investigation.",
      );
      loadAudit();
    } catch (error) {
      setSarError(
        userFacingError(error, "The investigation could not be completed."),
      );
      console.error("[SENTINEL] investigation failed", error);
    } finally {
      setInvestigating(false);
    }
  };
  const runAnalysis = async () => {
    setAnalyzing(true);
    setSarError("");
    setProgress("");
    try {
      const result = await api.runAnalysis(caseId);
      setAnalysis(result);
      setAgents((result.agents || null) as DataRecord | null);
      setAnalysisState("ready");
      setProgress(
        "Analysis stored: regulatory findings, completeness score, routing and next-best-action are ready. The SAR PDF can now be generated.",
      );
      loadAudit();
    } catch (error) {
      setSarError(userFacingError(error, "Analysis could not be completed."));
      console.error("[SENTINEL] analysis failed", error);
    } finally {
      setAnalyzing(false);
    }
  };
  const generateSar = async () => {
    setSarLoading(true);
    setSarError("");
    try {
      const blob = await api.sar(caseId);
      const url = URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = url;
      link.download = `SAR_${caseId}.pdf`;
      link.click();
      URL.revokeObjectURL(url);
      setSarDone(true);
      setProgress(
        `SAR PDF downloaded. It opens with the last four characters of account ${value(detail.case, ["account_id"])}.`,
      );
      loadAudit();
    } catch (error) {
      setSarError(userFacingError(error, "The SAR report could not be generated."));
      console.error("[SENTINEL] SAR generation failed", error);
    } finally {
      setSarLoading(false);
    }
  };
  const addReference = async () => {
    try {
      await api.addReference(caseId, "");
      setSaved(true);
    } catch (error) {
      setSarError(userFacingError(error, "The case could not be saved to references."));
    }
  };
  const sarReady = evidenceState === "ready" && !!analysis;
  const pipelineSteps = [
    { label: "Evidence bundle", done: evidenceState === "ready" },
    { label: "Hypothesis agents", done: !!agents },
    { label: "Regulatory + auditor", done: !!analysis },
    { label: "SAR report", done: sarDone },
  ];
  return (
    <div className="workspace-grid">
      <div className="workspace-main">
        <div className="panel">
          <div className="section-title compact">
            <div>
              <h2>Investigation pipeline</h2>
              <p>
                Evidence bundle → three hypothesis agents → regulatory
                analysis → SAR report.
              </p>
            </div>
            {analysisState !== "loading" && !agents && (
              <button
                className="button primary"
                disabled={investigating}
                onClick={startInvestigation}
              >
                {investigating ? (
                  "Investigation running"
                ) : (
                  <>
                    <Play size={15} />
                    Start investigation
                  </>
                )}
              </button>
            )}
            {agents && !analysis && (
              <button
                className="button primary"
                disabled={analyzing}
                onClick={runAnalysis}
              >
                {analyzing ? (
                  "Analysis running"
                ) : (
                  <>
                    <Play size={15} />
                    Run analysis
                  </>
                )}
              </button>
            )}
          </div>
          <PipelineSteps steps={pipelineSteps} />
          <Workflow agents={agents} />
          {progress && (
            <div className="inline-success">
              <Check size={16} />
              <span>{progress}</span>
            </div>
          )}
          {sarError && (
            <div className="inline-error">
              <X size={16} />
              {sarError}
            </div>
          )}
          {analysisState === "loading" ? (
            <LoadingState label="Checking for stored analysis" />
          ) : agents ? (
            <HypothesisResults agents={agents} />
          ) : (
            <EmptyState
              title="Investigation not started"
              detail="Start the investigation to bundle sanitized evidence and run the three hypothesis agents on the backend."
            />
          )}
          {analysis && <JsonBlock data={analysis} />}
        </div>
        {analysis && (
          <div className="panel">
            <div className="section-title compact">
              <div>
                <h2>Investigation assessment</h2>
                <p>
                  Auditor, routing and next-best-action from the stored
                  analysis.
                </p>
              </div>
            </div>
            <div className="evidence-section">
              <h3>Completeness &amp; routing</h3>
              <RecordGrid record={(analysis.auditor || {}) as DataRecord} />
            </div>
            <div className="evidence-section">
              <h3>Next best action</h3>
              <RecordGrid
                record={(analysis.next_best_action || {}) as DataRecord}
              />
            </div>
          </div>
        )}
        <div className="panel">
          <div className="section-title compact">
            <div>
              <h2>Audit trail</h2>
              <p>Chronological events returned by the backend.</p>
            </div>
            <Shield size={18} />
          </div>
          {auditError ? (
            <ErrorState message={auditError} />
          ) : audit.length ? (
            <div className="timeline">
              {audit.map((event, index) => (
                <div
                  className="timeline-item"
                  key={String(event.timestamp || event.event || index)}
                >
                  <span className="timeline-node" />
                  <div>
                    <strong>{value(event, ["event", "action"])}</strong>
                    <small>
                      {value(event, ["timestamp", "created_at"])} ·{" "}
                      {value(event, ["actor", "role"])}
                    </small>
                    <p>{value(event, ["details", "detail"])}</p>
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <EmptyState
              title="No audit events"
              detail="No audit events have been returned for this case."
            />
          )}
        </div>
        <div className="panel">
          <div className="section-title compact">
            <div>
              <h2>Authorized agent view</h2>
              <p>PII is never revealed automatically.</p>
            </div>
          </div>
          {role === "SENIOR" ? (
            <button
              className="button secondary"
              onClick={() =>
                api
                  .revealAgents(caseId)
                  .then(setReveal)
                  .catch((error) =>
                    setSarError(userFacingError(error, "The authorized agent view could not be revealed.")),
                  )
              }
            >
              <LockKeyhole size={15} />
              Reveal authorized view
            </button>
          ) : (
            <div className="restricted">
              <Shield size={16} />
              Available only to Senior investigators.
            </div>
          )}
          {reveal && <JsonBlock data={reveal} />}
        </div>
      </div>
      <aside className="workspace-side">
        <div className="panel action-panel">
          <div className="panel-icon">
            <FileText size={18} />
          </div>
          <h3>Suspicious Activity Report</h3>
          <p>
            Generate the protected PDF through the backend. The frontend never
            receives aliases or report secrets.
          </p>
          {!sarReady && (
            <p className="field-note">
              {evidenceState !== "ready"
                ? "The backend requires the evidence bundle first. Start the investigation above (or on the Overview tab), then run the analysis."
                : "Stored analysis is required first. Run the analysis above, then generate the SAR."}
            </p>
          )}
          <button
            className="button primary"
            disabled={sarLoading || !sarReady}
            onClick={generateSar}
          >
            {sarLoading ? (
              "Generating PDF..."
            ) : (
              <>
                <Download size={15} />
                Download SAR PDF
              </>
            )}
          </button>
          {sarError && <div className="inline-error">{sarError}</div>}
        </div>
        <div className="panel action-panel">
          <div className="panel-icon">
            <Save size={18} />
          </div>
          <h3>Reference memory</h3>
          <p>Retain this case explicitly for future investigations.</p>
          <button
            className="button secondary"
            disabled={saved}
            onClick={addReference}
          >
            {saved ? (
              <>
                <Check size={15} />
                Saved to references
              </>
            ) : (
              <>
                <Save size={15} />
                Save reference
              </>
            )}
          </button>
        </div>
      </aside>
    </div>
  );
}

export function App() {
  const { role } = useRole();
  return (
    <Routes>
      <Route
        path="/"
        element={role ? <Navigate to="/alerts" replace /> : <RoleScreen />}
      />
      <Route
        path="*"
        element={
          role ? (
            <Shell>
              <Routes>
                <Route path="/alerts" element={<CaseQueue />} />
                <Route
                  path="/escalated"
                  element={<CaseQueue mode="escalated" />}
                />
                <Route path="/audit" element={<CaseQueue mode="audit" />} />
                <Route path="/saved" element={<References />} />
                <Route path="/cases/:caseId" element={<CaseWorkspace />} />
                <Route path="*" element={<Navigate to="/alerts" replace />} />
              </Routes>
            </Shell>
          ) : (
            <Navigate to="/" replace />
          )
        }
      />
    </Routes>
  );
}
