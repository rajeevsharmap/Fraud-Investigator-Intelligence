import { useEffect, useRef, useState } from "react";
import {
  AlertTriangle,
  ArrowLeft,
  ArrowRight,
  Check,
  ChevronRight,
  Download,
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
import { SeniorAccountDeepDive } from "./seniorDeepDive";
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
  const enterWorkspace = () => {
    const name = investigatorName.trim();
    if (name) sessionStorage.setItem("sentinel-investigator-name", name);
    else sessionStorage.removeItem("sentinel-investigator-name");
    selectRole(choice);
  };
  return (
    <main className="role-screen">
      <div className="role-panel">
        <div className="brand-mark">
          <Shield size={23} />
          <span>SENTINEL</span>
        </div>
        <div className="eyebrow">Secure investigator access</div>
        <h1>
          Investigator
          <br />
          <em>Access</em>
        </h1>
        <p className="lede">
          Identify yourself to enter the secure investigation workspace.
          Authorization is determined by your selected investigator role.
        </p>
        <label className="access-label" htmlFor="access-name">Investigator Name</label>
        <input
          className="access-input"
          id="access-name"
          value={investigatorName}
          onChange={(event) => setInvestigatorName(event.target.value)}
          placeholder="Enter your name"
          autoComplete="name"
        />
        <div className="role-options">
          {(["JUNIOR", "SENIOR"] as Role[]).map((role) => (
            <button
              className={`role-option ${choice === role ? "selected" : ""}`}
              key={role}
              onClick={() => setChoice(role)}
            >
              <span className="role-radio">{choice === role && <span />}</span>
              <span>
                <strong>
                  {role === "JUNIOR"
                    ? "Junior Investigator"
                    : "Senior Investigator"}
                </strong>
                <small>
                  {role === "JUNIOR"
                    ? "Review new queue cases and escalate findings"
                    : "Access senior queue and authorized case intelligence"}
                </small>
              </span>
              <ChevronRight size={18} />
            </button>
          ))}
        </div>
        <button
          className="button primary enter-button"
          onClick={enterWorkspace}
        >
          Enter Investigation Workspace <ChevronRight size={17} />
        </button>
        <div className="role-foot">
          <span>
            <span className="live-dot" /> Backend authorization required
          </span>
          <span>v1.0 / INTERNAL</span>
        </div>
      </div>
      <div className="role-aside">
        <div className="signal-line" />
        <span className="aside-label">CASE INTELLIGENCE / 01</span>
        <h2>
          See the signal.
          <br />
          Follow the evidence.
        </h2>
        <p>
          A focused command surface for detection, investigation, and
          accountable action.
        </p>
        <div className="aside-stats">
          <Metric label="Operational mode" value="LIVE API" icon={Sparkles} />
          <Metric label="Evidence boundary" value="SANITIZED" icon={Shield} />
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
    { to: "/escalated", label: "Escalated Cases", icon: Users },
    { to: "/audit", label: "Audit-Ready Cases", icon: Shield },
    { to: "/saved", label: "Reference Cases", icon: FileText },
    ...(role === "SENIOR"
      ? [{ to: "/senior-deep-dive", label: "Senior Deep-Dive", icon: Search }]
      : []),
  ];
  return (
    <div className="app-shell">
      <aside className={`sidebar ${menu ? "open" : ""}`}>
        <div className="sidebar-head">
          <Link to="/alerts" className="brand-mark">
            <Shield size={21} />
            <span>SENTINEL</span>
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
            <span>Sentinel</span>
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
  useEffect(load, []);
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
  const [sort, setSort] = useState("case_id");
  const filtered = data
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
      return (
        matchesMode &&
        JSON.stringify(item).toLowerCase().includes(query.toLowerCase())
      );
    })
    .sort((a, b) => value(a, [sort]).localeCompare(value(b, [sort])));
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
        ? "Cases legitimately identified as moved to senior review."
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
            {loading ? "—" : filtered.length} records
          </span>
          <button className="button secondary" onClick={reload}>
            <icons.clock size={15} />
            Refresh
          </button>
        </div>
      </div>
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
          Sort by{" "}
          <select
            value={sort}
            onChange={(event) => setSort(event.target.value)}
          >
            <option value="case_id">Case ID</option>
            <option value="status">Status</option>
            <option value="primary_trigger">Primary trigger</option>
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
      .then(setDetail)
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
          <h3>Human review</h3>
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
        <div className="panel">
          <h3>Authorized view</h3>
          <div className="access-note">
            <Shield size={15} />
            <span>
              Role header: <strong>{role}</strong>
            </span>
          </div>
          <p className="muted">
            The backend remains authoritative for every record and action in
            this workspace.
          </p>
        </div>
      </aside>
    </div>
  );
}

function Graph({ caseId }: { caseId: string }) {
  const [container, setContainer] = useState<HTMLDivElement | null>(null);
  const [network, setNetwork] = useState<DataRecord | null>(null);
  const [selected, setSelected] = useState<DataRecord | null>(null);
  const graphRef = useRef<cytoscape.Core | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  useEffect(() => {
    api
      .getNetwork(caseId)
      .then((result) => setNetwork(result as DataRecord))
      .catch((error) => setError(userFacingError(error, "The case network could not be loaded.")))
      .finally(() => setLoading(false));
  }, [caseId]);
  useEffect(() => {
    if (!container || !network) return;
    const elements = Array.isArray(network.elements) ? network.elements : [];
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
            "background-color": "#287fa5",
            "border-width": 2,
            "border-color": "#64c5dd",
            "font-size": 11,
          },
        },
        {
          selector: "edge",
          style: {
            width: 1.5,
            color: "#8aa0ae",
            "line-color": "#355665",
            "target-arrow-color": "#64c5dd",
            "target-arrow-shape": "triangle",
            "font-size": 9,
          },
        },
      ],
      layout: { name: "cose", animate: false },
    });
    graphRef.current = graph;
    graph.on("select", "node, edge", (event) => {
      setSelected(event.target.data() as DataRecord);
    });
    return () => graph.destroy();
  }, [container, network]);
  if (loading) return <LoadingState label="Building case network" />;
  if (error) return <ErrorState message={error} />;
  const count = Array.isArray(network?.elements) ? network?.elements.length : 0;
  return (
    <div className="panel graph-panel">
      <div className="section-title compact">
        <div>
          <h2>Fund-flow network</h2>
          <p>
            {count
              ? `${count} backend elements`
              : "No network elements returned by the backend."}
          </p>
        </div>
        {count > 0 && (
          <button
            className="button secondary"
            onClick={() => graphRef.current?.fit(undefined, 35)}
          >
            Fit graph
          </button>
        )}
      </div>
      {count ? (
        <>
          <div className="graph-canvas" ref={setContainer} />
          {selected && (
            <div className="selected-element">
              <strong>Selected element</strong>
              <RecordGrid record={selected} />
            </div>
          )}
        </>
      ) : (
        <EmptyState
          title="No graph data"
          detail="This case has no network available from the backend."
          icon={GitBranch}
        />
      )}
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

function SarAudits({ caseId }: { caseId: string }) {
  const [audit, setAudit] = useState<DataRecord[]>([]);
  const [auditError, setAuditError] = useState("");
  const [sarLoading, setSarLoading] = useState(false);
  const [sarError, setSarError] = useState("");
  const [saved, setSaved] = useState(false);
  const [reveal, setReveal] = useState<DataRecord | null>(null);
  const { role } = useRole();
  useEffect(() => {
    api
      .getAudit(caseId)
      .then((result) => setAudit(result.events))
      .catch((error) =>
        setAuditError(userFacingError(error, "The audit trail could not be loaded.")),
      );
  }, [caseId]);
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
  return (
    <div className="workspace-grid">
      <div className="workspace-main">
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
          <button
            className="button primary"
            disabled={sarLoading}
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
                <Route
                  path="/senior-deep-dive"
                  element={<SeniorAccountDeepDive />}
                />
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
