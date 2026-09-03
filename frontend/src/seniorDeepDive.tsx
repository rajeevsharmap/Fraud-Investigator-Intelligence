import { useState } from "react";
import {
  ArrowLeft,
  BarChart3,
  Building2,
  CheckCircle2,
  Globe2,
  Shield,
  Smartphone,
  TrendingDown,
  TrendingUp,
  Upload,
} from "lucide-react";
import { Link } from "react-router-dom";
import { useRole } from "./role";

type SummaryEntry = {
  label: string;
  total: number;
  count: number;
};

type TrendPoint = {
  label: string;
  value: number;
};

type DeepDiveSummary = {
  rowsAnalyzed: number;
  credits: number;
  debits: number;
  averageSpending: number;
  spendingTrend: TrendPoint[];
  incomingTrend: TrendPoint[];
  topCreditBeneficiaries: SummaryEntry[];
  topDebitBeneficiaries: SummaryEntry[];
  beneficiaryConcentration: number;
  deviceSummary: SummaryEntry[];
  geographicSummary: SummaryEntry[];
};

function money(value: number) {
  return new Intl.NumberFormat("en-US", {
    style: "currency",
    currency: "USD",
    maximumFractionDigits: 2,
  }).format(value);
}

function shortLabel(value: string) {
  const trimmed = value.trim();
  if (!trimmed) return "Unknown";
  return trimmed.length > 28 ? `${trimmed.slice(0, 25)}…` : trimmed;
}

function safePercentage(value: number) {
  return `${(value * 100).toFixed(1)}%`;
}

function parseCsvLine(line: string) {
  const values: string[] = [];
  let current = "";
  let inQuotes = false;

  for (let index = 0; index < line.length; index += 1) {
    const char = line[index];
    const next = line[index + 1];

    if (char === '"') {
      if (inQuotes && next === '"') {
        current += '"';
        index += 1;
      } else {
        inQuotes = !inQuotes;
      }
      continue;
    }

    if (char === "," && !inQuotes) {
      values.push(current);
      current = "";
      continue;
    }

    if ((char === "\n" || char === "\r") && !inQuotes) {
      continue;
    }

    current += char;
  }

  values.push(current);
  return values.map((part) => part.trim());
}

function normalizeKey(value: string) {
  return value
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "_")
    .replace(/^_+|_+$/g, "");
}

function findField(row: Record<string, string>, aliases: string[]) {
  const entries = Object.entries(row);
  for (const alias of aliases) {
    const target = normalizeKey(alias);
    const match = entries.find(([key]) => normalizeKey(key) === target || normalizeKey(key).endsWith(`_${target}`) || normalizeKey(key).includes(target));
    if (match) return match[0];
  }
  return null;
}

function parseNumber(value: string | undefined) {
  if (!value) return null;
  const cleaned = value
    .replace(/[$€£¥₹,\s]/g, "")
    .replace(/\((.*)\)/, "-$1")
    .replace(/[^0-9.\-]/g, "");

  if (!cleaned || cleaned === "-") return null;
  const parsed = Number(cleaned);
  return Number.isFinite(parsed) ? parsed : null;
}

function parseDate(value: string | undefined) {
  if (!value) return null;
  const trimmed = value.trim();
  if (!trimmed) return null;

  const direct = new Date(trimmed);
  if (!Number.isNaN(direct.getTime())) return direct;

  const numeric = Number(trimmed);
  if (!Number.isNaN(numeric) && String(Math.abs(numeric)).length >= 8) {
    return new Date(numeric);
  }

  return null;
}

function formatBucket(date: Date) {
  return date.toLocaleDateString("en-US", { month: "short", year: "2-digit" });
}

function rowDirection(row: Record<string, string>) {
  const directionField = findField(row, [
    "direction",
    "transaction_type",
    "flow_type",
    "entry_type",
    "credit_debit",
    "debit_credit",
    "dr_cr",
    "type",
    "movement",
    "side",
  ]);

  if (directionField) {
    const value = (row[directionField] || "").toLowerCase();
    if (/credit|incoming|inflow|deposit|receipt|income|receive|top_up|payment_received|cr/.test(value)) {
      return "credit";
    }
    if (/debit|outgoing|outflow|withdrawal|transfer|withdraw|payment|expense|spend|dr/.test(value)) {
      return "debit";
    }
  }

  const amountField = findField(row, [
    "amount",
    "amount_inr",
    "transaction_amount",
    "value",
    "net_amount",
    "amt",
    "credit_amount",
    "debit_amount",
    "total",
  ]);

  if (amountField) {
    const parsed = parseNumber(row[amountField]);
    if (parsed !== null) {
      return parsed < 0 ? "debit" : "credit";
    }
  }

  return null;
}

function rowAmount(row: Record<string, string>) {
  const amountField = findField(row, [
    "amount",
    "amount_inr",
    "transaction_amount",
    "value",
    "net_amount",
    "amt",
    "credit_amount",
    "debit_amount",
    "total",
  ]);

  if (!amountField) return null;
  return parseNumber(row[amountField]);
}

function parseCsv(text: string) {
  const lines = text.split(/\r?\n/).filter((line) => line.trim().length > 0);
  if (lines.length < 2) return [] as Record<string, string>[];

  const headers = parseCsvLine(lines[0]);
  return lines.slice(1).map((line) => {
    const values = parseCsvLine(line);
    const row: Record<string, string> = {};
    headers.forEach((header, index) => {
      row[header] = (values[index] ?? "").trim();
    });
    return row;
  });
}

function buildTrend(rows: Record<string, string>[], direction: "credit" | "debit") {
  const buckets = new Map<string, number>();
  const dateField = findField(rows[0] ?? {}, [
    "date",
    "timestamp",
    "created_at",
    "posted_at",
    "transaction_date",
    "event_date",
    "datetime",
    "date_time",
  ]);

  rows.forEach((row) => {
    const amountValue = rowAmount(row);
    const dir = rowDirection(row);
    if (amountValue === null || dir !== direction) return;

    const date = dateField ? parseDate(row[dateField]) : null;
    if (!date) return;

    const bucketKey = `${date.getFullYear()}-${String(date.getMonth() + 1).padStart(2, "0")}`;
    const current = buckets.get(bucketKey) ?? 0;
    buckets.set(bucketKey, current + Math.abs(amountValue));
  });

  return Array.from(buckets.entries())
    .sort(([left], [right]) => left.localeCompare(right))
    .slice(-6)
    .map(([label, value]) => ({
      label: formatBucket(new Date(`${label}-01T00:00:00`)),
      value,
    }));
}

function summarizeRows(rows: Record<string, string>[]) {
  if (!rows.length) {
    throw new Error("No rows were found in the uploaded CSV.");
  }

  let credits = 0;
  let debits = 0;
  let spendingCount = 0;
  const creditByBeneficiary = new Map<string, number>();
  const debitByBeneficiary = new Map<string, number>();
  const creditByDevice = new Map<string, number>();
  const debitByDevice = new Map<string, number>();
  const creditByGeo = new Map<string, number>();
  const debitByGeo = new Map<string, number>();

  rows.forEach((row) => {
    const amount = rowAmount(row);
    if (amount === null) return;

    const direction = rowDirection(row) ?? (amount < 0 ? "debit" : "credit");
    const magnitude = Math.abs(amount);

    if (direction === "credit") {
      credits += magnitude;
    } else {
      debits += magnitude;
      spendingCount += 1;
    }

    const beneficiaryField = findField(row, [
      "beneficiary",
      "beneficiary_name",
      "payee",
      "merchant",
      "counterparty",
      "recipient",
      "name",
      "person_name",
      "account_name",
      "party",
    ]);

    const deviceField = findField(row, [
      "device",
      "device_id",
      "device_name",
      "device_model",
      "mobile_device",
      "user_agent",
      "os",
      "browser",
      "platform",
    ]);

    const geoField = findField(row, [
      "country",
      "country_name",
      "geo_country",
      "location_country",
      "city",
      "geo_city",
      "region",
      "state",
      "location",
      "locale",
    ]);

    const label = beneficiaryField ? shortLabel(row[beneficiaryField] || "Unknown") : "Unknown";
    if (direction === "credit") {
      creditByBeneficiary.set(label, (creditByBeneficiary.get(label) || 0) + magnitude);
    } else {
      debitByBeneficiary.set(label, (debitByBeneficiary.get(label) || 0) + magnitude);
    }

    if (deviceField) {
      const deviceLabel = shortLabel(row[deviceField] || "Unknown");
      if (direction === "credit") {
        creditByDevice.set(deviceLabel, (creditByDevice.get(deviceLabel) || 0) + magnitude);
      } else {
        debitByDevice.set(deviceLabel, (debitByDevice.get(deviceLabel) || 0) + magnitude);
      }
    }

    if (geoField) {
      const geoLabel = shortLabel(row[geoField] || "Unknown");
      if (direction === "credit") {
        creditByGeo.set(geoLabel, (creditByGeo.get(geoLabel) || 0) + magnitude);
      } else {
        debitByGeo.set(geoLabel, (debitByGeo.get(geoLabel) || 0) + magnitude);
      }
    }
  });

  const debitEntries = Array.from(debitByBeneficiary.entries())
    .map(([label, total]) => ({ label, total, count: 0 }))
    .sort((a, b) => b.total - a.total)
    .slice(0, 5);

  const creditEntries = Array.from(creditByBeneficiary.entries())
    .map(([label, total]) => ({ label, total, count: 0 }))
    .sort((a, b) => b.total - a.total)
    .slice(0, 5);

  const deviceSummary = Array.from(debitByDevice.entries())
    .map(([label, total]) => ({ label, total, count: 0 }))
    .sort((a, b) => b.total - a.total)
    .slice(0, 5);

  const geographicSummary = Array.from(debitByGeo.entries())
    .map(([label, total]) => ({ label, total, count: 0 }))
    .sort((a, b) => b.total - a.total)
    .slice(0, 5);

  const beneficiaryConcentration = debits > 0
    ? Array.from(debitByBeneficiary.entries())
        .sort((a, b) => b[1] - a[1])
        .slice(0, 3)
        .reduce((sum, [, total]) => sum + total, 0) / debits
    : 0;

  return {
    rowsAnalyzed: rows.length,
    credits,
    debits,
    averageSpending: spendingCount ? debits / spendingCount : 0,
    spendingTrend: buildTrend(rows, "debit"),
    incomingTrend: buildTrend(rows, "credit"),
    topCreditBeneficiaries: creditEntries,
    topDebitBeneficiaries: debitEntries,
    beneficiaryConcentration,
    deviceSummary,
    geographicSummary,
  } satisfies DeepDiveSummary;
}

export function SeniorAccountDeepDive() {
  const { role } = useRole();
  const [summary, setSummary] = useState<DeepDiveSummary | null>(null);
  const [error, setError] = useState("");
  const [fileName, setFileName] = useState("");

  if (role !== "SENIOR") {
    return (
      <section className="deep-dive-page">
        <div className="panel restriction-panel">
          <Shield size={20} />
          <h2>Senior access required</h2>
          <p>This deep-dive is intentionally restricted to senior investigators only.</p>
          <Link className="button secondary" to="/alerts">
            <ArrowLeft size={15} />
            Return to alerts
          </Link>
        </div>
      </section>
    );
  }

  const handleFile = async (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    if (!file) return;

    setFileName(file.name);
    setError("");

    try {
      const text = await file.text();
      const rows = parseCsv(text);
      const parsed = summarizeRows(rows);
      setSummary(parsed);
    } catch (caughtError) {
      const message = caughtError instanceof Error ? caughtError.message : "Unable to analyze the uploaded CSV.";
      setSummary(null);
      setError(message);
    }
  };

  return (
    <section className="deep-dive-page">
      <div className="page-heading">
        <div>
          <div className="eyebrow">Senior / account review</div>
          <h1>Senior Account Deep-Dive</h1>
          <p>Client-side CSV review. No raw data leaves the browser and nothing is sent to the backend.</p>
        </div>
      </div>

      <div className="panel deep-dive-panel">
        <div className="section-title compact">
          <div>
            <h2>Upload one account CSV</h2>
            <p>Parsed entirely in-browser and summarized without backend transmission.</p>
          </div>
          <Shield size={18} />
        </div>

        <label className="upload-box">
          <Upload size={18} />
          <span>{fileName || "Choose a CSV file"}</span>
          <input type="file" accept=".csv,text/csv" onChange={handleFile} />
        </label>

        {error && <div className="inline-error">{error}</div>}
      </div>

      {summary && (
        <>
          <div className="summary-grid">
            <div className="metric-card">
              <div className="metric-icon"><TrendingUp size={16} /></div>
              <span>Credits</span>
              <strong>{money(summary.credits)}</strong>
            </div>
            <div className="metric-card">
              <div className="metric-icon"><TrendingDown size={16} /></div>
              <span>Debits</span>
              <strong>{money(summary.debits)}</strong>
            </div>
            <div className="metric-card">
              <div className="metric-icon"><BarChart3 size={16} /></div>
              <span>Avg. spending</span>
              <strong>{money(summary.averageSpending)}</strong>
            </div>
            <div className="metric-card">
              <div className="metric-icon"><CheckCircle2 size={16} /></div>
              <span>Rows analyzed</span>
              <strong>{summary.rowsAnalyzed}</strong>
            </div>
          </div>

          <div className="panel">
            <div className="section-title compact">
              <div>
                <h2>Spending signal</h2>
                <p>Monthly trends derived only from the uploaded file.</p>
              </div>
            </div>

            <div className="trend-grid">
              <div>
                <h3>Spending trend</h3>
                <ul className="trend-list">
                  {summary.spendingTrend.length ? summary.spendingTrend.map((point) => (
                    <li key={point.label}><span>{point.label}</span><strong>{money(point.value)}</strong></li>
                  )) : <li><span>No data</span><strong>—</strong></li>}
                </ul>
              </div>
              <div>
                <h3>Incoming funds trend</h3>
                <ul className="trend-list">
                  {summary.incomingTrend.length ? summary.incomingTrend.map((point) => (
                    <li key={point.label}><span>{point.label}</span><strong>{money(point.value)}</strong></li>
                  )) : <li><span>No data</span><strong>—</strong></li>}
                </ul>
              </div>
            </div>
          </div>

          <div className="panel">
            <div className="section-title compact">
              <div>
                <h2>Beneficiary concentration</h2>
                <p>Top counterparties and cumulative concentration of debit volume.</p>
              </div>
            </div>
            <div className="analysis-grid">
              <div>
                <h3>Top credit beneficiaries</h3>
                <ul className="analysis-list">
                  {summary.topCreditBeneficiaries.length ? summary.topCreditBeneficiaries.map((entry) => (
                    <li key={entry.label}><span>{entry.label}</span><strong>{money(entry.total)}</strong></li>
                  )) : <li><span>No credit flows</span><strong>—</strong></li>}
                </ul>
              </div>
              <div>
                <h3>Top debit beneficiaries</h3>
                <ul className="analysis-list">
                  {summary.topDebitBeneficiaries.length ? summary.topDebitBeneficiaries.map((entry) => (
                    <li key={entry.label}><span>{entry.label}</span><strong>{money(entry.total)}</strong></li>
                  )) : <li><span>No debit flows</span><strong>—</strong></li>}
                </ul>
              </div>
            </div>
            <div className="concentration-box">
              <span>Top 3 beneficiary concentration</span>
              <strong>{safePercentage(summary.beneficiaryConcentration)}</strong>
            </div>
          </div>

          <div className="panel">
            <div className="section-title compact">
              <div>
                <h2>Operational summary</h2>
                <p>Sanitized device and geography grouping only.</p>
              </div>
            </div>
            <div className="analysis-grid">
              <div>
                <h3><Smartphone size={15} /> Device summary</h3>
                <ul className="analysis-list">
                  {summary.deviceSummary.length ? summary.deviceSummary.map((entry) => (
                    <li key={entry.label}><span>{entry.label}</span><strong>{money(entry.total)}</strong></li>
                  )) : <li><span>No device data</span><strong>—</strong></li>}
                </ul>
              </div>
              <div>
                <h3><Globe2 size={15} /> Geographic summary</h3>
                <ul className="analysis-list">
                  {summary.geographicSummary.length ? summary.geographicSummary.map((entry) => (
                    <li key={entry.label}><span>{entry.label}</span><strong>{money(entry.total)}</strong></li>
                  )) : <li><span>No geography data</span><strong>—</strong></li>}
                </ul>
              </div>
            </div>
          </div>
        </>
      )}
    </section>
  );
}
