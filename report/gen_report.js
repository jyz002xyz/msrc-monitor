/**
 * gen_report.js — state 駆動 + 解釈差し込み + テンプレート固定の docx 生成器
 *
 * 設計:
 *   - 事実（数値・表・チャート）は凍結 state/*.json から読む（ハードコードしない）。
 *   - 解釈（散文）は interpretation/{lang}.md から差し込む。
 *   - 日付分離ヘッダ / MSRC改訂注記 / §14中立性 / §13免責 はテンプレート固定
 *     （人間が解釈を編集しても必ず出る）。
 *
 * 使い方:  node gen_report.js --lang ja      -> drafts/report_ja.docx
 *          node gen_report.js --lang en      -> drafts/report_en.docx
 */
const {
  Document, Packer, Paragraph, TextRun, HeadingLevel, AlignmentType,
  Table, TableRow, TableCell, WidthType, BorderStyle, ShadingType,
  PageBreak, LevelFormat, ExternalHyperlink, ImageRun,
} = require("docx");
const fs = require("fs");
const path = require("path");

const HOME = process.env.MSRC_MONITOR_HOME || path.resolve(__dirname, "..");
const STATE = path.join(HOME, "state");
const MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul"];

// ---- 色・フォント ----------------------------------------------------------
const NAVY = "1F3864", ACCENT = "2E5496", GREY = "595959", LIGHT = "EEF2F8";
const REDBG = "F7E4E4", GREENBG = "E6F0E6", AMBERBG = "FBF3E2";
const RULE = { style: BorderStyle.SINGLE, size: 6, color: ACCENT };

// ---- 引数・言語 ------------------------------------------------------------
const argv = process.argv.slice(2);
const LANG = (argv[argv.indexOf("--lang") + 1] === "en") ? "en" : "ja";
const FONT = LANG === "ja" ? "Hiragino Sans" : "Arial";

// ===========================================================================
//  fixed templates (日英)。人間が解釈を編集しても消えない。
// ===========================================================================
const SNAPSHOT_DATE = "2026-07-15"; // 凍結スナップショット日 (state の snapshot_date)

const TPL = {
  ja: {
    reportKind: "技術レポート（機械生成の事実 + 人間の解釈）",
    headerTitle: "本レポートの構成と日付について",
    headerLines: (factsDate, interpDate) => [
      "本レポートは、自動監視スクリプトが生成した事実記録（数値・表・グラフ）に、人間の解釈を差し込んで構成される。",
      `事実データ取得日: ${factsDate}（スナップショットとして凍結）`,
      `解釈（本文分析）更新日: ${interpDate}`,
      "※事実は自動、解釈は人間が別途更新する。両者の日付が離れている場合は、解釈が最新の事実を反映していない可能性がある。",
    ],
    revisionTitle: "MSRC の事後改訂について",
    revisionLines: [
      "本レポートは 2026-07-15 確定値に基づく。MSRC は過去月を事後改訂しており（例：6月 CVE 1281→1205）、改訂後データでは異なる結果に見える場合がある。改訂記録は別途保持。",
    ],
    disclaimerTitle: "【免責・出典】",
    disclaimerLines: (factsDate) => [
      "本レポートは、脆弱性対応にあたる実務者を投影した仮想的な書き手による非公式な分析であり、特定の個人・組織の見解ではない。",
      "事実データの出典：Microsoft MSRC CVRF、CISA KEV、その他公開情報。",
      "分析の生成には AI（大規模言語モデル）を用いている。事実は可能な範囲で検証しているが、正確性・完全性を保証しない。重要な判断は一次情報で確認すること。",
      "事実は自動更新されるが解釈は随時更新であり、両者の日付が離れている場合がある（ヘッダ参照）。",
      `鮮度：本レポートの事実は ${factsDate} 時点。KEV や PoC 状況は時々刻々変わるため、最新は一次情報を参照。`,
    ],
    neutralityTitle: "【中立性に関する注記】",
    neutralityLines: [
      "本レポートの分析生成には Anthropic 社の AI（Claude）を用いている。本レポートは同社の Project Glasswing 等に言及するが、これは公開情報に基づく中立的な記述を意図したものであり、特定企業を推奨・擁護するものではない。読者は一次情報に当たり、独自に判断されたい。",
    ],
    dataSectionTitle: "実データ内訳 — 2026年7月 Patch Tuesday",
    dataSectionLead: "以下は MSRC CVRF v3.0 から取得した一次データの集計である（凍結スナップショット 2026-07-15）。母集団は「CVRF全体」と、Edge/Chromium・Mariner(Azure Linux)・Azureクラウドを除いた「MS本体相当」を併記する。",
    trendSectionTitle: "過去データとの比較 — 2026年1月〜7月の推移",
    tbl1Title: "表1. 深刻度別（母集団2種の併記）",
    tbl1Head: ["深刻度", "CVRF全体", "(%)", "MS本体相当", "(%)"],
    tbl2Title: "表2. 再起動クラス別（実務負荷の軸）",
    tbl2Head: ["クラス", "内容", "CVRF全体", "MS本体相当"],
    tbl2Desc: { "T3": "段階展開必須（Boot/Crypto）", "T2": "変更管理・メンテ枠が必要", "T0/T1": "自動更新・定常パイプライン" },
    tbl3Title: "表3. 発見者大分類（CVRF全体）",
    tbl3Head: ["区分", "件数", "(%)", "備考"],
    tbl4Title: "表4. Critical脆弱性の発見者内訳（集約・実名なし）",
    tbl4Head: ["発見主体", "Critical件数", "傾向"],
    tbl4Labels: {
      external: "外部研究者（実名）", anonymous: "匿名（Anonymous）",
      uncredited: "クレジット無し", ms_internal: "社内（ACS/WARP/MORSE等）",
      hash_anon: "ハッシュ識別子",
    },
    tbl4Trend: {
      external: "Criticalの多数派", anonymous: "", uncredited: "自動化の可能性（断定せず）",
      ms_internal: "少数（Networking/Hyper-V中心）", hash_anon: "",
    },
    tbl4KugelLabel: "Kugelblitz（Edge・参考）", tbl4KugelTrend: "Criticalには出現しない（面のみ）",
    tbl4Note: "件数のみ（個人実名は事実データに保存しない）。上4〜5行はバケット別で合計=Critical総数。Kugelblitz 行は横断参考（加算しない）。個別の研究者名・CVE例は解釈側に散文で記載。",
    tbl5Title: "表5. 製品カテゴリ別（CVRF全体）",
    tbl5Head: ["カテゴリ", "件数", "(%)"],
    trendTblTitle: "推移表（取得ラグに頑健な実数のみ）",
    trendHead: ["月", "CVE全体", "CVE本体", "Critical", "重い層(T2+T3)", "Kugelblitz", "社内(MS)"],
    total: "合計", monthName: (m) => `${MONTHS.indexOf(m) + 1}月`,
    finderLabels: {
      uncredited: ["クレジット無し", "自動化を含む可能性（断定不可）"],
      external: ["外部研究者（実名）", "実名の外部発見者"],
      anonymous: ["匿名（Anonymous）", "名乗り出た匿名"],
      ms_internal: ["社内（with Microsoft等）", "Kugelblitz/MORSE/WARP・ACS等を含む"],
      hash_anon: ["ハッシュ識別子", "MSが匿名化した識別子（正体不明）"],
    },
    finderOrder: ["uncredited", "external", "anonymous", "ms_internal", "hash_anon"],
    chartCaptions: ["図1: 総CVE件数の推移（CVRF全体 / MS本体相当）",
      "図2: Critical件数・重い層(T2+T3)の推移", "図3: クレジット「Kugelblitz」の月次出現",
      "図4: 社内(with Microsoft系)クレジット件数の推移"],
    apxHint: "（凍結スナップショット時点で未取得のため、過去月の詳細内訳は本表に含めない。）",
    kevEpssTitle: "KEV / EPSS — 即応の優先度づけ",
    kevEpssLead: "以下は対象CVE（T2/T3 ∨ Critical ∨ 外部研究者クレジット）を CISA KEV・FIRST EPSS と照合した結果。KEV = 悪用確認の離散的事実（通知トリガー）。EPSS = 悪用確率の推定（取得時点の値・日々変動・参考）。数値から発見主体・因果は断定しない。",
    kevTitle: "即応対象 — CISA KEV 収載（取得 {asof}）",
    kevHead: ["CVE", "製品名", "深刻度", "再起動クラス"],
    kevNone: "現時点で、対象CVEに CISA KEV 収載はない。",
    kevUnavail: "KEV 未取得（到達不能）。",
    epssTitle: "EPSS 上位 — 悪用確率の推定（取得時点 {asof}）",
    epssHead: ["CVE", "製品カテゴリ", "EPSS", "パーセンタイル"],
    epssNote: "※EPSS は毎日更新され値が変動する。上表は取得時点（{asof}）のスナップショットであり、単独のトレンド指標として用いない。通知トリガーには KEV のみを使う（EPSS は使わない）。",
    epssUnavail: "EPSS 未取得（到達不能）。",
    productSrc: "※製品名（KEV表）・製品カテゴリ（EPSS表）は CVRF（2026-07-15 凍結スナップショット）由来。KEV 収載状況・EPSS 値とは別ソース・別時点である。カテゴリは表5と同一の分類による。製品名/カテゴリの数値から発見主体・因果は断定しない。",
    prodUnknown: "—",
    enrichAbsent: "KEV/EPSS enrichment は未生成（enrich.py 未実行、またはオフライン）。本節は取得後に反映される。",
  },
  en: {
    reportKind: "Technical report (machine-generated facts + human interpretation)",
    headerTitle: "About this report's structure and dates",
    headerLines: (factsDate, interpDate) => [
      "This report is composed by injecting human interpretation into a factual record (figures, tables, charts) generated by an automated monitoring script.",
      `Fact data acquired: ${factsDate} (frozen as a snapshot)`,
      `Interpretation (analysis) updated: ${interpDate}`,
      "Note: facts are automatic, interpretation is updated separately by a human. If the two dates are far apart, the interpretation may not reflect the latest facts.",
    ],
    revisionTitle: "On MSRC's after-the-fact revisions",
    revisionLines: [
      "This report is based on values finalized on 2026-07-15. MSRC revises past months after the fact (e.g., June CVE 1281→1205), so post-revision data may appear to give different results. Revision records are retained separately.",
    ],
    disclaimerTitle: "[Disclaimer / Sources]",
    disclaimerLines: (factsDate) => [
      "This report is an informal analysis by a hypothetical author projecting a practitioner responsible for vulnerability response; it is not the view of any specific individual or organization.",
      "Fact data sources: Microsoft MSRC CVRF, CISA KEV, and other public information.",
      "The analysis is generated with AI (a large language model). Facts are verified where possible, but accuracy and completeness are not guaranteed. Confirm important judgments against primary sources.",
      "Facts are auto-updated but interpretation is updated as needed; the two dates may be far apart (see header).",
      `Freshness: the facts in this report are as of ${factsDate}. KEV and PoC status change moment to moment; consult primary sources for the latest.`,
    ],
    neutralityTitle: "[Note on neutrality]",
    neutralityLines: [
      "This report's analysis is generated using Anthropic's AI (Claude). The report refers to that company's Project Glasswing and the like, but this is intended as neutral description based on public information and does not endorse or advocate for any specific company. Readers should consult primary sources and judge independently.",
    ],
    dataSectionTitle: "Primary-data breakdown — July 2026 Patch Tuesday",
    dataSectionLead: "The following is a tally of primary data acquired from MSRC CVRF v3.0 (frozen snapshot 2026-07-15). The population is shown both as 'full CVRF' and as 'core Microsoft products' (excluding Edge/Chromium, Mariner (Azure Linux), and Azure cloud).",
    trendSectionTitle: "Comparison with historical data — the January–July 2026 trend",
    tbl1Title: "Table 1. By severity (two populations shown)",
    tbl1Head: ["Severity", "Full CVRF", "(%)", "Core MS products", "(%)"],
    tbl2Title: "Table 2. By reboot class (the operational-workload axis)",
    tbl2Head: ["Class", "Description", "Full CVRF", "Core MS products"],
    tbl2Desc: { "T3": "Staged rollout required (Boot/Crypto)", "T2": "Requires change management / maintenance window", "T0/T1": "Auto-update / steady pipeline" },
    tbl3Title: "Table 3. Finder major categories (full CVRF)",
    tbl3Head: ["Category", "Count", "(%)", "Note"],
    tbl4Title: "Table 4. Finder breakdown of Critical vulnerabilities (aggregated, no names)",
    tbl4Head: ["Discoverer", "Critical count", "Tendency"],
    tbl4Labels: {
      external: "External researchers (named)", anonymous: "Anonymous",
      uncredited: "Uncredited", ms_internal: "Internal (ACS/WARP/MORSE)",
      hash_anon: "Hash identifier",
    },
    tbl4Trend: {
      external: "Majority of Critical", anonymous: "", uncredited: "Possibly automation (not asserted)",
      ms_internal: "Few (mainly Networking/Hyper-V)", hash_anon: "",
    },
    tbl4KugelLabel: "Kugelblitz (Edge, ref.)", tbl4KugelTrend: "Does not appear in Critical (surface only)",
    tbl4Note: "Counts only (no personal names stored in the fact data). The top rows are per-bucket and sum to the Critical total. The Kugelblitz row is a cross-cutting reference (not additive). Individual researcher names and CVE examples are given as prose in the interpretation.",
    tbl5Title: "Table 5. By product category (full CVRF)",
    tbl5Head: ["Category", "Count", "(%)"],
    trendTblTitle: "Trend table (only real numbers robust to acquisition lag)",
    trendHead: ["Month", "CVE full", "CVE core", "Critical", "Heavy(T2+T3)", "Kugelblitz", "Internal(MS)"],
    total: "Total", monthName: (m) => m,
    finderLabels: {
      uncredited: ["Uncredited", "May include automation (not asserted)"],
      external: ["External researchers (named)", "Named external finders"],
      anonymous: ["Anonymous", "Self-identified anonymous"],
      ms_internal: ["Internal (with Microsoft etc.)", "Includes Kugelblitz/MORSE/WARP/ACS"],
      hash_anon: ["Hash identifier", "MS-anonymized identifier (identity unknown)"],
    },
    finderOrder: ["uncredited", "external", "anonymous", "ms_internal", "hash_anon"],
    chartCaptions: ["Fig 1: Total CVE count trend (full CVRF / core Microsoft products)",
      "Fig 2: Critical count and heavy tier (T2+T3) trend", "Fig 3: Monthly appearance of the credit \"Kugelblitz\"",
      "Fig 4: Internal (\"with Microsoft\") credit count trend"],
    apxHint: "(Not acquired at the frozen-snapshot time, so past-month detailed breakdowns are not included in this table.)",
    kevEpssTitle: "KEV / EPSS — prioritizing immediate response",
    kevEpssLead: "The following cross-references the target CVEs (T2/T3 ∨ Critical ∨ external-researcher credit) against CISA KEV and FIRST EPSS. KEV = a discrete fact of confirmed exploitation (the notification trigger). EPSS = an estimate of exploitation probability (a point-in-time value, changes daily, for reference). No discoverer or causation is asserted from these numbers.",
    kevTitle: "Immediate-response targets — listed in CISA KEV (as of {asof})",
    kevHead: ["CVE", "Product", "Severity", "Reboot class"],
    kevNone: "At this time, none of the target CVEs are listed in CISA KEV.",
    kevUnavail: "KEV not acquired (unreachable).",
    epssTitle: "Top EPSS — estimated exploitation probability (as of {asof})",
    epssHead: ["CVE", "Product category", "EPSS", "Percentile"],
    epssNote: "Note: EPSS is updated daily and its values change. The table above is a point-in-time snapshot (as of {asof}) and is not used as a standalone trend metric. Only KEV is used as a notification trigger (EPSS is not).",
    epssUnavail: "EPSS not acquired (unreachable).",
    productSrc: "Note: product names (KEV table) and product categories (EPSS table) are sourced from the CVRF (2026-07-15 frozen snapshot) — a separate source and point in time from KEV listing status and EPSS values. Categories use the same classification as Table 5. No discoverer or causation is asserted from these product names/categories.",
    prodUnknown: "—",
    enrichAbsent: "KEV/EPSS enrichment not generated (enrich.py not run, or offline). This section is populated after acquisition.",
  },
};
const L = TPL[LANG];

// ===========================================================================
//  docx ヘルパ
// ===========================================================================
const run = (text, o = {}) => new TextRun({ text, font: FONT, size: 20, ...o });
function h1(text) {
  return new Paragraph({ heading: HeadingLevel.HEADING_1, spacing: { before: 260, after: 140 }, border: { bottom: RULE },
    children: [new TextRun({ text, bold: true, size: 28, color: NAVY, font: FONT })] });
}
function h2(text) {
  return new Paragraph({ heading: HeadingLevel.HEADING_2, spacing: { before: 200, after: 100 },
    children: [new TextRun({ text, bold: true, size: 23, color: ACCENT, font: FONT })] });
}
function h3(text) {
  return new Paragraph({ heading: HeadingLevel.HEADING_3, spacing: { before: 140, after: 80 },
    children: [new TextRun({ text, bold: true, size: 21, color: ACCENT, font: FONT })] });
}
function body(runs, o = {}) {
  return new Paragraph({ spacing: { after: 120, line: 288 },
    children: Array.isArray(runs) ? runs : [new TextRun({ text: runs, size: 20, font: FONT, color: "222222" })], ...o });
}
function bullet(runs, level = 0) {
  return new Paragraph({ numbering: { reference: "bul", level }, spacing: { after: 80, line: 276 },
    children: Array.isArray(runs) ? runs : [run(runs)] });
}
function numbered(runs) {
  return new Paragraph({ numbering: { reference: "ol", level: 0 }, spacing: { after: 80, line: 276 },
    children: Array.isArray(runs) ? runs : [run(runs)] });
}
function link(text, url) {
  return new ExternalHyperlink({ link: url, children: [new TextRun({ text, style: "Hyperlink", size: 18, font: FONT })] });
}
function spacer() { return new Paragraph({ spacing: { after: 80 }, children: [] }); }
function pageBreak() { return new Paragraph({ children: [new PageBreak()] }); }

function callout(title, lineChildren, bg) {
  const edge = bg === REDBG ? "C0504D" : bg === GREENBG ? "4F7A4F" : bg === AMBERBG ? "BF9000" : ACCENT;
  const kids = [];
  if (title) kids.push(new Paragraph({ spacing: { after: 60 }, children: [new TextRun({ text: title, bold: true, size: 20, font: FONT, color: NAVY })] }));
  lineChildren.forEach(lc => kids.push(new Paragraph({ spacing: { after: 40, line: 264 },
    children: Array.isArray(lc) ? lc : [new TextRun({ text: lc, size: 19, font: FONT, color: "222222" })] })));
  const b = (c) => ({ style: BorderStyle.SINGLE, size: 2, color: c });
  return new Table({ width: { size: 100, type: WidthType.PERCENTAGE }, columnWidths: [9360],
    borders: { top: b(edge), bottom: b(edge), left: b(edge), right: b(edge), insideHorizontal: { style: BorderStyle.NONE }, insideVertical: { style: BorderStyle.NONE } },
    rows: [new TableRow({ children: [new TableCell({ shading: { type: ShadingType.CLEAR, fill: bg }, margins: { top: 100, bottom: 100, left: 160, right: 160 }, width: { size: 9360, type: WidthType.DXA }, children: kids })] })] });
}

function table(headers, rows, widths) {
  const headerRow = new TableRow({ tableHeader: true, children: headers.map((htext, i) => new TableCell({
    shading: { type: ShadingType.CLEAR, fill: NAVY }, margins: { top: 60, bottom: 60, left: 90, right: 90 }, width: { size: widths[i], type: WidthType.DXA },
    children: [new Paragraph({ children: [new TextRun({ text: htext, bold: true, color: "FFFFFF", size: 18, font: FONT })] })] })) });
  const bodyRows = rows.map((r, ri) => new TableRow({ children: r.map((cell, i) => new TableCell({
    shading: { type: ShadingType.CLEAR, fill: ri % 2 ? "FFFFFF" : LIGHT }, margins: { top: 50, bottom: 50, left: 90, right: 90 }, width: { size: widths[i], type: WidthType.DXA },
    children: (Array.isArray(cell) ? cell : [cell]).map(lineText => new Paragraph({ children: [new TextRun({ text: String(lineText), size: 17, font: FONT, color: "222222" })] })) })) }));
  return new Table({ width: { size: 100, type: WidthType.PERCENTAGE }, columnWidths: widths,
    borders: { top: RULE, bottom: RULE, left: RULE, right: RULE, insideHorizontal: { style: BorderStyle.SINGLE, size: 2, color: "BBBBBB" }, insideVertical: { style: BorderStyle.SINGLE, size: 2, color: "BBBBBB" } },
    rows: [headerRow, ...bodyRows] });
}

function chartImg(p, w, h) {
  return new Paragraph({ alignment: AlignmentType.CENTER, spacing: { before: 80, after: 60 },
    children: [new ImageRun({ type: "png", data: fs.readFileSync(p), transformation: { width: w, height: h } })] });
}
function caption(text) {
  return new Paragraph({ alignment: AlignmentType.CENTER, spacing: { after: 160 },
    children: [new TextRun({ text, size: 16, italics: true, color: GREY, font: FONT })] });
}

// ===========================================================================
//  state (事実) の読み込み
// ===========================================================================
function loadState(m) { return JSON.parse(fs.readFileSync(path.join(STATE, `2026-${m}.json`), "utf8")); }
const JUL = loadState("Jul");

// KEV/EPSS ライブ層 (gitignore・別ファイル)。無ければ null (未生成/オフライン)。
function loadEnrichment() {
  const p = path.join(STATE, "enrichment.json");
  if (!fs.existsSync(p)) return null;
  try { return JSON.parse(fs.readFileSync(p, "utf8")); } catch { return null; }
}

function pct(n, d) { return d ? `${Math.round((n / d) * 100)}%` : "-"; }

// 製品カテゴリの言語中立な内部キー <-> 日英表示ラベルの単一マップ (cvrf_parse と共有)。
// 描画は必ずこのマップ経由 (虫食い置換を防ぎ、英語版に日本語を出さない)。
const CATMAP = JSON.parse(fs.readFileSync(path.join(__dirname, "category_labels.json"), "utf8"));
// 内部キー、または凍結 state/enrichment に残る旧表示名を受け取り、LANG の表示ラベルを返す。
// 旧表示名は legacy_aliases で内部キーへ正規化してから引く。未登録なら raw を返す
// (内部キーは英数字なので、最悪でも英数字が出るだけで日本語は漏れない。未登録はテストで検出)。
function catLabel(raw) {
  if (raw == null || raw === "") return raw;
  const key = CATMAP.legacy_aliases[raw] || raw;
  const entry = CATMAP.labels[key];
  return entry ? entry[LANG] : raw;
}

// KEV表用: CVRF タイトル(凍結由来)から末尾の脆弱性種別句を落とし製品名/コンポーネント名を出す。
// 例: "Microsoft SharePoint Server Elevation of Privilege Vulnerability" -> "Microsoft SharePoint Server"。
// 落とせない/空なら元タイトル、タイトル自体が無ければ "—" (graceful)。事実の表示のみ。
const VULN_SUFFIX = /\s+(?:Elevation of Privilege|Remote Code Execution|Information Disclosure|Denial of Service|Security Feature Bypass|Privilege Escalation|Cross-Site Scripting|Memory Corruption|Spoofing|Tampering)?\s*Vulnerability\s*$/i;
function productName(title, unknown) {
  if (!title) return unknown;
  const stripped = title.replace(VULN_SUFFIX, "").trim();
  return stripped || title;
}

// 表1: 深刻度別 (全体/本体)
function tableSeverity() {
  const order = ["Critical", "Important", "Moderate", "Low", "Unrated"];
  const all = JUL.severity_count, core = JUL.severity_core;
  const at = JUL.cve_total, ct = JUL.core_total;
  const rows = order.map(s => [s, String(all[s] || 0), pct(all[s] || 0, at), String(core[s] || 0), pct(core[s] || 0, ct)]);
  rows.push([L.total, String(at), "100%", String(ct), "100%"]);
  return table(L.tbl1Head, rows, [2160, 1800, 1200, 2160, 1200]);
}
// 表2: 再起動クラス (全体/本体)
function tableTier() {
  const all = JUL.tier_count, core = JUL.tier_core;
  const rows = ["T3", "T2", "T0/T1"].map(t => [t, L.tbl2Desc[t], String(all[t] || 0), String(core[t] || 0)]);
  return table(L.tbl2Head, rows, [1200, 3960, 1680, 1680]);
}
// 表3: 発見者大分類 (全体)
function tableFinder() {
  const fb = JUL.finder_bucket, tot = JUL.cve_total;
  const rows = L.finderOrder.map(k => {
    const [label, note] = L.finderLabels[k];
    return [label, String(fb[k] || 0), pct(fb[k] || 0, tot), note];
  });
  return table(L.tbl3Head, rows, [3000, 1200, 1080, 4080]);
}
// 表4: Critical の発見者内訳 (集約・実名なし)。件数のみを state から。
function tableCriticalFinder() {
  const cbf = JUL.critical_by_finder || {};
  const entries = Object.entries(cbf).sort((a, b) => b[1] - a[1]);
  const rows = entries.map(([k, v]) => [L.tbl4Labels[k] || k, String(v), L.tbl4Trend[k] || "—"]);
  // Kugelblitz は横断参考行 (加算しない)
  rows.push([L.tbl4KugelLabel, String(JUL.kugelblitz_in_critical || 0), L.tbl4KugelTrend]);
  return table(L.tbl4Head, rows, [3600, 1800, 3960]);
}

// 表5: 製品カテゴリ (全体) — 上位を件数降順で
function tableProduct() {
  const pc = JUL.product_count, tot = JUL.cve_total;
  const entries = Object.entries(pc).sort((a, b) => b[1] - a[1]);
  // 凍結 state のキーは旧表示名(その他/Edge/Chromium 等)。catLabel で LANG 表示へ変換。
  const rows = entries.map(([k, v]) => [catLabel(k), String(v), pct(v, tot)]);
  return table(L.tbl5Head, rows, [5000, 1600, 1600]);
}
// 推移表: 7ヶ月 × 6列 (凍結値)
function tableTrend() {
  const rows = MONTHS.map(m => {
    const d = loadState(m), t = d.tier_count || {};
    return [L.monthName(m), String(d.cve_total), String(d.core_total),
      String((d.severity_count || {}).Critical || 0),
      String((t.T2 || 0) + (t.T3 || 0)), String(d.kugelblitz || 0), String(d.ms_internal || 0)];
  });
  return table(L.trendHead, rows, [900, 1320, 1320, 1320, 1800, 1320, 1380]);
}

// ===========================================================================
//  interpretation/{lang}.md のパース
// ===========================================================================
function parseInline(text) {
  // **bold**, [text](url), `code` を TextRun 配列へ
  const out = [];
  let i = 0;
  const re = /(\*\*([^*]+)\*\*)|(\[([^\]]+)\]\(([^)]+)\))|(`([^`]+)`)/g;
  let m, last = 0;
  while ((m = re.exec(text)) !== null) {
    if (m.index > last) out.push(run(text.slice(last, m.index)));
    if (m[1]) out.push(run(m[2], { bold: true }));
    else if (m[3]) out.push(link(m[4], m[5]));
    else if (m[6]) out.push(new TextRun({ text: m[7], font: "Consolas", size: 18, color: "1F3864" }));
    last = re.lastIndex;
  }
  if (last < text.length) out.push(run(text.slice(last)));
  return out.length ? out : [run(text)];
}

function parseMd(mdPath) {
  const lines = fs.readFileSync(mdPath, "utf8").split("\n");
  const title = {}; let footer = null;
  const sections = []; // {heading, lead:[], subs:[{key,nodes:[]}]}
  let cur = null, curSub = null, tableBuf = null;

  const pushTable = (target) => { if (tableBuf) { target.push({ type: "table", rows: tableBuf }); tableBuf = null; } };
  const target = () => curSub ? curSub.nodes : (cur ? cur.lead : null);

  for (let raw of lines) {
    const line = raw.replace(/\r$/, "");
    if (line.startsWith("<!--") || line.trim() === "-->" || (line.trim() === "")) {
      if (line.trim() === "") { const t = target(); if (t) pushTable(t); }
      continue;
    }
    let mt;
    if ((mt = line.match(/^# title:(.+)/))) { title[mt[1].trim()] = ""; lastTitleKey = mt[1].trim(); continue; }
    // タイトル本文行 (title: 見出しの直後の非見出し行)
    if ((mt = line.match(/^## (.+)/))) { pushTable(target()); cur = { heading: mt[1].trim(), lead: [], subs: [] }; curSub = null; sections.push(cur); continue; }
    if ((mt = line.match(/^#### callout:(.+)/)) || (mt = line.match(/^### callout:(.+)/))) {
      pushTable(target()); curSub = { key: "callout:" + mt[1].trim(), nodes: [], callout: mt[1].trim() }; cur.subs.push(curSub); continue;
    }
    if ((mt = line.match(/^### table:(.+)/))) { pushTable(target()); curSub = { key: "table:" + mt[1].trim(), nodes: [], qtable: mt[1].trim() }; cur.subs.push(curSub); continue; }
    if ((mt = line.match(/^### footer:(.+)/))) { pushTable(target()); curSub = { key: "footer", nodes: [], footer: true }; cur.subs.push(curSub); continue; }
    if ((mt = line.match(/^#### (.+)/)) || (mt = line.match(/^### (.+)/))) { pushTable(target()); curSub = { key: mt[1].trim(), nodes: [], sub: true }; cur.subs.push(curSub); continue; }
    if (line.startsWith("# ") && cur === null) { continue; }

    const t = target();
    if (t === null) {
      // title 本文
      if (typeof lastTitleKey === "string") { title[lastTitleKey] = (title[lastTitleKey] ? title[lastTitleKey] + " " : "") + line.trim(); }
      continue;
    }
    if (line.startsWith("|")) {
      const cells = line.split("|").slice(1, -1).map(c => c.trim());
      if (cells.every(c => /^-+$/.test(c) || c === "")) continue; // separator
      if (!tableBuf) tableBuf = [];
      tableBuf.push(cells);
      continue;
    }
    pushTable(t);
    if (line.startsWith("- ")) t.push({ type: "bullet", text: line.slice(2).trim() });
    else if (/^\d+\.\s/.test(line)) t.push({ type: "num", text: line.replace(/^\d+\.\s/, "").trim() });
    else t.push({ type: "para", text: line.trim() });
  }
  pushTable(target());
  return { title, sections };
}
let lastTitleKey = null;

// md ノード配列を docx 要素へ
function renderNodes(nodes) {
  const out = [];
  for (const n of nodes) {
    if (n.type === "para") out.push(body(parseInline(n.text)));
    else if (n.type === "bullet") out.push(bullet(parseInline(n.text)));
    else if (n.type === "num") out.push(numbered(parseInline(n.text)));
    else if (n.type === "table") {
      const [head, ...rest] = n.rows;
      const widths = head.map(() => Math.floor(9360 / head.length));
      out.push(table(head, rest, widths));
      out.push(spacer());
    }
  }
  return out;
}
function renderSub(sub) {
  const out = [];
  if (sub.callout) out.push(callout(sub.callout, sub.nodes.filter(x => x.type === "bullet" || x.type === "para").map(x => parseInline(x.text)), LIGHT));
  else if (sub.footer) { out.push(new Paragraph({ border: { top: RULE }, spacing: { before: 120, after: 40 }, children: [] })); sub.nodes.forEach(x => out.push(body([run(x.text, { italics: true, size: 16, color: GREY })]))); }
  else {
    if (!sub.qtable) out.push(h3(sub.key));
    out.push(...renderNodes(sub.nodes));
  }
  return out;
}

// ===========================================================================
//  組み立て
// ===========================================================================
function build() {
  const mdPath = path.join(HOME, "interpretation", `${LANG}.md`);
  const { title, sections } = parseMd(mdPath);
  const factsDate = JUL.snapshot_date || SNAPSHOT_DATE;
  const interpDate = new Date(fs.statSync(mdPath).mtime).toISOString().slice(0, 10);

  const subtitle = title[LANG === "ja" ? "サブタイトル" : "Subtitle"] || Object.values(title)[0] || "";
  const audience = title[LANG === "ja" ? "想定読者" : "Intended readers"] || "";

  const children = [];

  // --- 表紙 ---
  children.push(new Paragraph({ spacing: { before: 200, after: 60 }, children: [run(L.reportKind, { size: 18, color: GREY })] }));
  children.push(new Paragraph({ spacing: { after: 40 }, children: [new TextRun({ text: LANG === "ja" ? "フロンティアAIによる脆弱性発見の急増" : "The surge in vulnerability discovery by frontier AI", bold: true, size: 34, color: NAVY, font: FONT })] }));
  children.push(new Paragraph({ spacing: { after: 160 }, border: { bottom: RULE }, children: [run(subtitle, { size: 22, color: ACCENT })] }));
  if (audience) children.push(new Paragraph({ spacing: { after: 30 }, children: [run(audience, { size: 18, color: GREY })] }));

  // --- テンプレート固定: 日付分離ヘッダ ---
  children.push(callout(L.headerTitle, L.headerLines(factsDate, interpDate).map(x => [run(x, { size: 19 })]), AMBERBG));
  children.push(spacer());
  // --- テンプレート固定: MSRC 改訂注記 ---
  children.push(callout(L.revisionTitle, L.revisionLines.map(x => [run(x, { size: 19 })]), AMBERBG));
  children.push(spacer());
  // --- テンプレート固定: §13 免責 + §14 中立性 ---
  children.push(callout(L.disclaimerTitle, L.disclaimerLines(factsDate).map(x => [run("• " + x, { size: 18 })]), GREENBG));
  children.push(spacer());
  children.push(callout(L.neutralityTitle, L.neutralityLines.map(x => [run(x, { size: 18 })]), GREENBG));

  // --- 本文: 解釈セクション (index ベース) ---
  // 0:要旨 1:分析 2:示唆 3:内訳要点 4:推移 5:別紙
  const S = sections;
  const emitSection = (idx, { withHeading = true } = {}) => {
    const sec = S[idx]; if (!sec) return;
    if (withHeading) children.push(h1(sec.heading));
    children.push(...renderNodes(sec.lead));
    for (const sub of sec.subs) children.push(...renderSub(sub));
  };

  emitSection(0); // 要旨
  emitSection(1); // 分析 (三層 table は table: サブで描画)
  emitSection(2); // 示唆

  // --- 実データ内訳 (facts + 要点 interp を交互に) ---
  children.push(pageBreak());
  children.push(h1(L.dataSectionTitle));
  children.push(body(L.dataSectionLead));
  children.push(spacer());
  const pts = S[3].subs; // 表1..表4..表5..補遺 の要点
  const factForPoint = { 0: [L.tbl1Title, tableSeverity()], 1: [L.tbl2Title, tableTier()], 2: [L.tbl3Title, tableFinder()], 4: [L.tbl5Title, tableProduct()] };
  for (let i = 0; i < pts.length; i++) {
    if (factForPoint[i]) { children.push(h2(factForPoint[i][0])); children.push(factForPoint[i][1]); }
    else if (i === 3) { children.push(h2(L.tbl4Title)); children.push(tableCriticalFinder()); children.push(body([run(L.tbl4Note, { italics: true, color: GREY, size: 16 })])); }
    children.push(...renderSub(pts[i])); // その表の要点 (解釈)
    children.push(spacer());
  }

  // --- 推移 (facts 推移表 + charts + 図解釈) ---
  children.push(pageBreak());
  children.push(h1(L.trendSectionTitle));
  children.push(...renderNodes(S[4].lead)); // 推移の導入文 (解釈)
  children.push(h2(L.trendTblTitle));
  children.push(tableTrend());
  children.push(spacer());
  const chartFiles = ["chart1_cve.png", "chart2_critical.png", "chart3_kugelblitz.png", "chart4_internal.png"];
  const trendSubs = S[4].subs; // 図1..図4 解釈 + callout要約
  for (let i = 0; i < 4; i++) {
    const cp = path.join(__dirname, "assets", LANG, chartFiles[i]);
    if (fs.existsSync(cp)) { children.push(chartImg(cp, 452, 226)); children.push(caption(L.chartCaptions[i])); }
    if (trendSubs[i]) children.push(...renderSub(trendSubs[i]));
  }
  if (trendSubs[4]) children.push(...renderSub(trendSubs[4])); // callout 要約

  // --- KEV / EPSS (Phase 2)。事実(数値・時点)のみ。KEV=トリガー・EPSS=参考(時点付き) ---
  children.push(pageBreak());
  children.push(h1(L.kevEpssTitle));
  const enr = loadEnrichment();
  if (!enr) {
    children.push(body(L.enrichAbsent));
  } else {
    children.push(body(L.kevEpssLead));
    // KEV: 即応対象 (離散事実)
    const kevAsof = enr.kev_asof ? String(enr.kev_asof).slice(0, 10) : "-";
    children.push(h2(L.kevTitle.replace("{asof}", kevAsof)));
    // 製品名(具体)・カテゴリは target_cves の title/category (CVRF凍結由来。KEV/EPSS値とは別ソース)。
    const byCve = Object.fromEntries((enr.target_cves || []).map(t => [t.cve, t]));
    if (enr.kev_listed === null) {
      children.push(body(L.kevUnavail));
    } else if (!enr.kev_listed.length) {
      children.push(body(L.kevNone));
    } else {
      // KEV表: CVE / 製品名(具体) / 深刻度 / 再起動クラス(tier)
      const rows = enr.kev_listed.map(c => {
        const t = byCve[c] || {};
        return [c, productName(t.title, L.prodUnknown), t.severity || "-", t.tier || "-"];
      });
      children.push(table(L.kevHead, rows, [2600, 3760, 1900, 1900]));
    }
    children.push(spacer());
    // EPSS: 参考 (取得時点付き・日々変動)。通知には使わない。
    const epssAsof = enr.epss_asof || "-";
    children.push(h2(L.epssTitle.replace("{asof}", epssAsof)));
    if (!enr.epss) {
      children.push(body(L.epssUnavail));
    } else {
      // EPSS表: CVE / 製品カテゴリ / EPSS / パーセンタイル
      const top = Object.entries(enr.epss).sort((a, b) => b[1].epss - a[1].epss).slice(0, 15);
      const rows = top.map(([c, s]) => {
        const rawCat = (byCve[c] || {}).category;
        const cat = rawCat ? catLabel(rawCat) : L.prodUnknown;  // 内部キー -> LANG 表示
        // epss は小数(確率値)のまま。percentile は表示時のみ % 整形(小数1桁)。内部値は不変。
        return [c, cat, Number(s.epss).toFixed(4), (Number(s.percentile) * 100).toFixed(1) + "%"];
      });
      children.push(table(L.epssHead, rows, [2600, 3760, 1900, 1900]));
      children.push(body([run(L.epssNote.replace(/\{asof\}/g, epssAsof), { italics: true, color: GREY, size: 16 })]));
    }
    // 製品名/カテゴリの出所注記 (凍結CVRF・別ソース別時点。既存の日付分離の思想と同じ)
    children.push(body([run(L.productSrc, { italics: true, color: GREY, size: 16 })]));
  }

  // --- 別紙 ---
  children.push(pageBreak());
  emitSection(5);
  // footer サブ (別紙内の footer: がある場合 renderSub で処理済み)

  const doc = new Document({
    numbering: { config: [
      { reference: "bul", levels: [{ level: 0, format: LevelFormat.BULLET, text: "•", alignment: AlignmentType.LEFT, style: { paragraph: { indent: { left: 360, hanging: 220 } }, run: { font: FONT } } }] },
      { reference: "ol", levels: [{ level: 0, format: LevelFormat.DECIMAL, text: "%1.", alignment: AlignmentType.LEFT, style: { paragraph: { indent: { left: 400, hanging: 260 } }, run: { font: FONT } } }] },
    ] },
    styles: { default: { document: { run: { font: FONT, size: 20 } } } },
    // メタデータに個人名・組織名を入れない (匿名化)
    title: "Vulnerability situation report", creator: "Automated monitoring script", description: "Machine-generated facts with human interpretation",
    sections: [{ properties: { page: { margin: { top: 1000, bottom: 1000, left: 1100, right: 1100 } } }, children }],
  });

  const outDir = path.join(HOME, "drafts");
  fs.mkdirSync(outDir, { recursive: true });
  const outPath = path.join(outDir, `report_${LANG}.docx`);
  return Packer.toBuffer(doc).then(buf => { fs.writeFileSync(outPath, buf); console.log(`[gen_report] ${LANG}: ${buf.length} bytes -> ${outPath}`); return outPath; });
}

build().catch(e => { console.error(e); process.exit(1); });
