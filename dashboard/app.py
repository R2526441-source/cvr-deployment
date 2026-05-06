# ============================================================
# app.py — CVR Decision Support Dashboard
# ============================================================
import streamlit as st
import requests
import pandas as pd
import plotly.graph_objects as go
import plotly.express as px

# ── Configuration ─────────────────────────────────────────────
st.set_page_config(
    page_title="CVR — Vulnerability Decision Support",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ── Paste your Render URL here after deployment ───────────────
import os
API_URL = os.environ.get("API_URL", "https://cvr-deployment.onrender.com")   # update after Render deploy

# ── Colour scheme ─────────────────────────────────────────────
URGENT_COL = "#DC2626"
DEFER_COL  = "#16A34A"
MID_COL    = "#D97706"

# ── Helpers ───────────────────────────────────────────────────
def call_api(endpoint, payload):
    try:
        r = requests.post(f"{API_URL}/{endpoint}",
                          json=payload, timeout=30)
        r.raise_for_status()
        return r.json(), None
    except Exception as e:
        return None, str(e)

def score_badge(label):
    color = URGENT_COL if label == "URGENT" else DEFER_COL
    return f'<span style="background:{color};color:white;padding:4px 12px;border-radius:12px;font-weight:bold">{label}</span>'

# ── Sidebar: Enterprise Context ───────────────────────────────
st.sidebar.image(
    "https://img.icons8.com/color/96/shield.png",
    width=60
)
st.sidebar.title("🏢 Enterprise Context")
st.sidebar.markdown("Configure your organisation's profile. "
                    "The CVR model will use these values for every CVE scored.")

AC = st.sidebar.slider(
    "Asset Criticality (AC)", 1, 6, 3,
    help="1=non-critical → 6=mission-critical"
)
NE = st.sidebar.selectbox(
    "Network Exposure (NE)",
    options=[0, 1, 2],
    index=1,
    format_func=lambda x: {0:"Air-gapped",1:"Behind firewall",2:"Internet-facing"}[x]
)
TA = st.sidebar.slider(
    "Technology Age — years (TA)", 0.0, 15.0, 5.0, step=0.5,
    help="Years since the affected system was deployed"
)
CM = st.sidebar.selectbox(
    "Change Management Maturity (CM)",
    options=[1,2,3,4,5],
    index=1,
    format_func=lambda x: {
        1:"1 — Ad-hoc (no process)",
        2:"2 — Informal",
        3:"3 — Defined",
        4:"4 — Managed",
        5:"5 — Optimised (formal CAB)"
    }[x]
)
RO = st.sidebar.selectbox(
    "Regulatory Obligation (RO)",
    options=[0,1],
    format_func=lambda x: {0:"Not regulated",1:"Regulated"}[x]
)

context = {"AC":AC,"NE":NE,"TA":TA,"CM":CM,"RO":RO}

st.sidebar.markdown("---")
st.sidebar.markdown(
    "**Context profile summary**\n"
    f"- Criticality: {AC}/6\n"
    f"- Exposure: {['Air-gapped','Firewall','Internet'][NE]}\n"
    f"- System age: {TA}y {'⚠️ EOL risk' if TA>7 else '✅ Supported'}\n"
    f"- CM Maturity: {CM}/5\n"
    f"- Regulated: {'Yes' if RO else 'No'}"
)

# ── Main Area ─────────────────────────────────────────────────
st.title("🛡️ CVR — Contextual Vulnerability Ranking")
st.markdown(
    "**Real-time vulnerability prioritisation for resource-constrained enterprises.** "
    "Enter a CVE ID or paste a list below. The CVR model fuses live global threat "
    "intelligence with your organisation's context to produce an actionable priority ranking."
)

tab1, tab2, tab3, tab4 = st.tabs([
    "🔍 Score a CVE", "📋 Batch Triage",
    "📂 Risk Register Upload", "📊 About the Model"
])

# ── TAB 1: Single CVE ─────────────────────────────────────────
with tab1:
    st.subheader("Score a single CVE in real time")
    col1, col2 = st.columns([3, 1])
    with col1:
        cve_input = st.text_input(
            "CVE ID", value="CVE-2023-44487",
            placeholder="e.g. CVE-2023-44487"
        ).upper().strip()
    with col2:
        st.markdown("<br>", unsafe_allow_html=True)
        score_btn = st.button("⚡ Score Now", type="primary",
                              use_container_width=True)

    if score_btn and cve_input:
        with st.spinner(f"Fetching live data for {cve_input}..."):
            payload = {"cve_id": cve_input, **context}
            result, err = call_api("score", payload)

        if err:
            st.error(f"API error: {err}")
        elif result:
            st.markdown("---")

            # ── Score gauge ───────────────────────────────────
            col_a, col_b, col_c, col_d = st.columns(4)
            col_a.metric("CVR Score", f"{result['cvr_score']:.4f}")
            col_b.metric("CVSS Score", result.get('cvss_score','N/A'))
            col_c.metric("EPSS Score",
                         f"{result['epss_score']:.4f}",
                         f"p{result['epss_percentile']*100:.0f}")
            col_d.metric(
                "KEV Confirmed",
                "✅ YES" if result['kev_confirmed'] else "❌ No"
            )

            # ── Priority badge ────────────────────────────────
            label = result["priority_label"]
            col = URGENT_COL if label == "URGENT" else DEFER_COL
            st.markdown(
                f"<div style='background:{col};color:white;padding:20px;"
                f"border-radius:8px;text-align:center;margin:16px 0'>"
                f"<h2 style='margin:0;color:white'>CVR PRIORITY: {label}</h2>"
                f"<p style='margin:4px 0;opacity:0.9'>CVR Score: "
                f"{result['cvr_score']:.4f} | "
                f"Latency: {result.get('latency_ms','—')}ms</p></div>",
                unsafe_allow_html=True
            )

            # ── Score gauge chart ─────────────────────────────
            fig = go.Figure(go.Indicator(
                mode="gauge+number",
                value=result["cvr_score"],
                title={"text":"CVR Priority Score"},
                gauge={
                    "axis"  : {"range":[0,1]},
                    "bar"   : {"color": col},
                    "steps" : [
                        {"range":[0.0,0.35],"color":"#D1FAE5"},
                        {"range":[0.35,0.48],"color":"#FEF3C7"},
                        {"range":[0.48,1.0],"color":"#FEE2E2"},
                    ],
                    "threshold": {
                        "line":{"color":"red","width":4},
                        "thickness":0.75,
                        "value":0.4774
                    }
                }
            ))
            fig.update_layout(height=280, margin=dict(t=40,b=0,l=20,r=20))
            st.plotly_chart(fig, use_container_width=True)

            # ── Key drivers ───────────────────────────────────
            st.markdown("**🔑 Key Priority Drivers**")
            for driver in result.get("key_drivers",[]):
                icon = "🔴" if label=="URGENT" else "🟢"
                st.markdown(f"{icon} {driver}")

            # ── PoC warning ───────────────────────────────────
            if result.get("poc_available"):
                st.warning("⚠️ Public proof-of-concept exploit detected. "
                           "Treat as highest urgency regardless of CVSS score.")

# ── TAB 2: Batch Triage ───────────────────────────────────────
with tab2:
    st.subheader("Batch triage — paste your CVE inventory")
    st.markdown(
        "Enter one CVE ID per line. The model will score all of them "
        "using your organisation context from the sidebar and return a "
        "ranked remediation list."
    )

    default_cves = "\n".join([
        "CVE-2023-44487",
        "CVE-2021-44228",
        "CVE-2022-30190",
        "CVE-2023-23397",
        "CVE-2022-41082",
    ])
    cve_list_raw = st.text_area(
        "CVE IDs (one per line)", value=default_cves, height=180
    )
    batch_btn = st.button("⚡ Run Batch Triage", type="primary")

    if batch_btn:
        cve_ids = [c.strip().upper()
                   for c in cve_list_raw.strip().split("\n")
                   if c.strip()]

        if not cve_ids:
            st.warning("Please enter at least one CVE ID.")
        else:
            payload = {"items":[{"cve_id":c,**context} for c in cve_ids]}
            with st.spinner(f"Scoring {len(cve_ids)} CVEs..."):
                result, err = call_api("batch", payload)

            if err:
                st.error(f"API error: {err}")
            elif result:
                results = result.get("results",[])
                st.success(
                    f"✅ Scored {result['count']} CVEs in "
                    f"{result['latency_ms']}ms — ranked highest risk first."
                )

                # ── Summary metrics ───────────────────────────
                urgent = [r for r in results if r.get("priority")==1]
                defer  = [r for r in results if r.get("priority")==0]

                m1,m2,m3 = st.columns(3)
                m1.metric("Total CVEs", len(results))
                m2.metric("🔴 URGENT", len(urgent))
                m3.metric("🟢 DEFER",  len(defer))

                # ── Ranked table ──────────────────────────────
                df = pd.DataFrame([{
                    "Rank"      : i+1,
                    "CVE ID"    : r["cve_id"],
                    "CVR Score" : r.get("cvr_score","—"),
                    "Priority"  : r.get("priority_label","—"),
                    "EPSS"      : r.get("epss_score","—"),
                    "KEV"       : "✅" if r.get("kev_confirmed") else "❌",
                    "PoC"       : "✅" if r.get("poc_available") else "❌",
                    "CVSS"      : r.get("cvss_score","—"),
                } for i,r in enumerate(results)])

                def colour_row(row):
                    if row["Priority"] == "URGENT":
                        return [f"background-color:#FEE2E2"]*len(row)
                    return [""]*len(row)

                st.dataframe(
                    df.style.apply(colour_row, axis=1),
                    use_container_width=True, hide_index=True
                )

                # ── Priority breakdown bar chart ──────────────
                if results:
                    scores = [r.get("cvr_score",0) for r in results]
                    cve_labels = [r["cve_id"] for r in results]
                    colors = [URGENT_COL if r.get("priority")==1
                              else DEFER_COL for r in results]

                    fig2 = go.Figure(go.Bar(
                        x=cve_labels, y=scores,
                        marker_color=colors,
                        text=[f"{s:.3f}" for s in scores],
                        textposition="outside"
                    ))
                    fig2.add_hline(y=0.4774, line_dash="dash",
                                   line_color="red",
                                   annotation_text="Urgency threshold (p90)")
                    fig2.update_layout(
                        title="CVR Priority Scores — Ranked Inventory",
                        xaxis_title="CVE ID",
                        yaxis_title="CVR Score",
                        yaxis_range=[0,1.1],
                        height=400,
                        margin=dict(t=50,b=60)
                    )
                    st.plotly_chart(fig2, use_container_width=True)
# ── TAB 3: Risk Register Upload ───────────────────────────────
with tab3:
    st.subheader("📂 Upload Organisation Risk Register")
    st.markdown(
        "Upload your vulnerability scan export as a **CSV or Excel file**. "
        "The CVR model will score every CVE against your organisation context "
        "from the sidebar and return a fully ranked remediation list you can download."
    )

    # ── Template download ─────────────────────────────────────
    with st.expander("📥 Download upload template first"):
        st.markdown("Your file must have at least a `CVE_ID` column. "
                    "All other columns are optional and will be preserved.")
        template_df = pd.DataFrame({
            "CVE_ID"     : ["CVE-2023-44487","CVE-2021-44228","CVE-2022-30190"],
            "Asset_Name" : ["Web Server 01","ERP System","Workstation-05"],
            "Department" : ["IT","Finance","HR"],
            "Notes"      : ["Apache HTTP","Log4j","MSDT Follina"],
        })
        csv_template = template_df.to_csv(index=False)
        st.download_button(
            label="⬇️ Download CSV Template",
            data=csv_template,
            file_name="cvr_upload_template.csv",
            mime="text/csv"
        )
        st.dataframe(template_df, hide_index=True)

    st.markdown("---")

    # ── File uploader ─────────────────────────────────────────
    uploaded_file = st.file_uploader(
        "Upload your risk register",
        type=["csv", "xlsx", "xls"],
        help="CSV or Excel file with a CVE_ID column"
    )

    if uploaded_file:
        # ── Parse uploaded file ───────────────────────────────
        try:
            if uploaded_file.name.endswith(".csv"):
                upload_df = pd.read_csv(uploaded_file)
            else:
                upload_df = pd.read_excel(uploaded_file)
        except Exception as e:
            st.error(f"Could not read file: {e}")
            upload_df = None

        if upload_df is not None:
            # ── Find CVE ID column (flexible naming) ──────────
            cve_col = None
            for col in upload_df.columns:
                if col.upper().replace(" ","_") in [
                    "CVE_ID","CVE","CVEID","CVE_NUMBER","VULNERABILITY_ID"
                ]:
                    cve_col = col
                    break

            if not cve_col:
                st.error(
                    "❌ Could not find a CVE ID column. "
                    "Please name your CVE column: CVE_ID, CVE, or CVEID."
                )
            else:
                cve_list = upload_df[cve_col].dropna().str.strip().str.upper().tolist()
                # Remove duplicates, keep order
                seen = set()
                cve_list = [c for c in cve_list
                            if c.startswith("CVE-")
                            and not (c in seen or seen.add(c))]

                st.success(
                    f"✅ File loaded: **{len(upload_df)} rows**, "
                    f"**{len(cve_list)} valid CVE IDs** detected."
                )
                st.markdown(f"**Columns found:** {', '.join(upload_df.columns.tolist())}")
                st.dataframe(upload_df.head(5), hide_index=True)

                # ── Scoring button ────────────────────────────
                st.markdown("---")
                col_l, col_r = st.columns([2,1])
                with col_l:
                    st.markdown(
                        f"Ready to score **{len(cve_list)} CVEs** using your "
                        f"organisation context (AC={AC}, NE={['Air-gapped','Firewall','Internet'][NE]}, "
                        f"TA={TA}y, CM={CM}, RO={'Yes' if RO else 'No'})."
                    )
                with col_r:
                    run_btn = st.button(
                        "⚡ Run Prioritisation",
                        type="primary",
                        use_container_width=True
                    )

                if run_btn:
                    payload = {
                        "items": [
                            {"cve_id": c, "AC": AC, "NE": NE,
                             "TA": TA, "CM": CM, "RO": RO}
                            for c in cve_list
                        ]
                    }

                    progress = st.progress(0, text="Scoring CVEs...")
                    with st.spinner(
                        f"Fetching live NVD/EPSS/KEV data and scoring "
                        f"{len(cve_list)} CVEs — this may take up to "
                        f"{len(cve_list)*2} seconds..."
                    ):
                        result, err = call_api("batch", payload)
                        progress.progress(100, text="Complete!")

                    if err:
                        st.error(f"API error: {err}")
                    elif result:
                        results     = result.get("results", [])
                        latency     = result.get("latency_ms", "—")

                        # ── Build scored DataFrame ────────────
                        scored_df = pd.DataFrame([{
                            "CVE_ID"          : r["cve_id"],
                            "CVR_Score"       : r.get("cvr_score", 0),
                            "Priority"        : r.get("priority_label","—"),
                            "EPSS_Score"      : r.get("epss_score", 0),
                            "KEV_Confirmed"   : "YES" if r.get("kev_confirmed") else "No",
                            "PoC_Available"   : "YES" if r.get("poc_available") else "No",
                            "CVSS_Score"      : r.get("cvss_score","—"),
                            "Key_Drivers"     : " | ".join(r.get("key_drivers",[])),
                        } for r in results])

                        # Merge back with original upload columns
                        upload_df[cve_col] = (
                            upload_df[cve_col].str.strip().str.upper()
                        )
                        final_df = scored_df.merge(
                            upload_df.rename(columns={cve_col:"CVE_ID"}),
                            on="CVE_ID", how="left"
                        )

                        # ── Summary metrics ───────────────────
                        urgent = scored_df[scored_df["Priority"]=="URGENT"]
                        defer  = scored_df[scored_df["Priority"]=="DEFER"]
                        kev_ct = scored_df[scored_df["KEV_Confirmed"]=="YES"]

                        st.markdown("---")
                        st.subheader("🎯 Prioritised Remediation List")

                        m1,m2,m3,m4 = st.columns(4)
                        m1.metric("Total CVEs Scored", len(scored_df))
                        m2.metric("🔴 URGENT", len(urgent))
                        m3.metric("🟢 DEFER",  len(defer))
                        m4.metric("⚠️ KEV Confirmed", len(kev_ct))

                        st.markdown(
                            f"*Scored in {latency}ms — ranked highest risk first. "
                            f"Red rows require immediate attention.*"
                        )

                        # ── Styled results table ──────────────
                        def highlight_priority(row):
                            if row["Priority"] == "URGENT":
                                return ["background-color:#FEE2E2"]*len(row)
                            elif row["KEV_Confirmed"] == "YES":
                                return ["background-color:#FEF3C7"]*len(row)
                            return [""]*len(row)

                        st.dataframe(
                            final_df.style.apply(highlight_priority, axis=1),
                            use_container_width=True,
                            hide_index=True
                        )

                        # ── CVR score bar chart ───────────────
                        fig = go.Figure(go.Bar(
                            x=scored_df["CVE_ID"],
                            y=scored_df["CVR_Score"],
                            marker_color=[
                                URGENT_COL if p=="URGENT" else DEFER_COL
                                for p in scored_df["Priority"]
                            ],
                            text=scored_df["CVR_Score"].round(3),
                            textposition="outside"
                        ))
                        fig.add_hline(
                            y=0.4774, line_dash="dash",
                            line_color="red",
                            annotation_text="Urgency threshold"
                        )
                        fig.update_layout(
                            title="CVR Priority Scores — Your Vulnerability Inventory",
                            xaxis_title="CVE ID",
                            yaxis_title="CVR Score",
                            yaxis_range=[0,1.15],
                            height=420,
                            xaxis_tickangle=-45
                        )
                        st.plotly_chart(fig, use_container_width=True)

                        # ── Download buttons ──────────────────
                        st.markdown("---")
                        st.subheader("⬇️ Download Results")
                        col_a, col_b = st.columns(2)

                        with col_a:
                            csv_out = final_df.to_csv(index=False)
                            st.download_button(
                                label="📥 Download Full Results (CSV)",
                                data=csv_out,
                                file_name="cvr_prioritised_results.csv",
                                mime="text/csv",
                                use_container_width=True
                            )

                        with col_b:
                            urgent_csv = final_df[
                                final_df["Priority"]=="URGENT"
                            ].to_csv(index=False)
                            st.download_button(
                                label="🔴 Download URGENT Only (CSV)",
                                data=urgent_csv,
                                file_name="cvr_urgent_only.csv",
                                mime="text/csv",
                                use_container_width=True
                            )

                        st.info(
                            "💡 **How to use this list:** Address all RED rows "
                            "first — these are your highest-risk vulnerabilities. "
                            "Any CVE marked KEV Confirmed should be treated as "
                            "P1 regardless of your patching cycle. Share the "
                            "downloaded CSV with your IT team as your "
                            "prioritised work order."
                )
                        
# ── TAB 4: About ──────────────────────────────────────────────
with tab4:
    st.subheader("About the CVR Framework")
    st.markdown("""
    The **Contextual Vulnerability Ranking (CVR)** framework is a stacking
    ensemble machine-learning model that addresses the structural inadequacy
    of existing vulnerability scoring frameworks for resource-constrained
    enterprises in developing economies.

    ---
    **Architecture**
    - Base learners: Random Forest + XGBoost + LightGBM
    - Meta-learner: Logistic Regression
    - Training: Borderline-SMOTE balanced, 10-fold cross-validated

    **Performance vs Baselines (test set, n=2,000)**

    | Model | AUC-ROC | Workload Reduction |
    |---|---|---|
    | CVSS-Only (B1) | 0.7681 | 0.430 |
    | EPSS-Only (B2) | 0.7681 | 0.430 |
    | VMC Chain (B3) | 0.7684 | 0.420 |
    | SSVC (B4) | 0.8305 | 0.465 |
    | XGBoost Single (B5) | 0.9977 | 0.925 |
    | **CVR Ensemble** | **0.9974** | **0.920** |

    **CV AUC: 0.9988 ± 0.0004**

    ---
    **Global signals** fetched live at scoring time:
    - NVD CVSS v3.1 vectors
    - EPSS v3 exploitation probability (FIRST.org)
    - CISA KEV confirmed exploitation
    - PoC availability (exploit-db, GitHub, Metasploit)

    **Enterprise context** provided by the analyst via sidebar:
    - Asset Criticality (AC) — 1–6 ordinal
    - Network Exposure (NE) — air-gapped / firewall / internet
    - Technology Age (TA) — years since deployment
    - Change Management (CM) — 1–5 maturity
    - Regulatory Obligation (RO) — binary
    """)
# ── Keep API warm — ping every 14 minutes ─────────────────────
import threading

def keep_api_warm():
    while True:
        try:
            requests.get(f"{API_URL}/", timeout=10)
        except:
            pass
        threading.Event().wait(840)  # 14 minutes

if "warmer" not in st.session_state:
    st.session_state["warmer"] = True
    t = threading.Thread(target=keep_api_warm, daemon=True)
    t.start()
