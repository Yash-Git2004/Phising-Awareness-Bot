import json
import streamlit as st

from detector import PhishDetector

# ----------------- Page config -----------------
st.set_page_config(
    page_title="Phishing Awareness Bot",
    page_icon="🛡️",
    layout="wide"
)

# ----------------- Small custom CSS -----------------
st.markdown(
    """
    <style>
    .main-header {
        padding: 1.2rem 1.5rem;
        border-radius: 1rem;
        background: linear-gradient(135deg, #1f2937, #111827);
        color: white;
        margin-bottom: 1.5rem;
        border: 1px solid rgba(255,255,255,0.08);
    }
    .main-header h1 {
        font-size: 1.8rem;
        margin-bottom: 0.3rem;
    }
    .main-header p {
        margin: 0;
        opacity: 0.85;
        font-size: 0.95rem;
    }
    .score-badge {
        padding: 0.4rem 0.8rem;
        border-radius: 999px;
        font-size: 0.8rem;
        font-weight: 600;
        display: inline-block;
        margin-left: 0.5rem;
    }
    </style>
    """,
    unsafe_allow_html=True,
)

# ----------------- Header -----------------
st.markdown(
    """
    <div class="main-header">
        <h1>🛡️ Phishing Awareness Bot</h1>
        <p>Analyze suspicious emails, understand risk indicators, and learn how to stay safe from phishing attacks.</p>
    </div>
    """,
    unsafe_allow_html=True,
)

# ----------------- Sidebar -----------------
with st.sidebar:
    st.markdown("### ⚙️ Input options")
    sample_choice = st.selectbox(
        "Load a sample email",
        ["-- none --", "benign", "phish1", "phish2", "suspicious_attach"],
    )

    uploaded_file = st.file_uploader(
        "Or upload a .eml / .txt email file",
        type=["eml", "txt"],
        help="Export a raw email from your client and upload here.",
    )

    st.markdown("---")
    st.markdown("### 💡 Quick tips")
    st.markdown("- Paste **full headers (From, To, Subject)** for better results")
    st.markdown("- This is an **educational tool**, not a production-grade detector")
    st.markdown("- For attachments, include **raw MIME** or at least the filename")

# ----------------- Main layout -----------------
col_input, col_info = st.columns([2.4, 1.6])

with col_input:
    st.markdown("#### ✉️ Email content")
    raw_input = st.text_area(
        "Paste raw email (headers + body)",
        height=280,
        placeholder="From: ...\nTo: ...\nSubject: ...\n\nEmail body here...",
    )

    # Handle upload
    if uploaded_file is not None:
        try:
            raw_input = uploaded_file.read().decode("utf-8", errors="ignore")
        except Exception:
            st.warning("Could not decode file as UTF-8, please check the file encoding.")

    # Handle sample load (only if nothing typed / uploaded)
    if sample_choice != "-- none --" and not raw_input.strip() and uploaded_file is None:
        try:
            with open("sample_emails.json", "r", encoding="utf-8") as f:
                data = json.load(f)
            raw_input = data.get(sample_choice, "")
        except Exception:
            st.error("Could not load sample_emails.json. Please check the file is present.")

    analyze_btn = st.button("⚡ Analyze email", use_container_width=True)

with col_info:
    st.markdown("#### ℹ️ What this tool does")
    st.write(
        """
        - Performs **rule-based analysis** on email text  
        - Checks for **suspicious URLs, IP links, urgent language, attachments**  
        - Compares **sender domain vs link domains**  
        - Outputs a **risk score (0–100)** with recommended actions
        """
    )
    st.markdown("---")
    st.markdown("#### 🧩 Detection signals used")
    st.markdown("- Suspicious / IP / non-HTTPS URLs")
    st.markdown("- Urgent / phishing keywords")
    st.markdown("- Dangerous attachment extensions")
    st.markdown("- Sender vs link domain mismatch")
    st.markdown("- Weird / unusual domains")

# ----------------- Analysis + Results -----------------
if analyze_btn:
    if not raw_input.strip():
        st.error("Please paste an email, upload a file, or load a sample.")
    else:
        detector = PhishDetector()
        result = detector.analyze(raw_input)

        score = result["score"]
        urls = result.get("urls", [])

        # Risk label
        if score < 30:
            risk_label = "Low risk (likely legitimate)"
            badge_style = "background-color:#16a34a33;color:#bbf7d0;border:1px solid #22c55e55;"
        elif score < 60:
            risk_label = "Medium risk — review carefully"
            badge_style = "background-color:#facc1533;color:#fef3c7;border:1px solid #facc1555;"
        else:
            risk_label = "High risk — likely phishing"
            badge_style = "background-color:#ef444433;color:#fee2e2;border:1px solid #ef444455;"

        st.markdown("---")
        st.markdown("### 🧪 Analysis result")

        c1, c2, c3 = st.columns([1.5, 2, 1])
        with c1:
            st.metric("Phishing score", f"{score}/100")

        with c2:
            st.markdown(
                f'<span class="score-badge" style="{badge_style}">{risk_label}</span>',
                unsafe_allow_html=True,
            )

        with c3:
            st.metric("Links detected", len(urls))

        st.progress(score / 100)

        # Tabs for detailed view
        overview_tab, indicators_tab, meta_tab, raw_tab = st.tabs(
            ["Overview", "Indicators", "Metadata", "Raw email"]
        )

        with overview_tab:
            st.subheader("Overview")
            st.write(
                "This detector combines several rule-based checks to estimate how risky an email might be. "
                "Use the indicators tab to understand which rules were triggered."
            )
            st.write(
                f"**Rule score:** {result.get('raw_total')}/{result.get('max_possible_raw')} (normalized to 0–100)"
            )

            if score >= 60:
                st.error(
                    "- 🚨 Do **not** click links or open attachments\n"
                    "- Verify the sender via official channels (phone, official website)\n"
                    "- Report this email to your IT/security team"
                )
            elif score >= 30:
                st.warning(
                    "- ⚠️ Check each link by hovering or using a safe URL checker\n"
                    "- Do **not** enter passwords or sensitive info\n"
                    "- Be cautious if email asks for urgent action"
                )
            else:
                st.success(
                    "- ✅ Email appears low risk, but always stay cautious\n"
                    "- Avoid clicking links if you weren't expecting this email\n"
                    "- When in doubt, verify with the sender"
                )

        with indicators_tab:
            st.subheader("Indicators triggered")
            if not result["breakdown"]:
                st.info("No strong phishing indicators were triggered.")
            else:
                for name, val, explanation in result["breakdown"]:
                    with st.container(border=True):
                        st.markdown(f"**{name}**  \nScore: `{val}`")
                        st.write(explanation)

        with meta_tab:
            st.subheader("Headers & extracted data")
            st.write("**From header:**", result.get("sender") or "—")
            st.write("**Reply-To:**", result.get("reply_to") or "—")

            st.markdown("**Extracted URLs:**")
            if urls:
                for u in urls:
                    st.write(f"- `{u}`")
            else:
                st.write("No URLs detected.")

        with raw_tab:
            st.subheader("Raw email (with basic highlights)")

            highlighted = raw_input

            # Highlight URLs
            for u in urls:
                if u:
                    highlighted = highlighted.replace(u, f"**{u}**")

            # Highlight phishing keywords if returned
            for kw in result.get("keyword_hits", []):
                if kw:
                    highlighted = highlighted.replace(kw, f"__{kw}__")

            st.markdown(
                "> **Bold** = URL,  __Underlined__ = phishing keyword\n\n", unsafe_allow_html=True
            )
            st.markdown(highlighted.replace("  ", "&nbsp;&nbsp;"), unsafe_allow_html=True)
