from __future__ import annotations

import json
import sys
from datetime import UTC, datetime
from pathlib import Path

import pandas as pd
import streamlit as st


PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC = PROJECT_ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from threatguard.config import settings  # noqa: E402
from threatguard.data import DatasetValidationError  # noqa: E402
from threatguard.models import SUPPORTED_ALGORITHMS  # noqa: E402
from threatguard.service import service  # noqa: E402


st.set_page_config(
    page_title=settings.app_name,
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)


def login_screen() -> None:
    st.title("🛡️ ThreatGuard UniFlow AI")
    st.caption("AI-assisted detection of cyber threats from unidirectional IP-flow metadata")
    left, middle, right = st.columns([1, 1.25, 1])
    with middle:
        with st.form("login"):
            st.subheader("Authorized access")
            email = st.text_input("Email", value=settings.admin_email)
            password = st.text_input("Password", type="password")
            submitted = st.form_submit_button("Sign in", use_container_width=True)
        if submitted:
            user = service.database.authenticate(email, password)
            if user:
                st.session_state.user = user
                service.database.audit(user["email"], "DASHBOARD_LOGIN", {})
                st.rerun()
            st.error("Invalid email or password.")
        st.info("For the first local run, use the credentials documented in README.md and then change them in .env.")


def metric_card(label: str, value: object, help_text: str | None = None) -> None:
    st.metric(label, value, help=help_text)


def home_page() -> None:
    analytics = service.database.analytics()
    totals = analytics["totals"]
    st.title("Security Operations Dashboard")
    cols = st.columns(4)
    with cols[0]:
        metric_card("Flows analyzed", f"{totals['total']:,}")
    with cols[1]:
        metric_card("Normal", f"{totals['normal']:,}")
    with cols[2]:
        metric_card("Threats", f"{totals['attacks']:,}")
    with cols[3]:
        metric_card("Critical", f"{totals['critical']:,}")

    left, right = st.columns(2)
    with left:
        st.subheader("Risk distribution")
        risk = pd.DataFrame(analytics["risk_distribution"])
        if risk.empty:
            st.info("Run predictions to populate operational charts.")
        else:
            st.bar_chart(risk.set_index("label"))
    with right:
        st.subheader("Attack distribution")
        attacks = pd.DataFrame(analytics["attack_distribution"])
        if attacks.empty:
            st.info("No alerts have been generated.")
        else:
            st.bar_chart(attacks.set_index("label"))

    st.subheader("Recent alerts")
    alerts = pd.DataFrame(service.database.list_alerts(limit=10))
    if alerts.empty:
        st.info("No current alerts.")
    else:
        st.dataframe(alerts, use_container_width=True, hide_index=True)


def dataset_page() -> None:
    st.title("Dataset validation")
    st.write(
        "Upload a labeled network-flow CSV. Version 1 accepts flow metadata only and never requires packet payloads."
    )
    uploaded = st.file_uploader("Network-flow dataset", type=["csv"])
    if uploaded is not None:
        safe_name = "".join(c if c.isalnum() or c in "._-" else "_" for c in uploaded.name)
        destination = settings.uploads_dir / f"{datetime.now(UTC).strftime('%Y%m%d-%H%M%S')}_{safe_name}"
        if uploaded.size > settings.max_upload_mb * 1024 * 1024:
            st.error("The file exceeds the configured upload limit.")
            return
        destination.write_bytes(uploaded.getbuffer())
        st.session_state.dataset_path = str(destination)
        try:
            result = service.validate_dataset(destination)
            summary = result["summary"]
            st.success("Dataset passed structural validation.")
            cols = st.columns(4)
            cols[0].metric("Rows", f"{summary['rows']:,}")
            cols[1].metric("Columns", summary["columns"])
            cols[2].metric("Normal", f"{summary['normal_rows']:,}")
            cols[3].metric("Attacks", f"{summary['attack_rows']:,}")
            if result["reverse_fields_excluded"]:
                st.info(
                    "Reverse fields excluded from uni-flow experiment: "
                    + ", ".join(result["reverse_fields_excluded"])
                )
            st.subheader("Preview")
            st.dataframe(pd.DataFrame(result["preview"]), use_container_width=True)
            st.subheader("Class distribution")
            distribution = pd.DataFrame(
                summary["class_distribution"].items(), columns=["class", "rows"]
            )
            st.bar_chart(distribution.set_index("class"))
        except DatasetValidationError as exc:
            st.error(str(exc))
    elif "dataset_path" in st.session_state:
        st.info(f"Current dataset: {Path(st.session_state.dataset_path).name}")
    else:
        demo = settings.sample_dir / "demo_network_flows.csv"
        if demo.exists() and st.button("Use included synthetic demo dataset"):
            st.session_state.dataset_path = str(demo)
            st.rerun()


def training_page() -> None:
    st.title("Model training and selection")
    dataset_path = st.session_state.get("dataset_path")
    if not dataset_path:
        demo = settings.sample_dir / "demo_network_flows.csv"
        dataset_path = str(demo) if demo.exists() else None
    if not dataset_path:
        st.warning("Upload or generate a dataset first.")
        return
    st.caption(f"Dataset: {Path(dataset_path).name}")
    profile = st.radio(
        "Feature profile",
        ["unidirectional", "bidirectional"],
        horizontal=True,
        help="Use unidirectional for the main research result. Bidirectional is the comparison baseline.",
    )
    algorithms = st.multiselect(
        "Algorithms",
        options=list(SUPPORTED_ALGORITHMS),
        default=list(SUPPORTED_ALGORITHMS),
    )
    if st.button("Train and evaluate", type="primary", disabled=not algorithms):
        with st.spinner("Training with an unseen test set. This may take several minutes..."):
            try:
                result = service.train(
                    dataset_path,
                    profile_name=profile,
                    algorithms=algorithms,
                    actor=st.session_state.user["email"],
                )
                st.session_state.training_result = result
                st.success(
                    f"Best model: {result['model']['model_name']} — version {result['model']['version']}"
                )
            except Exception as exc:
                st.exception(exc)
    result = st.session_state.get("training_result")
    if result:
        comparison = pd.DataFrame(result["comparison"])
        display_columns = [
            "model",
            "accuracy",
            "precision",
            "recall",
            "f1",
            "pr_auc",
            "false_positive_rate",
            "false_negative_rate",
            "training_seconds",
            "prediction_ms_per_1000",
        ]
        st.subheader("Unseen test-set results")
        st.dataframe(comparison[display_columns], use_container_width=True, hide_index=True)
        importance = pd.DataFrame(result["model"]["feature_importance"])
        if not importance.empty:
            st.subheader("Top model features")
            st.bar_chart(importance.set_index("feature"))


def comparison_page() -> None:
    st.title("Uni-flow vs bi-flow research comparison")
    dataset_path = st.session_state.get("dataset_path")
    if not dataset_path:
        demo = settings.sample_dir / "demo_network_flows.csv"
        dataset_path = str(demo) if demo.exists() else None
    if not dataset_path:
        st.warning("Select a dataset first.")
        return
    algorithm = st.selectbox("Use the same algorithm for both experiments", SUPPORTED_ALGORITHMS, index=2)
    if st.button("Run controlled comparison", type="primary"):
        with st.spinner("Training both controlled profiles..."):
            try:
                result = service.compare_unidirectional_bidirectional(
                    dataset_path,
                    algorithms=[algorithm],
                    actor=st.session_state.user["email"],
                )
                st.session_state.profile_comparison = result
            except Exception as exc:
                st.exception(exc)
    result = st.session_state.get("profile_comparison")
    if result:
        st.success("Controlled comparison completed.")
        st.dataframe(pd.DataFrame(result["comparison"]), use_container_width=True, hide_index=True)
        st.caption(result["research_note"])


def detection_page() -> None:
    st.title("Threat detection")
    try:
        bundle = service.load_active_bundle()
    except RuntimeError as exc:
        st.warning(str(exc))
        return
    st.caption(
        f"Active model: {bundle.model_name} · {bundle.version} · {bundle.profile['name']} profile"
    )
    tab_manual, tab_batch = st.tabs(["Manual JSON", "Batch CSV"])
    defaults = {feature: 0 for feature in bundle.profile["features"]}
    for feature in bundle.profile.get("categorical_features", []):
        defaults[feature] = "unknown"
    with tab_manual:
        text = st.text_area("Flow feature object", json.dumps(defaults, indent=2), height=350)
        if st.button("Analyze flow", type="primary"):
            try:
                result = service.predict_one(json.loads(text), persist=True)
                color = "red" if result["prediction"] == "ATTACK" else "green"
                st.markdown(f"### :{color}[{result['prediction']}]")
                cols = st.columns(4)
                cols[0].metric("Attack type", result["attack_type"])
                cols[1].metric("Threat probability", f"{result['threat_probability']:.1%}")
                cols[2].metric("Risk", result["risk_level"])
                cols[3].metric("Latency", f"{result['latency_ms']:.3f} ms")
                if result.get("alert_id"):
                    st.warning(f"Alert #{result['alert_id']} created for analyst review.")
            except (json.JSONDecodeError, DatasetValidationError, ValueError) as exc:
                st.error(str(exc))
    with tab_batch:
        uploaded = st.file_uploader("Unlabeled flow CSV", type=["csv"], key="prediction_csv")
        if uploaded and st.button("Analyze batch"):
            try:
                frame = pd.read_csv(uploaded)
                if len(frame) > 10_000:
                    st.error("Dashboard batches are limited to 10,000 rows.")
                    return
                results = service.predict_frame(frame, persist=True)
                st.dataframe(pd.DataFrame(results), use_container_width=True, hide_index=True)
            except Exception as exc:
                st.exception(exc)


def alerts_page() -> None:
    st.title("Threat history and alert review")
    col1, col2, col3 = st.columns(3)
    risk = col1.selectbox("Risk level", ["All", "LOW", "MEDIUM", "HIGH", "CRITICAL"])
    attack = col2.text_input("Attack type (exact, optional)")
    protocol = col3.text_input("Protocol (exact, optional)")
    col4, col5, col6, col7 = st.columns(4)
    source = col4.text_input("Source contains")
    destination = col5.text_input("Destination contains")
    date_from_value = col6.date_input("From date", value=None)
    date_to_value = col7.date_input("To date", value=None)
    alerts = service.database.list_alerts(
        risk_level=None if risk == "All" else risk,
        attack_type=attack or None,
        protocol=protocol or None,
        source=source or None,
        destination=destination or None,
        date_from=f"{date_from_value.isoformat()}T00:00:00" if date_from_value else None,
        date_to=f"{date_to_value.isoformat()}T23:59:59" if date_to_value else None,
        limit=500,
    )
    if alerts:
        st.dataframe(pd.DataFrame(alerts), use_container_width=True, hide_index=True)
        st.download_button(
            "Download filtered alerts as CSV",
            pd.DataFrame(alerts).to_csv(index=False),
            file_name="threatguard_alerts.csv",
            mime="text/csv",
        )
    else:
        st.info("No matching alerts.")


def analytics_page() -> None:
    st.title("Analytics and model performance")
    try:
        metadata = service.model_performance()
    except RuntimeError as exc:
        st.warning(str(exc))
        return
    metrics = metadata["metrics"]["test"]
    cols = st.columns(5)
    for column, key in zip(cols, ["accuracy", "precision", "recall", "f1", "pr_auc"]):
        column.metric(key.replace("_", " ").title(), f"{metrics.get(key, 0):.3f}")
    st.subheader("Model comparison")
    st.dataframe(pd.DataFrame(metadata["metrics"]["comparison"]), use_container_width=True)
    st.subheader("Confusion matrix")
    matrix = metrics["confusion_matrix"]
    st.dataframe(
        pd.DataFrame(matrix, index=["Actual Normal", "Actual Attack"], columns=["Predicted Normal", "Predicted Attack"]),
        use_container_width=True,
    )
    st.warning(
        "These values describe the saved unseen test split only. Synthetic-demo scores must not be presented as real-network performance."
    )


def report_page() -> None:
    st.title("Evidence report")
    st.write("Generate a reproducible JSON report with model metadata, test metrics, analytics, alerts, and limitations.")
    if st.button("Generate report", type="primary"):
        try:
            path = service.create_report()
            st.session_state.report_path = str(path)
            st.success(f"Created {path.name}")
        except RuntimeError as exc:
            st.error(str(exc))
    if path_text := st.session_state.get("report_path"):
        path = Path(path_text)
        if path.exists():
            st.download_button(
                "Download report",
                path.read_bytes(),
                file_name=path.name,
                mime="application/json",
            )


if "user" not in st.session_state:
    login_screen()
    st.stop()

with st.sidebar:
    st.title("🛡️ ThreatGuard")
    st.caption(f"Signed in as {st.session_state.user['name']}")
    page = st.radio(
        "Navigation",
        [
            "Dashboard",
            "Dataset",
            "Training",
            "Uni vs Bi",
            "Detection",
            "Alerts",
            "Analytics",
            "Report",
        ],
    )
    if st.button("Sign out"):
        del st.session_state.user
        st.rerun()

PAGES = {
    "Dashboard": home_page,
    "Dataset": dataset_page,
    "Training": training_page,
    "Uni vs Bi": comparison_page,
    "Detection": detection_page,
    "Alerts": alerts_page,
    "Analytics": analytics_page,
    "Report": report_page,
}
PAGES[page]()
