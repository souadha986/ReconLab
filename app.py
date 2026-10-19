
import shutil
import sys
from datetime import datetime

import streamlit as st

import catalog
import ui
from runner import BACKENDS, ScanSession, start_scan
from validation import parse_target


# ---------------------------------------------------------------------
# Page configuration
# ---------------------------------------------------------------------

st.set_page_config(
    page_title="ReconLab",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed",
)

ui.inject_css()

ss = st.session_state
MODS = catalog.MODULES

NMAP_OK = shutil.which("nmap") is not None


# ---------------------------------------------------------------------
# Session state
# ---------------------------------------------------------------------

ss.setdefault("scan", ScanSession())

for m in MODS:
    ss.setdefault(f"mod_{m.id}", False)

    for o in m.options:
        ss.setdefault(f"opt_{m.id}_{o.id}", o.default)

ss.setdefault("nmap_auth", False)
ss.setdefault("host_discovery_method", "icmp")

if not NMAP_OK:
    ss["mod_nmap"] = False

scan: ScanSession = ss.scan
running = scan.running


# ---------------------------------------------------------------------
# Module selection
# ---------------------------------------------------------------------

def set_all(value: bool):
    """Select or deselect all available modules."""
    for m in MODS:
        ss[f"mod_{m.id}"] = value and (
            NMAP_OK or not m.needs_nmap
        )


def module_options(m):
    """Display module options."""

    if m.id == "nmap":
        st.caption(
            "Nmap found on this machine."
            if NMAP_OK
            else "Nmap is NOT installed or not in PATH."
        )

        for o in catalog.NMAP_SAFE:
            st.checkbox(
                o.label,
                key=f"opt_nmap_{o.id}",
                disabled=running,
            )

        st.divider()
        st.markdown("**Potentially intrusive categories**")

        st.warning(
            "These can disrupt or change the target. "
            "Only use them with explicit authorization."
        )

        for o in catalog.NMAP_INTRUSIVE:
            st.checkbox(
                o.label,
                key=f"opt_nmap_{o.id}",
                disabled=running,
            )

        st.checkbox(
            "I own this target or have written permission "
            "to run intrusive scripts.",
            key="nmap_auth",
            disabled=running,
        )

    elif m.id == "hosts":
        st.caption("Select exactly ONE discovery method.")

        selected = st.radio(
            "Discovery method",
            options=["icmp", "tcp"],
            format_func=lambda x: {
                "icmp": "ICMP Discovery (Ping)",
                "tcp": "TCP Discovery",
            }[x],
            key="host_discovery_method",
            disabled=running,
        )

        # Synchronize the selected radio value with the
        # option IDs used by validate() and the runner.
        for o in m.options:
            ss[f"opt_{m.id}_{o.id}"] = (o.id == selected)

    else:
        st.caption("Choose what this module collects.")

        for o in m.options:
            st.checkbox(
                o.label,
                key=f"opt_{m.id}_{o.id}",
                disabled=running,
            )


# ---------------------------------------------------------------------
# Input validation
# ---------------------------------------------------------------------

def validate():
    """Validate the target, modules, and selected options."""

    target, err = parse_target(ss.get("target", ""))
    errors = []

    if err:
        errors.append(err)

    selected_modules = [
        m for m in MODS
        if ss[f"mod_{m.id}"]
    ]

    options = {
        m.id: [
            o.id for o in m.options
            if ss[f"opt_{m.id}_{o.id}"]
        ]
        for m in selected_modules
    }

    if not selected_modules:
        errors.append("Select at least one module.")

    for m in selected_modules:
        if not options[m.id]:
            errors.append(
                f"{m.title}: choose at least one option (gear icon)."
            )

    if (
        "nmap" in options
        and set(options["nmap"]) & catalog.INTRUSIVE_IDS
        and not ss["nmap_auth"]
    ):
        errors.append(
            "Intrusive Nmap categories need the authorization checkbox ticked."
        )

    return target, selected_modules, options, errors


# ---------------------------------------------------------------------
# Terminal panel
# ---------------------------------------------------------------------

def terminal_panel(scan, status_at_run):
    """Display scan output and progress."""

    lines, total = scan.snapshot()

    st.markdown(
        ui.terminal_html(lines, scan.status, total),
        unsafe_allow_html=True,
    )

    if scan.status != "idle":
        module_count = len(scan.module_ids)
        completed = scan.done

        if scan.running:
            label = (
                f"Running {scan.current} "
                f"({completed}/{module_count} modules done)"
            )
        else:
            label = (
                f"Finished {completed}/{module_count} modules "
                f"in {scan.duration:.1f}s"
            )

        st.progress(
            completed / module_count if module_count else 0.0,
            text=label,
        )

    if scan.status != status_at_run:
        st.rerun()


# ---------------------------------------------------------------------
# Results helpers
# ---------------------------------------------------------------------

def outcome(module_id):
    return scan.outcomes.get(module_id, {})


def rows(module_id, key):
    return (
        outcome(module_id)
        .get("data", {})
        .get(key, [])
    )


def table(module_id, key, columns):
    """Display a result table or a status message."""

    data = rows(module_id, key)

    if data:
        st.dataframe(
            data,
            column_order=columns,
            hide_index=True,
            width="stretch",
        )
    else:
        result = outcome(module_id)

        message = {
            "not_implemented": (
                "Placeholder module: no data returned yet."
            ),
            "error": (
                f"Module failed: {result.get('error')}"
            ),
        }.get(
            result.get("status"),
            "No data returned.",
        )

        st.caption(message)


# ---------------------------------------------------------------------
# Results section
# ---------------------------------------------------------------------

def results_section():
    st.markdown(
        '<div class="sec">Scan Results</div>',
        unsafe_allow_html=True,
    )

    if scan.status == "idle":
        st.markdown(
            '<div class="empty">No results yet. '
            'Results appear here once a scan has finished.</div>',
            unsafe_allow_html=True,
        )
        return

    if running:
        st.markdown(
            '<div class="empty">Scan in progress. '
            'Results appear when it finishes.</div>',
            unsafe_allow_html=True,
        )
        return

    ran = scan.module_ids

    tab_definitions = [
        ("DNS", ["dns"]),
        ("Web", ["web"]),
        ("Hosts & Services", ["hosts", "services"]),
        ("Nmap", ["nmap"]),
    ]

    names = ["Overview"] + [
        name
        for name, module_ids in tab_definitions
        if any(module_id in ran for module_id in module_ids)
    ]

    tabs = dict(zip(names, st.tabs(names)))

    # Overview
    with tabs["Overview"]:
        columns = st.columns(4)

        stats = [
            ("Target", scan.target.host),
            ("Status", ui.STATUS[scan.status][0].title()),
            (
                "Started",
                datetime.fromtimestamp(scan.started).strftime(
                    "%H:%M:%S"
                ),
            ),
            ("Duration", f"{scan.duration:.1f}s"),
        ]

        for column, (label, value) in zip(columns, stats):
            column.markdown(
                ui.stat(label, value),
                unsafe_allow_html=True,
            )

        counts = [
            (label, len(rows(module_id, key)))
            for label, module_id, key in [
                ("DNS records", "dns", "records"),
                ("Web pages", "web", "pages"),
                ("Hosts", "hosts", "hosts"),
                ("Services", "services", "services"),
                ("Nmap findings", "nmap", "findings"),
            ]
            if module_id in ran
        ]

        if counts:
            st.write("")

            for column, (label, count) in zip(
                st.columns(len(counts)),
                counts,
            ):
                column.markdown(
                    ui.stat(label, count),
                    unsafe_allow_html=True,
                )

        outcome_labels = {
            "ok": "Completed",
            "not_implemented": "Placeholder (no scan run)",
            "error": "Failed",
        }

        st.write("")

        st.dataframe(
            [
                {
                    "module": m.title,
                    "outcome": outcome_labels.get(
                        outcome(m.id).get("status"),
                        "Unknown",
                    ),
                    "details": outcome(m.id).get("error", ""),
                }
                for m in MODS
                if m.id in ran
            ],
            hide_index=True,
            width="stretch",
        )

    # DNS
    if "DNS" in tabs:
        with tabs["DNS"]:
            table("dns", "records", ["type", "value", "status"])

    # Web
    if "Web" in tabs:
        with tabs["Web"]:
            table(
                "web",
                "pages",
                ["url", "status", "server", "title", "paths"],
            )

    # Hosts and services
    if "Hosts & Services" in tabs:
        with tabs["Hosts & Services"]:
            if "hosts" in ran:
                st.caption("Hosts")
                table("hosts", "hosts", ["ip", "state"])

            if "services" in ran:
                st.caption("Services")
                table(
                    "services",
                    "services",
                    ["ip", "port", "protocol", "service", "state"],
                )

    # Nmap
    if "Nmap" in tabs:
        with tabs["Nmap"]:
            st.caption(
                "Selected scripts: "
                + (
                    ", ".join(scan.options.get("nmap", []))
                    or "none"
                )
            )

            table("nmap", "findings", ["script", "detail"])


# ---------------------------------------------------------------------
# Main layout
# ---------------------------------------------------------------------

ui.header(scan.status)

# Sidebar
with st.sidebar:
    st.markdown("**Environment**")
    st.caption(
        f"Python {sys.version.split()[0]}  \n"
        f"Nmap: {'found' if NMAP_OK else 'not found'}"
    )

    st.markdown("**Backend status**")
    st.caption(
        "  \n".join(
            f"{m.title}: {BACKENDS[m.id].STATUS}"
            for m in MODS
        )
    )

    st.markdown("**Authorized use**")
    st.caption(
        "Only assess systems you own or have written permission to test."
    )


left, right = st.columns([5, 6], gap="medium")


# Left: target and modules
with left:
    with st.container(key="panel_target"):
        st.text_input(
            "Target",
            placeholder="Enter domain, URL, or IP address",
            key="target",
            disabled=running,
        )

        st.caption(
            "Only scan systems you own or have permission to assess. "
            "Nothing runs until you click RUN RECON."
        )

    with st.container(key="panel_modules"):
        heading, all_column, none_column = st.columns(
            [6, 1.3, 1.3],
            vertical_alignment="center",
        )

        heading.markdown(
            '<div class="ptitle">Reconnaissance modules</div>',
            unsafe_allow_html=True,
        )

        all_column.button(
            "All",
            key="sel_all",
            on_click=set_all,
            args=(True,),
            disabled=running,
            width="stretch",
        )

        none_column.button(
            "None",
            key="sel_none",
            on_click=set_all,
            args=(False,),
            disabled=running,
            width="stretch",
        )

        for m in MODS:
            blocked = m.needs_nmap and not NMAP_OK

            with st.container(key=f"row_{m.id}"):
                module_column, settings_column = st.columns(
                    [8, 1.2],
                    vertical_alignment="center",
                )

                with module_column:
                    st.checkbox(
                        m.title,
                        key=f"mod_{m.id}",
                        disabled=running or blocked,
                    )

                    st.markdown(
                        ui.module_caption(
                            m.desc,
                            BACKENDS[m.id].STATUS,
                            blocked,
                        ),
                        unsafe_allow_html=True,
                    )

                with settings_column:
                    with st.popover(
                        "⚙",
                        help=f"{m.title} options",
                        width="stretch",
                    ):
                        module_options(m)

        run_column, clear_column = st.columns([3, 2])

        run = run_column.button(
            "▶  RUN RECON",
            type="primary",
            key="btn_run",
            disabled=running,
            width="stretch",
        )

        clear = clear_column.button(
            "CLEAR RESULTS",
            key="btn_clear",
            disabled=running or scan.status == "idle",
            width="stretch",
        )

        selected_count = sum(ss[f"mod_{m.id}"] for m in MODS)

        st.caption(
            f"{selected_count} of {len(MODS)} modules selected"
        )

        if run:
            target, selected, options, errors = validate()

            if errors:
                st.error("\n".join(f"- {error}" for error in errors))
            else:
                ss.scan = start_scan(
                    target,
                    [m.id for m in selected],
                    options,
                )
                st.rerun()

        if clear:
            ss.scan = ScanSession()
            st.rerun()


# Right: terminal
with right:
    st.fragment(
        run_every=0.5 if running else None
    )(terminal_panel)(scan, scan.status)


# Results
results_section()
