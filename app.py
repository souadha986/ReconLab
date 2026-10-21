import sys
from datetime import datetime

import streamlit as st

import catalog
import ui
from runner import BACKENDS, ScanSession, start_scan
from validation import parse_target, validate_target_for_modules

st.set_page_config(
    page_title="ReconLab",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed",
)

ui.inject_css()

ss = st.session_state
MODS = catalog.MODULES

SERVICES = BACKENDS["services"]

PORT_MODE_LABELS = {
    "all_ports": "All ports (1-65535)",
    "well_known": "Well-known ports (1-1024)",
    "common": "Common service ports",
    "custom": "Custom ports",
}

ss.setdefault("scan", ScanSession())

for module in MODS:
    ss.setdefault(f"mod_{module.id}", False)

    for option in module.options:
        ss.setdefault(
            f"opt_{module.id}_{option.id}",
            option.default,
        )

ss.setdefault("host_discovery_method", "icmp")
ss.setdefault("services_port_mode", "all_ports")
ss.setdefault("services_custom_ports", "")
ss.setdefault("services_proto_tcp", True)
ss.setdefault("services_proto_udp", False)

scan = ss.scan
running = scan.running


def set_all(value):
    for module in MODS:
        ss[f"mod_{module.id}"] = value


def module_options(module):
    if module.id == "dns":
        st.caption("Standard DNS records (A, AAAA, MX, NS, TXT, CNAME, Subdomains) are queried automatically.")
        return

    if module.id == "services":
        st.caption("Choose protocol and which ports to scan.")

        proto_col1, proto_col2 = st.columns(2)

        proto_col1.checkbox(
            "TCP",
            key="services_proto_tcp",
            disabled=running,
        )
        proto_col2.checkbox(
            "UDP",
            key="services_proto_udp",
            disabled=running,
        )

        if not ss["services_proto_tcp"] and not ss["services_proto_udp"]:
            st.error("Select at least one protocol.")

        st.divider()

        mode = st.radio(
            "Port selection",
            options=list(PORT_MODE_LABELS),
            format_func=lambda value: PORT_MODE_LABELS[value],
            key="services_port_mode",
            disabled=running,
        )

        if mode == "custom":
            spec = st.text_input(
                "Ports",
                placeholder="e.g. 22,80,443,8000-8100",
                key="services_custom_ports",
                disabled=running,
            )

            if spec.strip():
                try:
                    count = len(SERVICES.parse_ports(spec))
                    st.caption(f"{count} port(s) selected.")
                except ValueError as exc:
                    st.error(str(exc))
            else:
                st.caption(
                    "Comma-separated ports and ranges, "
                    "e.g. 22,80,443,8000-8100"
                )
        elif mode == "common":
            st.caption(
                f"{len(set(SERVICES.COMMON_PORTS))} frequently used "
                "service ports."
            )

        if ss["services_proto_udp"] and mode == "all_ports":
            st.warning(
                "UDP across all 65535 ports is slow and results are "
                "ambiguous (no reply = open|filtered). Consider "
                "'Common service ports' or a custom list for UDP."
            )

        st.caption("TCP states: OPEN, CLOSED, FILTERED")
        st.caption("UDP states: OPEN, CLOSED, OPEN|FILTERED")
        return

    if module.id == "hosts":
        st.caption("Select exactly ONE discovery method.")

        selected = st.radio(
            "Discovery method",
            options=["icmp", "tcp"],
            format_func=lambda value: {
                "icmp": "ICMP Discovery (Ping)",
                "tcp": "TCP Discovery",
            }[value],
            key="host_discovery_method",
            disabled=running,
        )

        for option in module.options:
            ss[f"opt_{module.id}_{option.id}"] = (
                option.id == selected
            )

    else:
        st.caption("Choose what this module collects.")

        for option in module.options:
            st.checkbox(
                option.label,
                key=f"opt_{module.id}_{option.id}",
                disabled=running,
            )


def validate():
    raw_target = ss.get("target", "").strip()
    target, error = parse_target(raw_target)

    errors = []

    if error:
        errors.append(error)

    selected_modules = [
        module
        for module in MODS
        if ss[f"mod_{module.id}"]
    ]

    if not selected_modules:
        errors.append("Select at least one module.")

    if target and selected_modules:
        selected_ids = [m.id for m in selected_modules]
        target_errors = validate_target_for_modules(target, selected_ids)
        errors.extend(target_errors)

    options = {}

    for module in selected_modules:
        if module.id == "dns":
            options[module.id] = ["a", "aaaa", "mx", "ns", "txt", "cname", "subdomains"]
        elif module.id == "services":
            mode = ss["services_port_mode"]

            if mode == "custom":
                spec = ss["services_custom_ports"].strip()

                try:
                    SERVICES.parse_ports(spec)
                except ValueError as exc:
                    errors.append(
                        f"{module.title}: invalid custom ports. {exc}"
                    )

                port_option = f"custom:{spec}"
            else:
                port_option = mode

            protocol_options = []
            if ss["services_proto_tcp"]:
                protocol_options.append(SERVICES.PROTO_TCP)
            if ss["services_proto_udp"]:
                protocol_options.append(SERVICES.PROTO_UDP)

            if not protocol_options:
                errors.append(f"{module.title}: select at least one protocol.")

            options[module.id] = [port_option] + protocol_options
        else:
            options[module.id] = [
                option.id
                for option in module.options
                if ss[f"opt_{module.id}_{option.id}"]
            ]

    for module in selected_modules:
        if module.id in ("dns", "services"):
            continue

        if not options[module.id]:
            errors.append(
                f"{module.title}: choose at least one option (gear icon)."
            )

    return target, selected_modules, options, errors


def terminal_panel(scan, status_at_run):
    lines, total = scan.snapshot()

    st.markdown(
        ui.terminal_html(lines, scan.status, total),
        unsafe_allow_html=True,
    )

    if scan.status != "idle":
        module_count = len(scan.module_ids)

        if scan.running:
            label = (
                f"Running {scan.current} "
                f"({scan.done}/{module_count} modules done)"
            )
        else:
            label = (
                f"Finished {scan.done}/{module_count} modules "
                f"in {scan.duration:.1f}s"
            )

        st.progress(
            scan.done / module_count if module_count else 0.0,
            text=label,
        )

    if scan.status != status_at_run:
        st.rerun()


def outcome(module_id):
    return scan.outcomes.get(module_id, {})


def rows(module_id, key):
    return (
        outcome(module_id)
        .get("data", {})
        .get(key, [])
    )


def table(module_id, key, columns):
    data = rows(module_id, key)

    if data:
        st.dataframe(
            data,
            column_order=columns,
            hide_index=True,
            width="stretch",
        )
        return

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
            'Results appear here when it finishes.</div>',
            unsafe_allow_html=True,
        )
        return

    ran = scan.module_ids

    tab_definitions = [
        ("DNS", ["dns"]),
        ("Web", ["web"]),
        ("Hosts & Services", ["hosts", "services"]),
    ]

    names = ["Overview"] + [
        name
        for name, module_ids in tab_definitions
        if any(mid in ran for mid in module_ids)
    ]

    tabs = dict(zip(names, st.tabs(names)))

    with tabs["Overview"]:
        columns = st.columns(4)

        stats = [
            ("Target", scan.target.host),
            (
                "Status",
                ui.STATUS[scan.status][0].title(),
            ),
            (
                "Started",
                datetime.fromtimestamp(
                    scan.started
                ).strftime("%H:%M:%S"),
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
                    "module": module.title,
                    "outcome": outcome_labels.get(
                        outcome(module.id).get("status"),
                        "Unknown",
                    ),
                    "details": outcome(module.id).get("error", ""),
                }
                for module in MODS
                if module.id in ran
            ],
            hide_index=True,
            width="stretch",
        )

    if "DNS" in tabs:
        with tabs["DNS"]:
            table("dns", "records", ["type", "value", "status"])

    if "Web" in tabs:
        with tabs["Web"]:
            table(
                "web",
                "pages",
                ["url", "status", "server", "title", "paths"],
            )

    if "Hosts & Services" in tabs:
        with tabs["Hosts & Services"]:
            if "hosts" in ran:
                st.caption("Hosts")
                table("hosts", "hosts", ["ip", "state"])

            if "services" in ran:
                st.caption(
                    "Port states ("
                    + SERVICES.describe_selection(
                        scan.options.get("services", [])
                    )
                    + ")"
                )

                table(
                    "services",
                    "services",
                    [
                        "ip",
                        "port",
                        "protocol",
                        "service",
                        "state",
                    ],
                )


ui.header(scan.status)

with st.sidebar:
    st.markdown("**Environment**")

    st.caption(f"Python {sys.version.split()[0]}")

    st.markdown("**Backend status**")

    st.caption(
        "  \n".join(
            f"{module.title}: {BACKENDS[module.id].STATUS}"
            for module in MODS
        )
    )

    st.markdown("**Authorized use**")

    st.caption(
        "Only assess systems you own or have written permission to test."
    )


left, right = st.columns([5, 6], gap="medium")

with left:
    with st.container(key="panel_target"):
        st.text_input(
            "Target",
            placeholder="e.g. example.com",
            key="target",
            disabled=running,
        )

        st.caption(
            "Target constraints: DNS and Web modules require a domain name; Services accepts single IP/Domain; Hosts accepts CIDR ranges."
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

        for module in MODS:
            blocked = False

            with st.container(key=f"row_{module.id}"):
                module_column, settings_column = st.columns(
                    [8, 1.2],
                    vertical_alignment="center",
                )

                with module_column:
                    st.checkbox(
                        module.title,
                        key=f"mod_{module.id}",
                        disabled=running or blocked,
                    )

                    st.markdown(
                        ui.module_caption(
                            module.desc,
                            BACKENDS[module.id].STATUS,
                            blocked,
                        ),
                        unsafe_allow_html=True,
                    )

                with settings_column:
                    with st.popover(
                        "⚙",
                        help=f"{module.title} options",
                        width="stretch",
                    ):
                        module_options(module)

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

        selected_count = sum(
            ss[f"mod_{module.id}"]
            for module in MODS
        )

        st.caption(
            f"{selected_count} of {len(MODS)} modules selected"
        )

        if run:
            target, selected, options, errors = validate()

            if errors:
                st.error(
                    "\n".join(f"- {error}" for error in errors)
                )
            else:
                ss.scan = start_scan(
                    target,
                    [module.id for module in selected],
                    options,
                )
                st.rerun()

        if clear:
            ss.scan = ScanSession()
            st.rerun()

with right:
    st.fragment(
        run_every=0.5 if running else None
    )(terminal_panel)(scan, scan.status)

results_section()