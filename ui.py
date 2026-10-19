"""Theme and HTML helpers. Presentation only; no scan logic."""
import html
import streamlit as st

CSS = """<style>
@import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Sans:wght@400;500;600&family=JetBrains+Mono:wght@400;500&display=swap');
.stApp{background:#0B0B0D;color:#F5F5F5;font-family:'IBM Plex Sans',system-ui,sans-serif}
header[data-testid="stHeader"]{background:transparent}
#MainMenu,footer,[data-testid="stDecoration"]{visibility:hidden}
.block-container{max-width:1240px;padding:1rem 1.5rem 2.5rem}
[data-testid="stSidebar"]{background:#111114;border-right:1px solid #34343B}
[class*="st-key-panel_"]{background:#18181C;border:1px solid #34343B;border-radius:10px;padding:14px 16px;gap:.55rem;box-shadow:0 1px 2px rgba(0,0,0,.45)}
[class*="st-key-row_"]{border:1px solid transparent;border-radius:8px;padding:6px 10px;gap:0}
[class*="st-key-row_"]:hover{background:#202025}
[class*="st-key-row_"]:has([class*="st-key-mod_"] input:checked){border-color:#8B0000;background:rgba(139,0,0,.14)}
[class*="st-key-mod_"] label p{color:#F5F5F5;font-size:.92rem;font-weight:500}
[class*="st-key-sel_"] button{min-height:1.8rem;padding:0 .6rem;font-size:.75rem}
[data-baseweb="input"],[data-baseweb="base-input"]{background:#0B0B0D!important;border-radius:8px!important}
[data-baseweb="input"]{border:1px solid #34343B!important}
[data-baseweb="input"]:focus-within{border-color:#E53935!important}
input[type="text"]{font-family:'JetBrains Mono',ui-monospace,monospace!important;font-size:.9rem!important}
[data-testid="stBaseButton-primary"]{background:#E53935;border:0;border-radius:8px;color:#fff;font-weight:600;letter-spacing:.07em;min-height:2.8rem;box-shadow:0 1px 3px rgba(0,0,0,.5)}
[data-testid="stBaseButton-primary"]:hover:not(:disabled){background:#FF4D4D;color:#fff}
[data-testid="stBaseButton-primary"]:disabled{opacity:.4}
[data-testid="stBaseButton-secondary"],[data-testid="stPopover"] button{background:#202025;border:1px solid #34343B;border-radius:8px;color:#F5F5F5}
[data-testid="stBaseButton-secondary"]:hover:not(:disabled),[data-testid="stPopover"] button:hover{border-color:#8B0000;color:#FF4D4D}
button[data-baseweb="tab"]{color:#A1A1AA}
button[data-baseweb="tab"][aria-selected="true"]{color:#F5F5F5}
button[data-baseweb="tab"]:hover{color:#FF4D4D}
[data-testid="stAlert"]{border-radius:8px}
[data-testid="stDataFrame"]{border:1px solid #34343B;border-radius:8px;overflow:hidden}
.hdr{display:flex;align-items:center;justify-content:space-between;padding:2px 2px 12px;border-bottom:1px solid #34343B;margin-bottom:14px}
.hdr-l{display:flex;gap:12px;align-items:center}
.app-name{font-weight:600;font-size:1.25rem;letter-spacing:.02em;line-height:1.1}
.app-sub{color:#A1A1AA;font-size:.8rem}
.badge{display:inline-flex;align-items:center;gap:6px;padding:3px 10px;border-radius:999px;border:1px solid #34343B;font:600 .68rem 'JetBrains Mono',monospace;letter-spacing:.08em;color:#A1A1AA}
.badge i{width:6px;height:6px;border-radius:50%;background:currentColor}
.badge.running{color:#FBBF24;border-color:#5b4a14;background:rgba(251,191,36,.07)}
.badge.ok{color:#4ADE80;border-color:#1f5a38;background:rgba(74,222,128,.07)}
.badge.err{color:#FF5252;border-color:#6b1d1d;background:rgba(255,82,82,.07)}
.ptitle,.sec{font-size:.72rem;letter-spacing:.08em;text-transform:uppercase;color:#71717A;font-weight:600}
.sec{margin:1.3rem 0 .5rem}
.mcap{color:#A1A1AA;font-size:.78rem;padding-left:1.7rem;margin-top:-.45rem}
.tag{font:500 .62rem 'JetBrains Mono',monospace;padding:1px 6px;border-radius:4px;border:1px solid #34343B;color:#71717A;margin-left:6px}
.tag.warn{color:#FBBF24;border-color:#5b4a14}
.stat{background:#202025;border:1px solid #34343B;border-radius:10px;padding:9px 14px}
.stat b{display:block;font:500 1.05rem 'JetBrains Mono',monospace;margin-top:2px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.stat span{font-size:.68rem;letter-spacing:.08em;text-transform:uppercase;color:#71717A;font-weight:600}
.empty{border:1px dashed #34343B;border-radius:10px;padding:26px;text-align:center;color:#71717A}
.term{background:#050506;border:1px solid #34343B;border-radius:10px;overflow:hidden}
.term-h{display:flex;justify-content:space-between;align-items:center;padding:8px 14px;background:#111114;border-bottom:1px solid #34343B;font-weight:600;font-size:.85rem}
.term-b{height:380px;overflow-y:auto;display:flex;flex-direction:column-reverse;padding:10px 14px;font:400 .78rem/1.55 'JetBrains Mono',ui-monospace,Consolas,monospace}
.ln{display:flex;gap:10px;white-space:pre-wrap;word-break:break-word;flex:none}
.ln .ts{color:#52525B;flex:none}.ln .pf{flex:none;width:1.6em}
.ln.out .tx{color:#E4E4E7}.ln.info .tx,.ln.info .pf{color:#A1A1AA}
.ln.cmd .tx,.ln.cmd .pf,.ln.ok .tx,.ln.ok .pf{color:#4ADE80}
.ln.warn .tx,.ln.warn .pf{color:#FBBF24}.ln.error .tx,.ln.error .pf{color:#FF5252}
.ln.muted{color:#71717A}
</style>"""

STATUS = {"idle": ("IDLE", "idle"), "running": ("RUNNING", "running"),
          "completed": ("COMPLETED", "ok"), "completed_errors": ("COMPLETED WITH ERRORS", "err")}
PREFIX = {"info": "[*]", "ok": "[+]", "warn": "[!]", "error": "[x]", "cmd": "$", "out": ""}
SHIELD = ('<svg width="30" height="30" viewBox="0 0 24 24" fill="none" stroke="#E53935" stroke-width="1.6" '
          'stroke-linecap="round" stroke-linejoin="round"><path d="M12 3l8 3v6c0 5-3.5 8-8 9-4.5-1-8-4-8-9V6z"/>'
          '<path d="M9 10.5l2 1.8-2 1.8M13 14.5h2.5"/></svg>')


def inject_css():
    st.markdown(CSS, unsafe_allow_html=True)


def badge(status: str) -> str:
    label, cls = STATUS[status]
    return f'<span class="badge {cls}"><i></i>{label}</span>'


def header(status: str) -> None:
    st.markdown(f'<div class="hdr"><div class="hdr-l">{SHIELD}<div><div class="app-name">ReconLab</div>'
                f'<div class="app-sub">Lightweight Reconnaissance Toolkit</div></div></div>{badge(status)}</div>',
                unsafe_allow_html=True)


def terminal_html(lines, status: str, total: int) -> str:
    """Newest line is first in the DOM; column-reverse keeps the view pinned to the newest output."""
    if not lines:
        body = '<div class="ln muted">No output yet. Select modules and click RUN RECON; real output streams here.</div>'
    else:
        body = "".join(f'<div class="ln {l.level}"><span class="ts">{l.ts}</span><span class="pf">{PREFIX.get(l.level, "")}</span>'
                       f'<span class="tx">{html.escape(l.text) or "&nbsp;"}</span></div>' for l in reversed(lines))
        if total > len(lines):
            body += f'<div class="ln muted">... {total - len(lines)} earlier lines not shown</div>'
    return (f'<div class="term"><div class="term-h"><span>Live Terminal</span>{badge(status)}</div>'
            f'<div class="term-b">{body}</div></div>')


def stat(label: str, value) -> str:
    return f'<div class="stat"><span>{html.escape(label)}</span><b>{html.escape(str(value))}</b></div>'


def module_caption(desc: str, backend: str, blocked: bool) -> str:
    tag = "" if backend == "ready" else f'<span class="tag warn">{backend}</span>'
    if blocked:
        tag += '<span class="tag warn">nmap not found</span>'
    return f'<div class="mcap">{html.escape(desc)}{tag}</div>'
