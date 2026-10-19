"""Web Enumeration backend: PLACEHOLDER, not implemented yet.

Contract: run(target, options, emit) -> dict
  target  validation.Target
  options list of option ids selected in the UI (see catalog.py)
  emit    emit(level, text) writes one line to the Live Terminal. Levels: info ok warn error cmd out
  returns {"pages": [ {"url": "...", "status": 200, "server": "...", "title": "...", "paths": []} ]}
Use streaming.stream_command() for external tools so their real output reaches the terminal.
"""
STATUS = "placeholder"


def run(target, options, emit):
    raise NotImplementedError("Web Enumeration is not implemented yet. No requests were sent.")
