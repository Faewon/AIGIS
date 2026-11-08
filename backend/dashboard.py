"""Serve the single-source dashboard as HTML plus an external script.

Only shipped source is compiled here; request and database values never become
JavaScript. Template handlers are converted along with static HTML handlers.
"""
import html
import re
from pathlib import Path


def build_dashboard(path: str):
    source = Path(path).read_text(encoding="utf-8")
    handlers = []

    def handler(match):
        event, code = match.groups()
        if "${" in code:
            raise ValueError("Dynamic executable dashboard handler must use data attributes")
        index = len(handlers)
        handlers.append((event.lower(), html.unescape(code)))
        return f'data-handler-{event.lower()}="{index}"'

    source = re.sub(r'\bon(\w+)="([^"\n]*)"', handler, source)
    scripts = re.findall(r'<script>([\s\S]*?)</script>', source)
    source = re.sub(r'<script>[\s\S]*?</script>', '<script src="/assets/dashboard.js" defer></script>', source)
    source = re.sub(r'<meta http-equiv="Content-Security-Policy"[^>]*>', '', source)
    counts = {}

    def unique_id(match):
        name = match.group(1)
        counts[name] = counts.get(name, 0) + 1
        unique = name if counts[name] == 1 else f"{name}--{counts[name]}"
        return f'id="{unique}" data-control-id="{name}"'

    source = re.sub(r'(?<![\w-])id="([^"]+)"', unique_id, source)
    script = "\n".join(scripts)
    script = script.replace("document.getElementById(", "dashboardControl(")
    bootstrap = """
let dashboardControlScope = null;
function dashboardControl(id) {
    const controls = Array.from(document.querySelectorAll('[data-control-id="' + CSS.escape(id) + '"]'));
    if (dashboardControlScope) {
        const scoped = controls.find(element => dashboardControlScope.contains(element));
        if (scoped) return scoped;
    }
    return controls.find(element => element.getClientRects().length > 0)
        || document.getElementById(id);
}
const dashboardHandlers = {
"""
    bootstrap += ",\n".join(f"{i}: function(event) {{ {code.replace('document.getElementById(', 'dashboardControl(')} }}" for i, (_, code) in enumerate(handlers))
    bootstrap += "\n};\n"
    for event in sorted({event for event, _ in handlers}):
        bootstrap += f"""
document.addEventListener('{event}', function(event) {{
    const element = event.target.closest('[data-handler-{event}]');
    if (!element) return;
    dashboardControlScope = element.closest('[data-dashboard-controls]');
    try {{
        let current = element;
        while (current) {{
            const result = dashboardHandlers[current.getAttribute('data-handler-{event}')].call(current, event);
            if (result === false) event.preventDefault();
            if (event.cancelBubble) break;
            current = current.parentElement?.closest('[data-handler-{event}]');
        }}
    }} finally {{ dashboardControlScope = null; }}
}});
"""
    return source, bootstrap + script
