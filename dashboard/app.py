"""Dash application exposing real-time SOC analytics.

Reads enriched security events from SQLite and renders operational/security
views refreshed at a fixed interval.
"""

import os
import sqlite3
import pandas as pd
import dash
from dash import dcc, html
from dash.dependencies import Input, Output
import plotly.express as px
import plotly.graph_objects as go

DB_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "pipeline", "data", "security.db"
)

app = dash.Dash(__name__)
app.title = "CYNA SOC Dashboard"

DARK = {
    "paper_bgcolor": "#161b22",
    "plot_bgcolor":  "#0d1117",
    "font":          {"color": "#c9d1d9"},
    "margin":        {"t": 40, "l": 10, "r": 10, "b": 10},
}

_read_conn = sqlite3.connect(DB_PATH, check_same_thread=False)
_read_conn.execute("PRAGMA journal_mode=WAL;")


def query(sql: str) -> pd.DataFrame:
    """Execute a read-only SQL query and return a DataFrame.

    Returns an empty DataFrame if the query fails.
    """
    try:
        return pd.read_sql_query(sql, _read_conn)
    except Exception as e:
        print(f"[DB ERROR] {e}")
        return pd.DataFrame()


app.layout = html.Div(
    style={"backgroundColor": "#0d1117", "minHeight": "100vh", "fontFamily": "monospace", "padding": "20px"},
    children=[
        html.H1("🛡️ CYNA SOC Dashboard", style={"color": "#58a6ff", "textAlign": "center", "marginBottom": "4px"}),
        html.P(id="last-update", style={"color": "#8b949e", "textAlign": "center", "marginBottom": "20px"}),

        dcc.Interval(id="interval", interval=5000, n_intervals=0),

        # KPI Cards
        html.Div(
            style={"display": "flex", "justifyContent": "center", "gap": "20px", "marginBottom": "30px"},
            children=[
                html.Div(id="kpi-total",     style={"backgroundColor": "#161b22", "border": "1px solid #58a6ff", "borderRadius": "8px", "padding": "20px", "textAlign": "center", "minWidth": "180px"}),
                html.Div(id="kpi-malicious", style={"backgroundColor": "#161b22", "border": "1px solid #f85149", "borderRadius": "8px", "padding": "20px", "textAlign": "center", "minWidth": "180px"}),
                html.Div(id="kpi-ips",       style={"backgroundColor": "#161b22", "border": "1px solid #d29922", "borderRadius": "8px", "padding": "20px", "textAlign": "center", "minWidth": "180px"}),
                html.Div(id="kpi-ids",       style={"backgroundColor": "#161b22", "border": "1px solid #3fb950", "borderRadius": "8px", "padding": "20px", "textAlign": "center", "minWidth": "180px"}),
            ]
        ),

        # Row 1: Timeline + Log type pie
        html.Div(style={"display": "flex", "gap": "20px", "marginBottom": "20px"}, children=[
            html.Div(dcc.Graph(id="chart-timeline"), style={"flex": "2", "backgroundColor": "#161b22", "borderRadius": "8px"}),
            html.Div(dcc.Graph(id="chart-logtype"),  style={"flex": "1", "backgroundColor": "#161b22", "borderRadius": "8px"}),
        ]),

        # Row 2: Top malicious src IPs + Top malicious dst IPs
        html.Div(style={"display": "flex", "gap": "20px", "marginBottom": "20px"}, children=[
            html.Div(dcc.Graph(id="chart-top-ips-src"), style={"flex": "1", "backgroundColor": "#161b22", "borderRadius": "8px"}),
            html.Div(dcc.Graph(id="chart-top-ips-dst"), style={"flex": "1", "backgroundColor": "#161b22", "borderRadius": "8px"}),
        ]),

        # Row 3: Severity + HTTP status
        html.Div(style={"display": "flex", "gap": "20px", "marginBottom": "20px"}, children=[
            html.Div(dcc.Graph(id="chart-severity"), style={"flex": "1", "backgroundColor": "#161b22", "borderRadius": "8px"}),
            html.Div(dcc.Graph(id="chart-http"),     style={"flex": "1", "backgroundColor": "#161b22", "borderRadius": "8px"}),
        ]),

        # Row 4: Alert types
        html.Div(style={"marginBottom": "20px"}, children=[
            html.Div(dcc.Graph(id="chart-alerts"), style={"backgroundColor": "#161b22", "borderRadius": "8px"}),
        ]),

        # Malicious events table
        html.Div(
            style={"backgroundColor": "#161b22", "borderRadius": "8px", "padding": "20px", "border": "1px solid #30363d"},
            children=[
                html.H3("🚨 Latest Malicious Events", style={"color": "#f85149", "marginTop": "0"}),
                html.Div(id="table-malicious"),
            ]
        ),
    ]
)


def empty_fig(title: str) -> go.Figure:
    """Build a placeholder figure used when no data is available."""
    fig = go.Figure()
    fig.update_layout(title=f"{title} (no data yet)", **DARK)
    return fig


def kpi_card(label: str, value, color: str):
    """Render KPI card content used in the top summary section."""
    return [
        html.P(label, style={"color": "#8b949e", "margin": "0", "fontSize": "12px"}),
        html.H2(str(value), style={"color": color, "margin": "5px 0", "fontSize": "28px"}),
    ]


@app.callback(
    Output("last-update",       "children"),
    Output("kpi-total",         "children"),
    Output("kpi-malicious",     "children"),
    Output("kpi-ips",           "children"),
    Output("kpi-ids",           "children"),
    Output("chart-timeline",    "figure"),
    Output("chart-logtype",     "figure"),
    Output("chart-top-ips-src", "figure"),
    Output("chart-top-ips-dst", "figure"),
    Output("chart-severity",    "figure"),
    Output("chart-http",        "figure"),
    Output("chart-alerts",      "figure"),
    Output("table-malicious",   "children"),
    Input("interval", "n_intervals"),
)
def update(_):
    """Refresh dashboard KPIs, charts, and tables on each interval tick."""
    import datetime
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    total     = query("SELECT COUNT(*) as n FROM security_events")
    malicious = query("SELECT COUNT(*) as n FROM security_events WHERE is_malicious_src=1 OR is_malicious_dst=1")
    uniq_ips  = query("SELECT COUNT(DISTINCT src_ip) as n FROM security_events WHERE is_malicious_src=1")
    ids_count = query("SELECT COUNT(*) as n FROM security_events WHERE log_type='ids'")

    def safe_int(df):
        try:
            v = df["n"][0]
            return 0 if (df.empty or v != v) else int(v)
        except Exception:
            return 0

    n_total     = safe_int(total)
    n_malicious = safe_int(malicious)
    n_ips       = safe_int(uniq_ips)
    n_ids       = safe_int(ids_count)

    tl = query("""
        SELECT
            strftime('%H:%M', timestamp) as minute,
            SUM(CASE WHEN is_malicious_src=1 OR is_malicious_dst=1 THEN 1 ELSE 0 END) as malicious,
            COUNT(*) as total
        FROM security_events
        WHERE timestamp IS NOT NULL AND length(timestamp) >= 16
        GROUP BY minute ORDER BY minute ASC LIMIT 60
    """)
    if not tl.empty:
        fig_tl = go.Figure()
        fig_tl.add_trace(go.Scatter(x=tl["minute"], y=tl["total"],     name="Total",     line={"color": "#58a6ff", "width": 2}))
        fig_tl.add_trace(go.Scatter(x=tl["minute"], y=tl["malicious"], name="Malicious", line={"color": "#f85149", "width": 2}))
        fig_tl.update_layout(title="Events Over Time (per minute)", legend={"orientation": "h"}, **DARK)
    else:
        fig_tl = empty_fig("Events Over Time")

    lt = query("SELECT log_type, COUNT(*) as count FROM security_events GROUP BY log_type")
    if not lt.empty:
        fig_lt = px.pie(lt, names="log_type", values="count", title="Log Type Breakdown",
                        color_discrete_sequence=["#58a6ff", "#3fb950", "#d29922"])
        fig_lt.update_layout(**DARK)
    else:
        fig_lt = empty_fig("Log Type Breakdown")

    tip_src = query("""
        SELECT src_ip as ip, MAX(threat_score_src) as score, COUNT(*) as hits
        FROM security_events WHERE is_malicious_src=1
        GROUP BY src_ip ORDER BY hits DESC LIMIT 10
    """)
    if not tip_src.empty:
        fig_src = px.bar(tip_src, x="hits", y="ip", orientation="h",
                         title="Top 10 Malicious Source IPs (inbound threat)",
                         color="score", color_continuous_scale="Reds")
        fig_src.update_layout(**DARK)
    else:
        fig_src = empty_fig("Top 10 Malicious Source IPs")

    tip_dst = query("""
        SELECT dest_ip as ip, MAX(threat_score_dst) as score, COUNT(*) as hits
        FROM security_events WHERE is_malicious_dst=1
        GROUP BY dest_ip ORDER BY hits DESC LIMIT 10
    """)
    if not tip_dst.empty:
        fig_dst = px.bar(tip_dst, x="hits", y="ip", orientation="h",
                         title="Top 10 Malicious Destination IPs (exfiltration / C2)",
                         color="score", color_continuous_scale="Oranges")
        fig_dst.update_layout(**DARK)
    else:
        fig_dst = empty_fig("Top 10 Malicious Destination IPs")

    sev = query("""
        SELECT severity, COUNT(*) as count FROM security_events
        WHERE log_type='ids' GROUP BY severity ORDER BY count DESC
    """)
    if not sev.empty:
        fig_sev = px.bar(sev, x="severity", y="count", title="IDS Severity Breakdown",
                         color="severity", color_discrete_map={
                             "low_severity":      "#3fb950",
                             "medium_severity":   "#d29922",
                             "high_severity":     "#f0883e",
                             "critical_severity": "#f85149",
                         })
        fig_sev.update_layout(**DARK)
    else:
        fig_sev = empty_fig("IDS Severity Breakdown")

    http = query("""
        SELECT CAST(status AS TEXT) as status, COUNT(*) as count
        FROM security_events WHERE log_type='access' AND status IS NOT NULL
        GROUP BY status ORDER BY count DESC LIMIT 12
    """)
    if not http.empty:
        fig_http = px.bar(http, x="status", y="count", title="HTTP Status Codes",
                          color_discrete_sequence=["#58a6ff"])
        fig_http.update_layout(**DARK)
    else:
        fig_http = empty_fig("HTTP Status Codes")

    alerts = query("""
        SELECT alert_desc, COUNT(*) as count FROM security_events
        WHERE log_type='ids' AND alert_desc IS NOT NULL
        GROUP BY alert_desc ORDER BY count DESC
    """)
    if not alerts.empty:
        fig_alerts = px.bar(alerts, x="count", y="alert_desc", orientation="h",
                            title="IDS Alert Types",
                            color_discrete_sequence=["#d29922"])
        fig_alerts.update_layout(**DARK)
    else:
        fig_alerts = empty_fig("IDS Alert Types")

    mal = query("""
        SELECT timestamp, log_type,
               COALESCE(src_ip, client_ip) as src_ip,
               dest_ip,
               CASE
                 WHEN is_malicious_src=1 THEN threat_score_src
                 ELSE threat_score_dst
               END as threat_score,
               CASE
                 WHEN is_malicious_src=1 AND is_malicious_dst=1 THEN 'src + dst'
                 WHEN is_malicious_src=1 THEN 'src'
                 ELSE 'dst'
               END as direction,
               alert_desc
        FROM security_events
        WHERE is_malicious_src=1 OR is_malicious_dst=1
        ORDER BY timestamp DESC LIMIT 20
    """)
    if not mal.empty:
        table = html.Table(
            [html.Tr([
                html.Th(c, style={"color": "#58a6ff", "padding": "8px 12px",
                                  "borderBottom": "1px solid #30363d", "textAlign": "left"})
                for c in mal.columns
            ])] +
            [html.Tr([
                html.Td(str(v), style={"color": "#c9d1d9", "padding": "6px 12px", "fontSize": "12px"})
                for v in row
            ]) for _, row in mal.iterrows()],
            style={"width": "100%", "borderCollapse": "collapse"}
        )
    else:
        table = html.P("No malicious events detected yet.", style={"color": "#8b949e"})

    return (
        f"Last updated: {now}",
        kpi_card("Total Events",         f"{n_total:,}",     "#58a6ff"),
        kpi_card("Malicious Hits",       f"{n_malicious:,}", "#f85149"),
        kpi_card("Unique Malicious IPs", f"{n_ips:,}",       "#d29922"),
        kpi_card("IDS Events",           f"{n_ids:,}",       "#3fb950"),
        fig_tl, fig_lt, fig_src, fig_dst, fig_sev, fig_http, fig_alerts, table,
    )


if __name__ == "__main__":
    app.run(debug=False, host="0.0.0.0", port=8050)