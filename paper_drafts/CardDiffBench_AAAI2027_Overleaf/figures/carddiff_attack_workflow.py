"""Draw the A2ACardBench/CardDiff attack workflow as a publication figure.

The figure is intentionally schematic: it encodes the control-plane mechanism
and the seven active attack vectors discussed in the manuscript.  No empirical
values are plotted here; attack success is represented by the event-level
oracle implemented by the benchmark harness.
"""

from __future__ import annotations

from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import Circle, FancyArrowPatch, FancyBboxPatch, Polygon


# Mandatory publication/export settings: keep SVG text editable.
plt.rcParams["font.family"] = "sans-serif"
plt.rcParams["font.sans-serif"] = ["Arial", "DejaVu Sans", "Liberation Sans"]
plt.rcParams["svg.fonttype"] = "none"
plt.rcParams["pdf.fonttype"] = 42
plt.rcParams["font.size"] = 6.2
plt.rcParams["axes.linewidth"] = 0.8
plt.rcParams["legend.frameon"] = False


COLORS = {
    "ink": "#272727",
    "muted": "#686868",
    "line": "#A8A8A8",
    "panel": "#F8F8F8",
    "white": "#FFFFFF",
    "blue": "#0F4D92",
    "blue_2": "#3775BA",
    "blue_light": "#E9F1FA",
    "red": "#C83E4D",
    "red_light": "#FBE9EB",
    "state": "#7C6CCF",
    "state_light": "#F1EEFA",
    "select": "#248F83",
    "select_light": "#E6F6F3",
    "policy": "#B56D32",
    "policy_light": "#FBF0E6",
    "green": "#2E8B57",
    "green_light": "#E8F5ED",
}


def rounded_box(
    ax,
    x,
    y,
    w,
    h,
    *,
    facecolor="white",
    edgecolor=None,
    linewidth=0.8,
    radius=0.012,
    zorder=1,
    linestyle="-",
):
    patch = FancyBboxPatch(
        (x, y),
        w,
        h,
        boxstyle=f"round,pad=0.004,rounding_size={radius}",
        facecolor=facecolor,
        edgecolor=edgecolor or COLORS["line"],
        linewidth=linewidth,
        linestyle=linestyle,
        transform=ax.transAxes,
        clip_on=False,
        zorder=zorder,
    )
    ax.add_patch(patch)
    return patch


def arrow(ax, start, end, *, color=None, linewidth=1.25, mutation_scale=9, zorder=5, style="-|>"):
    patch = FancyArrowPatch(
        start,
        end,
        arrowstyle=style,
        mutation_scale=mutation_scale,
        linewidth=linewidth,
        color=color or COLORS["blue"],
        transform=ax.transAxes,
        connectionstyle="arc3,rad=0",
        shrinkA=0,
        shrinkB=0,
        clip_on=False,
        zorder=zorder,
    )
    ax.add_patch(patch)
    return patch


def text(ax, x, y, value, *, size=6.2, color=None, weight="normal", ha="left", va="center", zorder=10, **kwargs):
    return ax.text(
        x,
        y,
        value,
        transform=ax.transAxes,
        fontsize=size,
        color=color or COLORS["ink"],
        fontweight=weight,
        ha=ha,
        va=va,
        zorder=zorder,
        **kwargs,
    )


def pill(ax, x, y, w, label, *, facecolor, edgecolor, color=None, size=5.5, weight="bold"):
    rounded_box(
        ax,
        x,
        y,
        w,
        0.032,
        facecolor=facecolor,
        edgecolor=edgecolor,
        linewidth=0.65,
        radius=0.012,
        zorder=4,
    )
    text(ax, x + w / 2, y + 0.016, label, size=size, color=color or edgecolor, weight=weight, ha="center")


def stage_badge(ax, x, y, number, color):
    circ = Circle((x, y), 0.014, transform=ax.transAxes, facecolor=color, edgecolor="none", zorder=8)
    ax.add_patch(circ)
    text(ax, x, y, str(number), size=6.3, color=COLORS["white"], weight="bold", ha="center")


def document_icon(ax, x, y, w, h, *, title, rows, highlight_rows=(), edge=None):
    """Small AgentCard document with a folded corner and optional red rows."""
    edge = edge or COLORS["line"]
    rounded_box(ax, x, y, w, h, facecolor=COLORS["white"], edgecolor=edge, linewidth=0.8, radius=0.004, zorder=3)
    fold = 0.014
    tri = Polygon(
        [(x + w - fold, y + h), (x + w, y + h - fold), (x + w - fold, y + h - fold)],
        closed=True,
        transform=ax.transAxes,
        facecolor=COLORS["panel"],
        edgecolor=edge,
        linewidth=0.55,
        zorder=5,
    )
    ax.add_patch(tri)
    text(ax, x + 0.007, y + h - 0.019, title, size=5.3, weight="bold", va="top")
    row_y = y + h - 0.050
    for index, label in enumerate(rows):
        is_highlighted = index in set(highlight_rows)
        if is_highlighted:
            rounded_box(
                ax,
                x + 0.005,
                row_y - 0.009,
                w - 0.010,
                0.021,
                facecolor=COLORS["red_light"],
                edgecolor=COLORS["red"],
                linewidth=0.45,
                radius=0.003,
                zorder=4,
            )
        text(
            ax,
            x + 0.009,
            row_y,
            label,
            size=4.45,
            color=COLORS["red"] if is_highlighted else COLORS["muted"],
            weight="bold" if is_highlighted else "normal",
        )
        row_y -= 0.026


def attack_row(ax, x, y, w, attack_id, title, delta, outcome, *, accent, fill):
    rounded_box(ax, x, y, w, 0.072, facecolor=COLORS["white"], edgecolor=accent, linewidth=0.68, radius=0.007)
    pill(
        ax,
        x + 0.007,
        y + 0.033,
        0.036,
        attack_id,
        facecolor=fill,
        edgecolor=accent,
        color=accent,
        size=5.2,
    )
    text(ax, x + 0.050, y + 0.055, title, size=5.35, weight="bold", va="center")
    text(ax, x + 0.050, y + 0.026, delta, size=4.55, color=COLORS["red"], va="center")
    text(ax, x + w - 0.006, y + 0.026, outcome, size=4.55, color=COLORS["blue"], ha="right", va="center")
    arrow(
        ax,
        (x + w * 0.58, y + 0.026),
        (x + w * 0.68, y + 0.026),
        color=COLORS["muted"],
        linewidth=0.65,
        mutation_scale=5.5,
        zorder=7,
    )


def build_figure():
    fig = plt.figure(figsize=(7.2, 6.0), facecolor="white")
    ax = fig.add_axes([0, 0, 1, 1])
    ax.set_xlim(0, 1)
    ax.set_ylim(0, 1)
    ax.set_axis_off()

    # Panel a: complete attack path.
    text(ax, 0.017, 0.972, "a", size=8.6, weight="bold", va="top")
    text(ax, 0.046, 0.968, "How a schema-valid CardDiff attack unfolds", size=9.1, weight="bold", va="top")
    text(
        ax,
        0.046,
        0.943,
        "A minimal control-plane perturbation propagates from AgentCard state to observable protocol behavior.",
        size=5.7,
        color=COLORS["muted"],
        va="top",
    )

    panel_y, panel_h = 0.515, 0.397
    rounded_box(ax, 0.025, panel_y, 0.950, panel_h, facecolor="#FCFCFC", edgecolor="#C8C8C8", linewidth=0.75, radius=0.008)

    # 1) Interaction context.
    x, y, w, h = 0.045, 0.585, 0.145, 0.255
    rounded_box(ax, x, y, w, h, facecolor=COLORS["panel"], edgecolor=COLORS["line"], linewidth=0.75)
    text(ax, x + 0.010, y + h - 0.024, "Interaction context", size=6.5, weight="bold", va="top")
    pill(ax, x + 0.010, y + 0.167, 0.125, "task  t", facecolor=COLORS["white"], edgecolor=COLORS["blue_2"], color=COLORS["blue"])
    pill(ax, x + 0.010, y + 0.122, 0.125, "identity  i  ·  scopes  S", facecolor=COLORS["white"], edgecolor=COLORS["line"], color=COLORS["ink"], size=4.9)
    pill(ax, x + 0.010, y + 0.077, 0.125, "accepted modes  M", facecolor=COLORS["white"], edgecolor=COLORS["line"], color=COLORS["ink"], size=5.0)
    pill(ax, x + 0.010, y + 0.032, 0.125, "trusted policy  Π", facecolor=COLORS["green_light"], edgecolor=COLORS["green"], color=COLORS["green"], size=5.0)

    # 2) CardDiff construction and attack injection.
    x2, y2, w2, h2 = 0.230, 0.555, 0.205, 0.315
    rounded_box(ax, x2, y2, w2, h2, facecolor=COLORS["white"], edgecolor=COLORS["red"], linewidth=0.9)
    text(ax, x2 + 0.010, y2 + h2 - 0.023, "CardDiff construction", size=6.5, weight="bold", va="top")
    text(ax, x2 + w2 / 2, y2 + h2 - 0.055, "x = Gen(a, d, t, δ)", size=5.3, color=COLORS["muted"], ha="center")
    pill(ax, x2 + 0.012, y2 + 0.212, 0.052, "vector a", facecolor=COLORS["red_light"], edgecolor=COLORS["red"], color=COLORS["red"], size=4.6)
    pill(ax, x2 + 0.072, y2 + 0.212, 0.054, "domain d", facecolor=COLORS["panel"], edgecolor=COLORS["line"], color=COLORS["muted"], size=4.5)
    pill(ax, x2 + 0.134, y2 + 0.212, 0.058, "variant δ", facecolor=COLORS["panel"], edgecolor=COLORS["line"], color=COLORS["muted"], size=4.5)

    card_y = y2 + 0.028
    document_icon(
        ax,
        x2 + 0.012,
        card_y,
        0.083,
        0.158,
        title="Public card  C_p",
        rows=("skills", "interfaces", "security", "output modes"),
    )
    document_icon(
        ax,
        x2 + 0.111,
        card_y,
        0.082,
        0.158,
        title="Active  C_e(j)",
        rows=("+ skill", "URL / order / b,v", "scope req.", "MIME mode"),
        highlight_rows=(0, 1, 2, 3),
        edge=COLORS["red"],
    )
    arrow(ax, (x2 + 0.099, card_y + 0.079), (x2 + 0.108, card_y + 0.079), color=COLORS["red"], linewidth=1.0, mutation_scale=7)
    text(ax, x2 + 0.103, card_y + 0.100, "Δa", size=5.0, color=COLORS["red"], weight="bold", ha="center")
    text(ax, x2 + w2 / 2, y2 + 0.010, "only attack-relevant fields change; schema remains valid", size=4.3, color=COLORS["muted"], ha="center", va="bottom")

    # Attacker injects the differential, not the user's natural-language task.
    attacker_x, attacker_y = x2 + w2 / 2, 0.892
    circ = Circle((attacker_x, attacker_y), 0.015, transform=ax.transAxes, facecolor=COLORS["red"], edgecolor="none", zorder=8)
    ax.add_patch(circ)
    text(ax, attacker_x, attacker_y, "!", size=7.0, color=COLORS["white"], weight="bold", ha="center")
    text(ax, attacker_x + 0.023, attacker_y, "adversary", size=5.3, color=COLORS["red"], weight="bold")
    arrow(ax, (attacker_x, attacker_y - 0.017), (attacker_x, y2 + h2), color=COLORS["red"], linewidth=1.0, mutation_scale=7)

    # 3) Host control plane.
    x3, y3, w3, h3 = 0.480, 0.555, 0.270, 0.315
    rounded_box(ax, x3, y3, w3, h3, facecolor=COLORS["blue_light"], edgecolor=COLORS["blue_2"], linewidth=0.9)
    text(ax, x3 + 0.012, y3 + h3 - 0.023, "A2A Host control plane", size=6.5, weight="bold", va="top")
    text(ax, x3 + w3 - 0.012, y3 + h3 - 0.023, "F(ξ) = (d, k, u, b, v, q)", size=5.0, color=COLORS["blue"], ha="right", va="top")

    stages = [
        (1, "State admission", "fetch C_p  →  fetch / reuse C_e(j)", COLORS["state"], COLORS["state_light"]),
        (2, "Control-plane selection", "choose skill k  ·  interface u  ·  binding/version b,v", COLORS["select"], COLORS["select_light"]),
        (3, "Policy enforcement", "bind identity/scopes  ·  accepted modes  ·  artifact q", COLORS["policy"], COLORS["policy_light"]),
    ]
    stage_y = [y3 + 0.193, y3 + 0.112, y3 + 0.031]
    for idx, (number, title, detail, accent, fill) in enumerate(stages):
        sy = stage_y[idx]
        rounded_box(ax, x3 + 0.016, sy, w3 - 0.032, 0.064, facecolor=fill, edgecolor=accent, linewidth=0.72, radius=0.007)
        stage_badge(ax, x3 + 0.036, sy + 0.032, number, accent)
        text(ax, x3 + 0.058, sy + 0.043, title, size=5.65, weight="bold")
        text(ax, x3 + 0.058, sy + 0.019, detail, size=4.6, color=COLORS["muted"])
        if idx < 2:
            arrow(ax, (x3 + w3 / 2, sy - 0.002), (x3 + w3 / 2, stage_y[idx + 1] + 0.066), color=COLORS["blue_2"], linewidth=0.8, mutation_scale=6)

    # 4) Observable effects and event-level scoring.
    x4, y4, w4, h4 = 0.795, 0.555, 0.160, 0.315
    rounded_box(ax, x4, y4, w4, h4, facecolor=COLORS["white"], edgecolor=COLORS["blue_2"], linewidth=0.9)
    text(ax, x4 + 0.010, y4 + h4 - 0.023, "Observable effects", size=6.5, weight="bold", va="top")

    rounded_box(ax, x4 + 0.014, y4 + 0.206, w4 - 0.028, 0.063, facecolor=COLORS["blue_light"], edgecolor=COLORS["blue_2"], linewidth=0.65, radius=0.006)
    text(ax, x4 + w4 / 2, y4 + 0.247, "message dispatch", size=5.55, weight="bold", color=COLORS["blue"], ha="center")
    text(ax, x4 + w4 / 2, y4 + 0.222, "skill · URL · binding/version", size=4.55, color=COLORS["muted"], ha="center")

    rounded_box(ax, x4 + 0.014, y4 + 0.124, w4 - 0.028, 0.055, facecolor=COLORS["policy_light"], edgecolor=COLORS["policy"], linewidth=0.65, radius=0.006)
    text(ax, x4 + w4 / 2, y4 + 0.157, "artifact returned / accepted", size=5.1, weight="bold", color=COLORS["policy"], ha="center")
    text(ax, x4 + w4 / 2, y4 + 0.137, "artifact MIME", size=4.55, color=COLORS["muted"], ha="center")

    rounded_box(ax, x4 + 0.014, y4 + 0.025, w4 - 0.028, 0.071, facecolor=COLORS["green_light"], edgecolor=COLORS["green"], linewidth=0.75, radius=0.006)
    text(ax, x4 + w4 / 2, y4 + 0.076, "event trace  τ", size=5.35, weight="bold", color=COLORS["green"], ha="center")
    text(ax, x4 + w4 / 2, y4 + 0.052, "Φa(τ, ξ) = 1  →  attack success", size=4.65, color=COLORS["ink"], ha="center")
    text(ax, x4 + w4 / 2, y4 + 0.034, "ASR: control-plane event", size=4.35, color=COLORS["muted"], ha="center")

    arrow(ax, (x4 + w4 / 2, y4 + 0.204), (x4 + w4 / 2, y4 + 0.181), color=COLORS["blue_2"], linewidth=0.8, mutation_scale=6)
    arrow(ax, (x4 + w4 / 2, y4 + 0.122), (x4 + w4 / 2, y4 + 0.098), color=COLORS["blue_2"], linewidth=0.8, mutation_scale=6)

    # Major left-to-right flow arrows.
    arrow(ax, (0.191, 0.713), (0.226, 0.713), color=COLORS["blue"], linewidth=1.55, mutation_scale=10)
    arrow(ax, (0.437, 0.713), (0.476, 0.713), color=COLORS["blue"], linewidth=1.55, mutation_scale=10)
    arrow(ax, (0.752, 0.713), (0.791, 0.713), color=COLORS["blue"], linewidth=1.55, mutation_scale=10)
    text(ax, 0.208, 0.731, "instantiate", size=4.3, color=COLORS["muted"], ha="center")
    text(ax, 0.457, 0.731, "discover", size=4.3, color=COLORS["muted"], ha="center")
    text(ax, 0.772, 0.731, "execute", size=4.3, color=COLORS["muted"], ha="center")

    # Separate downstream impact from the event-level success criterion.
    rounded_box(ax, 0.815, 0.520, 0.120, 0.023, facecolor=COLORS["red_light"], edgecolor=COLORS["red"], linewidth=0.55, radius=0.009, linestyle="--")
    text(ax, 0.875, 0.5315, "separate impact oracle → DIR", size=4.35, color=COLORS["red"], weight="bold", ha="center")

    # Panel b: seven active attack vectors and their event-level success evidence.
    text(ax, 0.017, 0.478, "b", size=8.6, weight="bold", va="top")
    text(ax, 0.046, 0.475, "Seven active attack vectors map to three control-plane stages", size=8.0, weight="bold", va="top")
    text(ax, 0.954, 0.473, "red: injected differential     blue: observed target event", size=4.7, color=COLORS["muted"], ha="right", va="top")

    group_y, group_h = 0.055, 0.382
    groups = [
        (0.030, 0.355, "1", "AGENTCARD STATE ADMISSION", "public / extended / cached views", COLORS["state"], COLORS["state_light"]),
        (0.397, 0.275, "2", "CONTROL-PLANE SELECTION", "interface priority and protocol metadata", COLORS["select"], COLORS["select_light"]),
        (0.684, 0.286, "3", "POLICY ENFORCEMENT", "trusted scope and output constraints", COLORS["policy"], COLORS["policy_light"]),
    ]

    for gx, gw, number, title_value, subtitle, accent, fill in groups:
        rounded_box(ax, gx, group_y, gw, group_h, facecolor=fill, edgecolor=accent, linewidth=0.85, radius=0.009)
        stage_badge(ax, gx + 0.022, group_y + group_h - 0.028, number, accent)
        text(ax, gx + 0.043, group_y + group_h - 0.022, title_value, size=5.95, color=accent, weight="bold", va="top")
        text(ax, gx + 0.043, group_y + group_h - 0.044, subtitle, size=4.45, color=COLORS["muted"], va="top")

    # State-admission attacks.
    row_x, row_w = 0.041, 0.333
    attack_row(ax, row_x, 0.276, row_w, "A1", "Skill escalation", "C_e adds k_s", "k_s dispatched", accent=COLORS["state"], fill=COLORS["state_light"])
    attack_row(ax, row_x, 0.188, row_w, "A2", "Interface drift", "C_e adds URL u_d", "u_d selected", accent=COLORS["state"], fill=COLORS["state_light"])
    attack_row(ax, row_x, 0.100, row_w, "A3", "Cross-identity cache bleed", "i reuses C_e(j), i != j", "low-priv. k_s", accent=COLORS["state"], fill=COLORS["state_light"])

    # Selection attacks.
    row_x, row_w = 0.408, 0.253
    attack_row(ax, row_x, 0.231, row_w, "B1", "Interface order hijacking", "u_a moved to rank 1", "u_a selected", accent=COLORS["select"], fill=COLORS["select_light"])
    attack_row(ax, row_x, 0.127, row_w, "B2", "Binding / version confusion", "(b_a, v_a) != trusted", "adversarial pair used", accent=COLORS["select"], fill=COLORS["select_light"])

    # Policy attacks.
    row_x, row_w = 0.695, 0.264
    attack_row(ax, row_x, 0.231, row_w, "C1", "Authorization mismatch", "card req. < policy req.", "k_s sent; scope missing", accent=COLORS["policy"], fill=COLORS["policy_light"])
    attack_row(ax, row_x, 0.127, row_w, "C2", "Media mode drift", "MIME(y) outside M", "artifact accepted", accent=COLORS["policy"], fill=COLORS["policy_light"])

    text(
        ax,
        0.970,
        0.018,
        "Each trial preserves task intent and changes only the fields required by its attack-specific oracle.",
        size=4.7,
        color=COLORS["muted"],
        ha="right",
    )

    return fig


def main():
    out_dir = Path(__file__).resolve().parent
    base = out_dir / "carddiff_attack_workflow"
    fig = build_figure()
    fig.savefig(base.with_suffix(".svg"), bbox_inches="tight", pad_inches=0.03)
    fig.savefig(base.with_suffix(".pdf"), bbox_inches="tight", pad_inches=0.03)
    fig.savefig(base.with_suffix(".png"), dpi=300, bbox_inches="tight", pad_inches=0.03)
    fig.savefig(base.with_suffix(".tiff"), dpi=600, bbox_inches="tight", pad_inches=0.03)
    plt.close(fig)


if __name__ == "__main__":
    main()
