import glob
import os
import re

import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.backends.backend_pdf import PdfPages
from matplotlib.ticker import FuncFormatter

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RESULTS_DIR = os.path.join(ROOT, "results")
TVLA_THRESHOLD = 5.3
UTIL_ROWS = ["Slice LUTs", "Slice Registers", "Block RAM Tile", "DSPs"]
TIMING_KEYS = ["WNS(ns)", "TNS(ns)", "TNS failing endpoints", "TNS total endpoints",
               "WHS(ns)", "THS(ns)", "THS failing endpoints", "THS total endpoints"]

TARGET_POINTS = 5000
SAMPLES_PER_CYCLE = 4
DROP_FIRST = 168 * SAMPLES_PER_CYCLE
DROP_LAST = 540 * SAMPLES_PER_CYCLE
OP_LENGTH = 30486 * SAMPLES_PER_CYCLE
OPERATIONS = [
  (r"$\bar{\mathbf{O}}_b\mathbf{LU}$", 2640 * 2),
  (r"$\mathbf{vPv}$", 2353),
  (r"$\mathbf{vP}$", 3840),
  (r"$\mathbf{vP}\bar{\mathbf{O}}_b$", 2560),
  (r"$\mathbf{vP}$", 3840),
  (r"$\mathbf{vP}\bar{\mathbf{O}}_b$", 2560),
  (r"$\mathbf{GE}$", 9705),
  (r"$\mathbf{v}+\bar{\mathbf{O}}_b\mathbf{x}$", 187),
]
T_COLOR = (200 / 255, 30 / 255, 30 / 255)
TRACE_COLOR = "0.68"
RNG_ON_TLIM = 9.0
X_SCALE = 1e4
TRACE_SCALE = 1e3
PANEL_SIZE = (4.6, 3.0)


def readFile(name):
  path = os.path.join(RESULTS_DIR, name)
  if not os.path.isfile(path):
    return ""
  with open(path, errors="ignore") as f:
    return f.read()


def getLatencies(log):
  rows = []
  for lvl, cyc in re.findall(r"uov_wrapper_tb\[(\S+)\]: uov sign execution took (\d+) clock cycles", log):
    rows.append(("sign  " + lvl, cyc))
  for lvl, inv, cyc in re.findall(r"uov_wrapper_tb\[(\S+)\]: uov verif \(invalid=(\d+)\) took (\d+) clock cycles", log):
    rows.append(("verif %s (%s signature)" % (lvl, "valid" if inv == "0" else "invalid"), cyc))
  return rows


def getUtilization(rpt):
  rows = []
  for name in UTIL_ROWS:
    m = re.search(r"^\|\s*" + re.escape(name) + r"\*?\s*\|\s*(\d+)\s*\|[^|]*\|[^|]*\|\s*(\d+)\s*\|\s*(\S+)\s*\|", rpt, re.M)
    if m:
      rows.append((name, m.group(1), m.group(2), m.group(3)))
  return rows


def getTiming(rpt):
  m = re.search(r"^\s*WNS\(ns\).*\n\s*-+.*\n\s*(.+)$", rpt, re.M)
  if not m:
    return []
  return list(zip(TIMING_KEYS, m.group(1).split()))


def loadTvla():
  runs = []
  for path in sorted(glob.glob(os.path.join(RESULTS_DIR, "tvla_*.npz"))):
    d = np.load(path)
    t = np.asarray(d["t_values"], dtype=float).ravel()
    avg = np.asarray(d["avg_trace"], dtype=float).ravel()
    window = slice(DROP_FIRST, OP_LENGTH - DROP_LAST)
    if t[window].size:
      t, avg = t[window], avg[window]
    name = os.path.basename(path)[:-4]
    m = re.match(r"tvla_rng(On|Off)_(\d+)_", name)
    rng_on = m.group(1) == "On" if m else True
    n_pairs = int(m.group(2)) if m else 0
    runs.append({"rng_on": rng_on, "n": n_pairs, "t": t, "avg": avg,
                 "tmax": float(np.nanmax(np.abs(t)))})
  return runs


def peakPreservingIndices(values, target):
  ns = values.shape[0]
  if target >= ns:
    return np.arange(ns)
  bounds = np.linspace(0, ns, target + 1, dtype=int)
  keep = []
  a = bounds[0]
  for b in bounds[1:]:
    if b > a:
      keep.append(a + int(np.argmax(np.abs(values[a:b]))))
      a = b
  return np.array(sorted(set(keep)), dtype=int)


def envelopeIndices(values, target):
  ns = values.shape[0]
  nblocks = max(1, target // 2)
  if nblocks >= ns:
    return np.arange(ns)
  bounds = np.linspace(0, ns, nblocks + 1, dtype=int)
  keep = []
  for a, b in zip(bounds[:-1], bounds[1:]):
    if b > a:
      keep.extend(sorted((a + int(np.argmin(values[a:b])), a + int(np.argmax(values[a:b])))))
  return np.array(sorted(set(keep)), dtype=int)


def niceTLimit(tmax):
  if tmax <= TVLA_THRESHOLD * 1.5:
    return float(np.ceil(TVLA_THRESHOLD * 1.5))
  k = np.floor(np.log10(tmax))
  base = 10 ** k
  for m in (1, 2, 2.5, 5, 10):
    if m * base >= tmax:
      return float(m * base)


def operationOverlay(ax, ns, tlim):
  x = 0
  for i, (label, cycles) in enumerate(OPERATIONS):
    x0, x1 = x, x + cycles * SAMPLES_PER_CYCLE
    x = x1
    vx0, vx1 = max(0, x0), min(ns, x1)
    if vx1 <= vx0:
      continue
    if 0 < x1 < ns:
      ax.axvline(x1, color="k", ls=(0, (1, 1)), lw=0.5)
    if i == 0 or "GE" in label:
      ax.text(0.5 * (vx0 + vx1), -tlim, label, fontsize=10, ha="center", va="bottom")
    else:
      ax.text(0.5 * (vx0 + vx1), -tlim, label, fontsize=10, rotation=90,
              ha="center", va="bottom")


def tvlaPanel(fig, rect, run):
  t, avg = run["t"], run["avg"]
  ns = t.shape[0]
  tlim = RNG_ON_TLIM if run["rng_on"] else niceTLimit(run["tmax"])

  ax_tr = fig.add_axes(rect)
  sel = envelopeIndices(avg, TARGET_POINTS)
  ax_tr.plot(sel, avg[sel], color=TRACE_COLOR, lw=0.2)
  ax_tr.set_xlim(0, ns - 1)
  ax_tr.set_ylim(np.floor(avg.min()), np.ceil(avg.max()))
  ax_tr.yaxis.tick_right()
  ax_tr.yaxis.set_label_position("right")
  ax_tr.yaxis.set_major_formatter(FuncFormatter(lambda v, p: "%g" % (v / TRACE_SCALE)))
  ax_tr.set_ylabel("ADC Measurement $\\times 10^{3}$ (grey)", fontsize=8)
  ax_tr.set_xticks([])
  for side in ("top", "left", "bottom"):
    ax_tr.spines[side].set_visible(False)
  ax_tr.tick_params(labelsize=7)

  ax = fig.add_axes(rect, facecolor="none")
  sel = peakPreservingIndices(t, TARGET_POINTS)
  if run["rng_on"]:
    ax.axhline(TVLA_THRESHOLD, color="k", ls="--", lw=1.1)
    ax.axhline(-TVLA_THRESHOLD, color="k", ls="--", lw=1.1)
    ax.set_yticks([-tlim, -TVLA_THRESHOLD, 0, TVLA_THRESHOLD, tlim])
  ax.plot(sel, t[sel], color=T_COLOR, lw=0.3)
  ax.set_xlim(0, ns - 1)
  ax.set_ylim(-tlim, tlim)
  ax.xaxis.set_major_formatter(FuncFormatter(lambda v, p: "%g" % (v / X_SCALE)))
  ax.set_xlabel("Sample Nr. $\\times 10^{4}$", fontsize=8)
  ax.set_ylabel("$t$-value (red)", fontsize=8)
  for side in ("top", "right"):
    ax.spines[side].set_visible(False)
  ax.tick_params(labelsize=7)
  operationOverlay(ax, ns, tlim)
  ax.set_title("%s ($n_\\mathrm{tr}$ = %s traces)" % ("RNG On" if run["rng_on"] else "RNG Off",
                                                     "{:,}".format(run["n"])), fontsize=9)


def textPage(pdf, title, lines):
  fig = plt.figure(figsize=(8.27, 11.69))
  fig.text(0.08, 0.95, title, fontsize=15, weight="bold", va="top")
  fig.text(0.08, 0.90, "\n".join(lines), fontsize=8, family="monospace", va="top")
  pdf.savefig(fig)
  plt.close(fig)


def tvlaFigure(pdf, runs):
  pw, ph = PANEL_SIZE
  fw = 1.0 + pw * len(runs) + 1.5 * (len(runs) - 1) + 1.1
  fh = ph + 1.5
  fig = plt.figure(figsize=(fw, fh))
  fig.suptitle("TVLA", fontsize=12,
               weight="bold", y=1 - 0.4 / fh)
  for i, run in enumerate(runs):
    x0 = (1.0 + i * (pw + 1.5)) / fw
    tvlaPanel(fig, [x0, 0.7 / fh, pw / fw, ph / fh], run)
  pdf.savefig(fig)
  plt.close(fig)


if __name__ == "__main__":
  hls_log = readFile("vitis_hls.log")
  vivado_log = readFile("vivado.log")
  util = getUtilization(readFile("utilization.rpt"))
  timing = getTiming(readFile("timing.rpt"))
  tvla = loadTvla()

  lines = [""]

  lines += ["Stages", "------"]
  lines.append("  Vitis HLS        : %s" % ("passed" if "IP export passed" in hls_log else "MISSING/FAILED"))
  lines.append("  RTL simulation   : %s" % ("passed" if "uov_wrapper_tb: all checks passed" in vivado_log else "MISSING/FAILED"))
  lines.append("  Implementation   : %s" % ("passed" if "STATUS: Bitstream written" in vivado_log else "MISSING/FAILED"))
  lines.append("")

  lines += ["Simulated latency (clock cycles)", "-------------------------------"]
  latencies = getLatencies(vivado_log)
  if latencies:
    width = max(len(label) for label, _ in latencies)
    for label, cyc in latencies:
      lines.append("  %-*s %10s" % (width, label, cyc))
  else:
    lines.append("  no latency information in results/vivado.log")
  lines.append("")

  lines += ["Post-implementation utilization (uov_wrapper_inst)",
            "--------------------------------------------------"]
  if util:
    lines.append("  %-18s %10s %12s %8s" % ("site type", "used", "available", "util%"))
    for name, used, avail, pct in util:
      lines.append("  %-18s %10s %12s %8s" % (name, used, avail, pct))
  else:
    lines.append("  results/utilization.rpt missing")
  lines.append("")

  lines += ["Post-route timing", "-----------------"]
  if timing:
    for key, val in timing:
      lines.append("  %-24s %12s" % (key, val))
  else:
    lines.append("  results/timing.rpt missing")
  if not tvla:
    lines += ["", "TVLA", "----", "  no traces found in results/"]

  out = os.path.join(RESULTS_DIR, "report.pdf")
  with PdfPages(out) as pdf:
    textPage(pdf, "Summary Artifact Results - UOV Coprocessor", lines)
    final = [max((r for r in tvla if r["rng_on"] == on), key=lambda r: r["n"], default=None)
             for on in (False, True)]
    final = [r for r in final if r is not None]
    if final:
      tvlaFigure(pdf, final)
    shown = set(id(r) for r in final)
    for run in tvla:
      if id(run) not in shown:
        tvlaFigure(pdf, [run])

  print("Report written to " + out)
