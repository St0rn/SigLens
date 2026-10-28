from __future__ import annotations

import json
import queue
import threading
from datetime import datetime
from pathlib import Path

from .analysis import AnalysisCancelled, AnalysisOptions, AnalysisResult, analyze_artifact
from .region_context import hexdump
from .report import save_html, save_json


class SigLensApp:
    def __init__(self, root, initial_file: Path | None = None):
        import tkinter as tk
        from tkinter import filedialog, messagebox, ttk

        self.tk = tk
        self.ttk = ttk
        self.filedialog = filedialog
        self.messagebox = messagebox
        self.root = root
        self.root.title("SigLens — St0rn / CybersecurIT")
        self.root.geometry("1180x760")
        self.root.minsize(900, 620)
        self.events: queue.Queue = queue.Queue()
        self.cancel_event = threading.Event()
        self.worker: threading.Thread | None = None
        self.result: AnalysisResult | None = None

        self.file_var = tk.StringVar(value=str(initial_file or ""))
        self.engines_var = tk.StringVar()
        self.amsi_var = tk.BooleanVar(value=False)
        self.iocs_var = tk.BooleanVar(value=True)
        self.dissect_var = tk.BooleanVar(value=True)
        self.status_var = tk.StringVar(value="Ready")
        self.progress_var = tk.IntVar(value=0)
        self.offset_var = tk.StringVar(value="0x0")

        self._configure_style()
        self._build_layout()
        self.root.protocol("WM_DELETE_WINDOW", self._close)
        self.root.after(80, self._poll_events)

    def _configure_style(self):
        style = self.ttk.Style(self.root)
        if "clam" in style.theme_names():
            style.theme_use("clam")
        self.root.configure(bg="#0b1020")
        style.configure(".", background="#111a33", foreground="#dce7ff")
        style.configure("TFrame", background="#0b1020")
        style.configure("TLabelframe", background="#0b1020", foreground="#dce7ff")
        style.configure("TLabelframe.Label", background="#0b1020", foreground="#8fb7ff")
        style.configure("TLabel", background="#0b1020", foreground="#dce7ff")
        style.configure("TCheckbutton", background="#0b1020", foreground="#dce7ff")
        style.configure("TNotebook", background="#0b1020", borderwidth=0)
        style.configure("TNotebook.Tab", background="#111a33", foreground="#dce7ff", padding=(12, 7))
        style.map("TNotebook.Tab", background=[("selected", "#263b70")])
        style.configure("Treeview", background="#111a33", fieldbackground="#111a33", foreground="#dce7ff")
        style.configure("Treeview.Heading", background="#263b70", foreground="#ffffff")

    def _build_layout(self):
        top = self.ttk.Frame(self.root, padding=10)
        top.pack(fill="x")
        self.ttk.Label(top, text="Artifact").grid(row=0, column=0, padx=(0, 6))
        self.ttk.Entry(top, textvariable=self.file_var).grid(row=0, column=1, sticky="ew")
        self.ttk.Button(top, text="Browse", command=self._browse).grid(row=0, column=2, padx=6)
        self.scan_button = self.ttk.Button(top, text="Analyze", command=self._start_analysis)
        self.scan_button.grid(row=0, column=3, padx=6)
        self.cancel_button = self.ttk.Button(top, text="Cancel", command=self._cancel, state="disabled")
        self.cancel_button.grid(row=0, column=4)
        top.columnconfigure(1, weight=1)

        options = self.ttk.Frame(self.root, padding=(10, 0, 10, 8))
        options.pack(fill="x")
        self.ttk.Checkbutton(options, text="AMSI", variable=self.amsi_var).pack(side="left", padx=(0, 12))
        self.ttk.Checkbutton(options, text="IOCs", variable=self.iocs_var).pack(side="left", padx=(0, 12))
        self.ttk.Checkbutton(options, text="PE dissection", variable=self.dissect_var).pack(side="left", padx=(0, 12))
        self.ttk.Label(options, text="Engine config").pack(side="left")
        self.ttk.Entry(options, textvariable=self.engines_var, width=42).pack(side="left", padx=6)
        self.ttk.Button(options, text="…", width=3, command=self._browse_engines).pack(side="left")

        self.notebook = self.ttk.Notebook(self.root)
        self.notebook.pack(fill="both", expand=True, padx=10, pady=(0, 8))
        self.summary = self._text_tab("Dashboard")
        self.av_tree = self._av_tab()
        self.amsi = self._text_tab("AMSI")
        self.pe = self._text_tab("PE Explorer")
        self.map_canvas = self._map_tab()
        self.hex_text = self._hex_tab()
        self.reports = self._reports_tab()

        footer = self.ttk.Frame(self.root, padding=(10, 0, 10, 10))
        footer.pack(fill="x")
        self.ttk.Progressbar(footer, variable=self.progress_var, maximum=100).pack(side="left", fill="x", expand=True)
        self.ttk.Label(footer, textvariable=self.status_var).pack(side="left", padx=(10, 0))

    def _text_tab(self, title):
        frame = self.ttk.Frame(self.notebook)
        text = self.tk.Text(frame, bg="#0a0f1e", fg="#dce7ff", insertbackground="#ffffff", wrap="none")
        text.pack(fill="both", expand=True)
        self.notebook.add(frame, text=title)
        return text

    def _av_tab(self):
        frame = self.ttk.Frame(self.notebook)
        columns = ("engine", "status", "signature", "duration", "diagnostic")
        tree = self.ttk.Treeview(frame, columns=columns, show="headings")
        for column, width in zip(columns, (180, 100, 260, 100, 420)):
            tree.heading(column, text=column.title())
            tree.column(column, width=width, anchor="w")
        tree.pack(fill="both", expand=True)
        self.notebook.add(frame, text="AV Engines")
        return tree

    def _map_tab(self):
        frame = self.ttk.Frame(self.notebook)
        canvas = self.tk.Canvas(frame, bg="#0a0f1e", highlightthickness=0)
        canvas.pack(fill="both", expand=True)
        self.notebook.add(frame, text="Detection Map")
        return canvas

    def _hex_tab(self):
        frame = self.ttk.Frame(self.notebook)
        bar = self.ttk.Frame(frame, padding=5)
        bar.pack(fill="x")
        self.ttk.Label(bar, text="Offset").pack(side="left")
        self.ttk.Entry(bar, textvariable=self.offset_var, width=16).pack(side="left", padx=6)
        self.ttk.Button(bar, text="Go", command=self._show_hex).pack(side="left")
        text = self.tk.Text(frame, bg="#0a0f1e", fg="#dce7ff", font=("Consolas", 10), wrap="none")
        text.pack(fill="both", expand=True)
        self.notebook.add(frame, text="Hex Viewer")
        return text

    def _reports_tab(self):
        frame = self.ttk.Frame(self.notebook)
        bar = self.ttk.Frame(frame, padding=5)
        bar.pack(fill="x")
        self.ttk.Button(bar, text="Export JSON", command=lambda: self._export("json")).pack(side="left", padx=4)
        self.ttk.Button(bar, text="Export HTML", command=lambda: self._export("html")).pack(side="left", padx=4)
        text = self.tk.Text(frame, bg="#0a0f1e", fg="#dce7ff", wrap="none")
        text.pack(fill="both", expand=True)
        self.notebook.add(frame, text="Reports")
        return text

    def _browse(self):
        value = self.filedialog.askopenfilename(title="Select artifact")
        if value:
            self.file_var.set(value)

    def _browse_engines(self):
        value = self.filedialog.askopenfilename(title="Select engine configuration", filetypes=[("JSON", "*.json")])
        if value:
            self.engines_var.set(value)

    def _start_analysis(self):
        if self.worker and self.worker.is_alive():
            return
        path = Path(self.file_var.get().strip())
        if not path.is_file():
            self.messagebox.showerror("SigLens", "Select a readable artifact first.")
            return
        engines = self.engines_var.get().strip()
        self.cancel_event = threading.Event()
        options = AnalysisOptions(
            engines_path=Path(engines) if engines else None,
            run_amsi=self.amsi_var.get(),
            extract_iocs=self.iocs_var.get(),
            dissect_pe=self.dissect_var.get(),
        )
        self.scan_button.configure(state="disabled")
        self.cancel_button.configure(state="normal")
        self.progress_var.set(0)
        self.status_var.set("Starting")
        self.worker = threading.Thread(target=self._worker, args=(path, options), daemon=True)
        self.worker.start()

    def _worker(self, path, options):
        try:
            result = analyze_artifact(
                path,
                options,
                cancel_event=self.cancel_event,
                progress=lambda message, percent: self.events.put(("progress", message, percent)),
            )
            self.events.put(("result", result))
        except AnalysisCancelled:
            self.events.put(("cancelled",))
        except Exception as exc:
            self.events.put(("error", type(exc).__name__, str(exc)))

    def _cancel(self):
        self.cancel_event.set()
        self.status_var.set("Cancellation requested")

    def _poll_events(self):
        try:
            while True:
                event = self.events.get_nowait()
                if event[0] == "progress":
                    self.status_var.set(event[1])
                    self.progress_var.set(event[2])
                elif event[0] == "result":
                    self.result = event[1]
                    self._render_result()
                    self._finish("Complete")
                elif event[0] == "cancelled":
                    self._finish("Cancelled")
                elif event[0] == "error":
                    self._finish("Failed")
                    self.messagebox.showerror("SigLens", f"{event[1]}: {event[2]}")
        except queue.Empty:
            pass
        self.root.after(80, self._poll_events)

    def _finish(self, status):
        self.status_var.set(status)
        self.scan_button.configure(state="normal")
        self.cancel_button.configure(state="disabled")

    @staticmethod
    def _set_text(widget, value):
        widget.delete("1.0", "end")
        widget.insert("1.0", value)

    def _render_result(self):
        report = self.result.report
        summary = {
            "file": report.get("file"),
            "schema_version": report.get("schema_version"),
            "pe": report.get("pe", {}).get("is_pe"),
            "multiav": report.get("multiav", {}).get("summary"),
            "amsi": report.get("amsi", {}).get("status"),
            "limitations": report.get("limitations"),
            "timings": report.get("timings"),
        }
        self._set_text(self.summary, json.dumps(summary, indent=2, ensure_ascii=False))
        self._set_text(self.amsi, json.dumps(report.get("amsi", {}), indent=2, ensure_ascii=False))
        self._set_text(self.pe, json.dumps({"pe": report.get("pe"), "dissection": report.get("dissection")}, indent=2, ensure_ascii=False))
        self._set_text(self.reports, json.dumps(report, indent=2, ensure_ascii=False, default=str))
        for item in self.av_tree.get_children():
            self.av_tree.delete(item)
        for row in report.get("multiav", {}).get("results", []):
            self.av_tree.insert("", "end", values=(
                row.get("name"), row.get("status"), row.get("signature") or "-",
                row.get("duration_ms") or "-", row.get("error") or row.get("output_excerpt") or "-",
            ))
        self._render_map()
        self._show_hex()

    def _render_map(self):
        canvas = self.map_canvas
        canvas.delete("all")
        if not self.result or not self.result.data:
            return
        width = max(canvas.winfo_width(), 900) - 60
        y = 45
        size = len(self.result.data)
        canvas.create_text(30, 15, text=f"Artifact layout — {size} bytes", fill="#dce7ff", anchor="w")
        canvas.create_rectangle(30, y, 30 + width, y + 50, fill="#18264a", outline="#668ee8")
        colors = ("#315ea8", "#4779c4", "#5c8fd6", "#729fe0")
        for index, section in enumerate(self.result.report.get("dissection", {}).get("sections", [])):
            start = max(0, int(section.get("file_offset", 0)))
            end = min(size, int(section.get("file_end", start)))
            x1 = 30 + int(width * start / size)
            x2 = max(x1 + 2, 30 + int(width * end / size))
            canvas.create_rectangle(x1, y, x2, y + 50, fill=colors[index % len(colors)], outline="#0b1020")
            if x2 - x1 > 45:
                canvas.create_text((x1 + x2) // 2, y + 25, text=section.get("name", "?"), fill="white")

    def _show_hex(self):
        if not self.result:
            return
        try:
            offset = int(self.offset_var.get(), 0)
        except ValueError:
            self.messagebox.showerror("SigLens", "Offset must be decimal or hexadecimal.")
            return
        offset = max(0, min(offset, max(0, len(self.result.data) - 1)))
        blob = self.result.data[offset:offset + 512]
        self._set_text(self.hex_text, "\n".join(hexdump(blob, base_offset=offset)))

    def _export(self, kind):
        if not self.result:
            self.messagebox.showinfo("SigLens", "Run an analysis first.")
            return
        suffix = ".json" if kind == "json" else ".html"
        stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        default = f"{self.result.path.stem}-{stamp}{suffix}"
        target = self.filedialog.asksaveasfilename(defaultextension=suffix, initialfile=default)
        if not target:
            return
        if kind == "json":
            save_json(self.result.report, Path(target))
        else:
            save_html(self.result.report, Path(target))
        self.status_var.set(f"Saved {target}")

    def _close(self):
        self.cancel_event.set()
        self.root.destroy()


def launch_gui(initial_file: Path | None = None) -> None:
    try:
        import tkinter as tk
    except ImportError as exc:
        raise RuntimeError("Python was installed without tkinter support") from exc
    root = tk.Tk()
    SigLensApp(root, initial_file)
    root.mainloop()
