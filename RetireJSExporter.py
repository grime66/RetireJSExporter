# -*- coding: utf-8 -*-
# RetireJS_Exporter.py
# Burp Suite Pro extension - grabs Retire.js findings but only for .js files
# Skips the usual false positives (HTML pages, API endpoints etc.)

from burp import IBurpExtender, ITab
from javax.swing import (
    JPanel, JButton, JLabel, JScrollPane, JTextArea,
    JFileChooser, BorderFactory, BoxLayout, SwingConstants, JTextField,
    Box
)
from java.awt import BorderLayout, Color, Font, Dimension
from java.io import PrintWriter, File
from java.net import URL
import io
import json
import os
import re
from datetime import datetime


class BurpExtender(IBurpExtender, ITab):

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers   = callbacks.getHelpers()
        self._stdout    = PrintWriter(callbacks.getStdout(), True)
        self._stderr    = PrintWriter(callbacks.getStderr(), True)

        callbacks.setExtensionName("Retire.js Exporter")
        self._stdout.println("[*] Retire.js Exporter loaded (only .js endpoints)")

        from javax.swing import SwingUtilities
        if SwingUtilities.isEventDispatchThread():
            self._build_ui()
        else:
            SwingUtilities.invokeAndWait(self._build_ui)

        callbacks.addSuiteTab(self)

    def getTabCaption(self):
        return "Retire.js Exporter"

    def getUiComponent(self):
        return self._panel

    def _build_ui(self):
        self._panel = JPanel(BorderLayout(10, 10))
        self._panel.setBorder(BorderFactory.createEmptyBorder(15, 15, 15, 15))

        # yeah, we're putting our name on it
        header = JLabel(
            "Retire.js issues exporter by CodeGrazer",
            SwingConstants.LEFT
        )
        header.setFont(Font("SansSerif", Font.PLAIN, 14))
        self._panel.add(header, BorderLayout.NORTH)

        # log area - dark background, green text because it looks cool
        self._log = JTextArea()
        self._log.setEditable(False)
        self._log.setFont(Font("Monospaced", Font.PLAIN, 12))
        self._log.setBackground(Color(30, 30, 30))
        self._log.setForeground(Color(180, 255, 180))
        scroll = JScrollPane(self._log)
        scroll.setPreferredSize(Dimension(800, 400))
        self._panel.add(scroll, BorderLayout.CENTER)

        # bottom panel: folder picker + buttons
        south = JPanel()
        south.setLayout(BoxLayout(south, BoxLayout.Y_AXIS))

        # folder row with browse button on the left (so people actually see it)
        folder_row = JPanel()
        folder_row.setLayout(BoxLayout(folder_row, BoxLayout.X_AXIS))
        folder_row.setBorder(BorderFactory.createEmptyBorder(6, 0, 4, 0))

        lbl = JLabel("Output folder:")
        lbl.setPreferredSize(Dimension(100, 24))
        folder_row.add(lbl)
        folder_row.add(Box.createHorizontalStrut(5))

        self._btn_browse = JButton("Browse...")
        self._btn_browse.addActionListener(self._on_browse)
        folder_row.add(self._btn_browse)
        folder_row.add(Box.createHorizontalStrut(10))

        self._folder_field = JTextField(os.path.expanduser("~"))
        self._folder_field.setMaximumSize(Dimension(400, 24))
        folder_row.add(self._folder_field)

        south.add(folder_row)

        # three action buttons
        btn_row = JPanel()
        btn_row.setLayout(BoxLayout(btn_row, BoxLayout.X_AXIS))

        btn_scan = JButton("Scan for Retire.js Findings")
        btn_scan.addActionListener(self._on_scan)
        btn_scan.setToolTipText("Pull all scanner issues, keep only .js findings")

        btn_export = JButton("Export to JSON")
        btn_export.addActionListener(self._on_export)
        btn_export.setToolTipText("Save results to JSON file in selected folder")

        btn_clear = JButton("Clear Log")
        btn_clear.addActionListener(lambda e: self._log.setText(""))

        btn_row.add(btn_scan)
        btn_row.add(btn_export)
        btn_row.add(btn_clear)

        south.add(btn_row)
        self._panel.add(south, BorderLayout.SOUTH)

        self._findings = []
        self._log_msg("[*] Ready. Only .js endpoints will be kept.\n")

    def _on_browse(self, _event):
        chooser = JFileChooser()
        chooser.setDialogTitle("Select Output Folder")
        chooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY)
        current = self._folder_field.getText().strip()
        if current and os.path.isdir(current):
            chooser.setCurrentDirectory(File(current))
        if chooser.showOpenDialog(self._panel) == JFileChooser.APPROVE_OPTION:
            self._folder_field.setText(chooser.getSelectedFile().getAbsolutePath())

    def _log_msg(self, msg):
        self._log.append(msg + "\n")
        self._log.setCaretPosition(self._log.getDocument().getLength())
        self._stdout.println(msg)

    @staticmethod
    def _is_retirejs_specific(issue):
        # We only want the per-library issues, not the generic wrapper
        name   = (issue.getIssueName()   or "").lower()
        detail = (issue.getIssueDetail() or "").lower()
        bg     = (issue.getIssueBackground() or "").lower()
        is_retirejs = (
            "retire.js" in detail
            or "retire.js" in bg
            or "this issue was generated by the burp extension: retire.js" in detail
        )
        if not is_retirejs:
            return False
        is_specific = "vulnerable version of the library" in name
        is_wrapper  = ("vulnerable javascript dependency" in name or "we observed" in detail)
        return is_specific and not is_wrapper

    # ---------- .js filtering ----------
    @staticmethod
    def _is_js_endpoint(url_str):
        if not url_str:
            return False
        try:
            url_obj = URL(url_str)
            path = url_obj.getPath()
            if path and path.lower().endswith('.js'):
                return True
        except:
            if url_str.lower().endswith('.js'):
                return True
        return False

    @staticmethod
    def _extract_js_url_from_detail(raw_html):
        """grab first absolute URL that ends with .js from the issue detail"""
        urls = re.findall(r"https?://[^\s<>\"'\)]+", raw_html)
        rel_urls = re.findall(r"//[^\s<>\"'\)]+", raw_html)
        for u in rel_urls:
            if u.startswith("//"):
                u = "https:" + u
            urls.append(u)
        for u in urls:
            u = u.rstrip(".,;)")
            if BurpExtender._is_js_endpoint(u):
                return u
        return None

    # ---------- HTML cleanup (turned Burp's HTML into readable text) ----------
    @staticmethod
    def _decode_html_entities(text):
        text = text.replace("&lt;", "<").replace("&gt;", ">").replace("&amp;", "&")
        text = text.replace("&quot;", '"').replace("&#39;", "'").replace("&nbsp;", " ")
        text = text.replace("&#13;", "")
        return text

    @staticmethod
    def _tags_to_newlines(html):
        # turn <br>, </p>, <li> etc. into newlines before stripping tags
        html = re.sub(r"<br\s*/?>", "\n", html, flags=re.IGNORECASE)
        html = re.sub(r"</p>", "\n", html, flags=re.IGNORECASE)
        html = re.sub(r"<p[^>]*>", "\n", html, flags=re.IGNORECASE)
        html = re.sub(r"<li[^>]*>", "\n", html, flags=re.IGNORECASE)
        html = re.sub(r"</?(?:ul|ol)>", "\n", html, flags=re.IGNORECASE)
        html = re.sub(r"<[^>]+>", "", html)
        return html

    def _clean_text(self, raw):
        if not raw:
            return u""
        text = self._decode_html_entities(raw)
        text = self._tags_to_newlines(text)
        text = re.sub(r"\r\n|\r", "\n", text)
        lines = [l.rstrip() for l in text.split("\n")]
        # collapse consecutive blank lines
        result = []
        prev_blank = False
        for line in lines:
            is_blank = (line.strip() == "")
            if is_blank and prev_blank:
                continue
            result.append(line)
            prev_blank = is_blank
        return u"\n".join(result).strip()

    def _extract_section(self, raw_html, section_label):
        # pull out a specific section (e.g. "Affected versions") from Burp's HTML
        stop_heads = ["Issue detail", "Affected versions", "Other considerations", "Note", "Notes", "References", "Remediation", "Background", "Vulnerability classifications"]
        stop_alts = "|".join(re.escape(h) for h in stop_heads if h.lower() != section_label.lower())
        stop_pattern = r"(?:<b>|<strong>)\s*(?:" + stop_alts + r")\s*(?:</b>|</strong>)"
        start_pat = r"(?:<b>|<strong>)\s*" + re.escape(section_label) + r"\s*(?:</b>|</strong>)"
        start_m = re.search(start_pat, raw_html, re.IGNORECASE)
        if not start_m:
            return u""
        content_start = start_m.end()
        stop_m = re.search(stop_pattern, raw_html[content_start:], re.IGNORECASE)
        if stop_m:
            content_html = raw_html[content_start: content_start + stop_m.start()]
        else:
            content_html = raw_html[content_start:]
        return self._clean_text(content_html)

    def _parse_issue_detail(self, raw_html):
        section = self._extract_section(raw_html, "Issue detail")
        if not section:
            section = self._clean_text(raw_html)
        urls = re.findall(r"https?://[^\s<>\"'\)]+", raw_html)
        unique_urls = []
        seen = set()
        for u in urls:
            u = u.rstrip(".,;)")
            if u not in seen:
                seen.add(u)
                unique_urls.append(u)
        # try to pull the summary sentence
        summary_m = re.search(
            r"(The\s+(?:library\s+)?[\w\-\.]+\s+version\s+[\d][\d\.a-zA-Z]*"
            r"[\w\s,]*?(?:security\s+issues?|known\s+vulnerabilit[\w]*)\.?)",
            section, re.IGNORECASE
        )
        summary = summary_m.group(1).strip() if summary_m else section.split("\n")[0].strip()
        if summary and not summary.endswith("."):
            summary += "."
        parts = [summary]
        if unique_urls:
            parts.append("For more information, visit those websites:")
            parts.extend(unique_urls)
        return u"\n".join(parts)

    def _parse_affected_versions(self, raw_html):
        section = self._extract_section(raw_html, "Affected versions")
        if section:
            return u" ".join(section.split())
        clean = self._clean_text(raw_html)
        patterns = [
            r"((?:affecting\s+)?all\s+versions?\s+prior\s+[\d][\d\.a-zA-Z\-]*(?:\s*\([^)]+\))?)",
            r"(prior\s+[\d][\d\.a-zA-Z\-]*(?:\s*\([^)]+\))?)",
            r"([\d][\d\.a-zA-Z\-]+\s+and\s+below)",
            r"(versions?\s+before\s+[\d][\d\.a-zA-Z\-]*)",
        ]
        for pat in patterns:
            m = re.search(pat, clean, re.IGNORECASE)
            if m:
                return m.group(1).strip()
        return u""

    # ---------- main scan: fetch issues, filter .js, store ----------
    def _on_scan(self, _event):
        self._log_msg("[*] Scanning all scanner issues for Retire.js findings...")
        self._findings = []
        seen_urls = set()

        try:
            all_issues = self._callbacks.getScanIssues(None)
        except Exception as ex:
            self._log_msg("[-] Could not retrieve scan issues: " + str(ex))
            return

        if not all_issues:
            self._log_msg("[!] No scan issues found. Run an active/passive scan first.")
            return

        self._log_msg("[*] Total issues found in scanner: {}".format(len(all_issues)))

        for issue in all_issues:
            if not self._is_retirejs_specific(issue):
                continue

            try:
                main_url = str(issue.getUrl())
                raw_html = issue.getIssueDetail() or ""

                # figure out which URL to keep – must end with .js
                target_url = None
                if self._is_js_endpoint(main_url):
                    target_url = main_url
                else:
                    js_url = self._extract_js_url_from_detail(raw_html)
                    if js_url:
                        target_url = js_url

                if not target_url:
                    # not a .js endpoint -> skip silently
                    continue

                if target_url in seen_urls:
                    continue
                seen_urls.add(target_url)

                issue_detail      = self._parse_issue_detail(raw_html)
                affected_versions = self._parse_affected_versions(raw_html)

                entry = {
                    "url":               target_url,
                    "affected_versions": affected_versions,
                    "issue_detail":      issue_detail,
                }
                self._findings.append(entry)
                self._log_msg("[+] {} | {}".format(target_url, affected_versions or "affected versions: unknown"))

            except Exception as ex:
                self._stderr.println("[-] Error parsing issue: " + str(ex))

        self._log_msg("\n[=] Total Retire.js issues with .js endpoints: {}\n".format(len(self._findings)))
        if not self._findings:
            self._log_msg("[!] No .js endpoints found.")

    # ---------- export to JSON ----------
    def _on_export(self, _event):
        if not self._findings:
            self._log_msg("[!] Nothing to export. Run 'Scan' first.")
            return

        folder = self._folder_field.getText().strip()
        if not folder:
            folder = os.path.expanduser("~")
        if not os.path.isdir(folder):
            try:
                os.makedirs(folder)
                self._log_msg("[*] Created output folder: " + folder)
            except Exception as ex:
                self._log_msg("[-] Cannot create folder: " + str(ex))
                return

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename  = "retirejs_findings_{}.json".format(timestamp)
        path      = os.path.join(folder, filename)

        export_data = {
            "total_findings":   len(self._findings),
            "findings":         self._findings,
            "export_timestamp": datetime.now().isoformat(),
        }

        try:
            with io.open(path, "w", encoding="utf-8") as fh:
                data = json.dumps(export_data, indent=4, ensure_ascii=False)
                fh.write(unicode(data))
            self._log_msg("[+] Exported {} findings to:\n    {}".format(len(self._findings), path))
        except Exception as ex:
            self._log_msg("[-] Export failed: " + str(ex))
            self._stderr.println("[-] Export error: " + str(ex))
