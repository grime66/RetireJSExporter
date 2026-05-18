# Retire.js Exporter (Burp Suite Pro)

A Burp Suite Professional extension that extracts **Retire.js** scanner findings but **only for actual `.js` endpoints**.
Automatically ignores false positives (HTML pages, API endpoints, etc.) that Retire.js sometimes flags.

## Features

- Adds a new tab: **Retire.js Exporter**
- Scans all active/passive issues from Burp’s scanner
- Filters out the generic `"Vulnerable JavaScript dependency"` wrapper issues
- Keeps only findings where the endpoint **ends with `.js`** (main URL or any URL listed in the issue detail)
- Exports results to a timestamped JSON file
- Clean, dark‑theme log output

## Installation

1. Download `RetireJSExporter.py`
2. In Burp Suite Professional, go to **Extensions → Installed → Add**
3. Set **Extension Type** to `Python`
4. Select the `.py` file
5. Make sure you have **Jython 2.7** standalone JAR configured under **Extensions → Options → Python Environment**

## Usage

1. Run your usual active/passive scan with the **Retire.js** Burp extension enabled.
2. Go to the **Retire.js Exporter** tab.
3. (Optional) Click **Browse** to choose an output folder – defaults to your home directory.
4. Click **Scan for Retire.js Findings**.
   The extension will iterate through all scanner issues and show only `.js` matches in the log.
5. Click **Export to JSON** to save the findings.
   File name: `retirejs_findings_YYYYMMDD_HHMMSS.json`

## JSON Output Format

```json
{
  "total_findings": 1,
  "findings": [
    {
      "url": "https://example.com/js/app.js",
      "affected_versions": "all versions prior 3.4.2 (between 1.4.0 and 3.4.2)",
      "issue_detail": "The library jQuery version 1.7.2 has known security issues. For more information, visit those websites:\nhttps://...\nhttps://..."
    }
  ],
  "export_timestamp": "2026-05-15T10:30:00"
}

## Notes

- The script does not run Retire.js – it only parses existing issues from Burp’s scanner database.
- Only issues with the exact name `"Vulnerable version of the library X found"` are processed.
- Findings are deduplicated by URL.
- No extra dependencies required – uses only Jython standard libraries.

## Author

CodeGrazer

## License

Free to use, modify, and distribute.
