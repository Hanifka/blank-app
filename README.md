# 🔍 Wazuh Rule Visualizer

Turn raw Wazuh XML rules into interactive flowcharts powered by Plotly and Streamlit. The visualizer helps security engineers trace rule inheritance, conditions, and alerts at a glance so they can explain detection logic or plan tuning changes faster.

[![Open in Streamlit](https://static.streamlit.io/badges/streamlit_badge_black_white.svg)](https://blank-app-template.streamlit.app/)

## Features

- 📈 Plotly-based flow diagrams that highlight how rules trigger one another.
- 📂 XML ingestion that surfaces metadata (rule IDs, descriptions, frequency, etc.).
- ⚙️ Lightweight Streamlit experience you can extend with additional controls or visuals.

## Prerequisites

- Python 3.9+
- `pip` for dependency management

## Installation

1. (Optional) Create and activate a virtual environment.
2. Install the dependencies, including Plotly for interactive visualizations:

   ```bash
   pip install -r requirements.txt
   ```

## Running the app

Start Streamlit from the project root:

```bash
streamlit run streamlit_app.py
```

Streamlit will provide a local URL (default: http://localhost:8501). The browser session hosts the full Wazuh rule visualizer experience.

## Uploading Wazuh XML rules

1. Launch the app as described above.
2. Use the **Upload Wazuh rules (.xml)** widget in the sidebar or main pane.
3. Select any Wazuh rule file (e.g., `rules/local_rules.xml`). Multiple uploads are supported—each file is parsed independently.
4. Once uploaded, the app renders a Plotly flowchart so you can trace parent/child rules, match conditions, and thresholds. Use Plotly's built-in zoom, pan, and hover interactions to explore relationships.

If an upload fails, verify the XML is valid and that it follows Wazuh's rule schema. Malformed documents are skipped with an inline warning so you can correct the file and try again.

## Roadmap: Upcoming Rule Simulator

The next milestone is an interactive simulator layered on top of the visualizer. Planned capabilities include:

- 🎯 Crafting hypothetical events to see which rules would fire and why.
- 🧪 Tuning thresholds or decoding logic and re-running simulations instantly.
- 🧩 Plug-in hooks so contributors can add custom detectors or export formats.

Contributions are welcome! Focus on modular components (data parsers, Plotly traces, or simulator engines) so the roadmap can evolve without major refactors.
