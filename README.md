# SBOM Vulnerability Scanner

[![Streamlit App](https://static.streamlit.io/badges/streamlit_badge_black_white.svg)](https://your-username-streamlit-app-url.streamlit.app/)

A Python-based tool to scan Software Bill of Materials (SBOM) files for known vulnerabilities using the Sonatype OSS Index API.

## 🚀 Live Demo

Try the live demo on Streamlit Cloud: [https://your-username-streamlit-app-url.streamlit.app/](https://your-username-streamlit-app-url.streamlit.app/)

*Note: Replace the URL with your actual Streamlit Cloud URL after deployment*

## Features

- Supports CycloneDX and SPDX SBOM formats (JSON)
- Scans for vulnerabilities using the OSS Index API
- Interactive Streamlit web interface
- Generates detailed PDF reports
- Groups vulnerabilities by component and severity
- Displays CVSS scores and references

## 🛠️ Prerequisites

### For Local Development
- Python 3.9 or higher
- pip (Python package manager)

### For Streamlit Cloud Deployment
- A GitHub account
- A Streamlit Cloud account (free tier available)

## 🚀 Deployment to Streamlit Cloud

1. **Push your code to GitHub**
   ```bash
   git init
   git add .
   git commit -m "Initial commit"
   git branch -M main
   git remote add origin https://github.com/your-username/your-repo-name.git
   git push -u origin main
   ```

2. **Deploy to Streamlit Cloud**
   - Go to [Streamlit Cloud](https://share.streamlit.io/)
   - Click "New app"
   - Select your repository and branch
   - Set the main file path to `app.py`
   - Click "Deploy!"

3. **Set Environment Variables**
   In your Streamlit Cloud app settings, add these environment variables:
   - `OSS_INDEX_USERNAME`: Your OSS Index email
   - `OSS_INDEX_API_KEY`: Your OSS Index API key

## 💻 Local Installation

1. Clone the repository:
   ```bash
   git clone <repository-url>
   cd sbom-scanner
   ```

2. Create and activate a virtual environment (recommended):
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. Install the required packages:
   ```bash
   pip install -r requirements.txt
   ```

## Usage

1. Run the Streamlit application:
   ```bash
   streamlit run app.py
   ```

2. Open your web browser and navigate to the URL shown in the terminal (usually http://localhost:8501)

3. Upload an SBOM file in JSON format (CycloneDX or SPDX)

4. Click "Scan for Vulnerabilities" to analyze the components

5. View the results in the web interface or download a PDF report

## SBOM Format Support

The scanner supports the following SBOM formats:

- **CycloneDX** (JSON)
- **SPDX** (JSON)

## API Rate Limiting

The OSS Index API has rate limits. If you encounter rate limiting issues, consider:

1. Using an API key (not currently implemented)
2. Reducing the size of your SBOM files
3. Adding delays between requests

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- [Sonatype OSS Index](https://ossindex.sonatype.org/)
- [Streamlit](https://streamlit.io/)
- [ReportLab](https://www.reportlab.com/)
