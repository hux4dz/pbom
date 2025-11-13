import streamlit as st
import json
import requests
from typing import List, Dict, Any, Optional
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors
from reportlab.lib.units import inch
import io
import os
from datetime import datetime

# Configuration
OSS_INDEX_API = "https://ossindex.sonatype.org/api/v3/component-report"
MAX_PACKAGES_PER_REQUEST = 128  # OSS Index API limit

# Data Models
class Vulnerability:
    def __init__(self, data: Dict[str, Any]):
        self.id = data.get('id')
        self.title = data.get('title', 'No title')
        self.description = data.get('description', 'No description')
        self.cvss_score = data.get('cvssScore', 0.0)
        self.cvss_vector = data.get('cvssVector')
        self.cve = data.get('cve')
        self.reference = data.get('reference')
        self.severity = self._determine_severity()
    
    def _determine_severity(self) -> str:
        if self.cvss_score >= 9.0:
            return 'Critical'
        elif self.cvss_score >= 7.0:
            return 'High'
        elif self.cvss_score >= 4.0:
            return 'Medium'
        elif self.cvss_score > 0:
            return 'Low'
        return 'Info'

class Component:
    def __init__(self, purl: str):
        self.purl = purl
        self.vulnerabilities: List[Vulnerability] = []
        self.name = self._extract_name()
    
    def _extract_name(self) -> str:
        # Extract package name from purl
        parts = self.purl.split('@')
        if len(parts) > 1:
            return parts[0].split('/')[-1]
        return self.purl

# SBOM Parser
class SBOMParser:
    @staticmethod
    def parse_cyclonedx(sbom_data: Dict) -> List[str]:
        """Extract package URLs from CycloneDX SBOM"""
        purls = []
        components = sbom_data.get('components', [])
        for comp in components:
            if 'purl' in comp:
                purls.append(comp['purl'])
        return purls
    
    @staticmethod
    def parse_spdx(sbom_data: Dict) -> List[str]:
        """Extract package URLs from SPDX SBOM"""
        purls = []
        packages = sbom_data.get('packages', [])
        for pkg in packages:
            if 'externalRefs' in pkg:
                for ref in pkg['externalRefs']:
                    if ref.get('referenceType') == 'purl':
                        purls.append(ref['referenceLocator'])
        return purls

# OSS Index API Client
class OSSIndexClient:
    def __init__(self):
        self.base_url = OSS_INDEX_API
        self.session = requests.Session()
        self.session.auth = ('houssem4pro@gmail.com', 'a1d75133c45e342c68f86bedc347e00ac3ea3e15')
        self.session.headers.update({
            'Content-Type': 'application/json',
            'User-Agent': 'SBOM-Vulnerability-Scanner/1.0.0'
        })
    
    def get_vulnerabilities(self, purls: List[str]) -> Dict[str, Component]:
        """Query OSS Index API for vulnerabilities"""
        components = {purl: Component(purl) for purl in purls}
        
        # Process in batches due to API limits
        for i in range(0, len(purls), MAX_PACKAGES_PER_REQUEST):
            batch = purls[i:i + MAX_PACKAGES_PER_REQUEST]
            response = self._make_request(batch)
            self._process_response(response, components)
        
        return components
    
    def _make_request(self, purls: List[str]) -> Dict:
        """Make API request to OSS Index"""
        try:
            response = self.session.post(
                self.base_url,
                json={"coordinates": purls}
            )
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            st.error(f"Error querying OSS Index API: {str(e)}")
            return {}
    
    def _process_response(self, response_data: List[Dict], components: Dict[str, Component]) -> None:
        """Process API response and update components with vulnerabilities"""
        for item in response_data:
            purl = item.get('coordinates', '')
            if purl in components and 'vulnerabilities' in item:
                for vuln_data in item['vulnerabilities']:
                    components[purl].vulnerabilities.append(Vulnerability(vuln_data))

# Report Generator
class ReportGenerator:
    @staticmethod
    def generate_pdf_report(components: Dict[str, Component], output_path: str) -> None:
        """Generate PDF report with vulnerabilities"""
        # Create the directory if it doesn't exist
        os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
        
        # Set up the document with margins that allow for centering
        doc = SimpleDocTemplate(
            output_path,
            pagesize=letter,
            rightMargin=36,  # Reduced margins to allow more space for the table
            leftMargin=36,
            topMargin=72, 
            bottomMargin=72
        )
        
        styles = getSampleStyleSheet()
        styles.add(ParagraphStyle(name='Vulnerability', 
                                parent=styles['Normal'],
                                fontSize=10,
                                spaceAfter=6))
        
        elements = []
        
        # Title
        title_style = styles['Title']
        elements.append(Paragraph("SBOM Vulnerability Report", title_style))
        elements.append(Spacer(1, 12))
        
        # Summary
        summary = f"Report generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
        summary += f"Total components scanned: {len(components)}\n"
        
        # Count vulnerabilities by severity
        severity_counts = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0, 'Info': 0}
        for comp in components.values():
            for vuln in comp.vulnerabilities:
                severity_counts[vuln.severity] += 1
        
        summary += "\nVulnerabilities by severity:\n"
        for severity, count in severity_counts.items():
            if count > 0:
                summary += f"- {severity}: {count}\n"
        
        elements.append(Paragraph(summary.replace('\n', '<br/>'), styles['Normal']))
        elements.append(Spacer(1, 12))
        
        # Detailed vulnerabilities
        elements.append(Paragraph("Vulnerability Details", styles['Heading2']))
        elements.append(Spacer(1, 12))
        
        for purl, component in components.items():
            if not component.vulnerabilities:
                continue
                
            # Component header
            elements.append(Paragraph(f"Component: {component.name}", styles['Heading3']))
            elements.append(Paragraph(f"PURL: {purl}", styles['Italic']))
            
            # Vulnerabilities table
            table_data = [
                ['ID', 'Title', 'Severity', 'CVSS Score', 'CVE']
            ]
            
            for vuln in sorted(component.vulnerabilities, 
                             key=lambda x: x.cvss_score, 
                             reverse=True):
                # Ensure text is properly formatted for the table cells
                table_data.append([
                    Paragraph(vuln.id or 'N/A', styles['Normal']),
                    Paragraph(vuln.title, styles['Normal']),
                    Paragraph(vuln.severity, styles['Normal']),
                    Paragraph(str(vuln.cvss_score) if vuln.cvss_score else 'N/A', styles['Normal']),
                    Paragraph(vuln.cve or 'N/A', styles['Normal'])
                ])
            
            # Define column widths in points (1 inch = 72 points)
            col_widths = [
                72,      # ID (1 inch)
                216,     # Title (3 inches)
                72,      # Severity (1 inch)
                72,      # CVSS Score (1 inch)
                108      # CVE (1.5 inches)
            ]
            
            # Create a new table with explicit column widths and centered alignment
            table = Table(table_data, colWidths=col_widths, repeatRows=1)
            table.hAlign = 'CENTER'  # Center the table on the page
            
            # Define a more robust table style
            table_style = [
                # Header formatting
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#4b6c9e')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 8),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 8),
                ('TOPPADDING', (0, 0), (-1, 0), 6),
                ('LEFTPADDING', (0, 0), (-1, 0), 4),
                ('RIGHTPADDING', (0, 0), (-1, 0), 4),
                
                # Cell formatting
                ('FONTSIZE', (0, 1), (-1, -1), 8),
                ('LEFTPADDING', (0, 1), (-1, -1), 4),
                ('RIGHTPADDING', (0, 1), (-1, -1), 4),
                ('TOPPADDING', (0, 1), (-1, -1), 3),
                ('BOTTOMPADDING', (0, 1), (-1, -1), 3),
                ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                
                # Alternating row colors
                ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f5f9ff')]),
                
                # Text alignment
                ('ALIGN', (0, 0), (0, -1), 'LEFT'),   # ID
                ('ALIGN', (1, 0), (1, -1), 'LEFT'),   # Title
                ('ALIGN', (2, 0), (2, -1), 'CENTER'), # Severity
                ('ALIGN', (3, 0), (3, -1), 'CENTER'), # CVSS Score
                ('ALIGN', (4, 0), (4, -1), 'CENTER'), # CVE
                
                # Grid and borders
                ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#d0d0d0')),
                ('BOX', (0, 0), (-1, -1), 0.5, colors.HexColor('#808080')),
                
                # Word wrapping for all cells
                ('WORDWRAP', (0, 0), (-1, -1), True)
            ]
            
            # Apply the style to the table
            table.setStyle(TableStyle(table_style))
            
            # Set the minimum row height to ensure content fits
            table._argW = col_widths
            table._minRowHeights = [24] * len(table_data)  # 24 points minimum row height
            
            elements.append(table)
            elements.append(Spacer(1, 12))
            
            # Add vulnerability details
            for vuln in component.vulnerabilities:
                # Escape HTML special characters in the title
                from xml.sax.saxutils import escape
                safe_title = escape(str(vuln.title))
                safe_cve = escape(str(vuln.cve)) if vuln.cve else 'No CVE'
                elements.append(Paragraph(
                    f"<b>{safe_title} ({safe_cve}) - {vuln.severity} ({vuln.cvss_score})</b>", 
                    styles['Heading4']))
                elements.append(Paragraph(f"<b>Description:</b> {vuln.description}", styles['Vulnerability']))
                if vuln.cvss_vector:
                    elements.append(Paragraph(f"<b>CVSS Vector:</b> {vuln.cvss_vector}", styles['Vulnerability']))
                if vuln.reference:
                    elements.append(Paragraph(f"<b>Reference:</b> {vuln.reference}", styles['Vulnerability']))
                elements.append(Spacer(1, 6))
            
            elements.append(PageBreak())
        
        # Ensure the output directory exists
        output_dir = os.path.dirname(os.path.abspath(output_path))
        if output_dir and not os.path.exists(output_dir):
            os.makedirs(output_dir, exist_ok=True)
        
        try:
            # Debug: Print the output path
            print(f"Attempting to save PDF to: {os.path.abspath(output_path)}")
            
            # Build the PDF document with error handling
            doc.build(elements)
            print("PDF built successfully")
            
            # Verify the file was created and has content
            if not os.path.exists(output_path):
                error_msg = f"PDF file was not created at {os.path.abspath(output_path)}"
                print(error_msg)
                raise FileNotFoundError(error_msg)
                
            file_size = os.path.getsize(output_path)
            print(f"PDF file created with size: {file_size} bytes")
            
            if file_size == 0:
                error_msg = "Generated PDF file is empty"
                print(error_msg)
                raise ValueError(error_msg)
                
            return True
                
        except Exception as e:
            # Log the error
            error_type = type(e).__name__
            print(f"Error in PDF generation: {error_type}: {str(e)}")
            
            # Clean up partially created file if it exists
            if os.path.exists(output_path):
                try:
                    os.remove(output_path)
                    print(f"Cleaned up partial PDF file at {output_path}")
                except Exception as cleanup_error:
                    print(f"Error during cleanup: {str(cleanup_error)}")
            
            # Provide a more detailed error message
            raise Exception(f"Failed to generate PDF: {str(e)}") from e

# Streamlit App
def main():
    st.set_page_config(
        page_title="SBOM Vulnerability Scanner",
        page_icon="🔍",
        layout="wide"
    )
    
    st.title("🔍 SBOM Vulnerability Scanner")
    st.markdown("""
    Upload a Software Bill of Materials (SBOM) file in CycloneDX or SPDX format 
    to scan for known vulnerabilities using the OSS Index database.
    """)
    
    # File upload
    uploaded_file = st.file_uploader("Upload SBOM (JSON)", type=["json"])
    
    if uploaded_file is not None:
        try:
            # Parse SBOM
            sbom_data = json.load(uploaded_file)
            purls = []
            
            # Detect SBOM format and extract package URLs
            if 'bomFormat' in sbom_data and sbom_data['bomFormat'] == 'CycloneDX':
                purls = SBOMParser.parse_cyclonedx(sbom_data)
                st.success(f"Detected CycloneDX SBOM with {len(purls)} components")
            elif 'SPDXID' in sbom_data and sbom_data['SPDXID'].startswith('SPDXRef-DOCUMENT'):
                purls = SBOMParser.parse_spdx(sbom_data)
                st.success(f"Detected SPDX SBOM with {len(purls)} components")
            else:
                st.error("Unsupported SBOM format. Please upload a valid CycloneDX or SPDX JSON file.")
                return
            
            if not purls:
                st.warning("No package URLs found in the SBOM.")
                return
            
            # Scan for vulnerabilities
            if st.button("Scan for Vulnerabilities"):
                with st.spinner("Scanning components for vulnerabilities..."):
                    client = OSSIndexClient()
                    components = client.get_vulnerabilities(purls)
                    
                    # Display results
                    total_vulns = sum(len(comp.vulnerabilities) for comp in components.values())
                    
                    if total_vulns == 0:
                        st.success("🎉 No vulnerabilities found in the scanned components!")
                    else:
                        # Count vulnerabilities by severity
                        severity_counts = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0, 'Info': 0}
                        for comp in components.values():
                            for vuln in comp.vulnerabilities:
                                severity_counts[vuln.severity] += 1
                        
                        # Display summary
                        st.subheader("Scan Results")
                        col1, col2, col3, col4, col5 = st.columns(5)
                        
                        with col1:
                            st.metric("Total Components", len(components))
                        with col2:
                            st.metric("Critical", severity_counts['Critical'], 
                                     delta=None, delta_color="inverse", 
                                     help="Critical severity vulnerabilities")
                        with col3:
                            st.metric("High", severity_counts['High'], 
                                     delta=None, delta_color="inverse", 
                                     help="High severity vulnerabilities")
                        with col4:
                            st.metric("Medium", severity_counts['Medium'], 
                                     help="Medium severity vulnerabilities")
                        with col5:
                            st.metric("Low/Info", severity_counts['Low'] + severity_counts['Info'], 
                                     help="Low and Info severity vulnerabilities")
                        
                        # Generate and download report
                        st.subheader("Generate Report")
                        
                        # Create a unique filename with timestamp
                        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                        report_filename = f"sbom_vulnerability_report_{timestamp}.pdf"
                        
                        # Create a temporary directory for the report
                        import tempfile
                        import shutil
                        
                        with tempfile.TemporaryDirectory() as temp_dir:
                            report_path = os.path.join(temp_dir, report_filename)
                            
                            # Generate PDF
                            try:
                                with st.spinner("📄 Generating PDF report..."):
                                    # Ensure the directory exists
                                    os.makedirs(os.path.dirname(report_path), exist_ok=True)
                                    
                                    # Generate the PDF
                                    ReportGenerator.generate_pdf_report(components, report_path)
                                
                                # Check if file was created successfully
                                if os.path.exists(report_path) and os.path.getsize(report_path) > 0:
                                    # Read the generated PDF
                                    with open(report_path, 'rb') as f:
                                        pdf_data = f.read()
                                    
                                    # Create download button
                                    st.download_button(
                                        label="📥 Download PDF Report",
                                        data=pdf_data,
                                        file_name=report_filename,
                                        mime='application/pdf',
                                        help="Click to download the full vulnerability report in PDF format"
                                    )
                                    st.success("✓ PDF report generated successfully!")
                                else:
                                    st.error("Failed to generate PDF report. The file was not created or is empty.")
                                    
                            except Exception as e:
                                st.error(f"Error generating PDF: {str(e)}")
                                st.exception(e)  # Show full traceback for debugging
                        
                        # Display vulnerabilities in an expandable section
                        st.subheader("Vulnerable Components")
                        
                        for purl, component in components.items():
                            if not component.vulnerabilities:
                                continue
                                
                            with st.expander(f"{component.name} ({len(component.vulnerabilities)} vulnerabilities)"):
                                st.caption(f"Package URL: {purl}")
                                
                                for vuln in sorted(component.vulnerabilities, 
                                                 key=lambda x: x.cvss_score, 
                                                 reverse=True):
                                    # Define colors with better contrast
                                    severity_styles = {
                                        'Critical': {
                                            'bg': '#FFEBEE',  # Light red background
                                            'border': '#F44336',  # Red border
                                            'text': '#B71C1C'  # Dark red text
                                        },
                                        'High': {
                                            'bg': '#FFF3E0',  # Light orange background
                                            'border': '#FF9800',  # Orange border
                                            'text': '#E65100'  # Dark orange text
                                        },
                                        'Medium': {
                                            'bg': '#FFF8E1',  # Light yellow background
                                            'border': '#FFC107',  # Yellow border
                                            'text': '#FF8F00'  # Dark yellow text
                                        },
                                        'Low': {
                                            'bg': '#E8F5E9',  # Light green background
                                            'border': '#4CAF50',  # Green border
                                            'text': '#1B5E20'  # Dark green text
                                        },
                                        'Info': {
                                            'bg': '#E3F2FD',  # Light blue background
                                            'border': '#2196F3',  # Blue border
                                            'text': '#0D47A1'  # Dark blue text
                                        }
                                    }.get(vuln.severity, {
                                        'bg': '#F5F5F5',  # Default light gray
                                        'border': '#9E9E9E',  # Default gray
                                        'text': '#212121'  # Default dark gray
                                    })
                                    
                                    # Format the vulnerability details with better styling
                                    st.markdown(
                                        f"""
                                        <div style='
                                            border-left: 4px solid {severity_styles['border']};
                                            background-color: {severity_styles['bg']};
                                            padding: 12px 16px;
                                            margin: 12px 0;
                                            border-radius: 4px;
                                            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
                                        '>
                                            <div style='
                                                color: {severity_styles['text']};
                                                font-weight: 600;
                                                margin-bottom: 8px;
                                                display: flex;
                                                justify-content: space-between;
                                                align-items: center;
                                            '>
                                                <span>{vuln.title}</span>
                                                <span style='
                                                    background-color: {severity_styles['border']};
                                                    color: white;
                                                    padding: 2px 8px;
                                                    border-radius: 12px;
                                                    font-size: 0.8em;
                                                '>{vuln.severity}</span>
                                            </div>
                                            <div style='color: #333; font-size: 0.95em;'>
                                                <p style='margin: 6px 0;'><b>CVSS:</b> {vuln.cvss_score} <span style='font-family: monospace;'>{vuln.cvss_vector or ''}</span></p>
                                                <p style='margin: 6px 0;'><b>CVE:</b> {vuln.cve or 'N/A'}</p>
                                                <p style='margin: 8px 0 12px 0; line-height: 1.5;'>{vuln.description}</p>
                                                {f"<p style='margin: 8px 0 0 0;'><b>Reference:</b> <a href='{vuln.reference}' target='_blank' style='color: #1976D2; text-decoration: none;'>{vuln.reference}</a></p>" if vuln.reference else ""}
                                            </div>
                                        </div>
                                        """,
                                        unsafe_allow_html=True
                                    )
        
        except json.JSONDecodeError:
            st.error("Invalid JSON file. Please upload a valid SBOM JSON file.")
        except Exception as e:
            st.error(f"An error occurred: {str(e)}")
            st.exception(e)  # Show full traceback in the UI for debugging

if __name__ == "__main__":
    main()
