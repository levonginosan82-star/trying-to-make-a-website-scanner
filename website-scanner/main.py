import asyncio
import base64
from datetime import datetime
from urllib.parse import urlparse

import pandas as pd
import streamlit as st
from fpdf import FPDF

from scanner import (
    check_security_headers,
    check_ssl_certificate,
    scan_information_disclosure,
    check_ports,
    check_vulnerable_libraries,
    check_xss_vulnerabilities,
    check_broken_links,
    check_https_redirect,
    check_dos_vulnerabilities,
    check_seo_optimization,
    check_performance_metrics,
    check_html_validation
)


class PDFReport(FPDF):
    def header(self):
        self.set_font('Arial', 'B', 15)
        self.cell(0, 10, 'Web Vulnerability Scan Report', 0, 1, 'C')
        self.set_font('Arial', 'I', 10)
        self.cell(0, 10, f'Scan Date: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}', 0, 1, 'C')
        self.ln(5)

    def section_title(self, title: str):
        self.set_font('Arial', 'B', 12)
        self.set_fill_color(200, 200, 200)
        self.cell(0, 10, title, 0, 1, 'L', 1)
        self.ln(2)

    def add_result(self, key: str, value: str):
        self.set_font('Arial', '', 10)
        self.cell(50, 8, str(key)[:30], 0, 0)
        self.cell(0, 8, str(value)[:100], 0, 1)


def generate_pdf_report(target_url: str, results: dict) -> bytes:
    pdf = PDFReport()
    pdf.add_page()
    pdf.section_title(f"Target: {target_url}")
    pdf.ln(5)

    for module_name, module_results in results.items():
        pdf.section_title(module_name)
        if isinstance(module_results, dict):
            for key, value in module_results.items():
                if key != 'Details':
                    pdf.add_result(str(key), str(value))
        pdf.ln(5)

    return pdf.output(dest='S').encode('latin-1')


def parse_url(url: str) -> str:
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    return url


def highlight_result(val: str) -> str:
    if not isinstance(val, str):
        return val
    val_lower = val.lower()
    if any(x in val_lower for x in ['exposed', 'missing', 'expired', 'expiring', 'open', 'found']):
        return "🔴 " + val
    elif any(x in val_lower for x in ['present', 'valid', 'ok', 'protected', 'closed', 'not found']):
        return "🟢 " + val
    elif any(x in val_lower for x in ['weak', 'warning']):
        return "🟡 " + val
    return val


def render_vulnerability_details(module_name: str, results: dict, base_url: str):
    """Render vulnerability details with detailed fix recommendations."""
    
    details = results.get('Details', [])
    
    if module_name == "Info Disclosure" and details:
        st.markdown("#### 🔴 Exposed Files - Detailed Fix Guide")
        for detail in details:
            path = detail.get('path', '')
            severity = detail.get('severity', 'N/A')
            
            with st.expander(f"⚠️ {path} [{severity}]", expanded=False):
                col1, col2 = st.columns([3, 1])
                with col1:
                    st.markdown(f"**URL:** [{detail['url']}]({detail['url']})")
                with col2:
                    st.markdown(f"**Status:** {detail.get('status', '200')}")
                
                if detail.get('snippet'):
                    st.markdown("**Exposed Content:**")
                    st.code(detail['snippet'][:500], language='text')
                
                st.markdown("### 🔧 How to Fix")
                
                if '.git' in path:
                    st.info("""
                    **Solution:**
                    1. Block .git folder via web server:
                    
                    **Apache (.htaccess):**
                    ```apache
                    RewriteEngine On
                    RewriteRule "^\.git" - [F,L]
                    ```
                    
                    **Nginx:**
                    ```nginx
                    location ~ /\.git {
                        deny all;
                    }
                    ```
                    
                    2. Or remove .git folder from web root
                    3. Use git deploy tools instead
                    """)
                elif '.env' in path:
                    st.info("""
                    **Solution:**
                    1. Move .env file outside public_html/web root
                    2. Set correct file permissions (600)
                    3. Add to .gitignore
                    4. For Apache: `SetEnvIf ORIG_URI "\\.env$" deny access`
                    """)
                elif 'wp-config' in path or 'config.php' in path:
                    st.info("""
                    **Solution:**
                    1. Move config file outside web root
                    2. Set permissions to 400
                    3. Block direct access via .htaccess
                    """)
                else:
                    st.info(f"**Solution:** Block access to {path} via web server config or remove from public directory.")
                
                st.markdown(f"[**🔗 Open in Browser**]({detail['url']})")
                st.divider()
    
    elif module_name == "Broken Links" and details:
        st.markdown("#### 🔴 Broken Links - Detailed Fix Guide")
        for detail in details:
            with st.expander(f"⚠️ {detail['url']}", expanded=False):
                st.markdown(f"**URL:** [{detail['url']}]({detail['url']})")
                st.markdown(f"**Status:** HTTP {detail.get('status', 'N/A')}")
                
                st.markdown("### 🔧 How to Fix")
                st.info("""
                **Options:**
                1. **Update Link:** Fix the URL if page was moved
                2. **Create Redirect:** Add 301 redirect in .htaccess:
                   ```
                   Redirect 301 /old-page /new-page
                   ```
                3. **Remove Link:** Delete broken link from HTML
                4. **Tools:** Use Screaming Frog to find all broken links
                """)
                st.markdown(f"[**🔗 Try in Browser**]({detail['url']})")
                st.divider()
    
    elif module_name == "Security Headers" and details:
        st.markdown("#### ⚠️ Missing Headers - Detailed Fix Guide")
        for detail in details:
            header = detail.get('header', '')
            severity = detail.get('severity', 'N/A')
            
            with st.expander(f"⚠️ {header} [{severity}]", expanded=False):
                st.markdown(f"**Issue:** {detail.get('description', '')}")
                
                st.markdown("### 🔧 How to Fix")
                
                if header == 'Strict-Transport-Security':
                    st.info("""
                    **Add HSTS Header:**
                    
                    **Apache (.htaccess):**
                    ```apache
                    Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains"
                    ```
                    
                    **Nginx:**
                    ```nginx
                    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
                    ```
                    
                    **Time to fix:** 5-10 minutes
                    """)
                elif header == 'Content-Security-Policy':
                    st.info("""
                    **Add CSP Header:**
                    
                    **Basic CSP (Nginx):**
                    ```nginx
                    add_header Content-Security-Policy "default-src 'self';" always;
                    ```
                    
                    **Recommended CSP:**
                    ```
                    default-src 'self'; 
                    script-src 'self' 'unsafe-inline'; 
                    style-src 'self' 'unsafe-inline'; 
                    img-src 'self' data: https:;
                    ```
                    
                    Test with CSP Evaluator before deploying!
                    """)
                elif header == 'X-Frame-Options':
                    st.info("""
                    **Add X-Frame-Options:**
                    
                    ```apache
                    Header always set X-Frame-Options "DENY"
                    ```
                    
                    or
                    
                    ```nginx
                    add_header X-Frame-Options "SAMEORIGIN" always;
                    ```
                    """)
                else:
                    st.info(f"**Fix:** Add header to web server config: `{detail.get('recommendation', '')}`")
                
                st.markdown(f"[**🔗 Test URL**]({detail.get('url', base_url)})")
                st.divider()
    
    elif module_name == "XSS Analysis" and details:
        st.markdown("#### ⚠️ XSS Vulnerabilities - Detailed Fix Guide")
        for detail in details:
            input_name = detail.get('input', '')
            
            with st.expander(f"⚠️ XSS in parameter: {input_name}", expanded=False):
                st.markdown(f"**Vulnerable Input:** `{input_name}`")
                st.markdown(f"**Description:** {detail.get('description', '')}")
                
                st.markdown("### 🔧 How to Fix")
                st.info("""
                **Immediate Fixes:**
                
                1. **HTML Encoding** (Server-side):
                   - PHP: `htmlspecialchars($input, ENT_QUOTES, 'UTF-8')`
                   - Python: `import html; html.escape(user_input)`
                   - Node.js: `require('html-entities').encodeAll(input)`
                
                2. **Input Validation:**
                   ```python
                   import re
                   allowed = re.match(r'^[a-zA-Z0-9_]+$', user_input)
                   if not allowed:
                       return_error()
                   ```
                
                3. **Content Security Policy:**
                   ```nginx
                   add_header Content-Security-Policy "script-src 'self'" always;
                   ```
                
                4. **Use Framework:**
                   - React/Vue/Angular auto-escape by default
                   - Avoid raw HTML concatenation
                
                **Tools:** Use OWASP ZAP, Burp Suite for testing
                """)
                st.markdown(f"[**🔗 Test URL**]({detail.get('url', '')})")
                st.divider()
    
    elif module_name == "Vulnerable Libraries" and details:
        st.markdown("#### ⚠️ Outdated Libraries - Detailed Fix Guide")
        for detail in details:
            lib = detail.get('library', '')
            version = detail.get('version', '')
            safe = detail.get('min_safe', '')
            
            with st.expander(f"⚠️ {lib} v{version} (safe: {safe})", expanded=False):
                st.markdown(f"**Library:** {lib}")
                st.markdown(f"**Current:** v{version} → **Safe:** v{safe}")
                
                st.markdown("### 🔧 How to Update")
                
                st.info(f"""
                **Option 1 - npm (recommended):**
                ```bash
                npm update {lib}
                # or
                npm install {lib}@latest
                ```
                
                **Option 2 - CDN:**
                Update script src in HTML:
                ```html
                <script src="https://code.jquery.com/jquery-3.7.0.min.js"></script>
                ```
                
                **Option 3 - Composer (PHP):**
                ```bash
                composer require {lib}/{lib}:{safe} --update-with-all-dependencies
                ```
                
                **Prevention:**
                - Run `npm audit` regularly
                - Use dependabot for automated PRs
                - Set up snyk.io for monitoring
                """)
                st.divider()
    
    elif module_name == "DoS Protection" and details:
        st.markdown("#### ⚠️ DoS Protection - Detailed Fix Guide")
        for detail in details:
            with st.expander(f"⚠️ {detail.get('type', 'N/A')}", expanded=False):
                st.markdown(f"**Issue:** {detail.get('description', '')}")
                
                st.markdown("### 🔧 How to Fix")
                
                if 'rate_limit' in detail.get('type', '').lower():
                    st.info("""
                    **Implement Rate Limiting:**
                    
                    **Nginx:**
                    ```nginx
                    http {
                        limit_req_zone $binary_remote_addr zone=limit:10m rate=10r/s;
                        
                        server {
                            location / {
                                limit_req zone=limit burst=20 nodelay;
                            }
                        }
                    }
                    ```
                    
                    **Apache (.htaccess):**
                    ```apache
                    <IfModule mod_ratelimit.c>
                        SetEnv rate-limit 15
                    </IfModule>
                    ```
                    
                    **CloudFlare:**
                    - Dashboard → Security → Settings → Rate Limiting
                    """)
                elif 'slowloris' in detail.get('type', '').lower():
                    st.info("""
                    **Protect from Slowloris:**
                    
                    **Apache:**
                    ```apache
                    Timeout 30
                    KeepAlive On
                    MaxKeepAliveRequests 100
                    KeepAliveTimeout 3
                    ```
                    
                    **Nginx:**
                    ```nginx
                    client_body_timeout 10;
                    keepalive_timeout 5;
                    limit_conn addr 10;
                    ```
                    
                    **Use CDN:** CloudFlare, AWS CloudFront
                    """)
                else:
                    st.info("**Fix:** Implement proper request handling and timeouts on your web server.")
                
                st.divider()
    
    elif module_name == "SEO Analysis" and details:
        st.markdown("#### ⚠️ SEO Issues - Detailed Fix Guide")
        for detail in details:
            issue = detail.get('issue', '')
            issue_type = detail.get('type', '')
            
            with st.expander(f"⚠️ {issue}", expanded=False):
                st.markdown(f"**Issue:** {detail.get('description', '')}")
                
                st.markdown("### 🔧 How to Fix")
                
                if 'title' in issue_type:
                    st.info("""
                    **Fix Missing Title:**
                    
                    Add to `<head>` section:
                    ```html
                    <title>Your Page Title - Brand Name</title>
                    ```
                    
                    Best practices:
                    - 50-60 characters max
                    - Include primary keyword
                    - Unique for each page
                    - Readable for humans
                    """)
                elif 'meta_desc' in issue_type:
                    st.info("""
                    **Fix Missing Meta Description:**
                    
                    Add to `<head>`:
                    ```html
                    <meta name="description" content="Your unique description here. Include primary keyword and call-to-action. 150-160 characters.">
                    ```
                    """)
                elif 'h1' in issue_type:
                    st.info("""
                    **Fix H1 Heading:**
                    
                    Add exactly ONE H1 per page:
                    ```html
                    <h1>Your Main Heading Here</h1>
                    ```
                    
                    Rules:
                    - One H1 per page
                    - Match or relate to title
                    - Include main keyword
                    """)
                elif 'viewport' in issue_type:
                    st.info("""
                    **Fix Viewport Meta:**
                    
                    Add to `<head>`:
                    ```html
                    <meta name="viewport" content="width=device-width, initial-scale=1">
                    ```
                    
                    Critical for mobile SEO and UX!
                    """)
                else:
                    st.info(f"**Fix:** {detail.get('description', '')}")
                
                st.divider()
    
    elif module_name == "Performance" and details:
        st.markdown("#### ⚡ Performance - Optimization Guide")
        for detail in details:
            if detail.get('severity') != 'info':
                with st.expander(f"⚠️ {detail.get('metric', '')}: {detail.get('value', '')}", expanded=False):
                    st.markdown(f"**Value:** {detail.get('value', '')}")
                    st.markdown(f"**Description:** {detail.get('description', '')}")
                    
                    st.markdown("### 🔧 Optimization Steps")
                    
                    if 'Response Time' in detail.get('metric', ''):
                        st.info("""
                        **Speed Optimization:**
                        
                        1. **Enable Compression:**
                           - Nginx: `gzip on;`
                           - Apache: `AddOutputFilterByType DEFLATE text/html`
                        
                        2. **Browser Caching:**
                           ```nginx
                           expires 30d;
                           add_header Cache-Control "public";
                           ```
                        
                        3. **Use CDN:** CloudFlare, AWS CloudFront
                        
                        4. **Optimize Server:** Upgrade to faster hosting, use HTTP/2
                        """)
                    elif 'Page Size' in detail.get('metric', ''):
                        st.info("""
                        **Reduce Page Size:**
                        
                        1. **Compress Images:** Use WebP, optimize with TinyPNG
                        2. **Lazy Loading:** `<img loading="lazy">`
                        3. **Minify:** Minify HTML, CSS, JS
                        4. **Remove Unused Code:** Delete unused CSS/JS
                        """)
                    elif 'Scripts' in detail.get('metric', ''):
                        st.info("""
                        **Optimize Scripts:**
                        
                        1. **Defer Loading:** `<script defer>`
                        2. **Async:** `<script async>`
                        3. **Combine:** Merge multiple JS files
                        4. **Remove Unused:** Delete unused scripts
                        """)
                    
                    st.divider()
    
    elif module_name == "Technical Validation" and details:
        st.markdown("#### ✅ HTML Fixes - Detailed Guide")
        for detail in details:
            issue = detail.get('issue', '')
            
            with st.expander(f"⚠️ {issue}", expanded=False):
                st.markdown(f"**Issue:** {detail.get('description', '')}")
                
                st.markdown("### 🔧 How to Fix")
                
                if 'doctype' in detail.get('type', ''):
                    st.info("""
                    **Add DOCTYPE:**
                    ```html
                    <!DOCTYPE html>
                    <html lang="en">
                    ```
                    """)
                elif 'lang' in detail.get('type', ''):
                    st.info("""
                    **Add Language Attribute:**
                    ```html
                    <html lang="en">
                    ```
                    """)
                elif 'duplicate_id' in detail.get('type', ''):
                    st.info("""
                    **Fix Duplicate IDs:**
                    
                    Change to classes:
                    ```html
                    <!-- Instead of: -->
                    <div id="item">...</div>
                    <div id="item">...</div>
                    
                    <!-- Use: -->
                    <div class="item">...</div>
                    <div class="item">...</div>
                    ```
                    """)
                elif 'missing_alt' in detail.get('type', ''):
                    st.info("""
                    **Add Alt Text:**
                    ```html
                    <!-- For meaningful images: -->
                    <img src="photo.jpg" alt="Description of image">
                    
                    <!-- For decorative images: -->
                    <img src="decoration.png" alt="">
                    ```
                    
                    Required for accessibility (WCAG) and SEO!
                    """)
                
                st.divider()
    
    elif module_name == "SEO Analysis" and details:
        st.markdown("#### ⚠️ SEO Issues")
        for detail in details:
            severity_emoji = "🔴" if detail.get('severity') == 'high' else "🟡"
            with st.expander(f"{severity_emoji} {detail.get('issue', 'N/A')}", expanded=False):
                st.markdown(f"**Type:** {detail.get('type', '')}")
                st.markdown(f"**Description:** {detail.get('description', '')}")
                if detail.get('url'):
                    st.markdown(f"[**🔗 Open URL**]({detail.get('url', '')})")
                st.divider()
    
    elif module_name == "Performance" and details:
        st.markdown("#### 📊 Performance Metrics")
        for detail in details:
            severity_emoji = "🔴" if detail.get('severity') == 'medium' else "🟢"
            with st.expander(f"{severity_emoji} {detail.get('metric', 'N/A')}: {detail.get('value', '')}", expanded=False):
                st.markdown(f"**Value:** {detail.get('value', '')}")
                st.markdown(f"**Description:** {detail.get('description', '')}")
                st.divider()
    
    elif module_name == "Technical Validation" and details:
        st.markdown("#### ⚠️ HTML Issues")
        for detail in details:
            severity_emoji = "🔴" if detail.get('severity') == 'medium' else "🟡"
            with st.expander(f"{severity_emoji} {detail.get('issue', 'N/A')}", expanded=False):
                st.markdown(f"**Type:** {detail.get('type', '')}")
                st.markdown(f"**Description:** {detail.get('description', '')}")
                st.divider()


def main():
    st.set_page_config(
        page_title="Web Vulnerability Scanner",
        page_icon="🛡️",
        layout="wide",
        initial_sidebar_state="expanded"
    )

    st.markdown("""
    <style>
    .stApp { background-color: #0e1117; color: #fafafa; }
    .stMarkdown, .stText { color: #fafafa; }
    .stButton > button {
        background-color: #262730;
        color: #fafafa;
        border: 1px solid #4a4a4a;
    }
    .stButton > button:hover {
        background-color: #363843;
        border-color: #00cc96;
    }
    div[data-testid="stExpander"] {
        background-color: #1e1e2e;
        border: 1px solid #333;
    }
    .vuln-details {
        background-color: #2a1a1a;
        border: 1px solid #ff4444;
        border-radius: 8px;
        padding: 15px;
        margin: 10px 0;
    }
    </style>
    """, unsafe_allow_html=True)

    st.title("🛡️ Web Vulnerability Scanner")
    st.markdown("---")

    st.markdown("### ⚠️ Security Disclaimer")
    st.warning("""
    **This tool is intended for authorized penetration testing and educational purposes only.**
    Unauthorized scanning of websites you do not own or do not have permission to test may be illegal.
    Always ensure you have proper authorization before scanning any target.
    """)

    st.markdown("### 🎯 Target Configuration")

    col1, col2 = st.columns([3, 1])
    with col1:
        target_url = st.text_input(
            "Enter Target URL",
            placeholder="example.com or https://example.com",
            help="Enter the domain to scan"
        )
    with col2:
        st.markdown("<br>", unsafe_allow_html=True)
        scan_button = st.button("🔍 Start Full Scan", use_container_width=True)

    if scan_button and target_url:
        target_url = parse_url(target_url)
        parsed = urlparse(target_url)
        target_host = parsed.netloc

        st.markdown("---")
        progress_bar = st.progress(0)
        status_text = st.empty()
        scan_results = {}

        try:
            status_text.text("🔄 Scanning security headers...")
            progress_bar.progress(10)
            scan_results['Security Headers'] = asyncio.run(check_security_headers(target_url))

            status_text.text("🔄 Checking SSL/TLS certificate...")
            progress_bar.progress(20)
            scan_results['SSL/TLS'] = asyncio.run(check_ssl_certificate(target_url))

            status_text.text("🔄 Scanning information disclosure...")
            progress_bar.progress(30)
            scan_results['Info Disclosure'] = asyncio.run(scan_information_disclosure(target_url))

            status_text.text("🔄 Scanning ports...")
            progress_bar.progress(40)
            scan_results['Port Scanner'] = asyncio.run(check_ports(target_host))

            status_text.text("🔄 Checking vulnerable libraries...")
            progress_bar.progress(50)
            scan_results['Vulnerable Libraries'] = asyncio.run(check_vulnerable_libraries(target_url))

            status_text.text("🔄 Analyzing XSS vulnerabilities...")
            progress_bar.progress(60)
            scan_results['XSS Analysis'] = asyncio.run(check_xss_vulnerabilities(target_url))

            status_text.text("🔄 Checking broken links...")
            progress_bar.progress(70)
            scan_results['Broken Links'] = asyncio.run(check_broken_links(target_url))

            status_text.text("🔄 Checking HTTPS redirect...")
            progress_bar.progress(80)
            scan_results['HTTPS Redirect'] = asyncio.run(check_https_redirect(target_host))

            status_text.text("🔄 Checking DoS protection...")
            progress_bar.progress(90)
            scan_results['DoS Protection'] = asyncio.run(check_dos_vulnerabilities(target_url))

            status_text.text("🔄 Analyzing SEO...")
            progress_bar.progress(92)
            scan_results['SEO Analysis'] = asyncio.run(check_seo_optimization(target_url))

            status_text.text("🔄 Checking performance...")
            progress_bar.progress(94)
            scan_results['Performance'] = asyncio.run(check_performance_metrics(target_url))

            status_text.text("🔄 Validating HTML...")
            progress_bar.progress(96)
            scan_results['Technical Validation'] = asyncio.run(check_html_validation(target_url))

            progress_bar.progress(100)
            status_text.text("✅ Scan complete!")

            st.markdown("### 📊 Scan Results")

            module_names = {
                'Security Headers': 'Security Headers',
                'SSL/TLS': 'SSL/TLS',
                'Info Disclosure': 'Info Disclosure',
                'Port Scanner': 'Port Scanner',
                'Vulnerable Libraries': 'Vulnerable Libraries',
                'XSS Analysis': 'XSS Analysis',
                'Broken Links': 'Broken Links',
                'HTTPS Redirect': 'HTTPS Redirect',
                'DoS Protection': 'DoS Protection',
                'SEO Analysis': 'SEO Analysis',
                'Performance': 'Performance',
                'Technical Validation': 'Technical Validation'
            }

            for module_key, module_name in module_names.items():
                module_results = scan_results.get(module_key, {})
                
                has_issues = False
                if isinstance(module_results, dict):
                    for check, result in module_results.items():
                        if check != 'Details':
                            result_lower = result.lower() if isinstance(result, str) else ""
                            if any(x in result_lower for x in ['exposed', 'missing', 'expired', 'expiring', 'open', 'found', 'weak']):
                                has_issues = True
                                break
                
                icon = "🔴" if has_issues else "🟢"
                
                with st.expander(f"{icon} **{module_name}**", expanded=has_issues):
                    if isinstance(module_results, dict):
                        df_data = [(k, v) for k, v in module_results.items() if k != 'Details']
                        if df_data:
                            df = pd.DataFrame(df_data, columns=["Check", "Result"])
                            df['Result'] = df['Result'].apply(highlight_result)
                            st.dataframe(df, width='stretch', hide_index=True)
                        
                        render_vulnerability_details(module_name, module_results, target_url)

            total_issues = 0
            for module_key, module_results in scan_results.items():
                if isinstance(module_results, dict):
                    for check, result in module_results.items():
                        if check != 'Details':
                            result_lower = result.lower() if isinstance(result, str) else ""
                            if any(x in result_lower for x in ['exposed', 'missing', 'expired', 'expiring', 'open', 'found', 'weak']):
                                total_issues += 1

            st.markdown("### 📈 Summary")
            col_s1, col_s2, col_s3 = st.columns(3)
            with col_s1:
                st.metric("Modules Scanned", len(scan_results))
            with col_s2:
                st.metric("Potential Issues", total_issues)
            with col_s3:
                if total_issues == 0:
                    st.success("No major issues found!")
                else:
                    st.warning(f"{total_issues} issues found - review above")

            st.markdown("### 📥 Export Results")

            pdf_bytes = generate_pdf_report(target_url, scan_results)

            col_dl1, col_dl2 = st.columns(2)
            with col_dl1:
                b64_pdf = base64.b64encode(pdf_bytes).decode()
                href = f'<a href="data:application/octet-stream;base64,{b64_pdf}" download="vulnerability_scan_{target_host}_{datetime.now().strftime("%Y%m%d_%H%M%S")}.pdf"><button style="background-color:#00cc96;color:white;padding:10px 20px;border:none;border-radius:5px;cursor:pointer;width:100%;">📄 Download PDF Report</button></a>'
                st.markdown(href, unsafe_allow_html=True)
            with col_dl2:
                df_all = pd.DataFrame()
                for module_key, module_results in scan_results.items():
                    if isinstance(module_results, dict):
                        for k, v in module_results.items():
                            if k != 'Details':
                                temp_df = pd.DataFrame([{"Check": k, "Result": v, "Module": module_key}])
                                df_all = pd.concat([df_all, temp_df], ignore_index=True)

                csv = df_all.to_csv(index=False)
                b64_csv = base64.b64encode(csv.encode()).decode()
                href_csv = f'<a href="data:text/csv;base64,{b64_csv}" download="vulnerability_scan_{target_host}_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv"><button style="background-color:#4a4a4a;color:white;padding:10px 20px;border:none;border-radius:5px;cursor:pointer;width:100%;">📊 Download CSV Report</button></a>'
                st.markdown(href_csv, unsafe_allow_html=True)

        except Exception as e:
            st.error(f"❌ Scan failed: {str(e)}")
            st.info("Please ensure the target URL is valid and reachable.")

    elif scan_button and not target_url:
        st.warning("⚠️ Please enter a target URL to scan.")

    with st.sidebar:
        st.markdown("### ℹ️ About")
        st.info("""
        **Web Vulnerability Scanner** - Comprehensive web audit tool:
        
        🛡️ **Security:** Headers, SSL, XSS, DoS, Vulnerable libs
        
        🔍 **SEO:** Title, meta tags, H1/H2, Open Graph
        
        ⚡ **Performance:** Response time, page size, resources
        
        ✅ **Technical:** HTML validation, duplicate IDs, accessibility
        
        Click on modules to see detailed results and direct links.
        """)

        st.markdown("### 🔧 Module Status")
        for module in ["Headers", "SSL", "Info Disclosure", "Ports", "Libraries", "XSS", "Links", "HTTPS", "DoS", "SEO", "Performance", "Validation"]:
            st.success(f"✓ {module} Ready")


if __name__ == "__main__":
    main()