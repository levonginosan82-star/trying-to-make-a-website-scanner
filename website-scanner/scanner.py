import asyncio
import socket
import ssl
import datetime
import re
from typing import Dict, List, Tuple, Set, Any
from urllib.parse import urlparse, urljoin

import httpx


FIX_RECOMMENDATIONS = {
    'missing_header': {
        'title': 'Detailed Fix Guide',
        'steps': {
            'Apache': 'Add to .htaccess: Header always set [HEADER_NAME] "[VALUE]"',
            'Nginx': 'Add to server block: add_header [HEADER_NAME] "[VALUE]" always;',
            'IIS': 'Add to web.config: <customHeaders> section with header element',
            'Cloudflare': 'Add Transform Rule: Modify Response Header',
            'General': 'Contact your hosting provider or sysadmin to add missing security headers'
        },
        'time_to_fix': '15-30 minutes',
        'difficulty': 'Easy'
    },
    'sensitive_path': {
        'Apache': 'Add to .htaccess: RewriteRule ^path$ - [F,L] or deny from all',
        'Nginx': 'Add location block with deny all; or return 403;',
        'IIS': 'Add requestFiltering rule in web.config',
        'AWS_S3': 'Block public access in S3 bucket settings',
        'Git': 'Block .git folder via web server config or remove from web root',
        'Env': 'Move .env file outside public_html/document_root'
    },
    'xss': {
        'html_escape': 'Use htmlspecialchars() in PHP, or Jinja2 autoescape in Python',
        'input_validation': 'Validate and sanitize all user inputs on server side',
        'content_security': 'Set CSP header to prevent inline scripts',
        'http_only': 'Set HttpOnly flag on session cookies',
        'framework': 'Use modern frameworks (React, Vue, Angular) with auto-escaping'
    },
    'vulnerable_lib': {
        'npm': 'npm update [library-name] or npm install [library-name]@latest',
        'cdn': 'Update script src to latest version URL',
        'composer': 'composer update [library-name] --with-all-dependencies',
        'prevention': 'Use npm audit, dependabot, or snyk for automated alerts'
    },
    'broken_link': {
        'fix': 'Update the link URL or remove the broken link from HTML',
        'redirect': 'Create 301 redirect if page was moved',
        'check': 'Use Google Search Console or Screaming Frog to find all broken links'
    },
    'missing_title': {
        'fix': 'Add <title>Your Page Title</title> in <head> section',
        'best_practices': [
            'Use 50-60 characters',
            'Include primary keyword',
            'Make it unique for each page',
            'Write for users, not search engines'
        ]
    },
    'missing_meta_desc': {
        'fix': 'Add <meta name="description" content="Your description here">',
        'best_practices': [
            'Use 150-160 characters',
            'Include call-to-action',
            'Unique for each page',
            'Avoid duplicate descriptions'
        ]
    },
    'missing_h1': {
        'fix': 'Add exactly one <h1>Heading</h1> per page',
        'rules': [
            'One H1 per page',
            'Include main keyword',
            'Match page title or be similar',
            'Make descriptive and user-friendly'
        ]
    },
    'slow_loading': {
        'optimize_images': 'Use WebP format, compress images, lazy loading',
        'minify': 'Minify HTML, CSS, JS files',
        'caching': 'Enable browser caching, use CDN',
        'reduce_requests': 'Combine CSS/JS, inline critical CSS',
        'server': 'Use faster hosting, enable Gzip compression'
    },
    'large_page': {
        'lazy_loading': 'Implement lazy loading for images/videos',
        'code_splitting': 'Split JavaScript bundles',
        'remove_unused': 'Remove unused CSS/JS',
        'server_push': 'Use HTTP/2 server push for critical resources'
    },
    'duplicate_id': {
        'fix': 'Change duplicate IDs to classes or unique IDs',
        'css_fix': 'Use .class instead of #id for repeated elements',
        'js_fix': 'Update any getElementById calls to use classes'
    },
    'missing_alt': {
        'fix': 'Add alt="description" to all img tags',
        'decorative': 'Use alt="" for decorative images',
        'meaningful': 'Describe what the image shows for accessibility'
    },
    'no_rate_limiting': {
        'implement': 'Configure rate limiting in web server or application',
        'nginx': 'limit_req_zone $binary_remote_addr zone=limit:10m rate=10r/s;',
        'apache': 'Use mod_ratelimit or mod_evasive',
        'application': 'Implement IP-based or token-based request limits',
        'cloud': 'Use CloudFlare Rate Limiting or similar service'
    },
    'slowloris': {
        'apache': 'Set TimeOut and KeepAliveTimeout to lower values',
        'nginx': 'Configure client_body_timeout and keepalive_timeout',
        'firewall': 'Use fail2ban to block slowloris attack patterns',
        'cdn': 'CloudFlare, AWS CloudFront provide DoS protection'
    },
    'missing_viewport': {
        'fix': 'Add <meta name="viewport" content="width=device-width, initial-scale=1">',
        'importance': 'Critical for mobile SEO and user experience'
    }
}


SECURITY_HEADERS_INFO = {
    'Strict-Transport-Security': {
        'description': 'HSTS header enforces HTTPS usage',
        'recommendation': 'Add header: Strict-Transport-Security: max-age=31536000; includeSubDomains',
        'severity': 'high'
    },
    'Content-Security-Policy': {
        'description': 'CSP protects against XSS and content injection',
        'recommendation': 'Configure CSP policy for your domain',
        'severity': 'medium'
    },
    'X-Frame-Options': {
        'description': 'Protection against clickjacking',
        'recommendation': 'Add header: X-Frame-Options: DENY or SAMEORIGIN',
        'severity': 'medium'
    },
    'X-Content-Type-Options': {
        'description': 'Prevents MIME type sniffing',
        'recommendation': 'Add header: X-Content-Type-Options: nosniff',
        'severity': 'low'
    },
    'X-XSS-Protection': {
        'description': 'XSS filter in browsers (deprecated for modern browsers)',
        'recommendation': 'Use CSP instead for modern browsers',
        'severity': 'low'
    },
    'Referrer-Policy': {
        'description': 'Controls information in Referer header',
        'recommendation': 'Add header: Referrer-Policy: strict-origin-when-cross-origin',
        'severity': 'low'
    },
    'Permissions-Policy': {
        'description': 'Controls browser feature access',
        'recommendation': 'Configure Permissions-Policy according to app needs',
        'severity': 'low'
    }
}

VULNERABLE_LIBS = {
    "jquery": {"pattern": r"jquery[- ]?(\d+\.\d+\.\d+)", "min_safe": "3.0.0"},
    "lodash": {"pattern": r"lodash[- ]?(\d+\.\d+\.\d+)", "min_safe": "4.17.21"},
    "moment": {"pattern": r"moment[- ]?(\d+\.\d+\.\d+)", "min_safe": "2.29.4"},
    "vue": {"pattern": r"vue[- ]?(\d+\.\d+\.\d+)", "min_safe": "3.0.0"},
    "react": {"pattern": r"react[- ]?(\d+\.\d+\.\d+)", "min_safe": "18.0.0"},
    "angular": {"pattern": r"angular[- ]?(\d+\.\d+\.\d+)", "min_safe": "13.0.0"}
}

SENSITIVE_PATHS = [
    ".env", ".env.local", ".env.production",
    ".git/config", ".git/HEAD", ".git/index", ".gitignore",
    "config.php", "configuration.php", "wp-config.php",
    "settings.py", "secrets.py", "secrets.yaml",
    "admin/", "administrator/", "phpmyadmin/", "pma/",
    "backup/", "backups/", "test/", "tests/",
    "debug/", ".debug", ".htaccess", ".htpasswd",
    "robots.txt", "sitemap.xml", "composer.json",
    "package.json", "package-lock.json"
]

XSS_PAYLOADS = [
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert('XSS')>",
    "<svg onload=alert('XSS')>",
    "javascript:alert('XSS')",
    "<iframe src=javascript:alert('XSS')>",
    "<body onload=alert('XSS')>",
    "\"><script>alert('XSS')</script>",
    "'-alert('XSS')-'",
    '"><img src=x onerror=alert("XSS")>'
]


async def check_security_headers(target_url: str) -> Dict[str, Any]:
    """
    Analyze HTTP security headers for the target URL.
    Checks for missing recommended security headers with severity levels.
    """
    results = {}
    details = []

    try:
        async with httpx.AsyncClient(timeout=10.0, follow_redirects=True) as client:
            response = await client.get(target_url)
            response_headers = {k.lower(): v for k, v in response.headers.items()}

            for header, info in SECURITY_HEADERS_INFO.items():
                header_lower = header.lower()
                if header_lower in response_headers:
                    value = response_headers[header_lower].lower()
                    
                    if header == 'Strict-Transport-Security' and 'max-age=0' in value:
                        results[header] = f"Weak (max-age=0 disables protection)"
                    else:
                        results[header] = f"Present: {response_headers[header_lower][:50]}"
                else:
                    results[header] = f"MISSING ({info['severity']} severity)"
                    details.append({
                        'type': 'missing_header',
                        'header': header,
                        'severity': info['severity'],
                        'description': info['description'],
                        'recommendation': info['recommendation'],
                        'url': target_url,
                        'link': target_url
                    })

            results['Details'] = details

    except Exception as e:
        results['Error'] = str(e)

    return results


async def check_ssl_certificate(target_url: str) -> Dict[str, str]:
    """
    Validate SSL/TLS certificate and check expiration date.
    Returns certificate details and validation status.
    """
    results = {}

    try:
        parsed = urlparse(target_url)
        hostname = parsed.hostname if parsed.hostname else target_url.replace('https://', '').split('/')[0]
        port = parsed.port if parsed.port else 443

        context = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()

                if cert:
                    subject = dict(x[0] for x in cert['subject'])
                    issuer = dict(x[0] for x in cert['issuer'])

                    results['Subject'] = subject.get('commonName', 'Unknown')
                    results['Issuer'] = ', '.join([issuer.get(k, 'Unknown') for k in ['organizationName', 'commonName', 'organizationUnitName'] if issuer.get(k)])

                    not_after = cert.get('notAfter')

                    if not_after:
                        results['Valid Until'] = not_after
                        try:
                            exp_date = datetime.datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
                            days_remaining = (exp_date - datetime.datetime.now()).days
                            if days_remaining < 0:
                                results['Status'] = "EXPIRED"
                            elif days_remaining < 30:
                                results['Status'] = f"EXPIRING SOON ({days_remaining} days)"
                            else:
                                results['Status'] = f"Valid ({days_remaining} days remaining)"
                        except:
                            results['Status'] = "Unknown expiry"

                    results['Protocol'] = ssock.version()
                else:
                    results['Status'] = "No certificate found"

    except ssl.SSLCertVerificationError as e:
        results['Status'] = f"Certificate Error: {str(e)}"
    except Exception as e:
        results['Status'] = f"Connection Error: {str(e)}"

    return results


async def scan_information_disclosure(target_url: str) -> Dict[str, Any]:
    """
    Scan for publicly exposed sensitive files using asynchronous requests.
    Checks for common sensitive files that may expose information.
    Extended version with severity ratings and code snippets.
    """
    results = {}
    details = []

    try:
        parsed = urlparse(target_url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"

        async with httpx.AsyncClient(timeout=5.0, follow_redirects=False) as client:
            tasks = [client.get(base_url + '/' + path, timeout=5.0) for path in SENSITIVE_PATHS]
            responses = await asyncio.gather(*tasks, return_exceptions=True)

            for path, response in zip(SENSITIVE_PATHS, responses):
                severity = get_path_severity(path)
                full_url = base_url + '/' + path
                
                if isinstance(response, Exception):
                    results[path] = f"Error: {type(response).__name__}"
                elif response.status_code == 200:
                    content = response.text[:500] if hasattr(response, 'text') else ""
                    results[path] = f"EXPOSED [{severity}]"
                    details.append({
                        'path': path,
                        'url': full_url,
                        'severity': severity,
                        'status': 200,
                        'snippet': content
                    })
                elif response.status_code == 403:
                    results[path] = f"Protected (403)"
                else:
                    results[path] = f"Not Found ({response.status_code})"

            results['Details'] = details

    except Exception as e:
        results['Error'] = str(e)

    return results


def get_path_severity(path: str) -> str:
    """Determine vulnerability severity based on path."""
    critical = ['.env', 'config.php', 'settings.py', 'secrets.py', 'wp-config.php', '.git/']
    high = ['admin', 'administrator', 'phpmyadmin', 'pma', 'backup', 'backups', '.gitignore', '.htaccess']
    medium = ['test', 'tests', 'debug', '.debug']
    
    path_lower = path.lower()
    if any(p in path_lower for p in critical):
        return "CRITICAL"
    elif any(p in path_lower for p in high):
        return "HIGH"
    elif any(p in path_lower for p in medium):
        return "MEDIUM"
    return "LOW"


async def check_ports(target_host: str) -> Dict[str, str]:
    """
    Check if common vulnerable ports are open.
    Scans for FTP, SSH, MySQL, and PostgreSQL ports.
    """
    ports_to_check = {
        21: 'FTP',
        22: 'SSH',
        3306: 'MySQL',
        5432: 'PostgreSQL'
    }

    results = {}

    try:
        socket.setdefaulttimeout(3)

        tasks = []
        for port, service in ports_to_check.items():
            task = asyncio.create_task(check_single_port(target_host, port, service))
            tasks.append(task)

        port_results = await asyncio.gather(*tasks)
        for service, status in port_results:
            results[service] = status

    except Exception as e:
        results['Error'] = str(e)

    return results


async def check_single_port(host: str, port: int, service: str) -> Tuple[str, str]:
    """Check if a single port is open on the target host."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3)
        result = sock.connect_ex((host, port))
        sock.close()

        if result == 0:
            return (service, "OPEN")
        else:
            return (service, "Closed")

    except Exception as e:
        return (service, f"Error: {str(e)}")


async def check_vulnerable_libraries(target_url: str) -> Dict[str, Any]:
    """
    Check JavaScript libraries for known vulnerable versions.
    Detects outdated jQuery, lodash, moment, vue, react, angular.
    """
    results = {}
    details = []
    
    try:
        parsed = urlparse(target_url)
        
        async with httpx.AsyncClient(timeout=10.0, follow_redirects=True) as client:
            response = await client.get(target_url)
            html = response.text
            
            script_pattern = r'<script[^>]+src=["\']([^"\']*(?:jquery|lodash|moment|vue|react|angular)[^"\']*)["\']'
            script_matches = re.findall(script_pattern, html, re.IGNORECASE)
            
            for lib_name, lib_info in VULNERABLE_LIBS.items():
                pattern = lib_info['pattern']
                match = re.search(pattern, html, re.IGNORECASE)
                
                if match:
                    version = match.group(1)
                    results[lib_name] = f"Found v{version} (min safe: {lib_info['min_safe']})"
                    
                    script_url = next((s for s in script_matches if lib_name in s.lower()), None)
                    
                    details.append({
                        'type': 'vulnerable_lib',
                        'library': lib_name,
                        'version': version,
                        'min_safe': lib_info['min_safe'],
                        'url': script_url if script_url else target_url,
                        'link': script_url if script_url else target_url,
                        'severity': 'medium',
                        'description': f'{lib_name} v{version} has known vulnerabilities. Update to v{lib_info["min_safe"]}'
                    })
                else:
                    results[lib_name] = "Not detected or no version info"
            
            results['Details'] = details
                    
    except Exception as e:
        results['Error'] = str(e)
    
    return results


async def check_xss_vulnerabilities(target_url: str) -> Dict[str, str]:
    """
    Basic XSS vulnerability testing by checking form reflection.
    """
    results = {}
    
    try:
        parsed = urlparse(target_url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"
        
        async with httpx.AsyncClient(timeout=10.0, follow_redirects=False) as client:
            response = await client.get(target_url)
            html = response.text
            
            forms_found = 0
            potential_xss = 0
            
            form_pattern = r'<form[^>]*>'
            forms = re.findall(form_pattern, html, re.IGNORECASE)
            forms_found = len(forms)
            
            safe_payload = "<script>console.log('test')</script>"
            
            input_pattern = r'<input[^>]*name=["\']([^"\']+)["\'][^>]*>'
            inputs = re.findall(input_pattern, html, re.IGNORECASE)
            
            for input_name in inputs[:5]:
                if '?' in target_url:
                    test_url = f"{target_url}&{input_name}={safe_payload}"
                else:
                    test_url = f"{target_url}?{input_name}={safe_payload}"
                
                try:
                    test_response = await client.get(test_url, timeout=5.0)
                    if safe_payload in test_response.text:
                        escaped = any(e in test_response.text for e in ['&lt;', '&gt;', '&#60;', '&#62;'])
                        if not escaped:
                            potential_xss += 1
                except:
                    pass
            
            results['Forms Found'] = str(forms_found)
            results['Text Inputs'] = str(len(inputs))
            
            if potential_xss > 0:
                results['Potential XSS'] = f"Found {potential_xss} potential vulnerabilities"
                for input_name in inputs[:potential_xss]:
                    test_url = f"{target_url}?{input_name}=test"
                    details.append({
                        'type': 'xss',
                        'input': input_name,
                        'url': test_url,
                        'link': test_url,
                        'severity': 'high',
                        'description': f'Input parameter "{input_name}" may reflect values without escaping'
                    })
            else:
                results['Potential XSS'] = "Not detected"
            
            results['Details'] = details
            
    except Exception as e:
        results['Error'] = str(e)
    
    return results


async def check_broken_links(target_url: str, max_links: int = 20) -> Dict[str, Any]:
    """
    Check for broken links (404 errors) on the page.
    Returns detailed results with code snippets and links.
    """
    results = {}
    details = []
    
    try:
        parsed = urlparse(target_url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"
        
        async with httpx.AsyncClient(timeout=10.0, follow_redirects=True) as client:
            response = await client.get(target_url)
            html = response.text
            
            link_pattern = r'href=["\']([^"\']+)["\']'
            links = re.findall(link_pattern, html)
            
            broken_count = 0
            checked = 0
            
            for link in links[:max_links]:
                if link.startswith('http') and parsed.netloc in link:
                    checked += 1
                    try:
                        async with client.head(link, timeout=5.0) as resp:
                            if resp.status >= 400:
                                broken_count += 1
                                details.append({
                                    'url': link,
                                    'status': resp.status,
                                    'link': link
                                })
                    except Exception:
                        broken_count += 1
                        details.append({'url': link, 'status': 'Error', 'link': link})
            
            results['Links Checked'] = str(checked)
            results['Broken Links'] = str(broken_count)
            results['Status'] = "OK" if broken_count == 0 else f"Found {broken_count} broken links"
            results['Details'] = details
            
    except Exception as e:
        results['Error'] = str(e)
    
    return results


async def check_https_redirect(target_host: str) -> Dict[str, str]:
    """
    Check if HTTP redirects to HTTPS.
    """
    results = {}
    
    try:
        async with httpx.AsyncClient(timeout=10.0, follow_redirects=False) as client:
            response = await client.get(f"http://{target_host}")
            
            if response.status_code in (301, 302, 303, 307, 308):
                location = response.headers.get('location', '')
                if 'https' in location.lower():
                    results['HTTP to HTTPS'] = f"Redirects to {location[:50]}"
                else:
                    results['HTTP to HTTPS'] = f"Redirects elsewhere (status: {response.status_code})"
            elif response.status_code == 200:
                results['HTTP to HTTPS'] = "No redirect (potential security issue)"
            else:
                results['HTTP to HTTPS'] = f"Status: {response.status_code}"
                
    except Exception as e:
        results['Error'] = str(e)
    
    return results


async def run_full_scan(target_url: str) -> Dict[str, Dict]:
    """
    Run complete security scan with all modules.
    Returns dictionary with all scan results.
    """
    parsed = urlparse(target_url)
    hostname = parsed.hostname if parsed.hostname else target_url.replace('https://', '').split('/')[0]
    
    results = {}
    
    results['Security Headers'] = await check_security_headers(target_url)
    results['SSL/TLS Certificate'] = await check_ssl_certificate(target_url)
    results['Information Disclosure'] = await scan_information_disclosure(target_url)
    results['Port Scanner'] = await check_ports(hostname)
    results['Vulnerable Libraries'] = await check_vulnerable_libraries(target_url)
    results['XSS Analysis'] = await check_xss_vulnerabilities(target_url)
    results['Broken Links'] = await check_broken_links(target_url)
    results['HTTPS Redirect'] = await check_https_redirect(hostname)
    results['DoS Protection'] = await check_dos_vulnerabilities(target_url)
    results['SEO Analysis'] = await check_seo_optimization(target_url)
    results['Performance'] = await check_performance_metrics(target_url)
    results['Technical Validation'] = await check_html_validation(target_url)
    
    return results


async def check_dos_vulnerabilities(target_url: str) -> Dict[str, Any]:
    """Check for DoS (Denial of Service) vulnerabilities and missing protections."""
    results = {}
    details = []
    
    try:
        parsed = urlparse(target_url)
        
        async with httpx.AsyncClient(timeout=30.0, follow_redirects=True) as client:
            response = await client.get(target_url)
            headers = {k.lower(): v for k, v in response.headers.items()}
            
            rate_limit_headers = [
                'x-ratelimit-limit', 'x-rate-limit',
                'x-ratelimit-remaining', 'retry-after',
                'cf-ray', 'cf-cache-status'
            ]
            
            found_rate_limiting = False
            for header in rate_limit_headers:
                if header in headers:
                    found_rate_limiting = True
                    details.append({
                        'type': 'rate_limiting',
                        'header': header,
                        'value': str(headers[header]),
                        'severity': 'low',
                        'description': f'Rate limiting header: {header}'
                    })
            
            if not found_rate_limiting:
                details.append({
                    'type': 'no_rate_limiting',
                    'header': 'None',
                    'value': 'Not found',
                    'severity': 'medium',
                    'description': 'No rate limiting - vulnerable to brute-force'
                })
            
            if 'content-length' not in headers:
                details.append({
                    'type': 'no_content_length',
                    'header': 'Content-Length',
                    'value': 'Missing',
                    'severity': 'low',
                    'description': 'No Content-Length header'
                })
            
            server_header = headers.get('server', 'Unknown')
            details.append({
                'type': 'server_info',
                'header': 'Server',
                'value': server_header,
                'severity': 'info',
                'description': f'Server: {server_header}'
            })
            
            details.extend(await check_tls_handshake_timeout(parsed.hostname, parsed.port or 443))
            details.extend(await check_slowloris_protection(target_url))
            
            results['Rate Limiting'] = 'Found' if found_rate_limiting else 'NOT DETECTED'
            results['Content-Length Limit'] = 'Present' if 'content-length' in headers else 'Missing'
            results['Slowloris Test'] = 'Completed'
            results['Server'] = server_header
            results['Details'] = details
            
    except Exception as e:
        results['Error'] = str(e)
    
    return results


async def check_tls_handshake_timeout(hostname: str, port: int) -> List[Dict]:
    """Check TLS handshake configuration."""
    details = []
    
    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        
        try:
            wrapped = context.wrap_socket(sock, server_hostname=hostname)
            cipher = wrapped.cipher()
            wrapped.close()
            
            details.append({
                'type': 'tls_config',
                'header': 'Cipher',
                'value': cipher[0] if cipher else 'Unknown',
                'severity': 'info',
                'description': f'TLS cipher: {cipher[0] if cipher else "N/A"}'
            })
        except ssl.SSLError as e:
            if 'timeout' in str(e).lower():
                details.append({
                    'type': 'tls_timeout',
                    'header': 'TLS Timeout',
                    'value': 'Slow',
                    'severity': 'medium',
                    'description': 'Slow TLS handshake - DoS risk'
                })
    except Exception as e:
        pass
    
    return details


async def check_slowloris_protection(target_url: str) -> List[Dict]:
    """Check if server is vulnerable to Slowloris attack."""
    details = []
    parsed = urlparse(target_url)
    
    try:
        port = parsed.port or 80
        reader, writer = await asyncio.open_connection(parsed.hostname, port)
        
        writer.write(b"GET / HTTP/1.1\r\n")
        writer.write(f"Host: {parsed.hostname}\r\n".encode())
        writer.write(b"X-A: ")
        await writer.drain()
        
        await asyncio.sleep(2)
        
        try:
            writer.write(b"\r\n")
            await writer.drain()
            await asyncio.wait_for(reader.read(1024), timeout=3)
            
            details.append({
                'type': 'slowloris',
                'header': 'Test',
                'value': 'Responsive',
                'severity': 'low',
                'description': 'Server handles slow requests'
            })
        except asyncio.TimeoutError:
            details.append({
                'type': 'slowloris',
                'header': 'Test',
                'value': 'Slow Response',
                'severity': 'medium',
                'description': 'May be vulnerable to Slowloris'
            })
        
        writer.close()
        await writer.wait_closed()
        
    except Exception as e:
        details.append({
            'type': 'slowloris_error',
            'header': 'Test',
            'value': 'Failed',
            'severity': 'info',
            'description': f'Test error: {str(e)[:50]}'
        })
    
    return details


async def check_seo_optimization(target_url: str) -> Dict[str, Any]:
    """Check SEO optimization factors: meta tags, headings, sitemap, robots.txt."""
    results = {}
    details = []
    
    try:
        async with httpx.AsyncClient(timeout=15.0, follow_redirects=True) as client:
            response = await client.get(target_url)
            html = response.text.lower()
            
            title_match = re.search(r'<title[^>]*>([^<]+)</title>', html, re.IGNORECASE)
            title = title_match.group(1).strip() if title_match else None
            
            meta_desc = re.search(r'<meta[^>]+name=["\']description["\'][^>]+content=["\']([^"\']+)["\']', html, re.IGNORECASE)
            description = meta_desc.group(1).strip() if meta_desc else None
            
            h1_tags = re.findall(r'<h1[^>]*>([^<]+)</h1>', html, re.IGNORECASE)
            h2_tags = re.findall(r'<h2[^>]*>([^<]+)</h2>', html, re.IGNORECASE)
            
            viewport = re.search(r'<meta[^>]+name=["\']viewport["\']', html, re.IGNORECASE)
            charset = re.search(r'<meta[^>]+charset=["\']?([^"\'>\s]+)', html, re.IGNORECASE)
            
            canonical = re.search(r'<link[^>]+rel=["\']canonical["\'][^>]+href=["\']([^"\']+)["\']', html, re.IGNORECASE)
            
            og_tags = {
                'og:title': bool(re.search(r'<meta[^>]+property=["\']og:title["\']', html, re.IGNORECASE)),
                'og:description': bool(re.search(r'<meta[^>]+property=["\']og:description["\']', html, re.IGNORECASE)),
                'og:image': bool(re.search(r'<meta[^>]+property=["\']og:image["\']', html, re.IGNORECASE)),
                'og:url': bool(re.search(r'<meta[^>]+property=["\']og:url["\']', html, re.IGNORECASE))
            }
            
            results['Title Tag'] = f"Present: {title[:50]}..." if title else "MISSING"
            results['Meta Description'] = f"Present: {description[:50]}..." if description else "MISSING"
            results['H1 Tags'] = str(len(h1_tags))
            results['H2 Tags'] = str(len(h2_tags))
            results['Viewport Meta'] = "Present" if viewport else "MISSING"
            results['Canonical URL'] = "Present" if canonical else "Not Found"
            results['Open Graph'] = f"{sum(og_tags.values())}/4 tags"
            
            if not title:
                details.append({
                    'type': 'title',
                    'issue': 'Missing Title Tag',
                    'url': target_url,
                    'link': target_url,
                    'severity': 'high',
                    'description': 'Page is missing <title> tag - critical for SEO'
                })
            
            if not description:
                details.append({
                    'type': 'meta_desc',
                    'issue': 'Missing Meta Description',
                    'url': target_url,
                    'link': target_url,
                    'severity': 'medium',
                    'description': 'Page is missing meta description'
                })
            
            if len(h1_tags) == 0:
                details.append({
                    'type': 'h1',
                    'issue': 'Missing H1 Tag',
                    'url': target_url,
                    'link': target_url,
                    'severity': 'medium',
                    'description': 'Page should have exactly one H1 heading'
                })
            elif len(h1_tags) > 1:
                details.append({
                    'type': 'h1',
                    'issue': 'Multiple H1 Tags',
                    'url': target_url,
                    'link': target_url,
                    'severity': 'medium',
                    'description': f'Found {len(h1_tags)} H1 tags - should be exactly one'
                })
            
            if not viewport:
                details.append({
                    'type': 'viewport',
                    'issue': 'Missing Viewport Meta',
                    'url': target_url,
                    'link': target_url,
                    'severity': 'medium',
                    'description': 'Missing viewport meta tag - affects mobile'
                })
            
            for og_name, og_present in og_tags.items():
                if not og_present:
                    details.append({
                        'type': 'og_tag',
                        'issue': f'Missing {og_name}',
                        'url': target_url,
                        'link': target_url,
                        'severity': 'low',
                        'description': f'Open Graph tag {og_name} not found'
                    })
            
            results['Details'] = details
            
    except Exception as e:
        results['Error'] = str(e)
    
    return results


async def check_performance_metrics(target_url: str) -> Dict[str, Any]:
    """Check basic performance metrics: response time, page size, resource count."""
    results = {}
    details = []
    
    try:
        start_time = datetime.datetime.now()
        
        async with httpx.AsyncClient(timeout=30.0, follow_redirects=True) as client:
            response = await client.get(target_url)
            response_time = (datetime.datetime.now() - start_time).total_seconds() * 1000
            
            html = response.text
            page_size = len(html)
            
            images = re.findall(r'<img[^>]+src=["\']([^"\']+)["\']', html, re.IGNORECASE)
            scripts = re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', html, re.IGNORECASE)
            styles = re.findall(r'<link[^>]+href=["\']([^"\']+\.css[^"\']*)["\']', html, re.IGNORECASE)
            external_links = re.findall(r'<a[^>]+href=["\'](https?://[^"\']+)["\']', html, re.IGNORECASE)
            
            results['Response Time'] = f"{response_time:.0f} ms"
            results['Page Size'] = f"{page_size / 1024:.1f} KB"
            results['Images'] = str(len(images))
            results['Scripts'] = str(len(scripts))
            results['CSS Files'] = str(len(styles))
            results['External Links'] = str(len(external_links))
            
            details.append({
                'type': 'timing',
                'metric': 'Response Time',
                'value': f"{response_time:.0f} ms",
                'severity': 'info',
                'description': 'Server response time'
            })
            
            details.append({
                'type': 'size',
                'metric': 'Page Size',
                'value': f"{page_size / 1024:.1f} KB",
                'severity': 'info',
                'description': 'Total HTML size'
            })
            
            if response_time > 2000:
                details.append({
                    'type': 'slow_loading',
                    'metric': 'Response Time',
                    'value': f"{response_time:.0f} ms",
                    'severity': 'medium',
                    'description': 'Page loads slowly (>2s)'
                })
            
            if page_size > 500 * 1024:
                details.append({
                    'type': 'large_page',
                    'metric': 'Page Size',
                    'value': f"{page_size / 1024:.1f} KB",
                    'severity': 'medium',
                    'description': 'Large page size (>500KB)'
                })
            
            if len(scripts) > 10:
                details.append({
                    'type': 'many_scripts',
                    'metric': 'Scripts',
                    'value': str(len(scripts)),
                    'severity': 'low',
                    'description': f'{len(scripts)} external scripts - may affect performance'
                })
            
            results['Details'] = details
            
    except Exception as e:
        results['Error'] = str(e)
    
    return results


async def check_html_validation(target_url: str) -> Dict[str, Any]:
    """Check HTML structure and common issues."""
    results = {}
    details = []
    
    try:
        async with httpx.AsyncClient(timeout=15.0, follow_redirects=True) as client:
            response = await client.get(target_url)
            html = response.text
            
            doctype = re.search(r'<!DOCTYPE[^>]*>', html, re.IGNORECASE)
            html_tag = re.findall(r'<html[^>]*>', html, re.IGNORECASE)
            head_tag = re.findall(r'<head[^>]*>', html, re.IGNORECASE)
            body_tag = re.findall(r'<body[^>]*>', html, re.IGNORECASE)
            
            lang_attr = re.search(r'<html[^>]+lang=["\']([^"\']+)["\']', html, re.IGNORECASE)
            
            duplicate_ids = re.findall(r'id=["\']([^"\']+)["\']', html)
            id_counts = {}
            for dup_id in duplicate_ids:
                id_counts[dup_id] = id_counts.get(dup_id, 0) + 1
            duplicate_ids_list = {k: v for k, v in id_counts.items() if v > 1}
            
            inline_scripts = len(re.findall(r'<script[^>]*>.*?</script>', html, re.IGNORECASE | re.DOTALL))
            inline_styles = len(re.findall(r'<style[^>]*>.*?</style>', html, re.IGNORECASE | re.DOTALL))
            
            empty_links = re.findall(r'<a[^>]*href=["\']\s*["\']', html, re.IGNORECASE)
            
            img_no_alt = len(re.findall(r'<img[^>]+(?!alt=)[^>]*>', html, re.IGNORECASE))
            
            results['Doctype'] = "Present" if doctype else "MISSING"
            results['HTML Tag'] = "Present" if html_tag else "MISSING"
            results['Head Tag'] = "Present" if head_tag else "MISSING"
            results['Body Tag'] = "Present" if body_tag else "MISSING"
            results['Language'] = lang_attr.group(1) if lang_attr else "Not Set"
            results['Duplicate IDs'] = str(len(duplicate_ids_list))
            results['Inline Scripts'] = str(inline_scripts)
            results['Inline Styles'] = str(inline_styles)
            results['Empty Links'] = str(len(empty_links))
            results['Images Without Alt'] = str(img_no_alt)
            
            if not doctype:
                details.append({
                    'type': 'doctype',
                    'issue': 'Missing DOCTYPE',
                    'severity': 'medium',
                    'description': 'Page missing DOCTYPE declaration'
                })
            
            if not lang_attr:
                details.append({
                    'type': 'lang',
                    'issue': 'Missing lang attribute',
                    'severity': 'low',
                    'description': 'HTML tag should have lang attribute'
                })
            
            if duplicate_ids_list:
                for dup_id, count in list(duplicate_ids_list.items())[:3]:
                    details.append({
                        'type': 'duplicate_id',
                        'issue': f'Duplicate ID: {dup_id}',
                        'severity': 'low',
                        'description': f'ID "{dup_id}" used {count} times'
                    })
            
            if len(empty_links) > 0:
                details.append({
                    'type': 'empty_links',
                    'issue': f'{len(empty_links)} empty links',
                    'severity': 'low',
                    'description': 'Found links without href'
                })
            
            if img_no_alt > 5:
                details.append({
                    'type': 'missing_alt',
                    'issue': f'{img_no_alt} images without alt',
                    'severity': 'medium',
                    'description': 'Many images missing alt attribute'
                })
            
            results['Details'] = details
            
    except Exception as e:
        results['Error'] = str(e)
    
    return results