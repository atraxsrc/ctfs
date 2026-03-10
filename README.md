# Ctf Writeups

HTB, Vulnhub, Ethernaut
<img width="915" height="1151" alt="Screenshot" src="https://github.com/user-attachments/assets/fd0662c5-8ece-49c7-8856-08f6a45fc7f8" />


The IP address appearing as Hong Kong (e.g., 4.252.166.196, a Microsoft-owned address) in your QRadar logs during a corporate sign-in, even though the user is physically in Australia, is almost certainly normal and expected behavior for Microsoft 365 / Entra ID (formerly Azure AD) authentication traffic.
Microsoft's global cloud infrastructure routes authentication requests (like sign-ins to corporate resources such as Office 365, Teams, Outlook, or Entra ID-protected apps) through the nearest or most optimal data centers, edge nodes, or proxies worldwide. This means:

The source IP recorded in logs (including QRadar, which ingests these events) is often the IP of a Microsoft authentication endpoint, load balancer, or proxy server—not the user's actual public IP from their ISP in Australia.
Microsoft has data centers and points of presence (PoPs) in the East Asia region, including Hong Kong (e.g., the "East Asia" Azure region is Hong Kong-based).
Authentication traffic can egress or be proxied through these regional nodes for performance, latency optimization, redundancy, or load balancing—even if the user is connecting from Australia (which has its own Azure regions in Sydney and Melbourne).
This is especially common for cloud-based sign-ins, where the "source" in logs reflects Microsoft's infrastructure rather than the end-user's device IP.

Why This Shows Up in QRadar

QRadar ingests logs from sources like Microsoft 365 audit logs, Entra ID sign-in logs, or Windows event logs forwarded via agents/connectors.
In these logs, the source IP for successful UserLoggedIn / authentication events is frequently a Microsoft public IP (from the ranges you shared earlier), and geolocation databases tag it to Hong Kong if that's the registered location for that block.
The user's actual location isn't directly logged as the source IP; Microsoft doesn't always forward the original client IP for these auth events (or it's anonymized/proxied).

Common Reasons This Happens (Not Malicious)

Microsoft's anycast/global routing — Auth requests hit the closest Microsoft edge server, which could be in Hong Kong for certain paths from Asia-Pacific.
No VPN/proxy on user side needed — This occurs even on direct connections; it's Microsoft's side doing the routing.
Geolocation inaccuracies — IP-to-location mapping relies on third-party databases (which Microsoft uses), and Microsoft IPs can show varied countries even within the same ASN.
Similar reports exist for users in the US seeing non-US Microsoft IPs, or Australians seeing US/Virginia IPs—it's infrastructure-related, not user location spoofing.

When to Investigate Further (Rare Cases)
If this is unexpected or you suspect something else:

Check the Entra ID sign-in logs directly (Entra admin center > Monitoring & health > Sign-in logs) for the specific event:
Look at IP address, Location, Client app, Conditional Access status, and Risk level.
If it's a legitimate sign-in, the "Applied Conditional Access policies" might show nothing blocked, and risk could be low/none.

Confirm no corporate VPN, proxy, or Global Secure Access (Entra Internet Access) is forcing traffic through unusual paths.
Review user device: Is MFA satisfied? Any unusual app/protocol (e.g., legacy auth)?
If patterns look anomalous (e.g., multiple distant countries in short time, high-risk flags), treat as potential compromise and investigate.

In most corporate environments using Microsoft cloud services, this Hong Kong IP for Australian users is benign "noise" from legitimate auth routing. That's why you see it repeatedly from Windows servers/cloud endpoints worldwide—it's Microsoft's backend, not remote servers in HK accessing your network.
To reduce such noise in QRadar (as discussed earlier), continue excluding those Microsoft public IP ranges via Reference Sets or routing rules. If it's triggering false-positive alerts/rules, tune them to ignore known MSFT blocks or focus on risk signals instead of just location/IP. Let me know if you have the exact event details (e.g., event name, log source) for more specific tuning!
