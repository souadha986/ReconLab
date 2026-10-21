
# ReconLab

<img width="855" height="341" alt="image" src="https://github.com/user-attachments/assets/bc07095d-06b2-41a0-9667-59a5956376a7" />


ReconLab is a lightweight reconnaissance toolkit that I am building from scratch in Python.

The project initially combines some of  reconnaissance mechanisms and techniques that I learned during my penetration-testing learning path. However, the main purpose of ReconLab is not simply to use an existing reconnaissance tool, but to **build one myself and understand how each mechanism works internally**.

Reconnaissance is one of the first phases of a penetration-testing operation. It can be considered the **pre-processing phase**, where we gather information about a target and gradually build a complete picture of its infrastructure, technologies, services, domains, and potential attack surface.

Reconnaissance can generally be divided into two main approaches:

- **Passive reconnaissance:** gathering information without directly interacting with the target infrastructure. One of the most important concepts here is **OSINT (Open-Source Intelligence)**, where information is collected from publicly available sources.
- **Active reconnaissance:** directly interacting with the target to perform discovery and enumeration, such as scanning ports, identifying services, and discovering exposed infrastructure. Because this interaction generates traffic toward the target, it can potentially be detected or blocked by security mechanisms such as firewalls, IDS/IPS, or other monitoring systems.

For ReconLab, the main focus will be **active reconnaissance**.

Instead of simply relying on existing tools, I will implement the different reconnaissance mechanisms myself using Python. The objective is to understand what happens behind the tools I normally use during penetration testing and to gain practical experience by recreating their core functionality.

## ReconLab Functionalities

> **The functionalities of ReconLab will be listed here as the project develops.**

### 1. Host discovery:
In ReconLab, I implemented host discovery using two main methods: **ICMP and TCP**, with ARP as a fallback for private networks.
The ICMP method uses raw IPv4 sockets to send Echo Request (Type 8) packets to each target across three passes. To handle multiple targets efficiently, I used a background thread to send packets while the main thread listens for replies using `select.select()`. For private networks, I also use Scapy to send ARP requests to discover local hosts that may not respond to ICMP.
The TCP method uses Python's `socket` library to attempt TCP connections to target hosts. A host is considered reachable if the connection succeeds or is refused. To avoid slow, sequential connection attempts, I used `ThreadPoolExecutor` with 200 worker threads to establish TCP connections concurrently. Finally, all discovered hosts are combined into a single list, and duplicate IP addresses are removed.

### 2. Service enumeration:
For this,I implemented TCP and UDP port scanning using Python's socket library. The module supports scanning all ports, well-known ports, common ports, or custom port ranges. It identifies port states by analyzing connection results and responses. To improve performance, I used ThreadPoolExecutor with up to 300 worker threads to scan multiple ports concurrently. The module also retrieves standard service names when available and displays scan progress and results in real time, including open, closed, filtered, and ambiguous UDP ports.
### 3. Dns reconnaissance:
I implemented DNS enumeration using the dnspython library to retrieve common DNS records, including A, AAAA, MX, NS, TXT, and CNAME. The module also attempts DNS zone transfers (AXFR) and uses multithreading to discover subdomains from a predefined wordlist. Results are displayed in real time, with duplicate records removed.
### 4. Web reconnaissance:
 I implemented web enumeration using the httpx library to inspect HTTP response headers and discover common web paths. The module uses ThreadPoolExecutor to check multiple paths concurrently and reports discovered paths with their HTTP status codes in real time.
 ## Difficulties Faced
 During the development of ReconLab, I faced several challenges, including understanding low-level networking concepts, handling socket timeouts and connection errors, and managing concurrent tasks using ThreadPoolExecutor. I also had to handle different responses from TCP, UDP, DNS, and HTTP requests, avoid duplicate results, and display scan progress and errors clearly in the Streamlit interface. These challenges helped me better understand how reconnaissance techniques work behind the scenes.
## Future Improvements
In the future, I want to focus more on passive reconnaissance and OSINT by adding tools and features that gather information without directly interacting with the target. I also plan to expand Web Enumeration with more tools and functionalities, integrate vulnerability scanning, and develop  scripts to improve ReconLab's performance and capabilities.

## How to Run ReconLab
To run ReconLab, use the following command in the terminal with root privileges:
**sudo streamlit run app.py**
Root privileges may be required for certain features, such as raw socket operations used in ICMP host discovery.
## Feedback and Contact
For any feedback, suggestions, or questions about ReconLab, feel free to contact me at hamsashouad04@gmail.com
