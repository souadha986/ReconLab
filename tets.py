import httpx


def inspect_headers(
    target_url: str,
    timeout: float = 5.0,
    verify_ssl: bool = False
) -> dict:
   
    request_headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) ReconLab/1.0"
    }

    try:
       
        with httpx.Client(
            follow_redirects=False,
            timeout=timeout,
            verify=verify_ssl
        ) as client:
            response = client.get(target_url, headers=request_headers)

            return {
                "success": True,
                "url": str(response.url),
                "status_code": response.status_code,
                "status_reason": response.reason_phrase,
                "http_version": response.http_version,
                "server": response.headers.get("server", "Unknown"),
                "content_type": response.headers.get("content-type", "Unknown"),
                "location": response.headers.get("location", None),  # Populated if 30x redirect
                "headers": dict(response.headers),  # Case-insensitive dict converted to standard dict
                "error": None
            }

    except httpx.ConnectTimeout:
        return {"success": False, "error": f"Connection timed out after {timeout} seconds."}
    except httpx.ConnectError as exc:
        return {"success": False, "error": f"Failed to connect to host: {exc}"}
    except httpx.RequestError as exc:
        return {"success": False, "error": f"HTTP request error: {exc}"}
if __name__ == "__main__":
    import sys

    url = sys.argv[1] if len(sys.argv) > 1 else "https://example.com"
    print(f"[*] Testing Header Inspection on: {url}\n")

    result = inspect_headers(url)

    if result["success"]:
        print(f"[+] Status Code : {result['status_code']} ({result['status_reason']})")
        print(f"[+] HTTP Version: {result['http_version']}")
        print(f"[+] Server      : {result['server']}")
        if result["location"]:
            print(f"[+] Redirect To : {result['location']}")
        print("\n[*] Raw Headers:")
        for header, val in result["headers"].items():
            print(f"    {header}: {val}")
    else:
        print(f"[!] Failed: {result['error']}")
