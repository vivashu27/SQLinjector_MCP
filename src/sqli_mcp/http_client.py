"""HTTP client with authentication, proxy, and timeout support."""

import httpx
from typing import Optional, Any
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from sqli_mcp.models import AuthConfig, ProxyConfig, HttpMethod


class HttpClient:
    """HTTP client wrapper with auth, proxy, and scanning capabilities."""
    
    def __init__(
        self,
        auth: Optional[AuthConfig] = None,
        proxy: Optional[ProxyConfig] = None,
        timeout: float = 10.0,
        user_agent: str = "SQLi-MCP-Scanner/1.0"
    ):
        """
        Initialize HTTP client.
        
        Args:
            auth: Authentication configuration
            proxy: Proxy configuration
            timeout: Request timeout in seconds
            user_agent: User-Agent header value
        """
        self.auth = auth or AuthConfig()
        self.proxy = proxy
        self.timeout = timeout
        self.user_agent = user_agent
    
    def _build_headers(self, extra_headers: Optional[dict[str, str]] = None) -> dict[str, str]:
        """Build request headers including auth and custom headers."""
        headers = {
            "User-Agent": self.user_agent,
        }
        
        # Add custom headers from auth config
        headers.update(self.auth.headers)
        
        # Add Bearer token if provided
        if self.auth.bearer_token:
            headers["Authorization"] = f"Bearer {self.auth.bearer_token}"
        
        # Add extra headers
        if extra_headers:
            headers.update(extra_headers)
        
        return headers
    
    def _build_cookies(self, extra_cookies: Optional[dict[str, str]] = None) -> dict[str, str]:
        """Build cookies from auth config and extra cookies."""
        cookies = dict(self.auth.cookies)
        if extra_cookies:
            cookies.update(extra_cookies)
        return cookies
    
    def _get_proxy_config(self) -> Optional[str]:
        """Get proxy URL for httpx."""
        if not self.proxy:
            return None
        return self.proxy.http_proxy or self.proxy.https_proxy
    
    def _get_verify_ssl(self) -> bool:
        """Get SSL verification setting."""
        if self.proxy:
            return self.proxy.verify_ssl
        return True
    
    async def request(
        self,
        url: str,
        method: HttpMethod = HttpMethod.GET,
        params: Optional[dict[str, str]] = None,
        data: Optional[dict[str, str]] = None,
        json_data: Optional[dict[str, Any]] = None,
        extra_headers: Optional[dict[str, str]] = None,
        extra_cookies: Optional[dict[str, str]] = None,
        timeout: Optional[float] = None
    ) -> httpx.Response:
        """
        Make an HTTP request.
        
        Args:
            url: Target URL
            method: HTTP method
            params: Query parameters
            data: Form data for POST
            json_data: JSON data for POST
            extra_headers: Additional headers
            extra_cookies: Additional cookies
            timeout: Override default timeout
        
        Returns:
            httpx.Response object
        """
        headers = self._build_headers(extra_headers)
        cookies = self._build_cookies(extra_cookies)
        proxy = self._get_proxy_config()
        verify = self._get_verify_ssl()
        request_timeout = timeout or self.timeout
        
        async with httpx.AsyncClient(
            proxy=proxy,
            verify=verify,
            timeout=request_timeout,
            follow_redirects=True
        ) as client:
            if method == HttpMethod.GET:
                response = await client.get(
                    url,
                    params=params,
                    headers=headers,
                    cookies=cookies
                )
            else:  # POST
                response = await client.post(
                    url,
                    params=params,
                    data=data,
                    json=json_data,
                    headers=headers,
                    cookies=cookies
                )
            
            return response
    
    async def get(
        self,
        url: str,
        params: Optional[dict[str, str]] = None,
        **kwargs
    ) -> httpx.Response:
        """Make a GET request."""
        return await self.request(url, HttpMethod.GET, params=params, **kwargs)
    
    async def post(
        self,
        url: str,
        data: Optional[dict[str, str]] = None,
        json_data: Optional[dict[str, Any]] = None,
        **kwargs
    ) -> httpx.Response:
        """Make a POST request."""
        return await self.request(
            url, HttpMethod.POST, data=data, json_data=json_data, **kwargs
        )
    
    async def request_with_timing(
        self,
        url: str,
        method: HttpMethod = HttpMethod.GET,
        **kwargs
    ) -> tuple[httpx.Response, float]:
        """
        Make a request and return response with timing.
        
        Returns:
            Tuple of (response, elapsed_seconds)
        """
        import time
        start = time.perf_counter()
        response = await self.request(url, method, **kwargs)
        elapsed = time.perf_counter() - start
        return response, elapsed


def parse_url_params(url: str) -> dict[str, str]:
    """Parse query parameters from a URL."""
    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    # parse_qs returns lists, flatten to single values
    return {k: v[0] if len(v) == 1 else v for k, v in params.items()}


def rebuild_url_with_params(url: str, params: dict[str, str]) -> str:
    """Rebuild a URL with new query parameters."""
    parsed = urlparse(url)
    new_query = urlencode(params)
    return urlunparse((
        parsed.scheme,
        parsed.netloc,
        parsed.path,
        parsed.params,
        new_query,
        parsed.fragment
    ))


def inject_payload_in_url(url: str, parameter: str, payload: str) -> str:
    """
    Inject a payload into a specific URL parameter.
    
    Args:
        url: Original URL with parameters
        parameter: Parameter name to inject into
        payload: SQL injection payload
    
    Returns:
        URL with payload injected
    """
    params = parse_url_params(url)
    if parameter in params:
        original_value = params[parameter]
        if isinstance(original_value, str):
            params[parameter] = original_value + payload
        else:
            params[parameter] = str(original_value[0]) + payload
    else:
        params[parameter] = payload
    
    return rebuild_url_with_params(url, params)


def inject_payload_in_data(
    data: dict[str, str],
    parameter: str,
    payload: str
) -> dict[str, str]:
    """
    Inject a payload into POST data parameter.
    
    Args:
        data: Original POST data
        parameter: Parameter name to inject into
        payload: SQL injection payload
    
    Returns:
        New data dict with payload injected
    """
    new_data = dict(data)
    if parameter in new_data:
        new_data[parameter] = str(new_data[parameter]) + payload
    else:
        new_data[parameter] = payload
    return new_data
