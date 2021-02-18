import socket
import re
from typing import List, TypedDict, Dict, Optional

from utils import encode_punycode
from exceptions import ConnectTimeoutError, NoAuthorityServerError


Domain = str
WhoisText = str
PATTERN_AUTHORITY_SERVER = re.compile(r"whois:\s+([\d\w.-]+)")


class RequestParamsBase(TypedDict):
    domain: str
    server: str


class RequestParams(RequestParamsBase, total=False):
    port: int


class Whois:
    DEFAULT_PORT = 43
    DEFAULT_TIMEOUT = 5
    _BASE_WHOIS_SERVER = "whois.iana.org"

    def __init__(self, whois_timeout: Optional[int] = None) -> None:
        self.whois_timeout = whois_timeout

    def get_domain_whois(
        self, domain: Domain, server: str, port: int = DEFAULT_PORT
    ) -> WhoisText:
        return self._get_whois(domain, server, port)

    def get_domains_whois(
        self, request_params: List[RequestParams]
    ) -> Dict[Domain, WhoisText]:
        return {
            params["domain"]: self._get_whois(
                params["domain"],
                params["server"],
                params.get("port", self.DEFAULT_PORT),
            )
            for params in request_params
        }

    def get_domain_whois_authority(self, domain: Domain) -> WhoisText:
        whois_text = self._get_whois(domain, self._BASE_WHOIS_SERVER, self.DEFAULT_PORT)
        authority_server = self._extract_authority_whois_server(whois_text)

        return self._get_whois(domain, authority_server, self.DEFAULT_PORT)

    def get_domains_whois_authority(
        self, domains: List[Domain]
    ) -> Dict[Domain, WhoisText]:
        return {domain: self.get_domain_whois_authority(domain) for domain in domains}

    def _get_whois(self, domain: Domain, server: str, port: int) -> WhoisText:
        domain_puny = encode_punycode(domain)

        response = bytes()
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(self.whois_timeout or self.DEFAULT_TIMEOUT)
            try:
                sock.connect((server, port))
                sock.send(f"{domain_puny}\r\n".encode())
            except socket.timeout:
                raise ConnectTimeoutError

            while True:
                try:
                    data = sock.recv(4096)
                except socket.timeout:
                    raise ConnectTimeoutError

                if data:
                    response += data
                else:
                    break

        return response.decode("utf-8", "replace")

    @staticmethod
    def _extract_authority_whois_server(whois_text: WhoisText) -> str:
        result = PATTERN_AUTHORITY_SERVER.search(whois_text)
        if not result:
            raise NoAuthorityServerError

        return result.group(1)


class Nameserver(TypedDict):
    host: str
    ipv4_addresses: List[str]
    ipv6_addresses: List[str]


class WhoisParser:
    def __init__(self, whois_text: WhoisText):
        self.whois_text = whois_text

    def get_statuses(self) -> List[str]:
        pass

    def get_dates(self) -> Dict[str, str]:
        pass

    def get_nameservers(self) -> List[Nameserver]:
        pass
