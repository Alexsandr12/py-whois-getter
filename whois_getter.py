import socket
from typing import List, TypedDict, Dict

from utils import encode_punycode
from exceptions import GettingWhoisTextError


Domain = str
WhoisText = str


class RequestParamsBase(TypedDict):
    domain: str
    whois_server: str


class RequestParams(RequestParamsBase, total=False):
    whois_port: int


class Whois:
    def __init__(self, whois_timeout: int = 10) -> None:
        self.whois_timeout = whois_timeout

    def get_domain_whois(
        self, domain: Domain, whois_server: str, whois_port: int = 43
    ) -> WhoisText:
        pass

    def get_domains_whois(
        self, domains: List[RequestParams]
    ) -> Dict[Domain, WhoisText]:
        pass

    def get_domain_whois_authority(self, domain: Domain) -> WhoisText:
        pass

    def get_domains_whois_authority(
        self, domains: List[Domain]
    ) -> Dict[Domain, WhoisText]:
        pass

    def _get_whois(
        self, domain: Domain, whois_server: str, whois_port: int
    ) -> WhoisText:
        domain_puny = encode_punycode(domain)
        response = bytes()
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(self.whois_timeout)
            sock.connect((whois_server, whois_port))
            sock.send(f"{domain_puny}\r\n".encode())
            while True:
                try:
                    data = sock.recv(4096)
                except socket.timeout:
                    raise GettingWhoisTextError

                if data:
                    response += data
                else:
                    break

        return response.decode("utf-8", "replace")


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
