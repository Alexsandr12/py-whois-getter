from typing import List, TypedDict, Dict


Domain, WhoisText = str


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
        pass