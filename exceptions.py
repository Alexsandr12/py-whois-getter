class WhoisGetterError(Exception):
    pass


class ConnectTimeoutError(WhoisGetterError):
    pass


class NoAuthorityServerError(WhoisGetterError):
    pass
