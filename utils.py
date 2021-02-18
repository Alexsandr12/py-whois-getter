import idna


def encode_punycode(domain: str) -> str:
    return idna.encode(domain).decode()
