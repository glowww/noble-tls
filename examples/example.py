import asyncio, noble_tls
from noble_tls.utils.identifiers import Client
async def main():
    session = noble_tls.Session(Client.FIREFOX_147_PSK)
    session.proxies = {"http": "http://localhost:8083"}

    response = await session.get(
        "https://www.bet365.com/",
        headers={
            "user-agent": "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:149.0) Gecko/20100101 Firefox/149.0",
            "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "accept-language": "en-US,en;q=0.9",
            "accept-encoding": "gzip, deflate, br, zstd",
            "sec-gpc": "1",
            "upgrade-insecure-requests": "1",
            "sec-fetch-dest": "document",
            "sec-fetch-mode": "navigate",
            "sec-fetch-site": "none",
            "sec-fetch-user": "?1",
            "priority": "u=0, i",
            "te": "trailers",
        },
        insecure_skip_verify=True
    )

asyncio.run(main())
