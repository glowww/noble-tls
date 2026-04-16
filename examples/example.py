import asyncio, noble_tls
from noble_tls.utils.identifiers import Client
async def main():
    session = noble_tls.Session(Client.CHROME_133)
    session.proxies = {"http": "http://localhost:8083"}
    await session.get("https://httpbin.org/cookies/set/a/b", insecure_skip_verify=True)
    await session.get("https://httpbin.org/cookies/set/b/a123",  insecure_skip_verify=True)
    print((await session.get("https://httpbin.org/get", headers={"Cookie": None, "yarrak_1": "a", "yarrak_2": "b"},insecure_skip_verify=True)).json())

asyncio.run(main())
