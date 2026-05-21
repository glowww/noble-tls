import asyncio
import json

import noble_tls
from noble_tls import Client
from rich import pretty, print
from noble_tls.c.cffi import addCookiesToSession
# You can also use the following as `client_identifier`:
# Chrome --> chrome_103, chrome_104, chrome_105, chrome_106, chrome_107, chrome_108, chrome109, Chrome110,
#            chrome111, chrome112
# Firefox --> firefox_102, firefox_104, firefox108, Firefox110
# Opera --> opera_89, opera_90
# Safari --> safari_15_3, safari_15_6_1, safari_16_0
# iOS --> safari_ios_15_5, safari_ios_15_6, safari_ios_16_0
# iPadOS --> safari_ios_15_6
# Android --> okhttp4_android_7, okhttp4_android_8, okhttp4_android_9, okhttp4_android_10, okhttp4_android_11,
#             okhttp4_android_12, okhttp4_android_13


async def main():
    #await noble_tls.download_if_necessary()
    #await noble_tls.update_if_necessary()
    session = noble_tls.Session(
        client=Client.NIKE_IOS_MOBILE,
        debug=True,
    )

    res = await session.get(
        "https://httpbin.org/cookies/set/a/b",
        with_custom_cookie_jar=False,
        allow_redirects=False
    )
    #await session.clear_cookies()
    res = await session.get(
        "https://httpbin.org/cookies",
        with_custom_cookie_jar=False
    )
    print(res.json())
    print(session.cookies)



asyncio.run(main())
