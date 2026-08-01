"""Pure-Python Snefru hash family.

The deterministic Snefru S-boxes are encoded compactly after generation from
the published RAND digit table. The construction and compression function
match crypto-api (MIT license), CyberChef's reference implementation.
"""

from __future__ import annotations

import base64
import struct

_MASK32 = 0xFFFFFFFF
_SHIFT = (16, 8, 16, 24)
_SBOX_DATA = (
    b"GwD5ZPbN3f7i8Y98FBXXEdMYjIseiN/dVlCrbuHYzohZiRRJ1W/FaQNPmbc+7rwPQEkmPFh+VSHCP0vhkfVcLs74"
    b"79xIFioJNimBvmoMe/83ECXV8Uikr1rJr30/nKYe56sXpCPkkFjAcMuw9yVQyOOXTSRfWfMflmPsxBceGFl3tDXm"
    b"v31ONVN3b3nMUutmlfnDdyep4zLWrsyAnegrTii9WzcFPRqts0IbK3FMxBaov1RNetx95USBbexrBHFaUJYi2CSP"
    b"/IcJDsbLZgM5tpJg99kLp5PTiqAxHclx2ZxF9B5clLb6hmVBtP2+/KqO68bKS+WUevtO0IlXNc8T+qmNayMA8DNB"
    b"HCYkYjvyEvSkVl7nFiECMB9/8br5cpjQnGmjwaoC6PHcRdENk+DcT/AShI1289BsPbfmPX9zuoTyMDq0aZ9WRMrq"
    b"5ACw4421yBORlen+LtaDH4aQdJjWzu48eS8wHFfo0WU2SDGwB6tPhEyR6Du/FZoqPyzUX7meLUfnklvMlyKCJ1/u"
    b"YrV3U8+7jtvd3mH5YFybxQ2R0xutBtIm2BSFslJrz167eOp/rHlIUISoNO08HeU2HXRTF+3KR4zvQAqdIeJFMXDr"
    b"J9qjC3PfiYc8GKbAmnPG31iawTSxVC4kPqwCOUnMmdotewG8FY/HOP0pjzHVJ/WvSmAYaJzy7KKKw8PUGRBuk/uo"
    b"OXvtIBlhaAtvkKCJnoLHHEvvUpmMng6FkDoGzY4vAGe3jKzPEUui6mxOi5jfZvBGCOx+ymSmu8e9Fx2D5nX1Yw41"
    b"ZJdCDYdHoqRsAofVZ4GrrbZh0mRlqnsj2nBKx+EloAHJodqlsA5B93B26lrAUTL6PZMa/1kHuAoBVnjL3l/47TI/"
    b"udu+rm0y+DnFWAjS5ItjmwrIcqWfoeAo/JkgQ83DNzqFxZW/KsGSs9cHp2phavZSsYPUEl5bQ5YrgHU+MyulO6VR"
    b"n6lX4aG9DOfCeOB8rvxnImDRTaz/KkcJUUo6uLIKeeUEeoD9DTQi6Ra5m16d4vRKYvWv2alM/iy9ayD2t+MHbnTC"
    b"trlCW7wZaaAPxPLwtXohcvOdwRSuLYDztL6U4P8aEKJdVykFfLLNVbLdO6N9syhl2wUMdMRiaulGKHhABtcwbSyO"
    b"9Lve0+K8+jeeBDTmtQGNbYgtfi5afhMgQdeXD+kGuj5d5IYzrbglGwUTVFMDDHWbyHHQ+zjGoRF/GfsID+9RhkT4"
    b"Y5VAOENEL0VVTUZdTHbYAzjWuLEvugunENKzlKeSZuvZwgnUJoWDaBWK26aYbB91iJp23mhG7slzo4IaSaqWCIE2"
    b"I0LLVSz2BFQcn1yxT/cSQ27Acl3+b4tnqIop0Xwz/c4RggkdSgdaDqFS+KN1kmxQgksbft83xbN4TNqx+s5+JnL0"
    b"9kUwtsAfatbjmAJAlAzmJ7jx0ofMVp7fAxjNRZjgNR02x+fM8TtIA9cHcx9I+ejGEcET5v/GVTl87XARQdqVjvQb"
    b"w5khgNqk+5Rfex+lDd13qmJlI8trVcasG9u5QIB5jzflv+ZVHXPuv6XaYLybOKT7MxsEclacaGzCNmmd7neIPuuK"
    b"zrVQLZDneZX8PLFCK9P7M6cDBe4kKIa1rR7kFfcuQch1EkSdgsXOL7eD9F/fMTmPeypdLvl7Rkmp3lMGNc6EJlxe"
    b"ZX7YcSfxZ8wVu6F8CatSzz2YJvDdEFd/JiG09lgsZTIEMQGMqwuZIEnVGeaqrErlTJQ5PdHyMvzTrUCKoM1R1LDi"
    b"rgj+ntIP1bn911zq3UmnyVMi6hOq6y2DD2S+JGqSPuDeHOApGJ/1i7YAnQ9GiyPhNI59HtuaYZOfL7N27CyXvXap"
    b"H+MQu4+mnaQ7+x3Eh4XQ0a2lv4TP81AR4dS8pv/ZjAH2w3IF8a4vS6Z0WZXc59U1rip/WG9b/lPjqXS2T8qoJLoE"
    b"X4fG5WZivNw/wMVrAu8eZqsLdO3kNI4Fz0bptyWBaYjtSOxyo3MQseuFNKGcQqKiR3VA+hNnt1B9wxhUpS0Zlkuw"
    b"CxceAopR0ROssCr6YwnhEG5K3CtHWGLZ+PfqOZGXOGWFjUJwmcB6TTJIyyN2RGTju4wOawxusGNt04RMJD9xyUI1"
    b"wY0iK7slA8vp1sD4awYR3ieTZKg++DH8BgTYfWHdFvnTeZ/YwkRRYTFdtOtYKQAoNwqJVgg4W/BE6DoSFp6DhoMN"
    b"S5E8tAbFXro8z8n1YHygst4iFSecXe+ge8cLNkVPi30BwSncWuSbkFmnk9IsQbGW19cw/8gAgEqjI5FcwU61eE5x"
    b"LuS5R03q83hbjwd/OllsNBp6qKMS/subY5lDPY5t77IoYNS4ytUvbFZSZ2LzovIBCq6WvCCJmnCHbhS04rkIY7qn"
    b"vWSSaO2vovI3YOBpKfWmQ9sKABSBgvC90JCeVMkZc2o/IE+vzBptTnGJBUdNFgdfZmdwYSDssoIhDIGcK6AilyhT"
    b"hnap9nlBDhRJiHefXeGImlTbyiVv81fRwyGkMorpaLMNzZJa1Kh6dXjCCsLHUbUI6JGUhNZax02+M3xpM8rwuk5b"
    b"Ekazd9ZZ8sjZMAyGr9D60H8cLPcP/kNvjVw77P1Xl622aonfKtKFFxcYLeK/AhcJuG2vFrKAmk9e6G4wHHr1m8Rv"
    b"HKH3OucV4oHNPzZoyFeTPlX9Uu9Mq4s7lfSMPL3u/L4UtyX9PdiYxI0aLg2sZvnpRXQ4DuUZVEPEvn5e2biQqpY6"
    b"Gv/j5I9KzZl98spAStCU8V/LWidoNr4WSP9MOYun2+lrTNI47E6A7JZC+JbOzTgvjIj1CFXnFGSRe0qhCgYn8xSi"
    b"r41gvsLeux7pjPlh/lYh6aPXIk/ZqHY/M0uaVVkprTiefvHzkbrhhfum6+WM1NxzeP/D9VhgG0j3lzKK9Dsfj7Ja"
    b"eJNbSnpHXes0Yy4bJW0tEKl0+o/jB2KcXJHqdcLM7HPia3DdvT5seZXYG6lU3IHfr8lzP2MjtBlRJ2drn7EibnVQ"
    b"4lKxK6JG6nYy4lOj1mpZLwvbHguk2dMCQ3i0eJA+iWStyvBA1zqN9gcX/UbvZ5wc3obgtaZs7pZ0R6OaivSkG/2r"
    b"AY324T4Yeqr4X6765Bewgzkwi2YIbIJDrNSfhMXmU/v+ks7EysGIE1BDzxgRRAizT+yGjqBTxeAPniUVHPkFvkWs"
    b"tXyY14cUuklAiZNXSHaH1X9yWKnD499Yd8829BFNnjmpv6XwO6Nh72CsTKa60KgEctUNAw8yPbhFMLLK8PJm440A"
    b"XYE6pJfI8y01HR1XzLlEh/OLkpAgcuskoetezpn7k0K5O5xU2igooriqhXcZpJYCxzObJfYlIdqFXO69Fd/ox7cV"
    b"de+r4sGbwfxo+H9BNESIFHlRgmIcwdXG3AVHDuANcCIYr9LToCLom/FptjVctSvEUhKACvzwWxFW2Nc8nV8/tBZl"
    b"MMJHHCOhfiBJ8ZWnCVLYzLM0VP6uZ06Sgyysy2JmYdHtXqqB5oRr0lddxFxG+qjDOn7GDHy/oZqK4W8KL8MNwCyy"
    b"aQMoPU9VTpnTgPRo5vXPrWWyjjoxmCaDCYpWvWquyEsrbfVpyOoXD8e2Lnc8NEGfQgcdq1BvaoJ8CaL+g8ISGZlY"
    b"GM45SETk1TWGLf+x0GUXf1qGsZ9tMiAo5VnhrZAASXE8dZiL3Z3akaalu4IDDTDJBIkAsGwIvdNpbqfn1CTQTyQF"
    b"DF4aEMt9lGp790DoA1AMfR8PN3ztRVKAPz1e4A6IBnk1zb+6l8Z+GiQjBYzfyG4MiaUp0QJbp8fnHdgSZiq+2atj"
    b"Qh+2/XPeCmgAKjaeZFZV7TMx8gv6kCqgEClGnZ2U3dzRoNS3yc/le2fSszbLlRCUzRMTM/fbwOjGt0tBgfdtAQtR"
    b"VxHesCz2sNbMTge7t5UTf/ksee4+1m/qjpPWW2T8Aq+4erXahDfbjo8xFocBGk0WQWHyJrnmcrMGK/z4BA7Aepq4"
    b"JzelvOmXL3QqnH0fO7xxtGVxKUybYFFTkiASIeda0eVLRV+5/8AZ+Q7dyXAtb7/FdAljYqqYTR7ZAW67hCEePMRw"
    b"FVlDTSOFe668Bvu2du4xVCZdvP09SXft5C5xxTcEOKgaJu8uKzl5WsIyr7gKcvdB7GE6g6zt3xPEC5nEvFQP3Ihe"
    b"3f6BGNqA/RrqTcYsQP16zGeuJYUjxVQSoI7Vm2u1bb0vhtN1hawUN7pvRr9+2jhSzVn+28mK/Ck3NfLXl+TghKvD"
    b"SxFa8HV6iHvdA8btgOZvXpmzhCzasU6Iv8i4HIoJUaocI2LIISKsi+WHsyENQ4ogiw8/KtKc/6XqohJg5556FB1Q"
    b"KvYa5bK0TEjzPlk8JcA2tYIra2mpCpsQDL4peQvHGYo+zg6VZi8sHJ9FPbmP5j7/w6NiXLRiy5EJMFdMkQFqwHt/"
    b"9TEoGMpLt+fQ9lD6Yao8UgXPp+MRE+Tp0SEKKOGXQmp+xk3y5okx/E/zK7evZx5LzgI0VGeYpXkq4EgGF6yjADWN"
    b"IMZ2X39uvrRbpGP6aPHzJUE/b0AR82VlcAIigOW/2f38DPenNQeSkASPJ9yO2VzVxfXbAfLgmvzKDXn7J3f0q0Ov"
    b"wTjpJqYmG0D6IAeQe9lSJ7PR8c8k5Nmpq5nbQl+++Gzj6yzoO3P7OrZOc2tKQTYQfGZfl3djnQRgfFi6gwTRsczv"
    b"Gt5V0CkRkR4FciPWRmmnbuj5AIx2SJNsFrDwu1aZhG0fH47hFftdSTsDLjbjVjzFRE9Runx0cnjTiRsznF2on+/S"
    b"+BdJJUdvEBtTVdc3sFPws+/YzH0CuA7TLfSJWNcGAmGhNH0a2H3YkhWj9OVxDs/RRf4tsuvoAblezsAPyWD6LpBC"
    b"5y0GydA25HAcOLWlbUyCpoE9NB84flJPbDkBWa2VWgy1HZ4umCmfaFcVQu5xNMD34tfioZWHjU0yvMjDJOI5foMS"
    b"dD3uzT8U0noM1BMOaEq9eE0Z66L5UZTb3HGbhYlbT1ykqBTKA/CS75gddBZERKozu3+WniAwLgm4NWrYEHvBjK4I"
    b"v+HFP2lVE62AduhGZR6557YjsqR37jMF7QiVKP1EaTs5ts/K1gUJshmYL7e77Jx3dZpJB+zq7lqmlMMt9b0EXaLW"
    b"To4Agg8W3qb7agObZjqLInAKsV9YizPM36l4U6m8CMlb4llJl5qQRm6PrmbpgwbdtJT5ZaXNJmRAiEvCoJ1TMlBW"
    b"F2P/FcjQHsTLUKN0x/cxwrAxFoENjWzxviRW0lXVjOpH383sIW0SoIeo7SpUhL3BuaexG0yRfbbVoDfpjENz+DBw"
    b"x7D2cbp2RVdBRbz4SNNhnJ1XYBmt2sQXC8uklvbyk8Gir251lC8dfEMr/vQ644bLKMfU62SuGJ0wPuGf3vXgPIX5"
    b"oasYJ9yteGLOaB8kXtS3glyh1JMiOzLdnnPxa0pnf1hdW6reckePlmNKhobmCyZkPVGHR5qTlpKouwcAwk4IDY2B"
    b"1t9k/8uXIstEoUjbS75soWwd6ru3tvZathCBivluI/nmg4/JuGWcD4lKLSVo8JekLe3XpUUowpTEyKGdLi584rSi"
    b"i277F93DgtSMSZ9q/g0pWHCwwW0emnxxKfg6jrsHAgs82scv+BpVCbdznDcEeigK4l7lKnGDbXzE9Fa6ct+NhZTX"
    b"CfcMjJDz8Bg1m8a22wEvv8pNpy8nkc3Q7GzmvUa97j3Dj8hXb0Dhzlo4ZgBPRMPz1dV5OrkedXWFgX8+BSYcUm6r"
    b"quEPuOs4BOnnvkeWy2FOkFTq5ACuBV/Gei2hUXcIFSnY3BbuIQk704bdGkm91vCt+0DSyzJCEI2AM0KMCTmZMT8Z"
    b"euTBC0mxgkqKWrYCjtxMECz1qCR3YFxoyZWfx1D+ER3Nr43AA5oae9gRHxx/DiWESLKdlwEF3OuVM1W5qF7A40wc"
    b"5bGB5rATZndAO4cw2zb8yRfu8uxTbI/FzK0LZifEfYbV76VUbZv/rvFvUnl4juD/K5400GGHrdsL4NOoma7i9gPM"
    b"B9gO/eOKUA6rgkG3XSRJQ2WkINFBpkaysHo7r7uIZCofDTpLjOXH5+vyrz/9X0SQk8M4z+cHXZk2G0/ykWhvNb68"
    b"bm1i4qmNDlL9UB6eylvzLEc3V1AHae39xX4qiasMuhIk+7/eKBeIqQCgec5D2N0gLgRT+OhPPJxlVhnROScgYYqn"
    b"dQOWgBEGQnB4n+CFln7Rq68+URtj6wEeMyGtJpTAkKhgzxN2G3h+gdcTkaNY+lfpnrkxQdrvsSin+6xmSpRo/9FP"
    b"pHciFTN/+rP/WVuT36bf2RL6P2+/xvYMUolq3Z5lOadNVDglBYsh6jB8JVU0wrJ/khVrQ0oUi3sQupesGRIyBHMG"
    b"sxqDMSRcWsU+zQ+q6Gtg5ZvxiFzuQQhMZ3LjH/TE+RGunRuf0HZOhjHHN+amI33ZXD31MoAZFriED/qTcAjvyn5I"
    b"dIhzzPKYxrVfZFk2hc0NR2Ig6ejtFrXaBmsAObR4hreV/OF9jl1UWVtGFKB7/ns/0vcYi7ySkjVZA/f0zlUXc7J0"
    b"wh/eeb2/oMjMmJMizgKmYmFGubwG0jZT/nWj0oO0amqkpQJHPdfpovHgoiMKFImR3BgdWCuSmrMSYjWCqTL01aPC"
    b"VtNNW3ZfyPwKRTfhFUS83+zo6uMN7RMr1GBx+T3xol38cUBTRcEvdIfwUVde9fjBs2d0h2usrKrPfcA7mJWxsJtI"
    b"I0IYLCZnS5YcJ9MrcmQmcjBF1t5DoyoKoBb31NnW2rReNIQhDJksUQgt2SmacL4uaUwUAZ1LWDTWTmPkz2PJ7KqE"
    b"aTzvVtBOdmmlnNSAPo/F57q19cq1MGQ682Peu+SpmCK49h08Z00hEU9LgTAYuh/0hMesC33RZyI9CB42sTcFrYE1"
    b"vPai/d0siR46PG21Rg4UMquKjRPUc0fh33EOW1XgH13Tkbk/cWz08YyYJaOAbvYQSGMAsWCfanK6+Gc79E4RThUh"
    b"xQUcoVxM2O/hmbODG0ck5ffL9YKtQzupDGmyG6b6tTKoEkP5NLenriK9Jsb+iOfDgF5erz6+UnZhRHVEcqWVlju7"
    b"j+4/f+t9TpYtBYxRK7wLKlxfF8KJOHuaDI0NpyndzOpYZs3M5iW7NJAQObhvNVH2nnyYUs3BFgw8LTeOvevGL+Oj"
    b"XW45cuKwOFdoX4YXQUX4ZX8GQIt3YWUuq4H58MgUzrS3puzqNkAKsGK/Al797KZJVAQo/Qqyc9JmIWOoEw1Wh1CJ"
    b"MHUa1Xo/ZS3D29s8T9/JgNkSWD3zsftTwIXxwH49PHoQZGRooAd2hS5iEh1mNPOXF5lM23xgaWQ9BG5W2x7veY2J"
    b"BSwljlfJAQE4zXdD4Eapxxx9N7hSZQgmGSDFAHW5RGsp7bRIhjbVXJliABRzgou9rvnHwEQ4lOctfHCnoTPCKOWK"
    b"EugrWgdKjx/K114rZLV+kxF+2m9sXZvkTiSztKRTqhg0EwY6o2dgTWhYuoP+Td+bYfJJdFCEn3DLM9HKPxyU3oTk"
    b"KvXtdx148JVDflk7EK67MSOSyFDOQlOB8ObQQdnna+0oUJvE0rM+nE2tbvsB0r7VW6RLf8v/BnidV1u7IfitktVZ"
    b"MQy+0Ha249RaFgcB0jnpD/2qvEnlz/9Vg/fBLqUJmvNyJ7Q+XVq1GXkGSgL3s4OMHbpChurZrKzEUtOHRR+TYNeX"
    b"X6As1Owce8j84uKUD7YLS6NnyUDd/CcKFQsEnu7T6SkuWEErwkq44cRqGqXKvA7zeiMJt8PrGZ2lxIrJSyiTGtTp"
    b"GCD6a1HWsnP6ovkR8b8JzqpwpEEij4gl6FTnd44NM/cWq44VQojWxfamhcbeL7jlljrqCTYV3m3aGalPn77AJmlv"
    b"7Z7yVVXwhcJv4CNt15ySKkWvt0zH7zJHa53uCOSLDR1AIp1FbO6Cy4d1Ymh06IfevVx4QnmYTbmvMS8PHsEq/Ogw"
    b"72Eyz+EjMBrPhi+qSuIC8v/cCI3GN0h2zHRjoog+fJ99xZyUf6Am3bD6nsOhefjIuXvm3DWksPTgmiyR5ANW2L+b"
    b"OpXWkIL7X83rCppqIBYUenhsavGg2XRPvymRzouPVJNaDrGMA6sb0YobSf8n4yDaUwDcUc+Qbf6S2kfKkAOXgJWo"
    b"r1vcqcHjMTm2RgSE+2nQY5kCRtfR7CRxE+aRB/wYWUhM0DXWM6yW3wPT8mauVnAkqLKnoZzM2CeY6bYXD1n1e1f1"
    b"l/6i2HFUoSejg1GfN58H0KdAI3QwEcGHRSI71ies6mR+O6a/HC4AYJkJLA68A4pHxNSr4EJF1Cba/ssP0cGW9VKC"
    b"XOuURBTzYqP9gbr1dqPDdcoUokzd3mThl/qIUOAwCUvot88vsvSmMxFC6cd0x2Ytrou+Q0XUY8YwsY6QFb7j9GbV"
    b"uWO1lpNSQ+cbHj/2X02DSl6Y952rcfXGFsW0msGF5K5NHzE0l/Je3BO3mhUuPxbaJMhqN78G7CP+siIcm+Nfy+7x"
    b"Ui3oCMKGVlaT6gqrnyFH/der2+uFoQQkuRJzjCjY8qjaAokMYyu0ZWLvu8DvTD5OGICPeLe6Hu6dj5KTAyk9aIkG"
    b"ttPcDcuvesSkiD2c3fag/KV+RHJtiiDxEb64kf8EwMgtjdt/+SdHH55/x/A0F47t8ya/8vgNnj2DsOWkIOTmyiOk"
    b"cmdhlUnA5pryQVkHEijh2E9vDwAFaw08HJLvbGTCK7gIsGw5b4pgXciCd22qUGUYCexvaxML5yiIVs5XhK/T7JVa"
    b"MyPSDPSRJjtqe7azMr37plQ38IjQjnzoZ/hGF4UgxvkQZEIEODWnEMrCf6LeGnndvXb0LHSS7veYDh2TThazNci5"
    b"mQoGaR5TTLT+Znv6U1uKyemqlX17Ri8w3hG4dL1qhvMt07O1pFcx/Bn+UdKsjl0L1f9x2qMF6kfhqcYFWOkOyk0D"
    b"OZnfXtwlsTwIeVCEdoZtfXXPvLZyWclZjadBja3E0yo2KpGZF9H/BxRgFwn13NBpcFjWHoLgJ5S120sakXPDT5B8"
    b"kvtKhF2VjG+7xcDoh7l6tmzZKaWBcR/5BhuLYQy7GOdbYdeLWTqp1Rv4rlTjNiF3nP1Ezn6lzRALbtaHZ4l5PQQY"
    b"LBtovd8+K+b2FVS4aO8125Y44rW3EimQSMulmE+eqHfrYqIkfCH2UkGWCgiySec+0lNpbftIkNEDGZTkSZSGeG6/"
    b"+mw1+2UTJjrrwUtCcCUZoYKnnAEOfj+ddXUSnDkg8O3OvFetdzIVXEBFqIFWc6q8YJvVzJtiKqYQzVyiz2VbKzJY"
    b"Uxw6Tv1VDXnZMX3Da/BxHfxKM1XtrjQWRrp4S2m7c1w6X0p2PGqpzLCPTGgl9y845U+vYwEdj3qgWu2oBeI4rQvD"
    b"H88i/y4uQ3KLUcIyTs6HNAKs4HqYoJ9wWjk7CvhDQFs2jOSpIYWaFGvufdDz0qxG/N9YiTwiobPEMR2xPk1/za3j"
    b"KA++ALHlJEjFqrrXyekBcNSbsEnxgA8vAmZIQAwCKhn6bo0/B2f5e+wTGgFVNlfhr+ZuX4TZJUTM3sziGlHYtIHf"
    b"VZ6A19mD2NaMl8csxXx4XtEzAN03yVCgzV33l4DlnSlhsuJB8VRa6pAlZ367E6W+5m+QLCucAoZ0T9xVjjlTBUeW"
    b"4GOrC/3K3zdMJg8hcoJppq9nX4rZEsQjq4zRi8Z1cAQ3w05/8zP/kjkoZzo654PyMhDCn631XQw/lkW8T2YcpCsg"
    b"gC3Ax4Qec1T1hRCK+4AdYFWOli8SaOk1eI9a5GLmfb2tbm4778WXgIFnCwfzCOWx4/rkJAV4GrgYyQ/sS3fIQ6kS"
    b"JZsErQUrb1PCMuA28u3PsMSLN7jOuomyNUXDlA4N0HGjpVhaaa19Q+M5/L+GkTuMAyH536kKzgYfXaT43mK0okD3"
    b"aFhXosGDJmisD7PbKBn+YRFlikb01RzGAJhN5ffXmGulthiE0qUJXwvotJBSyLJJdxzxaX4rQRftwG9/zI2DVqJG"
    b"lW4ZhnXQmpt7CB2gMdIV1Eav/WBwCVf2INmfPy2IycPnOpsNoOi+fuZPsg74LgxrkcGg/t/067N+ud2E//3xFIv/"
    b"cgVr6YxQS/ZuCiKuWq4jRF7OvsJ8VifeY1yT/HNVB0fwJ1vmIv0h4VOHZvLX9estjeBHgwPaXqzp63wqLtnoP+Qv"
    b"VCNQvacfAkGbzzm6DZ0qkLici50kp3pmbQ/sqb9e8k1ZajgJYHmRdTsCyHks6uoHncnhXstkPaucGieV23YvAY7A"
    b"Gkj7PeciL4dc0UgpeSx4pDLSUG+KcvB4saqHWpzB4sSHc3buZBgqG9MQjXthMXHRVsTqDgaeedhItUW2ZctDQCn7"
    b"dKgw0BJLE3RofR+a7xhMHWPX2scpWPow+s2wSwjF4iDNkkBpwdTAPigDP4EXqQF9WJqPHwRw3LFq3NXjrt1Cl4Ix"
    b"LQKMGcuvnhxJbLxbOinT0wcA1RYgiLsEQSpcPPh67jclQLCOuuwTk5lH/L9Ep1WJM9aF76eZRFCGasqmlzI9uzaC"
    b"SrNPvsxtlDMUBnv8Gc7GxsPMrlRi46Htt3ee3TOhajX564jPPFEXtKHiveUul80kOIXu9FJX6EIRbAnzpD5Kk7Wy"
    b"qijW3z7qrFksuR6gvGSZONRdMNq3WZoBk8rSEbnTpvrKLndOdhdlcg5bTvuokY+jtWMGHZLx9DC2UQC1s8wWt1kb"
    b"vUomX2wU3uI08Wx89gCVt+Gwx06qmDQ7xwyjdkJlcagbjRZSCnQjGtDg1mHRniSjNp9/uz6ZG0m5/tvcXTbF/wyB"
    b"ggPscb/nSSJGcIFIW0qi89nkiEJDwvULUeF/JQ1MtpVm8GRBCNv3qp0RsXO4e5+PlkWE1qY0evAKPZRTbRbd+a9X"
    b"iXrlPLr4HmLJJxDp2lyYiVHI/jgVlNgVYRM8RKirMfkBTWD37TRrJl+0FN7U1TWs2FKF2M8VIc3Fy01t10xU74B8"
    b"de6SvPahVh5sC6K6Jq37nzjX9+GN7Ep5PM/pyUZ4moqFRnzF7S+puR8Uyym33flSvKaL9iDAzBmqSlhPlqX2O/d8"
    b"OwCazvBUA0Psp3cAz0ahOtN42UdSIZHfvHQwHTgIQD7E2jElh2Rf/u8LV/QXs9oSu6571tDVtMZ1fUHSpkKp0AIV"
    b"/3/ZPyjtw8YKjYaBxYtikkSVZ4avZxj9YeqjXHhVjVb0cS1KSdXJQyvelY2gdFxux/8gkUrRBQ3TSTCpFw6ovxBo"
    b"CfT1Xj8E8bRzppgCeG2Dd4Sk+ybnXoHCNJmMWAoiDyROOGlcPZNH7+U587joJhJiHExd90CAk3BLB9eoJWZFiSk2"
    b"iFAodsM3HWVNJ/Ukqz3K2+F+axiCgQ/YiQwhFHUwOpTEEW5OrWt+TchkUPCXzV0CAgPBS3Ll7XxwqZCPuu6IqymA"
    b"mbU52CRRo7busNyr3Yl2TQfoI1JGofKMUTLr1DmdJEXYwKhuXuMEOL96SCM+EZ0G5pq72t+0PzHFqHk/6iOiNg5T"
    b"iyL9pVDT0ZUJzBQrVikEQMwFnYfKuWQgDqSsrG6EnLLjyXaWinsrdcK84ntej9VrMkyP1OQ1aGBkw9ecepsmLJwH"
    b"DTr+g7ZzHk83RUKirxBmhn9X9hCq3RxWT/NrXTU9rkhw5JLEE6r9RAMFUVGrKuVqsvVZmpHtAHnGWoDjzfEboXkM"
    b"/DMVNTaOTc0FYIUf3Z8Lac/cNudqv0cdKsdmf38b8oW2vTyYv77rAZk7XwM0HxHrxv3OKM2e/FuwrC7ysstBnnwy"
    b"+OBv4uOChvxD/N9mutCn8p5IHcjg2VINaWhnE0XMFi4jwjVzWumb4doPLJZb/ydlWZczs23EYsXUPp6dTMEhqm9d"
    b"DZSOY1htMfnqsLNH0sr/MH26G87mCGEePaMeLlvwe1BL+f764uh90RSymFUT+GMWLVrSF/lf+u43Ti9Yc4cSErh6"
    b"8f4iUwAGybsyuwiFiYzwFSxZVECK09a3V0nbkbjSPi29N8sgrTTpiCJiWjTHLcAWtK+xWfQc+jl33CUacQoMiuET"
    b"TK9yXxHbyGqOwVO+uWmlGqQeVe+fQiqgkOcWvRoXuX7Yk9Z3OpkGjmB13puHGYDlvgl6w6x227iUcgjibWGBbOcP"
    b"87e9gpu81OSk+y8Bscc7BAyi0Ouf3s6Xki/4rhDmGW+wcAvgasiPmAEO4CoZQbUcjETukr6tB6CTcrO1VBvRYx/W"
    b"dArk6lUrp2HVp4PsBiiUiKV9oJCVS0LXTlt0Z1MYGqPvIWDKT2y13xXZwssY6Ug8Yzyui3GcZW/BVLf43vOCJ2jx"
    b"lveELElxpvXAM+z2RDEuQdwlQ1dssX76oYMBsZcJ6OYntlyQM89l+1aEdOqbsgWmXcOjHFwwvPXp0vS/1W8DdzT/"
    b"Y7FF/GjgmPT8KRK3+8OsgYuKU3iBz06YpEfape+eJY9l3HVkuWUYCDxK4Ul5YOYZG+mC05SXEFvhgZ8/iKNwRL4a"
    b"YEEH9Pmq9l4XjpcihO1xQjqJmoOQF56pZtXufUFrIw3JdTHbXnH3UzVyyVD7mgD2xftOajvNug/tl+yaaCmOXBNj"
    b"fmzi8H+ukgb/CLLbmz7eLr2+ZWrpZwjUxa9UyQGCsHMJ+P1/T8KVEcqtpRwfbb10VcSTs/rT38oRMPGZE6i8DriR"
    b"52B6rJdla+SnGNNJywlt3ycLhy/lzzdo9s41gDLmksWH+pP/ujeZzB/XXCCr3DhWek0QJQFIWHV5YuUfz7Y0GDG8"
    b"rHMjnHVh7BTfyzmk6rCvVAuWhtZ71ND9AjkGe8O6eIvVpMYmtlUAXC4QdiM+eBEEzfGjKqhu/FFD4hxwuwoqmzM3"
    b"2Qo90IBu0ZVir2+JKfZIBguj1I09RsuEP5b4lP8B3O9/jcARNlUZF3ypWfdquV7J4+BbMygFJVn+IUVSGoKxOHKA"
    b"tT3yZ6tOa+qF+aYNWsgbq+SQjO8OIyZFHIvrOJHNkRsMX86fK8cs9xcmT8Z9hffa8Tw3fdft6ijQhzggXxWaxLCz"
    b"UaLjetTyZ/KePS+rlEoiolV3KeMFAqenj8JR/sGuTBYPJ78BbYyYvLVT6z+dwMyGSYMsoQlDliqLV4ZLtztKG1Zp"
    b"8zJ+AwhbM97gaxXFrQnv58c0uJNSk3GnISgwWSadUuN22mH5RCwUy42586BXJFB2S0FalBLrjgdp3vjfLYxs600M"
    b"qb0WTcTpZv2NFjt2ZK1k11+mBpyilT9x1zJ3svBAj/BKIui1TAAUSFeSJ9h3iAQtWz7y1cJoc2KWhto6Qx2KmHSH"
    b"/gsOPB1Yrd3tVNYv/WlHD53ugcFhj9hfOrsdNPlDhVLPNSLZtC6oHg95zbUeT9KRwuZpqNJ09GHdWiDMqft7DIkE"
    b"K7/Yci2w5uxGKwrZ3ORAFKG4t2OK7qHRTYWDBeDRJA60Qt5kiZ54XbO0bm/HviDGuSSmmdPYkCHbWjAnsS2vZlg6"
    b"2/rIWOdEiF2A80uKcB2gFSjA9XmMO75mUyvk8zkAmVaCMQwsfEAWXhVFwOyEAkRsGnC2TELBvxNqnwOdyJJuT2J8"
    b"QKGVoIOExOEKx6ITAuJB/Mq6sxLMTkY27kuuB+gfnH8hJfXl3TXO1n16UM6c+Bi3B6zG0nN+bOdj5TalPBJWykg5"
    b"Sd0ZkNmIqhDiUSTI1rY+R1Tob1ClA7voMkwvM3IeHv4qV66xwXsNfLJ+w+FgqkL1oI6k8Z+4Z9BdGfq7DZsEGqpG"
    b"WTFHtNE28L0ubW2KGA3boM4SDnRjfiFIRGpPIz0ll2X8b++9ppQvG+4zwABsCrE2ozoXXfVa3LNfJk3PiQ4IsIYH"
    b"uFUAyM7DF2t0WrByeI0a0kAIt6Z3ro7+XFZp7fS84VVgL1xYYhpv4M3AZ62IrxJ3ymrCnD0FiBg+hes316sVkvyt"
    b"MN7mOBAfihzFcCZsWI2Q3Sv3Fc7DTfru6mi5yOnQRJwPILpB0d3T8UsC1MlkD+npIcRMwRGd5NkNmhnskl/wDZgb"
    b"QkXMHVaM/rhnkZwMSeuBTiePNso3O2DjzKwI6pJpUaw7UU/DDRBNgMSk3G45KZH8sBnSKTyqiid92mhIt5DoVFpz"
    b"bbSqiUVRrzDG1ujfgElVzDy+AhLUWYsHDGV7njqveoLZPm78eZ6u+9uqA9j3xVB/rz1l9LRnEW5Ac4w/MTmGZm6K"
    b"H18H2NH+y9Oc5Mdp4IEFk6ilseRyVMS7WL/dCX5oHcml/b+9NYfAiPlr4+m2qV7bBJRVlfsy9AiBok7ieTVmZBCA"
    b"CwDV5xR5cwT9MqTwp9GOuVpEP5ly7DJNmqLYBnO39nzJx0W2anvfeu/19xUu+1f3R+dUQ5ReaSZKI1lj5EepEZ2b"
    b"7Sx2QJje8VZoRjMRcJoKiRNhKRr1Sr2zSHU7FoRPG9W8Kpu5MNzBPGy18KmyciKBXzojC/LbULYbd6DxditWNg97"
    b"A9z/l0wQ0pjswiJvWZALYrYoErJC30NCvP1eF/vzAIstSpuG8+jDm9YwyBQ3hS4ddafqbeUxDAuE1IPXhZYzk4wG"
    b"LAO6j0e713Yr4g5tS3lGtZS4cdlT0gmLYVetoAa6d+4xnzVG7Md8V/1eglKV7b6kKsUlmJoCSOv4Wa664Q5Jz2QB"
    b"mbz+naSM56Y4T4mDqSs49SiCrGSfGcXKoQFBFrWoAS3nXGvyXY4ejvJgJeFbzb92s+UWMY0cs8sycSDjestmU/rA"
    b"ND5l18KIHJfQfSzG2qPQNAlnj4aP+uZ6I9W7Ils9zWaNKPkewVjP+YBOeFuRoTl0NkwTrmPEFpGWE54uOh9h+Acz"
    b"Ly3dN38knf/iweUhyEOrXO0FCuh07yhgyky9PKzwKUuHXab2YmzzLipLhyCqsaPQpWIcIicDxrSWsJPGfkHWQKir"
    b"6yWXeC3gufR1CeDmGpYEzLsk9mPLHqJ/f+oBLAVQQbK1vosqTrGyg6fRg6Nq+VJTrc0+BKEYGc7J5mv6b/PeUOIM"
    b"uPZ870NFUdZTmV2VV/IUSSSHJAoe2oVH2v+iJ9MUn8KTO7SEBoSgcathSnh7n89w1S/eW5UVcdT4OBinNDUdtz8T"
    b"Ug/YP76okELHRP91RuVUpZk0AuHjUia/njkgfYJ+36HuknAX8dN9Idn4H3wuPxEShQe9v/uTF/Fm9b+l5bDHg2sx"
    b"+3KaalJ1EubgQQm6VnHufc5TgWiiCn0NPqSjPKc97WEnGP93UL2gSttWHHGS5x3rpPA3god/6MRl7EON3AhC4YwP"
    b"2qtYghZOFfT9wt5JBVeNzQ86LGyIuxJcts3z74ztiSxnqet7VyEUKm+D0MaWfvm0aekxaXxsTlEAJnmngPe7C70b"
    b"Z1l2tgcHky1IN3kUr4ANpgU4wcr04XQwC1jO1rgwvgSjBW1idtHzl8rrER8guyP+Gmrkhqr/Sdq0YvUpZhuS4Nn1"
    b"0T1/81vUm2FPjuymOQnIKTQMfAxIbv6crNNf5mU7YXP5acaznoouvniWbygT/ZdXdV2AmcVBts+6dBCpR69DY0bL"
    b"A2TbyJSITANjJl7cQDwxUpkAopp4lrnk/S7hlcF91a19VATqqAZjejTy98YNXsLfYoQ8LGses3XSm+IZ1JF+0e+8"
    b"JDkAuSBzftBcSfDeDtBqw6uxhRfPC+KS6fA5saG5W2evpM+uy3YjE9OJRehWVKB5vGD4orX45Bq0Td8gi0LhoRoK"
    b"9jvxe/8n58BEy8SH9fchmzsfAY82lKQjboU/3pNvv1s/d24FIotU9kHf9G8kuPK/V43qZ3HVIp9pxadLc0ByJ1xd"
    b"qCAwA018CuPWD8StQTQ1dpsipVqQZVGBTvFJ2qVypk9frJ9NMOJLFcBceoqELz3OFFWhzAw2IVIeuA+vc1jdW49f"
    b"gvYo0hMRbJmtcFEAMpNTHEdge1a66eMqRjot51Vf11o8HexF/NzvEtg0G+6W+vgenTaJobHJVTUdfNxehFB3GLNL"
    b"YKBkhxWUmow6Gg4jM5FesAOeKyS3nbmjCvvXwp2EMzPUeHLSpu/Tta0orHg1wbLH8OwmCZFMN8GYbfF0Sgh0Ivqc"
    b"bT+Do8B6H/86tz2iCTmuUxafcT4vTiqyWspYOB7g66fFkN8XSj6wf5iqYr2LSCsGJba4a3ctCPy1QzLVkBSVJNHW"
    b"RZjoRBgB5i9Q+Z6dPhM4rClDhtNaJXsBJt3C/eZRaCWGcI4xYUj6KwbH6onGQFnuL7zDaEszYOK7kNqYcPIY+JfY"
    b"BkeZNy0h0OX3TJ9kydnNtV2ogg7pNVIRiGvHAhyrAit1Ro5ZT2ZkLqtFsrTNxH8QQrqKgCrq3vMblzaoVErMrlNC"
    b"aL4pECWSzG1qpbzksVCuwJQdAX4sFpzlQMPl2Av6cNTdeb6ynIiD1/bo7Rx6gUyPyYW33dgyAobZqooZOEeBoPzP"
    b"GTLSRpUWWbcM/BAVkVXDztUEO8wI7Sf0bA3KjOPI/uPuDsjX556pT/L5XbME2+DJsJoXRB9lB4uPAqrZKG4ZY6n7"
    b"h2bWjo3Fy/5E202V/t8Le7EWXYbAWKBJP6qrl13HrMp9waarkm90+O2uSG+11EGIahRq86uQw3OPVfvmngGxh1IC"
    b"lyayd2Mkrnb2ywbbI/kWkTj3kBrIFLROEYNZdROLemqolYzauNUOeN/E4rOcWmJATeT2jtzoRQgYnYvReoFbyIbC"
    b"3iAfJTNZbe6B7+32HmzR1DIMSski/TeEQ+5xMu4qV0IqlpFfmC1SHAw/slkEiGvYMTXGCEB6DSwpR3y5+U2WBBdK"
    b"xxMvNnhY1oyATOCxLAmFKPBtXhDCoGieuopXMOBkJRPW5SimQw4r1tsWC9kzJ4Ny5TosBcHAILZvS1M5UTezi4n8"
    b"nxcbR7hmbt/1QiHT/Powm0kl2U6ZbVwQ/2nNStMnGitnwPxreKIBY/LmNq1O9j/v28qzVmG7hAH9ub4XCWHs+qH/"
    b"4aL4JNIv5luPI89whY9a8rWuZD4dTyTrd0NGU6QfhmMFsnZeCVLcWnu7cuQUNW4e6N3Eqc56SMwVrJN9yXEclH92"
    b"olIQkb8J6v/w3D3+qvPrFby4NZIVhkB1NzRymji9oeF+G1QzVmjdGz7hB7OwS4GQeyHXURkiuQsARZ9oH7BoxdfS"
    b"810NzQ48yEQCKuh0JYWpIy/nAu0mjt3Lki1YBLzatv71zcyNTp5E4/H0bUOMDTtgJ0Taf9O9Jl9QgI4rfYzFczK3"
    b"6mJzORE4imGI+4tgFNf3BndGLiGtzu8ocQNsB9mkozZVtIdUZaMpNKxn1GXrfu54txK/mZaYEk0BVip3x4TizCFc"
    b"2C6k6JnQihV5oRqrwGoHSJopjaVnvkpUGdxUm5S4eVcxjcFJ+LY0rMVTpZLeZhPdlfFzOo0xQsUeMKYNxAzkrVPy"
    b"ZuV+RuyFVeq7Ga87gPTpfXxuAHmXobep8dhLpDmnK/vULzTsLdNP7bqJFz1/XQ9AlPWYx0eoBkWVCkwDnSwW4tDP"
    b"qVUugy1pyrKdz+mHIl7zDmHSwuznGqCcOUibJuSnr6DjbuG/ZXAI5/+mTIBWIhvidnRsebBBBTskfA+VCgBrQVgY"
    b"iTyl9SP4/ul1MkQ/kfDL4IR78gonD7s+9PfmHfcpHMM93maxwy6TEnQGDJy5gdpcEp290YJ8/a+nvGKJqMRCo1Fx"
    b"RWIDnwiCcMZJ6zBlX1vSuih+owuIIM2v+vBvtYLOXDN1AvuKjsFpHWDeCoKbuk++osg1w8rXQTen2U2XXhEdwlp/"
    b"xvk7OF+3rrzOUAP9h2vQtTzgIJhj8dVyyU9k40tMRqXLjwRX38mQlvrq+duaZPS/4wA8BTYRtrTRPVlnYOk+UDqZ"
    b"tJ8QGIMZGNVwxthRW7DlHDoPnB+qbL4xzKpQ0J6U5wetHr2aR6jV/M/W75Npk8uRLke2tURUYVi+YscC4Rses+Rj"
    b"t3Ef6MkXI56uCKQ59CSAUW/GMRcYyctongz7cd1/O9DrImJ9o+1XkAekNBo9JcKMnZf2ttx1VoOfvhnzQ9ccvuT+"
    b"Mk2H2Od3/evpN+hR+BUGN9wjhYPXGTNpUL2m1DqhDho/kblg5d2WCV+aNQRapk1M00inOQjpTqW7iuE80W88ve7H"
    b"AnYpDrS7uVjmAXnvYoqiZFqHCaVCRIP4CccCJzE/NQdl9jk7SYux9TeuEEAL4E146SERetOOkd7NnVLIBV1qgZiC"
    b"7QKE3eME4sMr/YlwFq9+Nq+WMmLapCVz/xjxqfkF+bnvT6XqlM1pUKq/d8C4oFdv2GATyHH+yNLrKThlqEwwoPFr"
    b"irg3oh30iqrstvfhU9kU4nl4BTM2p8pJ889F+hG0Y8DQJ366GThTMcFKACo//A4hXohGJs99cmZUv3+dqA7dqM7K"
    b"RzTbFAw/rCo4uDk1zkpRjVEKgYkXlcrirjXj9/BzQBEolCPl0FmIy5LSJxtdVq/7yH6N8JoGJP0nwRB7xwvv5wNf"
    b"upk+RX//2e4VUrWHTKsVeVijidNtznVewFXWKHNs0tr/ECUuzO6nn8MpBh1GnJzc1+xnLb2UXucqnmQ9KzpBbHwN"
    b"b3B7ErDfVWs2TlBWgiwgVyAk95jJtSxGlT5yXG51j0hZMhp36BEXpsCn5WN2VwFkmwhBGauOjO9VrmBUrDovJubU"
    b"R5qXXbAjmLEMao1/g4ag/w/NcAHY1YyFkByWU1YVxsQm8vJBLQbNz7gDTPJb34HqUvrie4v5YbMWE5DCvEu6Vak0"
    b"spMDZrwPImipgB9JYG34AL0irVqtvDvx81IoK/1CHNAdtL+TLMWUMGb8ANFYjwjM/kNdHjPGZg9I5gRyhMqgHd9L"
    b"+y7MMOot4BNFrEn7T0PU+ZxbfPTCeYgUNMKfA/yb26Nc3KHR1Hw9dpMvbe1urxOrSgWOHppPj9azhATD+grV11+F"
    b"MGmV2wfMsW10zn2WTnR19WzxtehDho7j6vDR4S3l4NqHZSGBSwxnxXocCrINrBKowzYURRpbaPijqao7JrnS6TzL"
    b"pLFP5IK8IZL+kJOyYxi0ai4+SpfFMfWJPqFcJUjTZYt4jyTs8Bb82O7e7FCSBwEJsh99PGtCpet6QXuE2UCLRoDm"
    b"xI2R88F8hrAeL2qqW27albPg9iwb4w0LadlkxJ5y3j1AOKKAC2GrM/RcxF94sMbkEtWZ1re7G1mGWnZTzxBLn78S"
    b"oboPmHBOKpnnevogu26Z976iGMnydN6CmyBUrXRNa/Zxt8UfKZKdFt9hd4jVZ7YAWV5C20QoL7f1wQqbOn5znGxH"
    b"hSvWrSJnlzKmRO2MaA2ElMWrincHQW9M2YqQ34P+PwVkD50uKdFWQ3TFtKvRjWd2TkzBf0r7ywL0dP1q8HDyhiKo"
    b"dtCNkc7Fl3rjvfdIHdEEavc+JKzKEKwzHjR6L3oVdV+BM3f0DoccWciM33iwrfMik1kaJWbv+wmoQml5Lh1Ul6na"
    b"cyNC8dIbso5+tdu/peGS+g59lCxEs0dky9J+yWo4BRjWZl6hrb2nGrwR6vbpFMCgM+UK7jX5BIruj4VtDYHWtmh8"
    b"oprcTn2JbpUaWIft1+lLJinbTf/CVziCoKkF4FAkzPHhUZlvECPeqvV1DOcfo+GDjt59T2O1I/coCY42cSs2hi2Y"
    b"6CEr+bPfUmNnRDG675kcTqsu56Vs/E5dvg4MfXGgmYFPtqExa5TGy1ZW78P+z8lmJ2I1HiH6iYv5UktnAW0CqHhJ"
    b"AfdR9j3UsBWDRv/WX4VjNJyiK2cSgxK8DacmRlp6ksj5HEi4YiKWHLqWEaLpXrq60GKxW9E7lGlc40cMmmHJjEjZ"
    b"hOJk8hsnmLN/wpcIx0ssIM9gqtZCfwY1oaVgiD5dPD2mzo8Kv2P6ni7wdAZ7sdOxcrA7cuUGNuQ3N8dJqiQYDe0N"
    b"FGsl23d4slhUn7TsaiVAbPsvqW5MqgY51W+GyT4ySUWrX7inJ8wYGbXXCHOtxxYeNwuFcXj9lTDmcDumruKA2Gkn"
    b"KD68ppujow9wmOhTTPMm9IooD5OdufGdufXPyNDpXUDIWnsh51C+ux9ROeaiLBswIMAAvG01ud1Djkp7Mk3t8w/y"
    b"vSm7HXlH1ENwj7ahW0UUYQsoPeZl//Zr5Tn8EG4Srj0Rz9fBlbdgy7PViRe3NsqbdWAwCAhWYYSGATqLzb6P6E18"
    b"pHusTeQtjeU/ZWi5oMxyDvrXgBeQk8wmLB9rW1mum+rsqcT42+MwwZwxlhGYEt6kowG2VMQyF9hbdeRx2DzauIuk"
    b"Cez9AuLCLf2IgFeebZGfmmz+ZUCemVMYIz95x7sWENz/VZOW9pLyftxKzs0WROIFRmzBhX/TQdRVaL1XT/VGh99z"
    b"p5wirgt3E4SCVBlLXrcDXMMEB8p8v93EVSlBsB1yM085socT9QOfPLeJ8zcXCySQ5gdF0jGSYTgZdhWcFYjZUrXe"
    b"QH522cPAxiB8l4FC4OGv+FEHKtMydMI/xdzx3TQfWGglUM077rKRAERp60pD5wIWWOsJ6osqCu+lAx5kIeBQ6/jO"
    b"jFy48C+A/u3j1Ukb3cQqzTRTLy34EyAMRUfS+9pV9MbAvll5XbSMbtM6V6yoCnONPBqxr1rkOEhmn1MAiMa/mwPQ"
    b"6xlf7thBAMqvOuq7kYJi2tSVXJ2mBNWtgrSaw6QUnl7wZeArOvwTKuzoUpD8Wm+vtaiaUak9MLsQKw7g28Gm3y6V"
    b"ay4j3BDuCW2TN5IuxB+fWrI59In/E+o/9cjHC1AYnTeglcJR95gvxIkimEAeokEfOW9Yfn7yh/gNDUDVeUuqCYSO"
    b"+Eb+cSmbimhItQg/OuCrhMG2kV6uwuT9cg4dJeX+1JJnGTf5jxB1kTUY6ObuuIyMs2datcw48c5oYiWL9RXYABII"
    b"geiJYYJ3fSZz6o0PuRm0O8NFVnBHgnUAd+GmekYJSvXGp0KHdnnKa7hhREpk1nEBP+PN+ynC64+wQTA+kNGAkOxl"
    b"vW89VoikbfXYTPbra0I0SfyShXzyjMpqGxHqHHruVzoNHOGsXthCmQc0YcQ7ZI76Acd/MoK+qUxtUlIzY38ELN33"
    b"qPOomEoa0dQudghQxyfAl/S934R7eqsoXDHjkx+AoQyb8WrkFI8zo4vkJeYFlmDLPvAtXzhgukUokG/Wln9c8L8k"
    b"C3MgKMszcZSKgkTU8fZDswVH7wv5dKWNbF3iAT55Mhcnew9PF3FLNnfa0bLp8cWmsaVMV3YwajjWlGit+tdWEZod"
    b"jaSvwJRHoAoMFaxI0ya+6v0pU97epY4eZ4G/405Z5lZsqSanJjR5ZZfF5OUivBljAMEq3a/ag6qhoefQrTuBSbHD"
    b"VbFw15PG18zFROlCTwbgA++0lcrDge49jNm8+1vhBx5J6XxmP3fW50sStiH3biprnIon0wSDmJqbrtJ1/+JJ/kZP"
    b"wpv2LMx0Np8To1rznmz+38Gf3KxfnruL3KpfvL1akLOzRKfvVPe3veNfhshZToTJpAZ4iDOg1zxRzX7S62OtgLqK"
    b"ThTaUJdOn10cdVsCAAJYLTdYwLZdoQpYbioCVBVUGrS2+mNIV5m3sFnR0EZQhivcDLunIHQpA0qiNobsTPJIhRa/"
    b"ovaw9IgQlDovDJbDXVKFVwYUUspNKzntrgiZ/O2rGM/bsbxb+Idh/zqucM08Q2TMI1sTMkV7RcVVUwrsGJMxLWl4"
    b"PWkhChRoZtXZWfsFsoUZxw6OuyqRbG7PxufP2SwT5+8oqxGXMiflPNIW1RLQoAlyBtN40ntL+nDTfUAdpOsL2yF2"
    b"2b/hIb6oZhtvG9oNZTC52326+1P5fQI5HJ3V6PDt4Bp0uGUFJA+LQ81iJKkWxqOWeq84VTY1Ta+D5bheQXNHahcj"
    b"6M6c/OKd/H7PA15p1GbO+B14tIgDnN1nc56PPlFcycAiTTG+lQeqVRGwG8vI/YDpzrdinJ4jLd7zrSwE3gTf/w+m"
    b"5lztMcjY7Lm1t2L5y7lUslPiH7o1B3+RrBYrfGDdxDWjZHyaFUDwIpKGaRfybqUgnYPJJDvQHmAS9EOicm39jQEO"
    b"GnLziTRBT8kgL5kvPCWHTQ=="
)
_SBOX_WORDS = struct.unpack("<4096I", base64.b64decode(_SBOX_DATA))
_SBOXES = tuple(_SBOX_WORDS[index * 256 : (index + 1) * 256] for index in range(16))


def _rotate_right(value: int, amount: int) -> int:
    return ((value >> amount) | (value << (32 - amount))) & _MASK32


def _compress(digest: list[int], block: tuple[int, ...], rounds: int) -> list[int]:
    work = digest + list(block)
    for round_index in range(0, rounds * 2, 2):
        for amount in _SHIFT:
            for index in range(16):
                substituted = _SBOXES[round_index + (index // 2) % 2][work[index] & 0xFF]
                work[(index - 1) & 15] ^= substituted
                work[(index + 1) & 15] ^= substituted
            work = [_rotate_right(value, amount) for value in work]
    return [(current ^ work[15 - index]) & _MASK32 for index, current in enumerate(digest)]


def snefru(data: bytes, bits: int = 128, rounds: int = 8) -> bytes:
    """Return a Snefru digest between 32 and 480 bits in 32-bit steps."""
    if not 32 <= bits <= 480 or bits % 32:
        raise ValueError("Snefru size must be 32..480 bits in 32-bit steps")
    if rounds not in {2, 4, 8}:
        raise ValueError("Snefru rounds must be 2, 4, or 8")
    digest = [0] * (bits // 32)
    block_size = (16 - len(digest)) * 4
    full_length = len(data) - len(data) % block_size
    for offset in range(0, full_length, block_size):
        block = struct.unpack(f">{block_size // 4}I", data[offset : offset + block_size])
        digest = _compress(digest, block, rounds)
    tail = data[full_length:]
    if tail:
        padded = tail + bytes(block_size - len(tail))
        digest = _compress(digest, struct.unpack(f">{block_size // 4}I", padded), rounds)
    length_payload = (len(data) * 8).to_bytes(8, "big")
    length_payload = bytes(max(0, block_size - 8)) + length_payload
    for offset in range(0, len(length_payload), block_size):
        length_block = length_payload[offset : offset + block_size]
        digest = _compress(
            digest,
            struct.unpack(f">{block_size // 4}I", length_block),
            rounds,
        )
    return struct.pack(f">{len(digest)}I", *digest)


__all__ = ["snefru"]
