#!/usr/bin/env python3

import os
import random
import string
import sys

import requests

from typing import Dict, Optional, List, Callable

from sploit import attack, AttackError, ConnectError

### Common checker stuffs ###

class WithExitCode(Exception):
    code: int

    def __init__(self, msg_opt: Optional[str] = None) -> None:
        msg = ""
        name = self.__class__.__name__
        if msg_opt is not None:
            msg = name + ": " + msg_opt
        else:
            msg = name
        super().__init__(msg)
class Corrupt(WithExitCode):
    code = 102
class Mumble(WithExitCode):
    code = 103
class Down(WithExitCode):
    code = 104
class CheckerError(WithExitCode):
    code = 110

class Color:
    value: bytes

    @classmethod
    def print(cls, msg: str) -> None:
        sys.stdout.buffer.write(b"\x1b[01;" + cls.value + b"m")
        sys.stdout.buffer.flush()
        print(msg)
        sys.stdout.buffer.write(b"\x1b[m")
        sys.stdout.buffer.flush()
class Red(Color):
    value = b"31"
class Green(Color):
    value = b"32"

def random_string(N=16, alph=string.ascii_lowercase + string.ascii_uppercase + string.digits):
    return "".join(random.choices(alph, k=N))

SERVICENAME = "restful_pieces"
PORT = 4001

def _log(msg):
    if msg:
        print(msg, file=sys.stderr, flush=True)

def close(code, public=None, private=""):
    if private:
        print(private, file=sys.stderr, flush=True)
    raise code(public)

### Logic starts here ###

def info(*args):
    print("vulns: 1")

def check(addr, *args) -> None:
    title, content = random_string(N=32), random_string(128)
    resp = store_post(addr, {
        'title': title,
        'content': content,
        'public': 1,
    })
    if resp is None:
        close(Down, public="Failed to store post")

    try:
        resp_json = resp.json() #type: ignore
        data = resp_json['data']
    except Exception as e:
        close(Mumble, public="Invalid json in store post", private=f"Exception: {e}")

    resp = get_post(addr, data)
    if resp is None:
        close(Down, public="Failed to get post")

    try:
        resp_json = resp.json() #type: ignore
        if resp_json['data']['title'] != title or resp_json['data']['content'] != content:
            close(Mumble,
                  public="Incorrect post by ID",
                  private=f"Got {resp_json} expected {title},{content}")
    except Exception as e:
        close(Mumble, public="Invalid json in get", private=f"Exception: {e}")

    title, content, token = random_string(N=32), random_string(N=128), random_string(N=24)
    resp = store_post(addr, {
        'title': title,
        'content': content,
        'public': 0,
        "token": token,
    })
    if resp is None:
        close(Down, public="Failed to store post")

    try:
        resp_json = resp.json() #type: ignore
        j = resp_json['data']
    except Exception as e:
        close(Mumble, public="Invalid json in store post", private=f"Exception: {e}")

    j['token'] = token
    resp = get_post(addr, j)
    if resp is None:
        close(Down, public="Failed to get post")

    try:
        resp_json = resp.json() #type: ignore
        if resp_json['data']['title'] != title or resp_json['data']['content'] != content:
            close(Mumble,
                  public="Incorrect post by ID",
                  private=f"Got {resp_json} expected {title},{content}")
    except Exception as e:
        close(Mumble, public="Invalid json in get", private=f"Exception: {e}")


def put(addr, token, flag, *args) -> str:
    if not token or token == "":
        token = random_string()
    resp = store_post(addr, {
        'title': random_string(),
        'content': flag,
        'public': 0,
        'token': token,
    })
    if resp is None:
        close(Down, public="Failed to store post")

    try:
        resp_json = resp.json() #type: ignore
        if resp_json['status'] != 'success':
            close(Mumble, public="Invalid status in store post")
    except Exception as e:
        close(Mumble, public="Invalid JSON in store post", private=f"Exception: {e}")

    # Store to jury.
    rtoken = f"{token}:{resp_json['data']['post_id']}"
    print(rtoken, flush=True)
    return rtoken


def get(addr, token, flag, *args) -> None:
    token, post_id = token.split(':')
    resp = get_post(addr, {
        'post_id': int(post_id),
        "token": token,
    })
    if resp is None:
        close(Down, public="Failed to get post")

    try:
        resp_json = resp.json() #type: ignore
        if resp_json['status'] != 'success' or resp_json['data']['content'] != flag:
            close(Corrupt,
                  public="Incorrect post by ID",
                  private=f"Got {resp_json} expected {flag} inside")
    except Exception as e:
        close(Mumble, public="Invalid json in get", private=f"Exception: {e}")

def do_attack(host: str, *args) -> None:
    attack(host, PORT)

def do_run(host: str, *args) -> None:
    check(host)
    Green.print("check")

    token, flag = random_string(), random_string()
    rtoken = put(host, token, flag)
    Green.print("put")

    check(host)
    Green.print("check")

    get(host, rtoken, flag)
    Green.print("get")

    check(host)
    Green.print("check")

    try:
        attack(host, PORT)
        Red.print("attack")
    except AttackError:
        Green.print("attack")


def store_post(addr: str, j) -> Optional[requests.Response]:
    try:
        return requests.post(f'http://{addr}:{PORT}/store', json=j)
    except Exception as e:
        _log(f"Exception in store_post: {e}")
        return None


def get_post(addr: str, j) -> Optional[requests.Response]:
    try:
        return requests.get(f'http://{addr}:{PORT}/get', json=j)
    except Exception as e:
        _log(f"Exception in get_post: {e}")
        return None

def main() -> int:
    commands: Dict[str, Callable[[str, str, str], Optional[str]]] = {
        'put': put,
        'check': check,
        'get': get,
        'info': info,
        'attack': do_attack,
        'run': do_run,
    }

    usage = "Usage: {} run|check|put|get|attack IP FLAGID FLAG".format(sys.argv[0])

    def error_arg(*args):
        print(usage)
        close(CheckerError, private="Wrong command {}".format(sys.argv[1]))

    try:
        commands.get(sys.argv[1], error_arg)(*sys.argv[2:])
        # if not thrown, everything is ok
        return 101
    except IndexError:
        print(usage)
        sys.exit(CheckerError.code)
    except WithExitCode as e:
        Red.print(str(e))
        return e.code
    except AttackError as e:
        Red.print("AttackError: " + str(e))
        return 1
    except ConnectError as e:
        # same as down but for sploit (separation of concerns, man)
        Red.print(str(e))
        return 1
    except Exception as e:
        Red.print("INTERNAL ERROR: {}".format(e))
        import traceback
        traceback.print_exc()
        return CheckerError.code

if __name__ == '__main__':
    sys.exit(main())
