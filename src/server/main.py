import hashlib
import json
import os
import time
import typing

import jwt
import sqlalchemy.exc
from sqlalchemy.orm import Session
from src.db.engine import engine
from src.db.models import User, Task, ListOfTasks
from src.server.dto import User as UserContract
from sqlalchemy import select
from dotenv import load_dotenv
load_dotenv()
SECRET = os.environ["SECRET"]
TTL = int(os.environ["TTL"])


async def read_body(receive):
    """
    Read and return the entire body from an incoming ASGI message.
    """
    body = b''
    more_body = True

    while more_body:
        message = await receive()
        body += message.get('body', b'')
        more_body = message.get('more_body', False)

    return body


async def respond(send, status_code, jsonned_response):
    await send({
        'type': 'http.response.start',
        'status': status_code,
        'headers': [
            [b'content-type', b'application/json'],
        ],
    })
    await send({
        'type': 'http.response.body',
        'body': json.dumps(jsonned_response).encode(),
    })


def user_data_validation(body: bytes) -> bool:
    try:
        jsonned = json.loads(body)
        if "nickname" not in jsonned or "password" not in jsonned:
            raise ValueError
    except (json.JSONDecodeError, ValueError):
        return False
    return True


def task_list_validation(body: bytes) -> bool:
    try:
        jsonned = json.loads(body)
        if "name" not in jsonned:
            raise ValueError
    except (json.JSONDecodeError, ValueError):
        return False
    return True


def validate_body(body: bytes, strategy: typing.Callable[[bytes], bool]):
    return strategy(body)


def generate_jwt(user: User) -> str:
    payload = {"nickname": user.nickname, "exp": int(time.time()) + TTL}
    return jwt.encode(payload, SECRET, algorithm="HS256")


def decode_jwt(token: str) -> UserContract | None:
    try:
        payload = jwt.decode(token, SECRET, algorithms=["HS256"])
        if "exp" not in  payload or payload["exp"] < int(time.time()):
            raise ValueError
    except (jwt.exceptions.PyJWTError, ValueError):
        return
    return UserContract(nickname=payload["nickname"])


def authorize(user: User | None, json_payload: dict):
    if user is None:
        return False
    new_hash = hashlib.sha256(json_payload["password"].encode()).hexdigest()
    if new_hash != user.password:
        return False
    return True


async def create_user(receive, send):
    body = await read_body(receive)
    if not validate_body(body, user_data_validation):
        await respond(send, 400, {"success": False})
        return
    jsonned_body = json.loads(body)
    try:
        with Session(engine) as session:
            hash_psw = hashlib.sha256(jsonned_body["password"].encode()).hexdigest()
            new_user = User(nickname=jsonned_body["nickname"], password=hash_psw)
            session.add(new_user)
            session.commit()
    except sqlalchemy.exc.IntegrityError:
        await respond(send, 400, {"success": False})
    await respond(send, 200, {"success": True})


async def get_token(receive, send):
    body = await read_body(receive)
    if not validate_body(body, user_data_validation):
        await respond(send, 400, {"success": False})
        return
    jsonned_body = json.loads(body)
    with Session(engine) as session:
        user = session.scalar(select(User).where(User.nickname == jsonned_body["nickname"]).limit(1))
        if not authorize(user, jsonned_body):
            await respond(send, 403, {"success": False})
            return
        encoded_jwt = generate_jwt(user)
        await respond(send, 200, {"success": True, "token": encoded_jwt})


async def user_route(scope, receive, send):
    prefix = "/user"
    path = scope["path"]
    if path.startswith(prefix + "/create") and scope["method"] == "POST":
        await create_user(receive, send)
    elif path.startswith(prefix + "/get_token") and scope["method"] == "POST":
        await get_token(receive, send)


async def secured_route(scope, receive, send, next_hop):
    headers = scope["headers"]
    auth_header = None
    for header in headers:
        if header[0].decode().lower() == "authorization":
            auth_header = header[1].decode().split()[1]
    if auth_header is None:
        await respond(send, 401, {"success": False})
        return
    user_model = decode_jwt(auth_header)
    if user_model is None:
        await respond(send, 403, {"success": False})
        return
    await next_hop(scope, receive, send, user_model)


async def create_list_of_tasks(scope, receive, send, user_model: UserContract):
    body = await read_body(receive)
    if not validate_body(body, task_list_validation):
        await respond(send, 400, {"success": False})
        return
    jsonned_body = json.loads(body)
    with Session(engine) as session:
        user = session.scalar(select(User).where(User.nickname == user_model.nickname).limit(1))
        new_task_list = ListOfTasks(name=jsonned_body["name"], user_id=user.id)
        session.add(new_task_list)
        session.commit()
    await respond(send, 200, {"success": True})


async def list_of_tasks(scope, receive, send, user_model):
    prefix = "/task_list"
    path = scope["path"]
    if path.startswith(prefix + "/create") and scope["method"] == "POST":
        await create_list_of_tasks(scope, receive, send, user_model)
    elif scope["method"] == "GET":
        ...  # TODO: see your lists


async def app(scope, receive, send):
    if scope['type'] != 'http':
        raise TypeError
    path = scope["path"]
    if path.startswith("/user"):
        await user_route(scope, receive, send)
    elif path.startswith("/task_list"):
        await secured_route(scope, receive, send, list_of_tasks)
    else:
        await send({
            'type': 'http.response.start',
            'status': 200,
            'headers': [
                [b'content-type', b'text/plain'],
            ],
        })
        await send({
            'type': 'http.response.body',
            'body': b'Hello, world!',
        })
