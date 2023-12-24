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
from sqlalchemy import select, delete
from dotenv import load_dotenv

load_dotenv()
SECRET = os.environ["SECRET"]
TTL = int(os.environ["TTL"])


async def read_body(receive):
    """
    Read and return the entire body from an incoming ASGI message.
    """
    body = b""
    more_body = True

    while more_body:
        message = await receive()
        body += message.get("body", b"")
        more_body = message.get("more_body", False)

    return body


async def respond(send, status_code, jsonned_response):
    await send(
        {
            "type": "http.response.start",
            "status": status_code,
            "headers": [
                [b"content-type", b"application/json"],
            ],
        }
    )
    await send(
        {
            "type": "http.response.body",
            "body": json.dumps(jsonned_response).encode(),
        }
    )


def bytes_to_jsone(body: bytes) -> dict | None:
    try:
        return json.loads(body)
    except json.JSONDecodeError:
        return None


def user_data_validation(body: bytes) -> bool:
    jsonned = bytes_to_jsone(body)
    if jsonned is None:
        return False
    if "nickname" not in jsonned or "password" not in jsonned:
        raise ValueError
    return True


def task_list_create_validation(body: bytes) -> bool:
    jsonned = bytes_to_jsone(body)
    if jsonned is None:
        return False
    if "name" not in jsonned:
        return False
    return True


def task_list_update_validation(body: bytes) -> bool:
    jsonned = bytes_to_jsone(body)
    if jsonned is None:
        return False
    if "id" not in jsonned or "new_name" not in jsonned:
        return False
    return True


def task_list_delete_validation(body: bytes) -> bool:
    jsonned = bytes_to_jsone(body)
    if jsonned is None:
        return False
    if "id" not in jsonned:
        return False
    return True


def validate_body(body: bytes, strategy: typing.Callable[[bytes], bool]):
    return strategy(body)


def generate_jwt(user: User) -> str:
    payload = {"id": user.id, "exp": int(time.time()) + TTL}
    return jwt.encode(payload, SECRET, algorithm="HS256")


def decode_jwt(token: str) -> UserContract | None:
    try:
        payload = jwt.decode(token, SECRET, algorithms=["HS256"])
        if "exp" not in payload or payload["exp"] < int(time.time()):
            raise ValueError
    except (jwt.exceptions.PyJWTError, ValueError):
        return
    return UserContract(id=payload["id"])


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


async def authenticate_user(receive, send):
    body = await read_body(receive)
    if not validate_body(body, user_data_validation):
        await respond(send, 400, {"success": False})
        return
    jsonned_body = json.loads(body)
    with Session(engine) as session:
        user = session.scalar(
            select(User).where(User.nickname == jsonned_body["nickname"]).limit(1)
        )
        if not authorize(user, jsonned_body):
            await respond(send, 403, {"success": False})
            return
        encoded_jwt = generate_jwt(user)
        await respond(send, 200, {"success": True, "token": encoded_jwt})


async def user_route(scope, receive, send):
    """
    Handle user routes.

    create_user and get_token both require nickname and password fields in POST body.
    """
    prefix = "/user"
    path = scope["path"]
    if path.startswith(prefix + "/create") and scope["method"] == "POST":
        await create_user(receive, send)
    elif path.startswith(prefix + "/get_token") and scope["method"] == "POST":
        await authenticate_user(receive, send)
    else:
        await respond(send, 405, {})


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


async def create_list_of_tasks(receive, send, user_model: UserContract):
    body = await read_body(receive)
    if not validate_body(body, task_list_create_validation):
        await respond(send, 400, {"success": False})
        return
    jsonned_body = json.loads(body)
    with Session(engine) as session:
        user = session.scalar(select(User).where(User.id == user_model.id).limit(1))
        new_task_list = ListOfTasks(name=jsonned_body["name"], user_id=user.id)
        session.add(new_task_list)
        session.commit()
    await respond(send, 200, {"success": True})


async def get_lists_of_tasks(send, user_model: UserContract):
    with Session(engine) as session:
        user = session.scalar(select(User).where(User.id == user_model.id).limit(1))
        if user.is_admin:
            viewable_lists = [lst for lst in session.scalars(select(ListOfTasks))]
        else:
            viewable_lists = [
                lst
                for lst in session.scalars(
                    select(ListOfTasks).where(ListOfTasks.user_id == user.id)
                )
            ]
    response = {
        "success": True,
        "lists": [
            {"id": lst.id, "name": lst.name, "owner_id": lst.user_id}
            for lst in viewable_lists
        ],
    }
    await respond(send, 200, response)


async def update_list_of_tasks(receive, send, user_model):
    body = await read_body(receive)
    if not validate_body(body, task_list_update_validation):
        await respond(send, 400, {"success": False})
        return
    jsonned_body = json.loads(body)
    with Session(engine) as session:
        user = session.scalar(select(User).where(User.id == user_model.id))
        modified_list = session.scalar(
            select(ListOfTasks).where(
                ListOfTasks.user_id == user.id, ListOfTasks.id == jsonned_body["id"]
            )
        )

        if modified_list is None:
            await respond(send, 404, {"success": False})
            return
        modified_list.name = jsonned_body["new_name"]
        session.commit()
    await respond(send, 200, {"success": True})


async def delete_list_of_tasks(receive, send, user_model):
    body = await read_body(receive)
    if not validate_body(body, task_list_delete_validation):
        await respond(send, 400, {"success": False})
        return
    jsonned_body = json.loads(body)
    with Session(engine) as session:
        user = session.scalar(select(User).where(User.id == user_model.id))
        delete_list = session.scalar(
            select(ListOfTasks).where(
                ListOfTasks.user_id == user.id, ListOfTasks.id == jsonned_body["id"]
            )
        )
        if delete_list is None:
            await respond(send, 404, {"success": False})
            return
        stmnt = delete(ListOfTasks).where(
            ListOfTasks.user_id == user.id, ListOfTasks.id == jsonned_body["id"]
        )
        session.execute(stmnt)
        session.commit()
    await respond(send, 200, {"success": True})


async def list_of_tasks(scope, receive, send, user_model):
    """
    All Endpoints require authentication Bearer header with issued JWT.
    GET Endpoint takes no params
    POST Endpoint requires body params:
        name - str
    PUT Endpoint requires body params:
        id - int (task_list id)
        new_name - str
    DELETE Endpoint requires body params:
        id - int (task_list id)
    """
    if scope["method"] == "POST":
        await create_list_of_tasks(receive, send, user_model)
    elif scope["method"] == "PUT":
        await update_list_of_tasks(receive, send, user_model)
    elif scope["method"] == "DELETE":
        await delete_list_of_tasks(receive, send, user_model)
    elif scope["method"] == "GET":
        await get_lists_of_tasks(send, user_model)
    else:
        await respond(send, 405, {})


async def create_task(receive, send, user_model):
    pass


async def update_task(receive, send, user_model):
    pass


async def delete_task(receive, send, user_model):
    pass


async def get_task(send, user_model, query: str):
    kwarg = query.split("=")
    if len(kwarg) != 2 or kwarg[0] != "list_id" or not kwarg[1].isnumeric():
        await respond(send, 400, {"success": False})
    list_id = int(kwarg[1])
    with Session(engine) as session:
        user = session.scalar(select(User).where(User.id == user_model.id))
        if user.is_admin:
            tasks = session.scalars(select(Task).where(Task.list_id == list_id))
        else:
            tasks = session.scalars(
                select(Task, ListOfTasks).where(
                    Task.list_id == list_id,
                    ListOfTasks.id == list_id,
                    ListOfTasks.user_id == user.id,
                )
            )
        serialised = [
            {
                "id": tsk.id,
                "name": tsk.name,
                "description": tsk.description,
                "is_done": tsk.is_done
            }
            for tsk in tasks
        ]
    await respond(send, 200, {"success": True, "tasks": serialised})


async def task(scope, receive, send, user_model):
    """
    All Endpoints require authentication Bearer header with issued JWT.
    GET Endpoint requres query param:
        list_id - int
    POST Endpoint requires body params:
        name - str
        description - str
        list_id - int
    PUT Endpoint requires body params:
        id - int (task id)
        list_id - int (task_list id)
        any combination of following params:
            name - str
            description - str
            is_done - bool
    DELETE Endpoint requires body params:
        id - int (task id)
        list_id - int (task_list id)
    """
    if scope["method"] == "POST":
        await create_task(receive, send, user_model)
    elif scope["method"] == "PUT":
        await update_task(receive, send, user_model)
    elif scope["method"] == "DELETE":
        await delete_task(receive, send, user_model)
    elif scope["method"] == "GET":
        query = scope["query_string"].decode()
        await get_task(send, user_model, query)
    else:
        await respond(send, 405, {})


async def app(scope, receive, send):
    """
    Use app to run API.

    API logic:
        routes with prefix /user are handled by user_route,
            which routes the request depending on the request method
        routes with preifx /task_list are handled in the same way by list_of_tasks.
            (As this endpoind requires authn and authz, secured_route firstly checks credentials)
    """
    if scope["type"] != "http":
        raise TypeError
    path = scope["path"]
    if path.startswith("/user"):
        await user_route(scope, receive, send)
    elif path.startswith("/task_list"):
        await secured_route(scope, receive, send, list_of_tasks)
    elif path.startswith("/task"):
        await secured_route(scope, receive, send, task)
    else:
        await respond(send, 404, {})
