import asyncio
from fastapi import FastAPI, Response
from fastapi.responses import JSONResponse, RedirectResponse

harness_app = FastAPI(title="Local Controlled Execution Test Harness")


@harness_app.get("/health")
def harness_health():
    return {"status": "ok", "harness": True}


@harness_app.get("/users")
def list_users(page: int = 1):
    return [{"id": "00000000-0000-0000-0000-000000000001", "username": "alice", "page": page}]


@harness_app.post("/users")
def create_user(payload: dict):
    return {"id": "00000000-0000-0000-0000-000000000002", "received": payload}


@harness_app.get("/users/{user_id}")
def get_user(user_id: str):
    if user_id == "00000000-0000-0000-0000-000000000000":
        return JSONResponse(status_code=403, content={"error": "Forbidden"})
    return {"id": user_id, "username": "alice"}


@harness_app.get("/redirect")
def redirect_endpoint():
    return RedirectResponse(url="http://evil.example.com/stolen", status_code=302)


@harness_app.get("/large-response")
def large_response():
    # Return a payload larger than 200 KB
    return Response(content="A" * 250000, media_type="text/plain")


@harness_app.get("/slow-response")
async def slow_response():
    await asyncio.sleep(5)
    return {"status": "slow"}
