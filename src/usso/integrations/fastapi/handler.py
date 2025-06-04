from fastapi import Request
from fastapi.responses import JSONResponse

from ...exceptions import USSOException


async def usso_exception_handler(request: Request, exc: USSOException):
    return JSONResponse(
        status_code=exc.status_code,
        content={"message": exc.message, "error": exc.error},
    )


EXCEPTION_HANDLERS = {
    USSOException: usso_exception_handler,
}
