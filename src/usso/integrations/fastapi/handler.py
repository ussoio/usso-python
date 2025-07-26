from fastapi import Request
from fastapi.responses import JSONResponse

from ...exceptions import USSOException


def usso_exception_handler(
    request: Request, exc: USSOException
) -> JSONResponse:
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "message": exc.message,
            "error": exc.error,
            "detail": exc.detail,
            **exc.data,
        },
    )


EXCEPTION_HANDLERS = {
    USSOException: usso_exception_handler,
}
