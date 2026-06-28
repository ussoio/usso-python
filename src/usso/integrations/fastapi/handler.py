"""FastAPI exception handlers for USSO."""

from fastapi import Request
from fastapi.responses import JSONResponse

from ...exceptions import USSOException


def usso_exception_handler(
    request: Request, exc: USSOException
) -> JSONResponse:
    """
    FastAPI exception handler for USSO exceptions.

    Converts USSOException instances into JSON responses with
    appropriate status codes and error details.

    Args:
        request: The FastAPI request object.
        exc: The USSOException instance to handle.

    Returns:
        JSONResponse: JSON response with error details.

    """
    if request.headers.get("accept-language"):
        locales = request.headers.get("accept-language").split(",")
        msg = {}
        for locale in locales:
            lang = locale.split("-")[0]
            if lang in exc.message:
                msg[lang] = exc.message.get(lang)
        message = msg
    else:
        message = exc.message

    return JSONResponse(
        status_code=exc.status_code,
        content={
            "message": message,
            "error_code": exc.error_code,
            "detail": exc.detail,
            **exc.data,
        },
    )


EXCEPTION_HANDLERS = {
    USSOException: usso_exception_handler,
}
