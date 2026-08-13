"""FastAPI exception handlers for USSO."""

from fastapi import Request
from fastapi.responses import JSONResponse
from usso.exceptions import USSOException


def usso_exception_handler(
    request: Request,
    exc: Exception,
) -> JSONResponse:
    """
    FastAPI exception handler for USSO exceptions.

    Converts USSOException instances into JSON responses with
    appropriate status codes and error details.
    """
    if not isinstance(exc, USSOException):
        raise TypeError(
            "usso_exception_handler expects USSOException"
        ) from None

    accept = request.headers.get("accept-language")
    if accept:
        locales = accept.split(",")
        msg: dict[str, object] = {}
        for locale in locales:
            lang = locale.split("-")[0]
            if lang in exc.message:
                msg[lang] = exc.message.get(lang)
        message: dict[str, object] | object = msg
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
