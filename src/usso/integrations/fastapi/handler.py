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
