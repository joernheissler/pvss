from typing import ContextManager, Optional, Type


class ExceptionInfo:
    ...


def raises(exc: Type[Exception], match: Optional[str] = None) -> ContextManager[ExceptionInfo]:
    ...
