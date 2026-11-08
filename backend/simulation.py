"""Task-local stores: concurrent simulation runs never reset each other's target."""
from contextlib import contextmanager
from contextvars import ContextVar
from functools import wraps
import secrets
import uuid

_store = ContextVar("aigis_mock_store", default=None)
_run = ContextVar("aigis_run", default=None)


class StoreProxy:
    def __init__(self, default):
        object.__setattr__(self, "_default", default)

    def __getattr__(self, name):
        return getattr(_store.get() or self._default, name)

    def __setattr__(self, name, value):
        setattr(_store.get() or self._default, name, value)

    def __delattr__(self, name):
        delattr(_store.get() or self._default, name)


@contextmanager
def simulation_scope(seed=None):
    from backend.mock_target.store import VulnerableVoucherStore
    seed = secrets.randbits(32) if seed is None else int(seed)
    context = {"run_id": uuid.uuid4().hex, "seed": seed}
    store_token = _store.set(VulnerableVoucherStore())
    run_token = _run.set(context)
    try:
        yield context
    finally:
        _run.reset(run_token)
        _store.reset(store_token)


def current_run():
    return _run.get()


def isolated_training(function):
    @wraps(function)
    async def wrapped(*args, **kwargs):
        import inspect
        parameters = inspect.signature(function).bind_partial(*args, **kwargs)
        with simulation_scope(parameters.arguments.get("seed")):
            try:
                return await function(*args, **kwargs)
            except BaseException as error:
                from backend.observability import event
                event("simulation.failed", **current_run(), error_type=type(error).__name__)
                raise
    return wrapped
