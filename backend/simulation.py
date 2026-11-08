"""Task-local stores: concurrent simulation runs never reset each other's target."""
from contextlib import contextmanager
from contextvars import ContextVar
from functools import wraps
import secrets
import uuid
import asyncio

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
def simulation_scope(seed=None, run_id=None):
    from backend.mock_target.store import VulnerableVoucherStore
    seed = secrets.randbits(32) if seed is None else int(seed)
    context = {"run_id": run_id or uuid.uuid4().hex, "seed": seed}
    store_token = _store.set(VulnerableVoucherStore())
    run_token = _run.set(context)
    try:
        yield context
    finally:
        _run.reset(run_token)
        _store.reset(store_token)


def current_run():
    return _run.get()


def current_target():
    return _store.get()


@contextmanager
def target_scope(store):
    token = _store.set(store)
    try:
        yield
    finally:
        _store.reset(token)


def isolated_training(function):
    @wraps(function)
    async def wrapped(*args, **kwargs):
        import inspect
        parameters = inspect.signature(function).bind_partial(*args, **kwargs)
        with simulation_scope(parameters.arguments.get("seed"), parameters.arguments.get("run_id")):
            from backend.run_store import save_run, get_run
            from backend.wargame_workload import VERSION
            config = {**current_run(), "kind": "training", "simulation_version": VERSION,
                      "total_rounds": parameters.arguments.get("total_rounds", 5),
                      "burst_streams": parameters.arguments.get("burst_streams", 15)}
            # Persist synchronously at lifecycle boundaries, including cancellation.
            save_run(config["run_id"], config, {"stage": "STARTING"}, "RUNNING")
            try:
                return await function(*args, **kwargs)
            except BaseException as error:
                from backend.observability import event
                saved = get_run(config['run_id'])
                save_run(config["run_id"], saved['configuration'] if saved else config,
                         {**(saved['result'] if saved else {}), "error_type": type(error).__name__,
                         "assessment_state": "NOT_ASSESSED"},
                         "CANCELLED" if isinstance(error, asyncio.CancelledError) else "FAILED")
                event("simulation.failed", **current_run(), error_type=type(error).__name__)
                raise
    return wrapped
