# API-side custom debug adapters

Plugins can implement a debug backend using the public C++ or Python debugger
API. The core bridge calls plugin-provided callbacks; plugins do not subclass
the internal `DebugAdapter` or link against its implementation.

This change supplies the common registration bridge and the C++/Python wrappers
only. It adds no emulator dependencies, Rust bindings, or production backends.

## Registration and ownership

In C++, subclass `BinaryNinjaDebuggerAPI::CustomDebugAdapter` and implement the
backend operations. Subclass `CustomDebugAdapterType` and return an instance
from `Create(Ref<BinaryView>)` as a `std::unique_ptr<CustomDebugAdapter>`. Register
with `DebugAdapterType::Register(new MyAdapterType())`, following the C++
BinaryViewType/Architecture convention. Successful registration retains a
registration reference and stores the core handle on the factory; do not
manually delete a registered type. Registration returns `false` if the name is
empty or already registered. An instance `Register()` call is also available.

In Python, subclass `CustomDebugAdapter`, set a class `name`, and call
`MyAdapter.register()`, following Python BinaryView/Architecture registration.
Its constructor receives the controller's actual BinaryView; the base class
retains it as `self.view`. Registration retains the factory and callbacks in
`MyAdapter.registered_adapter_type`. Class methods `is_valid_for_data`,
`can_execute`, and `can_connect` determine availability. Type names must be
nonempty and unique; registration failure raises `ValueError`.

```python
from debugger.customdebugadapter import CustomDebugAdapter
from debugger.debugger_enums import DebugStopReason

class ExampleAdapter(CustomDebugAdapter):
    name = "EXAMPLE"

    def execute(self, path):
        # Initialize your backend before reporting the initial stop.
        self.post_stopped(int(DebugStopReason.InitialBreakpoint))
        return True

adapter_type = ExampleAdapter.register()
```

The explicit `CustomDebugAdapterType` factory API remains available for custom
construction policies: implement `create(self, bv)` and register a factory
instance. It is a `DebugAdapterType`, so registered factories can also be
looked up using `DebugAdapterType.get_by_name(name)`.

The snippet illustrates registration, not a working backend. A usable adapter
must also report its target architecture, registers, threads, memory, and other
operations it supports. Unsupported operations return failure or empty results.

The controller owns the bridge and its created adapter implementation. The
C++ wrapper transfers ownership only after bridge creation succeeds; the bridge
deletes the implementation at teardown. Python retains callback objects and
adapter instances until the bridge's release callback runs. Registration is
process-global; unloading registered plugin code and unregistering types are
not supported.

## Events and concurrency

Report execution stops through `AdapterStoppedEventType`: C++ calls `PostEvent`
with a `BNDebuggerEvent`, and Python can use `post_stopped`. Report normal exit
with `TargetExitedEventType` and the exit code, not just a stopped event. Report
resume/step events when the backend starts running so the controller updates
its state. Input strings and callback argument pointers are borrowed only for
the duration of each call.

Callbacks may run on controller worker/interrupt threads, not the UI thread.
Run-control callbacks must return promptly; arrange for your backend to wait
asynchronously and then post its stop. Allow `BreakInto` / `break_into` to
interrupt that work without blocking on a lock held by the wait. Stop and join
backend-owned workers before releasing the adapter; they must never post to a
destroyed bridge. Do not let a C++ exception cross the C callback boundary.
The Python wrapper catches exceptions around the complete callback, including
result conversion, and returns a failure value, as Binary Ninja's Python
Architecture and BinaryView wrappers do.

## Callback results

The bridge copies lists and out-parameter structures, then invokes their
matching `free*` callbacks. The public wrappers manage these buffers and retain
Python string storage through the copy. Each result is retained separately by
its pointer until its own release callback, including overlapping requests.
Architecture and backend-command
strings use the debugger string allocator. Returned data buffers, metadata,
and settings transfer one owned reference to the bridge. The wrappers perform
that reference transfer; Python `get_adapter_settings` returns its retained
`binaryninja.Settings` object.

## Focused tests

Build the standard plugin and generated Python bindings with
`-DBUILD_CUSTOM_ADAPTER_TESTS=ON`, then run `pytest test/custom_adapter_test.py`
in the standalone build environment described in the local guide. The C++
fixture is a test-only module in `build/test`; it is not installed as a user
plugin. Both fixtures are deterministic in-memory adapters and require no
external emulator or target process.

The tests exercise registration, factory view propagation, settings, launch,
stepping, continue/stop events, register/string conversion, memory reads/writes,
unmapped-write rejection, and teardown through the real controller. These
checks validate the API boundary, not a production backend's correctness.
