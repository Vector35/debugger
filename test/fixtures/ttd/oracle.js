// Run in the pinned CDB JavaScript provider. No Binary Ninja code is involved.
function hex(value) { return "0x" + value.toString(16); }
function position(value) { return [Number(value.Sequence), Number(value.Steps)]; }
function oracle(arch) {
    const data = arch === "x64" ? 0x7ff73e7d30b0 : 0x7e3388;
    const entry = arch === "x64" ? 0x7ff73e7d1010 : 0x7e1010;
    const func = arch === "x64" ? 0x7ff73e7d1080 : 0x7e1060;
    const ttd = host.currentSession.TTD;
    let result = {arch: arch, data_address: data, execute_address: entry,
                  call_address: func, memory: {}, calls: []};
    for (const access of ["r", "w", "e", "rw"]) {
        const address = access === "e" ? entry : data;
        let events = [];
        for (const e of ttd.Memory(address, address + 1, access)) {
            events.push({thread_id: Number(e.ThreadId), unique_thread_id: Number(e.UniqueThreadId),
                         time_start: position(e.TimeStart), time_end: position(e.TimeEnd),
                         address: hex(e.Address), instruction_address: hex(e.IP),
                         size: Number(e.Size), value: hex(e.Value),
                         access_type: e.AccessType.toString()});
        }
        result.memory[access] = events;
    }
    for (const c of ttd.Calls(hex(func))) {
        let parameters = [];
        for (const p of c.Parameters) { parameters.push(hex(p)); }
        result.calls.push({thread_id: Number(c.ThreadId), unique_thread_id: Number(c.UniqueThreadId),
                           time_start: position(c.TimeStart), time_end: position(c.TimeEnd),
                           function_address: hex(c.FunctionAddress), return_address: hex(c.ReturnAddress),
                           return_value: hex(c.ReturnValue), parameters: parameters});
    }
    host.diagnostics.debugLog("TTD_ORACLE " + JSON.stringify(result) + "\n");
    return "TTD_ORACLE_DONE";
}
