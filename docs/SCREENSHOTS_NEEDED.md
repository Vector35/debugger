# Screenshot Placeholders for TTD Documentation

This document lists all screenshot placeholders that need to be captured and added to the TTD documentation.

## Location: docs/guide/dbgeng-ttd.md

### TTD Widgets

1. **TTD Calls widget**
   - Description: TTD Calls widget with query parameters and results
   - Should show:
     - Query Parameters section (can be collapsed or expanded)
     - Symbols input field with example query (e.g., "user32!MessageBoxA")
     - Return Address Range inputs
     - Results table populated with sample call events
     - Multiple rows showing: Index, Time Start, Time End, Function, Function Address, Return Address, Return Value, Parameters
     - Multi-tab interface with + button visible
     - Sample data from a real trace

2. **TTD Memory widget**
   - Description: TTD Memory widget with query parameters and results
   - Should show:
     - Query Parameters section (can be collapsed or expanded)
     - Start/End Address input fields
     - Access Types checkboxes (Read, Write, Execute)
     - Results table populated with sample memory events
     - Multiple rows showing: Index, Time Start, Access Type, Address, Size, Value, IP
     - Multi-tab interface with + button visible
     - Sample data showing R/W/E operations

3. **TTD Events widget - Modules tab**
   - Description: TTD Events widget showing module load events
   - Should show:
     - Tabbed interface: All Events, Modules, Threads, Exceptions tabs visible
     - Modules tab selected
     - List of loaded modules with addresses, sizes, and positions
     - Module names (DLLs/system libraries like kernel32.dll, ntdll.dll)
     - Clear, readable data

4. **TTD Events widget - Threads tab**
   - Description: TTD Events widget showing thread creation/termination events
   - Should show:
     - Threads tab selected
     - List of thread events with thread IDs and positions
     - Thread lifetime information
     - Clear, readable data

5. **TTD Events widget - Exceptions tab**
   - Description: TTD Events widget showing exception events
   - Should show:
     - Exceptions tab selected
     - Exception events with type, code, and PC
     - Exception position information
     - Clear, readable data (if trace has exceptions; otherwise can be empty)

6. **TTD Analysis dialog**
   - Description: TTD Analysis dialog with code coverage analysis
   - Should show:
     - Analysis type list/selector with "Code Coverage" visible
     - Run Analysis button
     - Result count displayed after analysis completes
     - Cache options section (auto-cache checkbox, save/load/clear buttons)
     - Status label showing completion
     - Optional: Progress bar

7. **Code coverage visualization**
   - Description: Disassembly view showing executed instruction highlights
   - Should show:
     - Disassembly view (Linear or Graph view)
     - Instructions highlighted in green (executed during trace)
     - Some instructions without highlighting (not executed)
     - Clear visual contrast between executed and non-executed code
     - Representative function with mixed coverage

### Context Menus

8. **TTD Calls context menu**
   - Description: Context menu in TTD Calls results table
   - Should show:
     - Right-click menu on a result row
     - Menu options: Copy, Copy Row, Copy Table, Column Visibility..., Reset Columns to Default

9. **TTD Memory context menu**
   - Description: Context menu in TTD Memory results table
   - Should show:
     - Right-click menu on a result row
     - Menu options: Copy, Copy Row, Copy Table, Column Visibility..., Reset Columns to Default

## Screenshot Guidelines

### General Requirements

- **Resolution**: High resolution (at least 1080p)
- **Format**: PNG format preferred
- **Save Location**: `docs/img/debugger/` directory
- **Naming Convention**:
  - `ttd_calls_widget.png`
  - `ttd_memory_widget.png`
  - `ttd_events_modules.png`
  - `ttd_events_threads.png`
  - `ttd_events_exceptions.png`
  - `ttd_analysis_dialog.png`
  - `ttd_code_coverage.png`
  - `ttd_calls_context_menu.png`
  - `ttd_memory_context_menu.png`

### Content Guidelines

- Use a real TTD trace with meaningful data (not lorem ipsum or test data)
- Show realistic function names and addresses
- Ensure Binary Ninja theme is consistent with other documentation screenshots
- Crop screenshots to focus on relevant UI elements
- Ensure text is readable at documentation display size

### Sample Trace Suggestions

For best results, use a simple Windows application that:
- Calls common Windows APIs (MessageBox, CreateFile, etc.)
- Has clear code paths for coverage visualization
- Is not too complex to understand at a glance
- Does not contain sensitive or proprietary information

Example: A simple "Hello World" program that creates a file and shows a message box would demonstrate:
- Function calls to kernel32 and user32 APIs (e.g., user32!MessageBoxA, kernel32!CreateFileA)
- Memory reads/writes for string handling
- Module loads (kernel32.dll, user32.dll, ntdll.dll)
- Clear execution flow for coverage

**Note**: For TTD Calls queries, remember that the symbol format must include the module name (e.g., "user32!MessageBoxA" or "*!MessageBoxA" for wildcards).

## Implementation Checklist

- [ ] Screenshot 1: TTD Calls widget
- [ ] Screenshot 2: TTD Memory widget
- [ ] Screenshot 3: TTD Events widget - Modules tab
- [ ] Screenshot 4: TTD Events widget - Threads tab
- [ ] Screenshot 5: TTD Events widget - Exceptions tab
- [ ] Screenshot 6: TTD Analysis dialog
- [ ] Screenshot 7: Code coverage visualization
- [ ] Screenshot 8: TTD Calls context menu
- [ ] Screenshot 9: TTD Memory context menu

## After Screenshots Are Captured

1. Save all screenshots to `docs/img/debugger/` directory
2. Update markdown files to replace placeholders with image tags:
   - Replace `**Screenshot placeholder: TTD Calls widget with query parameters and results**`
     with `<img src="../../img/debugger/ttd_calls_widget.png" width="600px">`
   - Replace `**Screenshot placeholder: TTD Memory widget with query parameters and results**`
     with `<img src="../../img/debugger/ttd_memory_widget.png" width="600px">`
   - Replace `**Screenshot placeholder: TTD Events widget - Modules tab**`
     with `<img src="../../img/debugger/ttd_events_modules.png" width="600px">`
   - Replace `**Screenshot placeholder: TTD Events widget - Threads tab**`
     with `<img src="../../img/debugger/ttd_events_threads.png" width="600px">`
   - Replace `**Screenshot placeholder: TTD Events widget - Exceptions tab**`
     with `<img src="../../img/debugger/ttd_events_exceptions.png" width="600px">`
   - Replace `**Screenshot placeholder: TTD Analysis dialog with code coverage**`
     with `<img src="../../img/debugger/ttd_analysis_dialog.png" width="600px">`
   - Replace `**Screenshot placeholder: Code coverage visualization in disassembly view**`
     with `<img src="../../img/debugger/ttd_code_coverage.png" width="600px">`
   - Replace `**Screenshot placeholder: TTD Calls context menu**`
     with `<img src="../../img/debugger/ttd_calls_context_menu.png" width="400px">`
   - Replace `**Screenshot placeholder: TTD Memory context menu**`
     with `<img src="../../img/debugger/ttd_memory_context_menu.png" width="400px">`
3. Verify all images display correctly in rendered markdown
4. Commit screenshots with descriptive commit message
