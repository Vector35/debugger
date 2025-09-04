# Debugger Bookmark Feature

This feature adds timestamp bookmarking capability to the Binary Ninja debugger, particularly useful for Time Travel Debugging (TTD) scenarios.

## Features

### Bookmark Management
- **Create bookmarks** at current debugger position with custom descriptions
- **Navigate to bookmarks** with double-click (attempts TTD position navigation + address navigation)
- **Persistent storage** - bookmarks are saved with the binary view
- **Time tracking** - each bookmark stores when it was created

### UI Components

#### Bookmarks Tab
A new "Bookmarks" tab is added to the debugger sidebar with the following columns:
- **Description**: User-provided description of the bookmark
- **TTD Position**: Time Travel Debugging position (if available)
- **Address**: Memory address where bookmark was created
- **Timestamp**: When the bookmark was created

#### Context Menu Actions
- **Add Bookmark...**: Create a new bookmark at current position
- **Jump To Bookmark**: Navigate to selected bookmark 
- **Remove Bookmark**: Delete selected bookmark(s)

#### Global Action
- **Debugger > Add Bookmark** (Ctrl+M): Quick bookmark creation from anywhere in the UI

## Usage

### Creating Bookmarks

1. **Via Bookmarks Tab**: 
   - Navigate to desired debugger position
   - Open Debugger sidebar > Bookmarks tab
   - Right-click > "Add Bookmark..." or use the Add button
   - Enter a description

2. **Via Global Action**:
   - Navigate to desired debugger position  
   - Press Ctrl+M or use Debugger menu > Add Bookmark
   - Enter a description

### Navigating to Bookmarks

1. **Double-click** any bookmark in the Bookmarks tab
2. Or right-click > "Jump To Bookmark"

The navigation system will:
1. First attempt TTD position navigation (if TTD is available)
2. Fall back to address navigation 
3. Provide feedback on success/failure

### TTD Integration

For Time Travel Debugging sessions, the bookmark system:
- Automatically detects TTD capability
- Attempts to capture current TTD position using `!tt` command
- On navigation, tries multiple TTD position commands (`!tt <position>`, `!position <position>`)
- Falls back gracefully to address navigation if TTD positioning fails

## Implementation Notes

### Data Storage
Bookmarks are stored in Binary Ninja metadata under the key "debugger.bookmarks" as an array of objects containing:
```json
{
  "description": "User description", 
  "ttdPosition": "12A:B4",
  "address": 4194304,
  "timestamp": "2024-01-01 12:00:00"
}
```

### TTD Command Compatibility
The system attempts multiple TTD command formats for maximum compatibility:
- `!tt <position>` (WinDbg TTD)
- `!position <position>` (alternate format)

### Error Handling
- Graceful fallback when TTD commands fail
- User-friendly error messages
- Automatic refresh of bookmark list
- Input validation and sanitization

## Development Notes

The bookmark feature follows existing debugger UI patterns:
- Uses same model/view/delegate pattern as breakpoints widget
- Integrates with existing action/menu system
- Follows Binary Ninja theming and font management
- Uses established metadata persistence patterns

Files added:
- `ui/bookmarkswidget.h` - Header with BookmarkItem, model, delegate, and widget classes
- `ui/bookmarkswidget.cpp` - Implementation with TTD integration
- Modified `ui/debuggerwidget.h/cpp` - Integration into main debugger UI
- Modified `ui/ui.cpp` - Global action registration