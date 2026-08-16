# v2.6.2 — Files UI aligned with Terminal + cleaner server actions

## UX improvements

- Redesigned **Files** as a full-screen workspace using the same interaction pattern as the integrated Terminal.
- Added a compact **Files** action next to Terminal on every **connected server**.
- Removed Terminal from **Saved servers**. Saved profiles now focus on profile management: Connect, Edit and Delete.
- Removed the old expandable Files section from the main dashboard, reducing visual clutter.
- Files header now displays the active server and allows switching among current SSH connections.
- `Esc` closes Files just like it closes Terminal.

## File manager behavior

- Preserves the two-pane Local / Remote SFTP workflow.
- Upload, download, rename, delete and create-folder operations remain available.
- SSH private-key browsing still works without an active remote connection by opening Files in local-only mode.
- Selecting a private key closes Files and returns directly to the server form.

## Security carried forward from v2.6.1

- Removed unsafe dynamic `innerHTML` usage from the application UI.
- Hardened `.cgw` key import against path traversal.
- Added shared validation for imported tunnel definitions.
- Reduced global mutex contention around SSH and SFTP operations.
- Improved synchronization around SSH connection state and host fingerprints.

Version updated to **2.6.2**.
