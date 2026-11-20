// Magpie/OpenCode registration entry.
//
// Magpie's plugin host loads `exports["."]` / `main` / an index file and asks
// the module for OpenCode plugin *functions* (see its `servers()` helper): a
// default object with `id`/`tui` but no `server` function is treated as empty.
// So export the wrapper plugin function directly - do NOT wrap it in a
// `{ id, setup }` object here.

export { ZCodeKeyringAuthPlugin, ZCodeKeyringAuthPlugin as default } from './plugin.mjs';
