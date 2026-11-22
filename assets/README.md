# NetBridge launcher icon

Selected design: cyber-style cyan network bridge with mint wireless arcs, a
transparent background and generous empty margins for the black launcher.
No background tile or text. The earlier solid-tile design was rejected and is
not part of the project assets.

- `netbridge-icon-master.png`: original generated RGBA artwork.
- `netbridge-icon.png`: 100 × 100 RGBA launcher export, with padding preserved.
- `../scripts/build-icon.ps1`: deterministic Windows export using System.Drawing.
- Device destination: `/usr/share/APPLaunch/share/images/netbridge-icon.png`.
- Desktop entry: `Icon=share/images/netbridge-icon.png`.

Created on 2026-11-21 with the built-in imagegen tool, not the API/CLI fallback.
Only resolution conversion was performed after generation; alpha was retained.

Generation prompt:

> Create a single cyber-style app icon for NetBridge, an embedded networking
> application. TRUE transparent background, no tile, no background rectangle.
> Centered compact angular network bridge emblem, two strong geometric endpoint
> pillars connected by an electric cyan bridge span, with a small mint circuit
> junction and two restrained angular wireless signal arcs. Futuristic precision
> hardware / cyber aesthetic, crisp bold silhouette, subtle cyan edge glow only
> close to the symbol. Readable at 64px. The entire artwork must occupy ONLY the
> central 65 percent of the square canvas, leaving at least 17 percent fully
> transparent empty margin on every side. Designed for a pure black launcher
> backdrop. Cyan with mint accents, no white fill backdrop, no text, no letters,
> no shield, no skull, no detailed circuit-board background, no presentation
> mockup. Single isolated symbol.
