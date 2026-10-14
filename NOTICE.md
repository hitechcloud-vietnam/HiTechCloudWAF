# NOTICE

HiTechCloud WAF
Copyright (C) 2026 Pho Tue SoftWare Solutions JSC / HiTechCloud-VN

This project is a modified version of **SafeLine** (https://github.com/chaitin/safeline),
Copyright (C) Beijing Chaitin Technology Co., Ltd., released under the
GNU General Public License v3.0. The original upstream commit imported here is
`7dee6104b2c8e94ddee9bac1e7c05fa783d769db` (2026-09-22).

This modified version is also distributed under the GNU General Public License
v3.0 (see `LICENSE.md`). Modifications by HiTechCloud include, among others:

- Rebranding of the GPL-licensed source code (MCP server, management sources,
  documentation and logo).
- The new `cluster/` module (controller, node agent, health-checked
  authoritative DNS) written by HiTechCloud.

Third-party components kept under their own licenses:

- `yanshi/` – by Fangrui Song (MaskRay), see its own headers.
- `sdk/lua-resty-t1k/` – see `sdk/lua-resty-t1k/LICENSE`.

## Not covered by this repository

The pre-built Docker images published by Chaitin (`chaitin/safeline-*`:
mgt, detector, tengine, luigi, fvm, chaos, postgres) are **not** part of this
source tree and are distributed by their owner under a separate end-user
licence agreement. HiTechCloud WAF does not modify, repackage or redistribute
those images. See `docs/LICENSING.vi.md`.

"SafeLine" and "雷池" are trademarks of their respective owner and are used here
only to identify the upstream origin of the code.
