# Console white-label overlay

Builds a branded console image **from** the upstream image without changing
how it runs.

- `brand/static/` – files copied over `/app/static` at the same path
  (e.g. `favicon.png`, `icons/...`). Put your logo/favicon files here.
- `brand/replacements.tsv` – exact product-name phrases to replace.

Then set `IMAGE_PREFIX`/image name of the `mgt` service in `compose.yaml` to
your private registry.

> ⚠️ Chỉ build/phân phối khi đã có **văn bản cho phép** của chủ sở hữu bản quyền
> image (Chaitin) bao gồm quyền sửa đổi và phân phối lại. Không đổi nội dung
> EULA / thông báo bản quyền. Xem `docs/LICENSING.vi.md`.
