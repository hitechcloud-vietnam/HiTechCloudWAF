# 03 – Helm chart hỗ trợ đăng ký node (enrollment token)

**Trạng thái:** chưa làm. **Ưu tiên:** trung bình.
**Code:** `deploy/helm/hitechcloud-waf/templates/{agent-configmap.yaml,controller.yaml,secret-cluster.yaml}`,
`deploy/kubernetes/`, `cluster/deploy/bootstrap-controller.sh`, `docs/kubernetes.vi.md`.

## Bối cảnh
Cluster đã có token dùng một lần + secret riêng cho từng node
(`docs/cluster.vi.md` mục *Đăng ký node*). Chart và script bootstrap Docker vẫn
dùng `node_token` dùng chung (vẫn chạy, nhưng bị đánh dấu lỗi thời).

## Việc cần làm
1. Values mới `agent.enrollTokenSecret` (tên Secret chứa token `hcwe_...`);
   agent ghi `enroll_token_file`. Agent lưu secret ở `data_dir` – với
   DaemonSet cần volume bền (hostPath) để khởi động lại không phải đăng ký lại.
2. Values `controller.requireEnrollment` → `require_enrollment`.
3. `bootstrap-controller.sh`: in hướng dẫn tạo enrollment token.
4. Cập nhật tài liệu, `ci/full-values.yaml`; chạy `helm lint --strict`,
   `helm template`, kubeconform, `deploy/kubernetes/render.sh --check`.

## Hoàn thành khi
Job `helm` trong CI xanh; tài liệu có ví dụ cài agent bằng enrollment token.
