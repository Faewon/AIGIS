# Review & Check History

> Status: Historical report index · Updated: 2026-11-08

[Documentation index](../README.md) · [Current architecture](../architecture.md) · [Backend reliability](../backend-reliability.md)

Các report dưới đây giữ kết quả của từng đợt kiểm tra. Test count, source line, cấu hình đăng nhập và coverage limit có thể khác giữa các snapshot. Resolution được ghi riêng; **không có ngày kiểm tra lại tổng thể mới** chỉ vì tài liệu được sắp xếp lại.

| Report | Trạng thái được ghi nhận | Cách tái hiện từ repository root |
| :--- | :--- | :--- |
| [Project check — 2026-11-07](project-check-2026-11-07.md) | Findings gốc đã xử lý; mô tả access/CSP thuộc các giai đoạn cũ | `python -m scratch.check_project` |
| [Project review — 2026-11-08](review-2026-11-08.md) | 5 findings đã xử lý | `python -m scratch.review_confirmations` |
| [Follow-up review — 2026-11-08](followup-review-2026-11-08.md) | 4 findings đã xử lý | `python -m scratch.check_additional_findings` |
| [Audit fixes](audit-fixes.md) | Bản ghi thay đổi API, dashboard và telemetry | `python -m unittest discover -s tests -v` |
| [Frontend check](frontend-check.md) | Browser smoke check; ngày chạy gốc không được ghi lại | `python -m scratch.check_browser` |

## Trạng thái hiện hành tra cứu ở đâu?

- **Dashboard:** không yêu cầu username/password; tự gửi API token. Xem [README](../../README.md#launching-the-platform).
- **Evidence, cache, matched round, seed/replay:** xem [architecture](../architecture.md#6-evidence-isolation-và-replay).
- **Performance và stress evaluation:** xem [backend reliability](../backend-reliability.md), gồm giới hạn của số liệu lịch sử và lệnh chạy lại.
- **Kết quả mới:** ghi ngày, command, môi trường và phạm vi vào report mới hoặc phần verification có ngày rõ ràng. Chạy lệnh tái hiện không đảm bảo số test/timing giống snapshot gốc.
