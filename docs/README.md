# AIGIS Documentation

> Status: Current navigation · Updated: 2026-11-09 · Scope: Local simulation and read-only data sources

[Project README](../README.md) là điểm bắt đầu để cài đặt và chạy AIGIS. Các tài liệu dưới đây đi sâu theo mục đích đọc.

## Chọn lộ trình đọc

| Mục đích | Tài liệu |
| :--- | :--- |
| Hiểu project nhanh | [Overview](overview.md) |
| Cài đặt và chạy | [Quick Start](../README.md#quick-start-guide) |
| Chuẩn bị thuyết trình | [Demo: chuẩn bị, thao tác, lời thoại](demo.md) |
| Hiểu cách backend hoạt động | [Architecture](architecture.md) → [Backend reliability](backend-reliability.md) |
| Kiểm chứng wargame và giới hạn | [Wargame improvements](wargame-improvements.md) |
| Kết nối nguồn PostgreSQL | [PostgreSQL read-only snapshots](postgresql.md) |
| Chỉnh giao diện | [Design system](design-system.md) và [frontend check](reports/frontend-check.md) |
| Tra cứu các đợt kiểm tra | [Report index](reports/README.md) |

## Vai trò và nguồn thông tin

### Cập nhật hiện hành

- PostgreSQL là **nguồn chỉ đọc → snapshot SQLite có giới hạn**, không phải thay database runtime hay kết nối phân tích live. Cài driver/profile và xem giới hạn tại [PostgreSQL](postgresql.md).
- Wargame có durable queue/Cancel/heartbeat, history, manifest replay v3 và temporal shadow không chặn. Chi tiết ở [Wargame improvements](wargame-improvements.md).
- Kết quả kiểm chứng gần nhất được ghi nhận trước lần cập nhật tài liệu này: 85 test, 83 đạt / 2 PostgreSQL integration skip; browser suite tổng đạt. Không diễn giải skip thành xác nhận PostgreSQL thật. Xem [Backend reliability](backend-reliability.md#commands).

- **README gốc:** giới thiệu, quick start, feature grid và API overview.
- **Overview:** bản tóm tắt tiếng Việt; không thay thế đặc tả kỹ thuật.
- **Architecture:** component, luồng dữ liệu, evidence, isolation và persistence.
- **Demo:** checklist chuẩn bị và kịch bản trình bày; đọc số liệu thực tế của từng lần chạy.
- **Backend reliability:** chi tiết triển khai, giới hạn phép đo và lệnh tái hiện.
- **Design system:** định hướng thiết kế; không phải xác nhận UI khớp mọi token.
- **Reports:** bằng chứng tại thời điểm kiểm tra, gồm finding gốc và resolution. Không dùng số test hoặc source line lịch sử như thông tin của checkout hiện tại.

Khi cần xác minh API, đối chiếu `backend/server.py`. Đặt biến môi trường `AIGIS_ENABLE_DOCS=1` trước khi khởi động server để bật OpenAPI tại `http://127.0.0.1:8000/docs` (mặc định tắt). Đường dẫn code và các lệnh trong tài liệu được hiểu từ **thư mục gốc repository**.

## Quy ước cập nhật

1. Ghi rõ **đã triển khai** và **định hướng**; kết luận phải khớp phạm vi evidence.
2. Cập nhật tài liệu chuyên trách trước, sau đó đồng bộ phần tóm tắt có liên quan.
3. `Updated` là ngày sửa tài liệu, không tự động là ngày chạy lại kiểm thử. Report phải phân biệt ngày kiểm tra với ngày lập chỉ mục.
4. Kết quả benchmark cần kèm lệnh, workload/seed nếu có, môi trường và giới hạn phép đo. Metadata thiếu phải được ghi nhận là thiếu.
5. Giữ report lịch sử; thêm resolution/link đến tài liệu hiện hành thay vì viết lại lịch sử kiểm tra.
6. Dùng relative link cho tài liệu nội bộ. Khi đổi tên/di chuyển file, cập nhật mục lục và nơi tham chiếu.

## Kiểm tra tài liệu

Từ thư mục gốc:

```powershell
python -m scratch.check_docs
npx --yes markdownlint-cli2@0.17.2
```

Checker Python kiểm tra đích file và heading anchor của các link Markdown nội bộ cùng local HTML `href`/`src` trong README và `docs/`. Không gửi request mạng; URL ngoài và URL runtime không được kiểm tra. Markdownlint chạy các quy tắc định dạng được chọn trong `.markdownlint-cli2.jsonc`, giữ tương thích với bảng, Mermaid và HTML trong README. CI chạy cả hai kiểm tra.
