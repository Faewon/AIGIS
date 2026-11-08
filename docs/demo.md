# AIGIS — Kịch Bản Demo 3 Phút
> Status: Current · Updated: 2026-11-09 · Scope: Local simulation with optional read-only data snapshots
>
> [Mục lục](README.md) · [Kiến trúc](architecture.md)

**AIGIS: Adversarial Intelligence for Generative Immunity & Security**

> [!IMPORTANT]
> **Nói rõ ngay từ đầu:** đây là **bản mô phỏng (proof-of-concept)** chạy trên một mock target trong cùng tiến trình với dữ liệu giả lập. Các con số trên màn hình được **đo trên mock target**, không phải số liệu của hệ thống thật. Trung thực về phạm vi giúp tránh bị bắt bẻ và tăng độ tin cậy với ban giám khảo / chuyên gia.
>
> **4 khoảnh khắc chính:**
> 1. **Tìm endpoint ẩn:** quét client bundle, tìm Shadow API không có trong tài liệu.
> 2. **Red Team tái hiện race condition:** 15 lời gọi đồng thời vào mock target, nhiều lần nhận voucher trái phép.
> 3. **Blue Team vá & kiểm thử lại:** bật khóa trên mock target, retest chỉ còn 1 lần nhận hợp lệ; regression đo tỷ lệ chặn nhầm và độ trễ.
> 4. **Lượng hóa:** báo cáo thất thoát trước/sau vá và nội dung PR (mô phỏng).

---

## Chuẩn bị trước demo

1. Từ thư mục gốc, cài dependencies theo [Quick Start](../README.md#quick-start-guide), chạy `python run_server.py` và mở `http://127.0.0.1:8000`.
2. Dùng offline heuristic provider nếu không cần trình diễn LLM; xác nhận cấu hình agent trước khi bấm chạy. Dashboard tự gửi API token, không yêu cầu đăng nhập.
3. Nếu trình diễn Data/Sentinel/Investigator, chuẩn bị telemetry bằng UI: generate dataset rồi sync database. Wargame trên mock store không đòi hỏi dataset một triệu dòng.
4. Chọn cùng cấu hình cho các lần tập: ví dụ 1 round, 15 burst streams. Khi chạy qua API, có thể gửi `seed: 42` vào `/api/v1/wargame/run_full`; không giả định UI có ô seed. Seed không cố định latency hoặc ID.
5. Về màn hình Wargame, kiểm tra target đã reset. UI cô lập trạng thái stage theo tab; API legacy thiếu header session vẫn dùng trạng thái chung. Tập một lượt để xác nhận nhãn nút và kết quả trên phiên bản UI đang dùng.
6. Khi trình bày, đọc số liệu của lần chạy thực tế. Nếu lỗi hoặc thiếu dữ liệu, hiển thị trạng thái đó và chạy lại sau khi kiểm tra cấu hình.

### Phần mở rộng tùy chọn (ngoài demo 3 phút)

- **Queue benchmark / Cancel job:** minh họa nhận job, polling, hủy và lịch sử. Chỉ job `COMPLETED` có kết quả tương thích mới được trình bày là đã kiểm chứng trong mock. Hủy, timeout hay gián đoạn không phải pass.
- **History / Replay:** replay training dùng manifest v3 đã lưu và kiểm tra source version; 409 khi code không tương thích là hành vi mong đợi, không cố bỏ kiểm tra để demo chạy.
- **PostgreSQL:** chuẩn bị trước driver/profile chỉ đọc theo [hướng dẫn](postgresql.md). Test connection → chọn schema/table → Load / refresh snapshot. Chỉ rõ capture time, truncation và việc SQL console phân tích SQLite snapshot, không phải live PostgreSQL. Không chiếu password/DSN lên màn hình. Không có server test thì bỏ phần này, không giả lập kết quả kết nối thành công.
- **Temporal shadow:** nhấn Inspect temporal shadow signals; giải thích đây là tín hiệu thời gian từ mẫu tối đa 2.000 event, không chặn giao dịch hay chứng minh có gian lận. Chỉ số trên snapshot không đại diện toàn bộ nguồn remote.

## Timeline

```mermaid
timeline
    title 180 giây demo AIGIS
    0:00 - 0:30 : Mở đầu : Lỗi logic nghiệp vụ - bản mô phỏng
    0:30 - 1:15 : Cảnh 1 (Red Team) : Tìm Shadow API -> 15 lời gọi đồng thời -> đo thất thoát
    1:15 - 2:15 : Cảnh 2 (Blue Team) : Mã vá mẫu -> bật khóa -> retest + regression
    2:15 - 3:00 : Cảnh 3 (Báo cáo) : Financial Exposure Dossier -> PR mô phỏng -> hướng phát triển
```

---

### PHẦN MỞ ĐẦU (0:00 – 0:30)

* **Màn hình:** dashboard AIGIS ở chế độ Wargame.
* **Lời thoại:**
  > *"Trong FinTech và TMĐT, nhiều thiệt hại không đến từ việc server bị hack mà từ **lỗi logic nghiệp vụ**: kẻ gian gửi hàng chục request nhận voucher cùng lúc, trước khi hệ thống kịp ghi nhận lần nhận đầu tiên. Loại lỗi phụ thuộc thời gian này rất khó bắt bằng công cụ quét tĩnh/động thông thường.*
  >
  > *AIGIS là một **bản mô phỏng** đấu trường: Red Team AI tấn công một hệ thống mẫu, Blue Team AI đề xuất bản vá và kiểm thử lại — tất cả được quy đổi thành số tiền."*

---

### CẢNH 1 (0:30 – 1:15) — TÌM ENDPOINT ẨN & RED TEAM

* **Thao tác:**
  1. Bấm **Start Wargame**.
  2. REA quét `checkout_bundle.js` (regex) và liệt kê endpoint không có trong tài liệu API.
  3. Cerebrus chạy 15 lời gọi đồng thời vào mock store. Đoạn code hiển thị tương đương:
     ```python
     # Mô phỏng: 15 coroutine đồng thời trên mock store (không gửi HTTP)
     results = await asyncio.gather(*[
         mock_store.claim_voucher(user_id=attacker, voucher_code="TET2026_VIP", amount=500.0)
         for _ in range(15)
     ])
     ```
  4. Sandbox hiển thị số lần nhận thành công và số tiền thất thoát **đo được**.
* **Lời thoại:**
  > *"Mock target này mô phỏng một API nhận voucher thiếu khóa nguyên tử. Khi 15 yêu cầu đến cùng lúc, hệ thống duyệt nhiều lần cho cùng một tài khoản. Đây là con số đo được trên hệ thống mẫu, quy ra tiền thất thoát."*

---

### CẢNH 2 (1:15 – 2:15) — BLUE TEAM VÁ & KIỂM THỬ LẠI

* **Thao tác:**
  1. Aegis hiển thị nguyên nhân gốc: thiếu ràng buộc nguyên tử khi kiểm tra và ghi nhận lượt nhận.
  2. Hiển thị **mã vá mẫu**. Cách sửa gốc là ở tầng cơ sở dữ liệu:
     ```sql
     ALTER TABLE voucher_claims ADD CONSTRAINT uq_voucher_claim_user UNIQUE (user_id, voucher_code);
     INSERT INTO voucher_claims (user_id, voucher_code, amount, claimed_at)
     VALUES ($1, $2, $3, now()) ON CONFLICT (user_id, voucher_code) DO NOTHING;
     ```
     Kèm mẫu khóa ở tầng ứng dụng/WAF (FastAPI, Spring, Gin, NGINX, Cloudflare, AWS WAF). Mã mẫu **chỉ để review**, AIGIS không thực thi.
  3. Bật bản vá trên mock target và bấm **Re-test**: chỉ **1** request được duyệt, các request trùng bị chặn (`429`).
  4. Regression check: chạy cùng một nhóm người dùng hợp lệ khi tắt/bật bản vá, hiển thị **tỷ lệ chặn nhầm** và **độ trễ tăng thêm** đo được.
* **Lời thoại:**
  > *"Blue Team đề xuất cách sửa gốc bằng ràng buộc duy nhất ở cơ sở dữ liệu, kèm mẫu cho các nền tảng phổ biến. Khi bật bản vá trên hệ thống mẫu, chạy lại đúng đợt tấn công cũ và kiểm tra có đúng một yêu cầu hợp lệ được duyệt hay không. Dashboard hiển thị tỷ lệ chặn nhầm và độ trễ tăng thêm đo được trong lần chạy này."*

---

### CẢNH 3 (2:15 – 3:00) — BÁO CÁO & HƯỚNG PHÁT TRIỂN

* **Thao tác:**
  1. Arbiter mở **Financial Exposure Dossier**:
      * Thất thoát trước vá / sau vá và số tiền giữ lại được **trong lần chạy này**. Với voucher, không tính lượt nhận hợp lệ đầu tiên vào thất thoát: nếu 15 lượt thành công, $500/lượt thì tổng được duyệt $7,500 nhưng thất thoát trùng là $7,000.
     * Điểm an toàn heuristic trước → sau (điểm demo, không phải chứng nhận).
     * Bảng tuân thủ: các mục ở trạng thái `NOT_ASSESSED` / `VERIFIED_IN_MOCK_TARGET`.
  2. Hiển thị nội dung **Pull Request mô phỏng** (tiêu đề, branch, diff). AIGIS không gọi GitHub API.
* **Lời kết:**
  > *"Trong 3 phút, AIGIS đi hết vòng lặp: tìm endpoint ẩn, tái hiện race condition, đo thất thoát, đề xuất bản vá và chứng minh bản vá có hiệu quả — trên hệ thống mẫu. Bước tiếp theo của chúng tôi là gửi request HTTP đồng thời thật vào một service mục tiêu riêng và mở rộng sang các kịch bản gian lận ngân hàng như thử thẻ hay tài khoản mule. Xin cảm ơn!"*

---

## Câu hỏi thường gặp — chuẩn bị trả lời

| Câu hỏi | Trả lời trung thực |
| :--- | :--- |
| Có chạy được trên hệ thống thật không? | Tấn công/vá/retest chỉ ở mock. Có thể đọc nguồn PostgreSQL được cấp phép thành snapshot local; không tấn công hay deploy lên nguồn đó. |
| PostgreSQL có live không? | Không. Refresh thủ công, giới hạn 100.000 dòng / 50 MiB dữ liệu chuyển đổi; phân tích SQLite snapshot. |
| Có dùng HTTP/2 single-packet thật không? | Chưa. Hiện là coroutine đồng thời, không có network I/O. |
| Bản vá có được tự động deploy không? | Không. Mã vá là mẫu để review; trên mock chỉ bật cờ khóa. |
| PR có được tạo trên GitHub không? | Không, là nội dung PR mô phỏng. |
| Độ chính xác của bộ phân loại? | Có báo cáo precision/recall/FPR, nhưng trên dữ liệu giả lập do chính project sinh ra — chỉ là kiểm tra hợp lý, không phải đánh giá độc lập. |
| Tỷ lệ tấn công trong dữ liệu có thực tế không? | Không. Dữ liệu giả lập có ~31% dòng tấn công, cao hơn nhiều so với thực tế. |
