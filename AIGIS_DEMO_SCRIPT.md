# AIGIS — Kịch Bản Demo 3 Phút
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
  > *"Blue Team đề xuất cách sửa gốc bằng ràng buộc duy nhất ở cơ sở dữ liệu, kèm mẫu cho các nền tảng phổ biến. Khi bật bản vá trên hệ thống mẫu, chạy lại đúng đợt tấn công cũ: chỉ một yêu cầu hợp lệ được duyệt. Bài regression cho thấy khách hàng bình thường không bị chặn nhầm."*

---

### CẢNH 3 (2:15 – 3:00) — BÁO CÁO & HƯỚNG PHÁT TRIỂN

* **Thao tác:**
  1. Arbiter mở **Financial Exposure Dossier**:
     * Thất thoát trước vá / sau vá và số tiền giữ lại được **trong lần chạy này**.
     * Điểm an toàn heuristic trước → sau (điểm demo, không phải chứng nhận).
     * Bảng tuân thủ: các mục ở trạng thái `NOT_ASSESSED` / `VERIFIED_IN_MOCK_TARGET`.
  2. Hiển thị nội dung **Pull Request mô phỏng** (tiêu đề, branch, diff). AIGIS không gọi GitHub API.
* **Lời kết:**
  > *"Trong 3 phút, AIGIS đi hết vòng lặp: tìm endpoint ẩn, tái hiện race condition, đo thất thoát, đề xuất bản vá và chứng minh bản vá có hiệu quả — trên hệ thống mẫu. Bước tiếp theo của chúng tôi là gửi request HTTP đồng thời thật vào một service mục tiêu riêng và mở rộng sang các kịch bản gian lận ngân hàng như thử thẻ hay tài khoản mule. Xin cảm ơn!"*

---

## Câu hỏi thường gặp — chuẩn bị trả lời

| Câu hỏi | Trả lời trung thực |
| :--- | :--- |
| Có chạy được trên hệ thống thật không? | Chưa. Hiện chỉ chạy trên mock target trong tiến trình. |
| Có dùng HTTP/2 single-packet thật không? | Chưa. Hiện là coroutine đồng thời, không có network I/O. |
| Bản vá có được tự động deploy không? | Không. Mã vá là mẫu để review; trên mock chỉ bật cờ khóa. |
| PR có được tạo trên GitHub không? | Không, là nội dung PR mô phỏng. |
| Độ chính xác của bộ phân loại? | Có báo cáo precision/recall/FPR, nhưng trên dữ liệu giả lập do chính project sinh ra — chỉ là kiểm tra hợp lý, không phải đánh giá độc lập. |
| Tỷ lệ tấn công trong dữ liệu có thực tế không? | Không. Dữ liệu giả lập có ~31% dòng tấn công, cao hơn nhiều so với thực tế. |
