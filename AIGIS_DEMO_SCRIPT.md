# 🎬 AIGIS — Kịch Bản Trình Diễn Demo 3 Phút (Hackathon Winning Pitch)
**AIGIS: Adversarial Intelligence for Generative Immunity & Security**

> [!IMPORTANT]
> **Định nghĩa Tên gọi Chuẩn xác (Exact Acronym):**
> $$\mathbf{A} \cdot \mathbf{I} \cdot \mathbf{G} \cdot \mathbf{I} \cdot \mathbf{S}$$
> * **A** — **A**dversarial *(Tác chiến Đối kháng / Red Teaming)*
> * **I** — **I**ntelligence for *(Hệ điều phối Đa Agent Thông minh)*
> * **G** — **G**enerative *(Tự sinh Đòn Tấn công & Tự sinh Bản vá)*
> * **I** — **I**mmunity & *(Cơ chế Tự sinh Miễn dịch Số / Self-Healing)*
> * **S** — **S**ecurity *(Bảo vệ Toàn diện Logic Nghiệp vụ FinTech)*
>
> **Mục tiêu của 180 giây này:** Không nói lý thuyết bảo mật chung chung! Bạn phải đưa Ban Giám Khảo vào một **trận đấu trí nghẹt thở (Wargame) giữa 2 con AI** với **4 khoảnh khắc "Wow" liên tiếp**:
> 1. **Wow #1 (Dịch ngược REA):** Bóc tách file client JavaScript bundle chỉ trong 5 giây, tìm thấy Shadow API và lỗi logic mà các tool DAST/SAST truyền thống hoàn toàn "mù".
> 2. **Wow #2 (Red Team Single-Packet Attack):** Hacker AI (Cerebrus) tự viết code Python nén 15 request vào 1 gói tin TCP HTTP/2, chiếm đoạt \$7,500 tiền voucher ngay trong Sandbox.
> 3. **Wow #3 (Blue Team tự vá lỗi chuẩn CRS):** Defender AI (Aegis) tự viết middleware gài Redis Distributed Lock, chặn đứng đợt tấn công cũ và kiểm tra không làm phiền khách thật.
> 4. **Wow #4 (Lượng hóa giá trị):** Xuất bản Financial Exposure Dossier cứu được \$150,000 ngân sách chiến dịch kèm nút 1-Click đẩy Pull Request lên GitHub.

---

## ⏱️ Timeline Chi Tiết Từng Giây

```mermaid
timeline
    title 180 Giây Thuyết Trình AIGIS
    0:00 - 0:30 : Mở đầu & Nỗi đau : Hacker không hack server, hacker hack Logic Nghiệp Vụ
    0:30 - 1:15 : Cảnh 1 (REA & Red Team) : REA mổ xẻ code JS -> Cerebrus bắn 15 request Single-Packet -> Thất thoát $7,500
    1:15 - 2:15 : Cảnh 2 (Blue Team Tự Vá) : Aegis phân tích root-cause -> Tự sinh Redis Lock -> Chặn đứng 14/15 request
    2:15 - 3:00 : Cảnh 3 (Giá trị & 1-Click PR) : Financial Exposure Dossier -> Cứu $150,000/ngày -> 1-Click GitHub PR
```

---

### 🎙️ PHẦN MỞ ĐẦU (0:00 – 0:30) — CÂU HOOK GÂY SỐC

* **Thao tác màn hình:** Màn hình chính mở giao diện **AIGIS: Dual-Agent Wargame** chia làm 2 nửa đối xứng: bên trái màu Đỏ rực (`RED TEAM - ATTACK`), bên phải màu Xanh thẫm (`BLUE TEAM - DEFENSE`).
* **Lời thoại người thuyết trình:**
  > *"Kính thưa Ban Giám khảo, trong thế giới FinTech và Thương mại Điện tử, các vụ thiệt hại hàng triệu đô la gần đây không hề đến từ việc server bị hack hay rò rỉ mật khẩu. Kẻ gian hack **Logic Nghiệp vụ (Business Logic)**!*
  > 
  > *Chúng sử dụng kỹ thuật nén gói tin để gửi hàng chục request rút tiền trong cùng 1 mili-giây trước khi cơ sở dữ liệu kịp trừ tiền, hoặc bóc tách mã nguồn client để tìm các endpoint ẩn nhằm rút sạch ngân sách khuyến mãi. Các công cụ quét bảo mật thông thường hoàn toàn 'mù' trước lỗi logic này.*
  > 
  > *Hôm nay, chúng tôi mang tới **AIGIS — Adversarial Intelligence for Generative Immunity & Security** — Đấu trường đối kháng đầu tiên nơi Hacker AI tự tìm lỗ hổng bòn rút tiền, và Defender AI tự sinh rào chắn vá lỗi trước khi tính năng kịp lên Production!"*

---

### 🎬 CẢNH 1 (0:30 – 1:15) — REA MỔ XẺ & RED TEAM RA ĐÒN (WOW #1 & #2)

* **Thao tác màn hình:**
  1. Bạn kéo thả 2 file vào đấu trường:
     * File API Swagger: `Voucher_Campaign_v1.json`
     * File Client Bundle: `checkout.min.js`
  2. Bấm nút: **`[⚔️ BẮT ĐẦU WARGAME]`**.
  3. Cửa sổ bên trái (Red Team) chạy hiệu ứng bóc tách:
     * Tool REA bóc tách file `checkout.min.js`, bôi đỏ hàm `onClaimVoucher()`: *"Phát hiện client không khóa nút bấm và backend thiếu Idempotency Key"*.
  4. Agent **Cerebrus (Red Team)** lập tức tự động sinh ra đoạn script Python:
     ```python
     # Cerebrus HTTP/2 Single-Packet Fuzzer: Bắn 15 requests trong 1 gói tin TCP
     async with httpx.AsyncClient(http2=True) as client:
         tasks = [client.post("/api/v1/voucher/claim", json={"code": "TET2026"}) for _ in range(15)]
         await asyncio.gather(*tasks)
     ```
  5. Cửa sổ **Sandbox Execution** nhảy số:
     * `HTTP 200 OK x 15 requests!`
     * `Tài khoản test chiếm đoạt 15 vouchers trị giá $7,500 từ ngân sách!`
* **Lời thoại người thuyết trình:**
  > *"Chỉ mất 5 giây! Công cụ REA độc quyền của AIGIS đã bóc trần mã client và phát hiện sơ hở. Không cần con người can thiệp, Red Team AI tự viết một con Bot đua lệnh, nén 15 request đồng thời vào 1 gói tin TCP duy nhất để bắn vào Sandbox. Kết quả: một tài khoản vừa ẵm trọn \$7,500 tiền voucher khuyến mãi. Nếu tính năng này lên Production tối nay, công ty sẽ mất trắng hàng trăm ngàn đô!"*

---

### 🎬 CẢNH 2 (1:15 – 2:15) — BLUE TEAM TỰ ĐỘNG PHẢN CÔNG & VÁ LỖI (WOW #3)

* **Thao tác màn hình:**
  1. Cột bên phải (Blue Team - Màu Xanh) lập tức bừng sáng:
     * Agent **Aegis** phân tích nguyên nhân gốc (Root-cause Analysis): *"Lỗ hổng: Concurrency Race Condition. Giải pháp: Idempotent Lock via Redis."*
  2. Màn hình hiển thị đoạn mã middleware do Blue Team tự động sinh:
     ```python
     @app.middleware("http")
     async def idempotency_guard(request: Request, call_next):
         lock_key = f"lock:voucher:{request.user_id}"
         if not await redis.set(lock_key, "1", nx=True, ex=5):
             return JSONResponse(status_code=429, content={"error": "Too Many Requests"})
         return await call_next(request)
     ```
  3. Blue Team tự động nạp middleware vào Sandbox và bấm **`[Re-test Exploit]`**:
     * 1 request đầu tiên: `200 OK` (Voucher hợp lệ).
     * 14 request còn lại: `429 Too Many Requests (Blocked by Aegis Guard)`.
  4. Blue Team chạy thêm bài kiểm tra **Zero-Regression**:
     * Giả lập 100 khách hàng bình thường mua sắm: Tỷ lệ duyệt 100%, độ trễ chỉ tăng thêm $1.8\text{ms}$.
* **Lời thoại người thuyết trình:**
  > *"Ngay khi lỗ hổng bị lộ, Blue Team AI nhảy vào cuộc! Với cơ chế Self-Healing độc quyền, nó **tự động viết code vá lỗi**. Một lớp khóa phân tán Redis được gài tự động vào hệ thống. Blue Team bắn lại chính đợt tấn công vừa rồi: 14 request gian lận bị chặn đứng ngay lập tức! Và quan trọng nhất: khách hàng bình thường không hề bị ảnh hưởng."*

---

### 🎬 CẢNH 3 (2:15 – 3:00) — FINANCIAL DOSSIER & 1-CLICK GITHUB PULL REQUEST (WOW #4)

* **Thao tác màn hình:**
  1. Agent **Arbiter** bung ra báo cáo tổng kết giữa màn hình:
     * **Bản Đánh Giá Rủi Ro Tài Chính (Financial Exposure Dossier):**
       * `Điểm An Toàn Logic: Tăng từ 28/100 -> 99/100 (SECURE)`.
       * `Thiệt hại tiềm tàng đã triệt tiêu: $150,000 / ngày sự kiện`.
       * `Bằng chứng khai thác: Đính kèm video log mô phỏng Sandbox`.
  2. Bạn bấm nút lớn màu xanh lá: **`[⚡ 1-Click Create GitHub Pull Request]`**.
  3. Màn hình hiện popup thông báo: *"PR #142 đã được tạo trên kho mã nguồn với đầy đủ unit test và đoạn code middleware."*
* **Lời thoại kết thúc của người thuyết trình:**
  > *"Đây là kết quả của AIGIS: Từ một file code chưa ra mắt, chúng ta phát hiện lỗ hổng logic, mô phỏng thiệt hại tài chính thực tế (\$150,000), tự sinh bản vá và tạo luôn Pull Request lên GitHub — tất cả diễn ra trong chưa đầy 3 phút!*
  > 
  > *Đừng đợi kẻ gian ngoài đời dạy cho doanh nghiệp của bạn một bài học kinh doanh đắt giá. Hãy để **AIGIS** tấn công và bảo vệ bạn trước! Xin cảm ơn Ban Giám khảo!"*
