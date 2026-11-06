/**
 * Production Frontend Bundle: checkout.bundle.min.js
 * E-Commerce Checkout & Tet 2026 Voucher Campaign Module
 * (Cố tình để lộ sơ hở nghiệp vụ & Shadow API để REA bóc tách)
 */

(function (window, document) {
    'use strict';

    var API_BASE = "/api/v1";

    // SHADOW API: Endpoint nội bộ của đội Marketing chưa công bố trong Swagger
    var SHADOW_ENDPOINTS = {
        CLAIM_TEST_PROMO: "/api/v1/voucher/claim",
        DEV_VIP_CREDIT: "/api/v1/internal/grant_credit",
        BYPASS_KYC_TEST: "/api/v1/checkout/direct_confirm"
    };

    // Client-side validation: Lập trình viên chỉ disable nút bấm ở UI
    // nhưng không có khóa throttle ở Backend!
    function initVoucherClaimButton() {
        var claimBtn = document.getElementById("claim-tet-voucher-btn");
        if (!claimBtn) return;

        claimBtn.addEventListener("click", function (e) {
            e.preventDefault();
            
            // Client-side check chỉ mang tính hình thức
            claimBtn.disabled = true;
            claimBtn.innerText = "Đang xử lý...";

            var payload = {
                voucher_code: "TET2026_VIP",
                channel: "WEB_DIRECT",
                client_timestamp: Date.now()
            };

            fetch(API_BASE + "/voucher/claim", {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                    "X-User-ID": "usr_test_attacker_99"
                },
                body: JSON.stringify(payload)
            })
            .then(function (res) { return res.json(); })
            .then(function (data) {
                alert("Chúc mừng bạn đã nhận voucher " + data.claim_id);
            })
            .catch(function (err) {
                console.error("Lỗi nhận voucher:", err);
            });
        });
    }

    window.CheckoutApp = {
        init: initVoucherClaimButton,
        shadow: SHADOW_ENDPOINTS
    };

})(window, document);
