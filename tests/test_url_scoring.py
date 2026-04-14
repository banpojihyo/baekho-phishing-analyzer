import unittest

from app.analyzers.url_scoring import analyze_url


class UrlScoringTests(unittest.TestCase):
    def test_static_url_analysis_does_not_probe_by_default(self):
        result = analyze_url("https://billing.example.com/invoice/receipt?payment_id=123")

        self.assertEqual(result["score"], 0)
        self.assertFalse(result["probe"]["performed"])

    def test_email_in_query_is_not_treated_as_userinfo(self):
        result = analyze_url(
            "http://192.0.2.10:13001/resp/ecmresponse.jsp?recipient=user@example.com"
        )

        self.assertNotIn("사용자정보(userinfo) 형태의 '@' 포함 URL", result["evidence"])
        self.assertIn("도메인 대신 IP 주소 사용", result["evidence"])
        rule_ids = {rule["rule_id"] for rule in result["matched_rules"]}
        self.assertIn("url.ip_host", rule_ids)

    def test_userinfo_style_url_is_still_flagged(self):
        result = analyze_url("http://paypal.com@192.0.2.10/login")

        self.assertIn("사용자정보(userinfo) 형태의 '@' 포함 URL", result["evidence"])
        self.assertIn("도메인 대신 IP 주소 사용", result["evidence"])
        rule_ids = {rule["rule_id"] for rule in result["matched_rules"]}
        self.assertIn("url.userinfo_at_sign", rule_ids)

    def test_ip_hosts_do_not_also_trigger_subdomain_depth(self):
        result = analyze_url("http://192.0.2.10/tracking")

        self.assertIn("도메인 대신 IP 주소 사용", result["evidence"])
        self.assertNotIn("서브도메인 깊이 과도", result["evidence"])

    def test_malformed_ipv6_style_url_does_not_crash(self):
        result = analyze_url("http://[not-an-ipv6]/login")

        self.assertEqual(result["severity"], "low")
        self.assertIn("URL 파싱 실패", result["evidence"][0])
        self.assertEqual(result["matched_rules"][0]["rule_id"], "url.parse_failure")

    def test_business_context_path_is_detected_when_other_url_signals_exist(self):
        result = analyze_url("http://invoice-secure-login.zip/세금계산서/verify?payment=true")

        rule_ids = {rule["rule_id"] for rule in result["matched_rules"]}
        self.assertIn("url.business_context_path", rule_ids)
        self.assertIn("결제/송금", result["detected_contexts"])

    def test_hostname_auth_cluster_increases_score_for_lure_subdomain(self):
        result = analyze_url("https://secure-login.identity-mail.example/login/confirm")

        rule_ids = {rule["rule_id"] for rule in result["matched_rules"]}
        self.assertIn("url.hostname_auth_cluster", rule_ids)
        self.assertGreaterEqual(result["score"], 20)

    def test_single_auth_keyword_in_hostname_does_not_trigger_cluster_rule(self):
        result = analyze_url("https://accounts.example.com/login")

        rule_ids = {rule["rule_id"] for rule in result["matched_rules"]}
        self.assertNotIn("url.hostname_auth_cluster", rule_ids)

    def test_transactional_terms_alone_do_not_trigger_social_engineering_rule(self):
        result = analyze_url("https://billing.example.com/invoice/receipt?payment_id=123")

        rule_ids = {rule["rule_id"] for rule in result["matched_rules"]}
        self.assertNotIn("url.social_engineering_terms", rule_ids)
        self.assertEqual(result["score"], 0)

    def test_generic_tracking_path_is_not_treated_as_shipping_context(self):
        result = analyze_url("https://news.example.com/tracking/click?utm_source=newsletter")

        self.assertNotIn("배송/주문", result["detected_contexts"])
        rule_ids = {rule["rule_id"] for rule in result["matched_rules"]}
        self.assertNotIn("url.business_context_path", rule_ids)

    def test_probe_boosts_score_for_client_redirect_and_cloaking(self):
        probe_result = {
            "performed": True,
            "browser": {
                "meta_robots": "noindex, nofollow",
                "title": "",
                "client_redirect_url": "https://redirect.evil.example/landing",
                "client_redirect_kind": "javascript",
                "redirect_hop_count": 0,
            },
            "crawler": {
                "meta_robots": "index, follow",
                "title": "카리나 일루미나티 떡밥 정리",
            },
        }

        result = analyze_url(
            "https://normal.example/2025-%EC%B9%B4%EB%A6%AC%EB%82%98/ce7a75",
            probe_result=probe_result,
        )

        rule_ids = {rule["rule_id"] for rule in result["matched_rules"]}
        self.assertIn("url.client_side_redirect", rule_ids)
        self.assertIn("url.external_domain_redirect", rule_ids)
        self.assertIn("url.search_result_cloaking", rule_ids)
        self.assertGreaterEqual(result["score"], 80)

    def test_probe_detects_multi_hop_redirect(self):
        probe_result = {
            "performed": True,
            "browser": {
                "meta_robots": "",
                "title": "정상처럼 보이는 페이지",
                "client_redirect_url": None,
                "client_redirect_kind": None,
                "redirect_hop_count": 3,
            },
            "crawler": {},
        }

        result = analyze_url("https://normal.example/path", probe_result=probe_result)

        rule_ids = {rule["rule_id"] for rule in result["matched_rules"]}
        self.assertIn("url.multi_hop_redirect", rule_ids)
        self.assertGreaterEqual(result["score"], 16)

    def test_probe_detects_form_iframe_and_download_signals(self):
        probe_result = {
            "performed": True,
            "browser": {
                "meta_robots": "",
                "title": "계정 인증",
                "client_redirect_url": "https://redirect.evil.test/landing",
                "client_redirect_kind": "javascript",
                "redirect_hop_count": 0,
                "offdomain_form_action_count": 1,
                "password_input_count": 1,
                "hidden_iframe_count": 1,
                "asset_reference_count": 6,
                "external_asset_count": 5,
                "anchor_count": 5,
                "external_anchor_count": 5,
                "suspicious_js_function_count": 3,
                "suspicious_js_functions": ["eval x1", "document.write x1", "unescape x1"],
                "suspicious_download_link_count": 1,
            },
            "crawler": {},
        }

        result = analyze_url("https://secure.example.com/login", probe_result=probe_result)

        rule_ids = {rule["rule_id"] for rule in result["matched_rules"]}
        self.assertIn("url.offdomain_form_action", rule_ids)
        self.assertIn("url.hidden_iframe", rule_ids)
        self.assertIn("url.suspicious_js_functions", rule_ids)
        self.assertIn("url.external_asset_ratio_high", rule_ids)
        self.assertIn("url.external_anchor_ratio_high", rule_ids)
        self.assertIn("url.password_form_present", rule_ids)
        self.assertIn("url.suspicious_download_link", rule_ids)
        self.assertGreaterEqual(result["score"], 90)

    def test_password_field_alone_does_not_raise_probe_rule(self):
        probe_result = {
            "performed": True,
            "browser": {
                "meta_robots": "",
                "title": "정상 로그인",
                "client_redirect_url": None,
                "client_redirect_kind": None,
                "redirect_hop_count": 0,
                "offdomain_form_action_count": 0,
                "password_input_count": 1,
                "hidden_iframe_count": 0,
                "asset_reference_count": 2,
                "external_asset_count": 0,
                "anchor_count": 1,
                "external_anchor_count": 0,
                "suspicious_js_function_count": 0,
                "suspicious_js_functions": [],
                "suspicious_download_link_count": 0,
            },
            "crawler": {},
        }

        result = analyze_url("https://accounts.example.com/login", probe_result=probe_result)

        rule_ids = {rule["rule_id"] for rule in result["matched_rules"]}
        self.assertNotIn("url.password_form_present", rule_ids)
        self.assertLess(result["score"], 20)


if __name__ == "__main__":
    unittest.main()
