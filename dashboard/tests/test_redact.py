from ts_dashboard.redact import REDACTED, redact


def test_sensitive_keys_are_replaced_at_any_depth():
    data = {"rule": "9500001", "Authorization": "Bearer abc", "headers": {"Cookie": "sid=1", "host": "x"},
            "items": [{"api_key": "k"}, {"password": "p", "user": "bob"}], "db_passwd": "p2", "csrf-token": "t"}
    out = redact(data)
    assert out["rule"] == "9500001" and out["headers"]["host"] == "x" and out["items"][1]["user"] == "bob"
    assert out["Authorization"] == out["headers"]["Cookie"] == out["items"][0]["api_key"] == REDACTED
    assert out["items"][1]["password"] == out["db_passwd"] == out["csrf-token"] == REDACTED
    assert "Bearer" not in str(out) and "sid=1" not in str(out)


def test_credentials_inside_urls_are_masked():
    out = redact({"link": "see http://admin:hunter2@evil.example/x and https://ok.example/y"})
    assert "hunter2" not in out["link"] and "admin" not in out["link"]
    assert "http://[redacted]@evil.example/x" in out["link"] and "https://ok.example/y" in out["link"]


def test_input_is_not_modified_and_plain_values_pass_through():
    data = {"n": 1, "ok": True, "none": None, "list": [1, "a"], "password": "p"}
    out = redact(data)
    assert data["password"] == "p" and out["n"] == 1 and out["ok"] is True and out["none"] is None and out["list"] == [1, "a"]


def test_absurdly_deep_data_is_cut_off_not_crashed():
    data: dict = {}
    node = data
    for _ in range(50):
        node["x"] = {}
        node = node["x"]
    assert "[truncated]" in str(redact(data))
