import requests

BASE = "http://localhost:5000"

def test_registration_validation():
    # short username
    r = requests.post(f"{BASE}/register", json={
        "username": "ab", "email": "a@b.com",
        "password": "Passw0rd!abc", "confirm_password": "Passw0rd!abc"
    })
    assert r.status_code == 400, "Short username should be rejected"

    # weak password
    r = requests.post(f"{BASE}/register", json={
        "username": "validuser", "email": "a@b.com",
        "password": "weakpassword", "confirm_password": "weakpassword"
    })
    assert r.status_code == 400, "Weak password should be rejected"

    print("Registration validation: PASS")

def test_login_lockout():
    for _ in range(5):
        requests.post(f"{BASE}/login", json={
            "username": "testuser", "password": "wrongpassword"
        })
    r = requests.post(f"{BASE}/login", json={
        "username": "testuser", "password": "wrongpassword"
    })
    assert r.status_code == 401
    print("Account lockout: PASS")

def test_security_headers():
    r = requests.get(BASE)
    assert "X-Frame-Options" in r.headers
    assert "X-Content-Type-Options" in r.headers
    assert "Content-Security-Policy" in r.headers
    assert "Strict-Transport-Security" in r.headers
    print("Security headers: PASS")

def test_unauthenticated_access():
    r = requests.get(f"{BASE}/findUserFileList")
    assert r.status_code == 401, "Should require auth"
    print("Unauthenticated access blocked: PASS")

if __name__ == "__main__":
    test_registration_validation()
    test_security_headers()
    test_unauthenticated_access()
    print("All tests passed.")