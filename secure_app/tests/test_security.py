import os
import sys
import unittest
from io import StringIO
from colorama import Fore, Style, init as color_init

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

# Import the Flask app and the core DB helpers
from __init__ import app
import app as routes  
from models import (
    ensure_schema_and_migrations,
    db_query,
    db_exec,
    create_user,
    _hash_password,
)

# Added color to look good in terminal 
color_init(autoreset=True)


class SecureShopTests(unittest.TestCase):
    """Security + functionality test suite for SecureShop"""
    @classmethod
    def setUpClass(cls):
        ensure_schema_and_migrations()
        app.config.update(
            TESTING=True,
            WTF_CSRF_ENABLED=False,  # app uses custom CSRF
            SECRET_KEY="testing-key",
        )
        cls.client = app.test_client()

    def tearDown(self):
        db_exec("DELETE FROM users;")
        db_exec("DELETE FROM products;")
        db_exec("DELETE FROM orders;")
        db_exec("DELETE FROM reviews;")
        # Do not delete audit_events or suspicious tables here; they help debug when tests fail

    # Helpers
    def _csrf(self):
        with self.client.session_transaction() as sess:
            sess["_csrf"] = "bypass"
            return "bypass"

    def safe_login(self, username, password):
        token = self._csrf()
        return self.client.post(
            "/login",
            data={"username": username, "password": password, "csrf_token": token},
            follow_redirects=True,
        )

    # Tests

    def test_01_user_registration_and_login(self):
        pw_hash = _hash_password("Test12345!")
        create_user("testuser", "t@example.com", pw_hash)

        user = db_query("SELECT * FROM users WHERE username=?", ("testuser",), one=True)
        self.assertIsNotNone(user, "User not created in DB")

        # Validate Argon2 verification to assert hashing is correct
        from argon2 import PasswordHasher
        ph = PasswordHasher()
        verified = False
        try:
            verified = ph.verify(user["password_hash"], "Test12345!")
        except Exception:
            verified = False

        self.assertTrue(verified, "Password verification failed")

        # Simulate an authenticated session
        with self.client.session_transaction() as sess:
            sess["_user_id"] = str(user["id"])

        # A simple GET to home should render the site chrome tested here
        home = self.client.get("/", follow_redirects=True)
        self.assertIn(b"Secure Shop", home.data)

    def test_02_seller_add_product(self):
        pw_hash = _hash_password("Seller123!")
        create_user("seller", "seller@example.com", pw_hash)
        user = db_query("SELECT id FROM users WHERE username=?", ("seller",), one=True)
        self.assertIsNotNone(user, "Seller not created")

    
        db_exec("UPDATE users SET role='seller' WHERE id=?", (user["id"],))
        self.safe_login("seller", "Seller123!")

        # POST to seller add product route (image omitted) with CSRF
        token = self._csrf()
        resp = self.client.post(
            "/seller/add",
            data={
                "name": "Test Product",
                "description": "Functional test product",
                "price": "9.99",
                "stock": "5",
                "csrf_token": token,
            },
            follow_redirects=True,
        )

        self.assertNotEqual(resp.status_code, 404, "Seller add route missing")
        # tolerate multiple possible success messages
        self.assertTrue(
            b"Product" in resp.data or b"added" in resp.data or b"created" in resp.data,
            "Product creation confirmation missing",
        )

    def test_03_admin_dashboard_access(self):
        """Checks if admin dashboard can be accessed"""
        pw_hash = _hash_password("Admin123!")
        create_user("admin", "admin@example.com", pw_hash)
        uid_row = db_query("SELECT id FROM users WHERE username=?", ("admin",), one=True)
        self.assertIsNotNone(uid_row, "Admin user not created")
        db_exec("UPDATE users SET role='admin' WHERE id=?", (uid_row["id"],))

        # Simulate admin session
        self.safe_login("admin", "Admin123!")

        resp = self.client.get("/admin", follow_redirects=True)
        self.assertNotEqual(resp.status_code, 404)
        self.assertTrue(
            b"dashboard" in resp.data.lower() or b"admin" in resp.data.lower(),
            "Admin dashboard not visible",
        )

    def test_04_sql_injection_protection(self):
        # Inject typical DROP TABLE sentinel into search param
        inj = "'; DROP TABLE users; --"
        self.client.get(f"/search?q={inj}", follow_redirects=True)

        # Confirm users table still exists
        table = db_query(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='users';", one=True
        )
        self.assertIsNotNone(table, "Users table dropped due to SQL injection")

    def test_05_security_headers_present(self):
        """Verifies presence of security headers on the homepage"""
        r = self.client.get("/")
        self.assertIn("Content-Security-Policy", r.headers)
        self.assertIn("X-Frame-Options", r.headers)
        self.assertIn("Referrer-Policy", r.headers)

    def test_06_rate_limiting_on_login(self):
        """Checks login rate limiting enforcement"""
        token = self._csrf()
        for _ in range(12):
            self.client.post("/login", data={"username": "fake", "password": "x", "csrf_token": token})
        resp = self.client.post("/login", data={"username": "fake", "password": "x", "csrf_token": token})
        self.assertTrue(
            b"Too many requests" in resp.data
            or b"Try again" in resp.data
            or b"rate" in resp.data.lower()
            or resp.status_code == 429,
            "Rate limiting not enforced",
        )

    # New aggressive SQLi probes

    def test_07_sql_injection_union_probe(self):
        payload = "1' UNION SELECT name,sql,1,1 FROM sqlite_master --"
        r = self.client.get(f"/search?q={payload}", follow_redirects=True)

        # The app should respond (200 OK) and not 404 (route missing)
        self.assertIn(r.status_code, (200, 302), "App did not respond correctly to UNION probe")

        # Verify users table still exists after the probe
        table = db_query(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='users';", one=True
        )
        self.assertIsNotNone(table, "Users table missing after UNION-style SQLi probe")

    def test_08_sql_injection_time_like_probe(self):
        noise = " OR ".join(["'1'='1'"] * 300)  # long repetitive pattern
        payload = f"test{noise} --"
        r = self.client.get(f"/search?q={payload}", follow_redirects=True)

        # App should respond within a normal request path (200 expected)
        self.assertEqual(r.status_code, 200, "App failed to handle long/time-like probe gracefully")

        # Ensure DB still intact
        table = db_query(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='users';", one=True
        )
        self.assertIsNotNone(table, "Users table missing after long/time-like SQLi probe")


# Pretty Summary Reporter
def run_tests_with_summary():
    stream = StringIO()
    runner = unittest.TextTestRunner(stream=stream, verbosity=2)
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(SecureShopTests)
    result = runner.run(suite)

    # Print captured test output (full)
    print(stream.getvalue())

    total = result.testsRun
    failed = len(result.failures)
    errored = len(result.errors)
    passed = total - failed - errored

    print("=" * 60)
    print(f"{Fore.CYAN}SECURE SHOP TEST SUMMARY{Style.RESET_ALL}")
    print("=" * 60)
    print(f"{Fore.GREEN}Passed: {passed}{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}Failed: {failed}{Style.RESET_ALL}")
    print(f"{Fore.RED}Errors: {errored}{Style.RESET_ALL}")
    print("-" * 60)

    if result.failures or result.errors:
        print(f"{Fore.RED} Some tests failed. Review logs above.{Style.RESET_ALL}")
    else:
        print(f"{Fore.GREEN} All tests passed successfully!{Style.RESET_ALL}")
    print("=" * 60)


if __name__ == "__main__":
    run_tests_with_summary()
