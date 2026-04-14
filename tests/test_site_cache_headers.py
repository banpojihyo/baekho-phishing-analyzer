import importlib.util
import unittest


FASTAPI_RUNTIME_AVAILABLE = all(
    importlib.util.find_spec(name) is not None
    for name in ("fastapi", "starlette", "pydantic", "multipart")
)


@unittest.skipUnless(FASTAPI_RUNTIME_AVAILABLE, "FastAPI runtime dependencies are not installed")
class SiteCacheHeaderTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from fastapi.testclient import TestClient

        from app.main import create_app

        cls.client = TestClient(create_app())

    def test_site_pages_disable_cache(self):
        response = self.client.get("/demo")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers["cache-control"], "no-cache, max-age=0, must-revalidate")
        self.assertEqual(response.headers["pragma"], "no-cache")
        self.assertEqual(response.headers["expires"], "0")

    def test_tech_page_redirects_to_home_section(self):
        response = self.client.get("/tech", follow_redirects=False)

        self.assertEqual(response.status_code, 308)
        self.assertEqual(response.headers["location"], "/#tech")
        self.assertEqual(response.headers["cache-control"], "no-cache, max-age=0, must-revalidate")
        self.assertEqual(response.headers["pragma"], "no-cache")
        self.assertEqual(response.headers["expires"], "0")

    def test_demo_assets_disable_cache(self):
        response = self.client.get("/demo-assets/app.js")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers["cache-control"], "no-cache, max-age=0, must-revalidate")
        self.assertEqual(response.headers["pragma"], "no-cache")
        self.assertEqual(response.headers["expires"], "0")

    def test_api_routes_keep_default_cache_behavior(self):
        response = self.client.get("/health")

        self.assertEqual(response.status_code, 200)
        self.assertNotIn("cache-control", response.headers)


if __name__ == "__main__":
    unittest.main()
