"""Settings loading/validation and per-OS locations."""

from __future__ import annotations

import tomllib
from pathlib import Path

import pytest

from sigil.infrastructure import paths
from sigil.infrastructure.config import (
    CONFIG_TEMPLATE,
    AgentSettings,
    ConfigError,
    load_settings,
    normalize_origin,
    resolve_config_path,
    write_config_template,
)


class TestNormalizeOrigin:
    @pytest.mark.parametrize(
        ("raw", "expected"),
        [
            ("https://ERP.Example.com/", "https://erp.example.com"),
            ("https://erp.example.com:443", "https://erp.example.com"),
            ("http://localhost:3000", "http://localhost:3000"),
            ("http://[::1]:8080", "http://[::1]:8080"),
        ],
    )
    def test_canonical_form(self, raw: str, expected: str) -> None:
        assert normalize_origin(raw) == expected

    @pytest.mark.parametrize(
        "raw", ["null", "ftp://x.com", "https://x.com/path", "https://u:p@x.com", "x.com"]
    )
    def test_rejects_non_origins(self, raw: str) -> None:
        with pytest.raises(ValueError, match="origin"):
            normalize_origin(raw)


class TestLoadSettings:
    def test_defaults_without_file_or_env(self, tmp_path: Path) -> None:
        # Never read the developer's real per-user config file.
        settings = load_settings(env={"SIGIL_CONFIG": str(tmp_path / "absent.toml")})
        assert settings.host == "127.0.0.1"
        assert settings.port == 8765
        assert settings.allowed_origins == ("http://localhost:3000",)
        assert settings.is_loopback_only
        assert settings.base_url == "http://127.0.0.1:8765"

    def test_precedence_file_then_env_then_overrides(self, tmp_path: Path) -> None:
        config = tmp_path / "config.toml"
        config.write_text(
            'port = 9000\nallowed_origins = ["https://erp.example.com"]\nlog_level = "DEBUG"\n'
        )
        env = {
            "SIGIL_PORT": "9100",
            "SIGIL_ALLOWED_ORIGINS": "https://a.example.com, https://b.example.com/",
            "SIGIL_PDF_STRICT_PARSING": "true",
        }
        settings = load_settings(config, env=env, host="127.0.0.1", port=None)
        assert settings.port == 9100
        assert settings.allowed_origins == ("https://a.example.com", "https://b.example.com")
        assert settings.log_level == "DEBUG"
        assert settings.pdf_strict_parsing is True
        assert load_settings(config, env=env, port=9200).port == 9200

    def test_config_path_can_come_from_env(self, tmp_path: Path) -> None:
        config = tmp_path / "custom.toml"
        config.write_text("port = 9300\n")
        assert load_settings(env={"SIGIL_CONFIG": str(config)}).port == 9300

    def test_legacy_pkcs11_lib_path_variable_is_honoured(self, tmp_path: Path) -> None:
        env = {
            "PKCS11_LIB_PATH": "/opt/vendor/lib.so",
            "SIGIL_CONFIG": str(tmp_path / "absent.toml"),
        }
        assert load_settings(env=env).pkcs11_module == Path("/opt/vendor/lib.so")
        env["SIGIL_PKCS11_MODULE"] = "/opt/other.so"
        assert load_settings(env=env).pkcs11_module == Path("/opt/other.so")

    @pytest.mark.parametrize(
        "content",
        [
            'allowed_origins = ["*"]',
            "port = 0",
            'tsa_url = "ftp://tsa"',
            'ssl_certfile = "/c.pem"',
            "unknown_key = 1",
            "this is not toml",
        ],
    )
    def test_invalid_configuration_raises_config_error(self, tmp_path: Path, content: str) -> None:
        config = tmp_path / "config.toml"
        config.write_text(content)
        with pytest.raises(ConfigError):
            load_settings(config, env={})

    def test_missing_explicit_file(self, tmp_path: Path) -> None:
        with pytest.raises(ConfigError, match="does not exist"):
            load_settings(tmp_path / "missing.toml", env={})

    def test_derived_values(self) -> None:
        settings = AgentSettings(
            host="0.0.0.0",
            ssl_certfile=Path("c.pem"),
            ssl_keyfile=Path("k.pem"),
            max_upload_mb=2,
        )
        assert settings.base_url == "https://127.0.0.1:8765"
        assert not settings.is_loopback_only
        assert settings.max_upload_bytes == 2 * 1024 * 1024


class TestTemplate:
    def test_template_is_valid_and_documents_every_setting(self) -> None:
        data = tomllib.loads(CONFIG_TEMPLATE)
        AgentSettings.model_validate(data)
        for name in AgentSettings.model_fields:
            assert name in CONFIG_TEMPLATE, f"{name} missing from CONFIG_TEMPLATE"

    def test_write_refuses_to_overwrite(self, tmp_path: Path) -> None:
        target = tmp_path / "sub" / "config.toml"
        write_config_template(target)
        with pytest.raises(ConfigError, match="already exists"):
            write_config_template(target)
        write_config_template(target, overwrite=True)
        assert target.read_text() == CONFIG_TEMPLATE

    def test_resolve_prefers_explicit_path(self, tmp_path: Path) -> None:
        assert resolve_config_path(tmp_path / "x.toml", env={}) == tmp_path / "x.toml"


class TestPaths:
    home = Path("/home/u")

    def test_windows(self) -> None:
        env = {
            "APPDATA": r"C:\Users\u\AppData\Roaming",
            "LOCALAPPDATA": r"C:\Users\u\AppData\Local",
        }
        assert paths.config_dir("Windows", env, self.home) == Path(env["APPDATA"]) / "Sigil"
        assert (
            paths.log_dir("Windows", env, self.home) == Path(env["LOCALAPPDATA"]) / "Sigil" / "logs"
        )

    def test_macos(self) -> None:
        assert (
            paths.config_dir("Darwin", {}, self.home)
            == self.home / "Library/Application Support/Sigil"
        )
        assert paths.log_dir("Darwin", {}, self.home) == self.home / "Library/Logs/Sigil"

    def test_linux_xdg(self) -> None:
        assert paths.config_dir("Linux", {}, self.home) == self.home / ".config/sigil"
        assert paths.log_dir("Linux", {}, self.home) == self.home / ".local/state/sigil/logs"
        env = {"XDG_CONFIG_HOME": "/cfg", "XDG_STATE_HOME": "/state"}
        assert paths.default_config_file("Linux", env, self.home) == Path("/cfg/sigil/config.toml")
        assert paths.log_dir("Linux", env, self.home) == Path("/state/sigil/logs")
