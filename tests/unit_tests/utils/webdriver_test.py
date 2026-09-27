# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements.  See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership.  The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.

from typing import Any
from unittest.mock import patch

import pytest
from flask import current_app
from packaging.version import Version
from selenium import __version__ as selenium_version
from selenium.webdriver import chrome, firefox, FirefoxProfile

from superset.utils.webdriver import WebDriverSelenium


def test_selenium_version_includes_security_fixes() -> None:
    # CVE-2023-5590 is fixed in 4.14.0, CVE-2022-28108 in 4.0.0
    assert Version(selenium_version) >= Version("4.14.0")


def test_build_driver_kwargs_default_configuration_firefox() -> None:
    """The default ``{"service_log_path": "/dev/null"}`` config keeps working."""
    options = firefox.options.Options()
    kwargs = WebDriverSelenium.build_driver_kwargs(
        "firefox", options, {"service_log_path": "/dev/null"}
    )

    assert set(kwargs) == {"options", "service"}
    assert kwargs["options"] is options
    assert isinstance(kwargs["service"], firefox.service.Service)
    assert kwargs["service"].log_output.name == "/dev/null"


def test_build_driver_kwargs_service_keys_chrome() -> None:
    options = chrome.options.Options()
    kwargs = WebDriverSelenium.build_driver_kwargs(
        "chrome",
        options,
        {
            "executable_path": "/opt/chromedriver",
            "port": 9515,
            "service_args": ["--verbose"],
            "service_log_path": "/dev/null",
            "keep_alive": False,
        },
    )

    service = kwargs["service"]
    assert isinstance(service, chrome.service.Service)
    assert service.path == "/opt/chromedriver"
    assert service.port == 9515
    assert "--verbose" in service.service_args
    assert kwargs["keep_alive"] is False


def test_build_driver_kwargs_desired_capabilities() -> None:
    options = chrome.options.Options()
    kwargs = WebDriverSelenium.build_driver_kwargs(
        "chrome",
        options,
        {"desired_capabilities": {"acceptInsecureCerts": True}},
    )

    assert set(kwargs) == {"options"}
    assert options.capabilities["acceptInsecureCerts"] is True


def test_build_driver_kwargs_firefox_profile_and_binary() -> None:
    options = firefox.options.Options()
    profile = FirefoxProfile()
    kwargs = WebDriverSelenium.build_driver_kwargs(
        "firefox",
        options,
        {"firefox_profile": profile, "binary_location": "/usr/bin/firefox"},
    )

    assert set(kwargs) == {"options"}
    assert options.profile is profile
    assert options.binary_location == "/usr/bin/firefox"


def test_build_driver_kwargs_firefox_profile_requires_firefox() -> None:
    with pytest.raises(ValueError, match="requires WEBDRIVER_TYPE = 'firefox'"):
        WebDriverSelenium.build_driver_kwargs(
            "chrome", chrome.options.Options(), {"firefox_profile": FirefoxProfile()}
        )


def test_build_driver_kwargs_passes_service_object_through() -> None:
    options = chrome.options.Options()
    service = chrome.service.Service()
    kwargs = WebDriverSelenium.build_driver_kwargs(
        "chrome", options, {"service": service}
    )

    assert kwargs == {"options": options, "service": service}


def test_build_driver_kwargs_rejects_service_object_with_service_keys() -> None:
    with pytest.raises(ValueError, match="cannot combine 'service'"):
        WebDriverSelenium.build_driver_kwargs(
            "chrome",
            chrome.options.Options(),
            {"service": chrome.service.Service(), "executable_path": "/x"},
        )


@pytest.mark.parametrize("key", ["chrome_options", "firefox_options", "proxy"])
def test_build_driver_kwargs_rejects_removed_keys(key: str) -> None:
    with pytest.raises(ValueError, match=f"WEBDRIVER_CONFIGURATION\\['{key}'\\]"):
        WebDriverSelenium.build_driver_kwargs(
            "chrome", chrome.options.Options(), {key: object()}
        )


@pytest.mark.parametrize(
    "driver_type, module",
    [("firefox", firefox), ("chrome", chrome)],
)
def test_create_uses_selenium_4_constructor(driver_type: str, module: Any) -> None:
    """``create`` only passes ``options``/``service`` to the WebDriver class."""
    config = {
        "WEBDRIVER_CONFIGURATION": {"service_log_path": "/dev/null"},
        "WEBDRIVER_OPTION_ARGS": ["--headless"],
        "WEBDRIVER_WINDOW": {"pixel_density": 2},
    }
    with (
        patch.dict(current_app.config, config),
        patch.object(module.webdriver, "WebDriver") as mock_driver,
    ):
        WebDriverSelenium(driver_type, (800, 600)).create()

    mock_driver.assert_called_once()
    kwargs = mock_driver.call_args.kwargs
    assert set(kwargs) == {"options", "service"}
    options = kwargs["options"]
    assert "--headless" in options.arguments
    assert isinstance(kwargs["service"], module.service.Service)
    if driver_type == "firefox":
        assert isinstance(options.profile, FirefoxProfile)
    else:
        assert "--force-device-scale-factor=2" in options.arguments
        assert "--window-size=800,600" in options.arguments
