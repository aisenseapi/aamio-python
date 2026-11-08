"""The add-on template in examples/addon-template, published as github.com/aisenseapi/aamio-addon-template.

Its check passes as it stands, a copy renamed with its own rename.py passes it
too and runs through this core, nothing of the old name is left behind, and the
template's own Python tests pass. The PHP half has its own tests, run with PHP.
"""

import json
import os
import shutil
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
TEMPLATE = os.path.join(HERE, "..", "examples", "addon-template")
CORE = os.path.join(HERE, "..", "src")
IGNORE = shutil.ignore_patterns("__pycache__", "*.egg-info", ".pytest_cache", "build", "dist")


def run(*command, env=None, cwd=None):
    return subprocess.run(list(command), capture_output=True, text=True, env=env, cwd=cwd, timeout=120)


def test_the_check_passes_on_the_template_as_it_stands():
    done = run(sys.executable, os.path.join(TEMPLATE, "check.py"))
    assert done.returncode == 0 and "0 to fix" in done.stdout, done.stdout
    first = open(os.path.join(TEMPLATE, "aamio-addon.json"), "rb").read()
    assert first == open(os.path.join(TEMPLATE, "python", "src", "aamio_example", "aamio-addon.json"), "rb").read(), "the two copies of the manifest are the same bytes"


def test_the_check_says_which_file_disagrees(tmp_path):
    copy = tmp_path / "copy"
    shutil.copytree(TEMPLATE, copy, ignore=IGNORE)
    init = copy / "python" / "src" / "aamio_example" / "__init__.py"
    init.write_text(init.read_text(encoding="utf-8").replace('__version__ = "0.1.0"', '__version__ = "0.2.0"'), encoding="utf-8")
    done = run(sys.executable, str(copy / "check.py"))
    assert done.returncode == 1 and "FIX   __version__ in aamio_example/__init__.py is 0.1.0" in done.stdout and "1 to fix" in done.stdout, done.stdout


def test_a_renamed_copy_checks_out_and_runs_through_the_core(tmp_path):
    copy = tmp_path / "weather"
    shutil.copytree(TEMPLATE, copy, ignore=IGNORE)
    done = run(sys.executable, str(copy / "rename.py"), "weather")
    assert done.returncode == 0 and "0 to fix" in done.stdout, done.stdout + done.stderr
    assert not (copy / "python" / "src" / "aamio_example").exists() and (copy / "python" / "src" / "aamio_weather" / "aamio-addon.json").exists()
    manifest = json.loads((copy / "aamio-addon.json").read_text(encoding="utf-8"))
    assert manifest["name"] == "weather" and manifest["process"]["python"] == "aamio_weather.process" and manifest["tools"][0]["name"] == "aamio_addon_weather_wave"
    composer = json.loads((copy / "composer.json").read_text(encoding="utf-8"))
    assert composer["name"] == "your-vendor/aamio-weather" and composer["extra"]["aamio-addon"]["name"] == "weather" and composer["autoload"]["psr-4"] == {"AamioWeather\\": "src/"}
    assert "namespace AamioWeather;" in (copy / "src" / "Process.php").read_text(encoding="utf-8")
    for folder, _dirs, files in os.walk(copy):
        for name in files:
            if name in ("README.md", "LICENSE", "rename.py") and folder == str(copy):
                continue
            text = open(os.path.join(folder, name), encoding="utf-8", errors="replace").read()
            assert "example" not in text.lower(), "%s still says example" % os.path.join(folder, name)
    env = dict(os.environ, AAMIO_ADDONS="aamio_weather", AAMIO_HOME=str(tmp_path / "home"),
               PYTHONPATH=os.pathsep.join([str(copy / "python" / "src"), CORE]))
    listed = run(sys.executable, "-m", "aamio", "--no-archive", "addon", "list", env=env)
    row = json.loads(listed.stdout)["addons"][0]
    assert row["name"] == "weather" and row["contract"] == 2 and row["commands"] == ["wave"] and row["mcp_tools"] == ["aamio_addon_weather_wave"], listed.stderr
    waved = run(sys.executable, "-m", "aamio", "--no-archive", "addon", "weather", "wave", "--to", "Kari", env=env)
    assert waved.returncode == 0 and json.loads(waved.stdout) == {"hello": "Kari"}, waved.stderr


def test_rename_refuses_a_name_the_core_would_not_take(tmp_path):
    copy = tmp_path / "copy"
    shutil.copytree(TEMPLATE, copy, ignore=IGNORE)
    for name in ("Weather", "my-tool", "9lives", "list", "example", "a" * 33):
        done = run(sys.executable, str(copy / "rename.py"), name)
        assert done.returncode == 2 and "Give the new name" in done.stderr, name
    assert (copy / "python" / "src" / "aamio_example").exists(), "nothing was changed"


def test_the_template_s_own_python_tests_pass(tmp_path):
    copy = tmp_path / "copy"
    shutil.copytree(TEMPLATE, copy, ignore=IGNORE)
    env = dict(os.environ, PYTHONPATH=CORE)
    done = run(sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", "--basetemp", str(tmp_path / "inner"), str(copy / "python" / "tests"), env=env, cwd=str(copy / "python"))
    assert done.returncode == 0 and "5 passed" in done.stdout, done.stdout[-1500:]
