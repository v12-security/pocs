#!/usr/bin/env python3
"""Inject supplied HTML into Telegram's widget sandbox on an owned Android device."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import sys
import time
from typing import Any

import frida
import frida_tools


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_HTML = ROOT / "poc.html"
DEFAULT_PACKAGE = "org.telegram.messenger"
DEFAULT_LIBRARY = "libtmessages.49.so"


def run(argv: list[str], *, check: bool = True) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(argv, text=True, capture_output=True)
    if check and result.returncode != 0:
        raise RuntimeError(
            f"command failed ({result.returncode}): {' '.join(argv)}\n"
            f"{result.stdout}{result.stderr}"
        )
    return result


def choose_serial(adb: str, requested: str | None) -> str:
    if requested:
        return requested
    output = run([adb, "devices"]).stdout.splitlines()[1:]
    devices = [line.split()[0] for line in output if line.strip().endswith("\tdevice")]
    if len(devices) != 1:
        raise RuntimeError(f"expected one authorized ADB device, found {devices!r}; pass --serial")
    return devices[0]


def parse_int(value: str) -> int:
    return int(value, 0)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--adb", default=os.environ.get("ADB", shutil.which("adb") or "adb"))
    parser.add_argument("--serial")
    parser.add_argument("--package", default=DEFAULT_PACKAGE)
    parser.add_argument("--library", default=DEFAULT_LIBRARY)
    parser.add_argument("--html", type=Path, default=DEFAULT_HTML)
    parser.add_argument("--wait-seconds", type=int, default=12)
    parser.add_argument("--expect-text", default="TG-WIDGET-PROBE")
    parser.add_argument("--qjs-eval-rva", type=parse_int,
                        help="optional exact-build qjs_eval RVA (hex or decimal)")
    parser.add_argument("--root-command", default="/data/local/tmp/ksud shell",
                        help="device-side root command prefix, e.g. '/data/local/tmp/ksud shell' or 'su -c'")
    parser.add_argument("--allow-network", action="store_true",
                        help="do not isolate Telegram from the network during local injection")
    parser.add_argument("--keep-app-running", action="store_true",
                        help="leave Telegram running after detach (less reliable with Java hooks)")
    args = parser.parse_args()

    if args.wait_seconds < 1:
        raise RuntimeError("--wait-seconds must be positive")
    html_path = args.html.expanduser().resolve()
    html = html_path.read_text(encoding="utf-8")
    serial = choose_serial(args.adb, args.serial)

    def shell_result(script: str) -> subprocess.CompletedProcess[str]:
        return run([args.adb, "-s", serial, "shell", script], check=False)

    def shell(script: str, *, check: bool = True) -> str:
        result = shell_result(script)
        if check and result.returncode != 0:
            raise RuntimeError(f"device command failed ({result.returncode}): {script}\n{result.stdout}{result.stderr}")
        return result.stdout.strip()

    def root_result(script: str) -> subprocess.CompletedProcess[str]:
        return shell_result(args.root_command + " " + shlex.quote(script))

    def root_shell(script: str, *, check: bool = True) -> str:
        result = root_result(script)
        if check and result.returncode != 0:
            raise RuntimeError(f"root command failed ({result.returncode}): {script}\n{result.stdout}{result.stderr}")
        return result.stdout.strip()

    package_q = shlex.quote(args.package)
    identity = {
        "serial": serial,
        "device": shell("getprop ro.product.device"),
        "model": shell("getprop ro.product.model"),
        "android": shell("getprop ro.build.version.release"),
        "sdk": shell("getprop ro.build.version.sdk"),
        "build": shell("getprop ro.build.id"),
        "kernel": shell("uname -r"),
        "selinux": shell("getenforce", check=False),
    }
    if "uid=0" not in root_shell("id"):
        raise RuntimeError("configured root command is not active")
    if not shell("pidof frida-server", check=False):
        raise RuntimeError("frida-server is not active on the device")
    package_line = shell(f"cmd package list packages -U {package_q}")
    uid_match = re.search(r"\buid:(\d+)", package_line)
    if not uid_match:
        raise RuntimeError(f"could not determine UID for {args.package}: {package_line!r}")
    package_uid = int(uid_match.group(1))
    package_info = shell(
        f"dumpsys package {package_q} | grep -E -m 4 'versionCode=|versionName=|primaryCpuAbi=|secondaryCpuAbi='",
        check=False,
    ).splitlines()
    print(json.dumps({"event": "target", "identity": identity, "package": args.package,
                      "uid": package_uid, "package_info": package_info,
                      "html": str(html_path), "html_bytes": len(html.encode('utf-8'))}), flush=True)

    run([args.adb, "-s", serial, "forward", "tcp:27042", "tcp:27042"])
    bridge_root = Path(next(iter(frida_tools.__path__)))
    bridge = (bridge_root / "bridges" / "java.js").read_text(encoding="utf-8")
    qjs_hook = ""
    if args.qjs_eval_rva is not None:
        qjs_hook = f"""
const evalPtr = mod.base.add({args.qjs_eval_rva});
Interceptor.attach(evalPtr, {{
  onEnter(args) {{
    evalCount++;
    emit({{event:'qjs-eval', count:evalCount, thread:Process.getCurrentThreadId(),
      address:evalPtr.toString(), rva:evalPtr.sub(mod.base).toString()}});
  }}
}});
"""
    agent = r'''
let held = [], recordCount = 0, createCount = 0, evalCount = 0;
function emit(x) { send(x); }
function decode(bytes) {
  const JString = Java.use('java.lang.String');
  const Charset = Java.use('java.nio.charset.Charset');
  try { return JString.$new(bytes, Charset.forName('UTF-8')).toString(); }
  catch (e) { return String(e); }
}
const mod = Process.getModuleByName(__LIBRARY__);
emit({event:'module', name:mod.name, path:mod.path, base:mod.base.toString(), size:mod.size});
const createPtr = mod.getExportByName(
  'Java_org_telegram_utils_twidget_WidgetSandboxNative_create');
Interceptor.attach(createPtr, {
  onEnter(args) {
    createCount++;
    emit({event:'native-widget-create', count:createCount,
      thread:Process.getCurrentThreadId(), address:createPtr.toString(),
      rva:createPtr.sub(mod.base).toString()});
  },
  onLeave(retval) {
    emit({event:'native-widget-create-return', count:createCount,
      handle:retval.toString()});
  }
});
__QJS_HOOK__
Java.perform(function () {
  try {
    const K0 = Java.use('org.telegram.utils.twidget.k0');
    const Backend = Java.use('org.telegram.utils.twidget.WidgetSandboxBackend');
    const ActivityThread = Java.use('android.app.ActivityThread');
    K0.a.overload().implementation = function () { return false; };
    const signal = Backend.signal.overload('int', '[B');
    signal.implementation = function (kind, bytes) {
      const text = decode(bytes);
      emit({event:'backend-signal', kind:Number(kind), text:text.slice(0, 16384)});
      return signal.call(this, kind, bytes);
    };
    const record = Backend.record.overload(
      '[B','[B','double','int','int','float','float','int','int');
    record.implementation = function (paint, layers, t, a, b, c, d, e, f) {
      const p = decode(paint), l = decode(layers); recordCount++;
      emit({event:'backend-record', count:recordCount,
        paint:p.slice(0, 32768), layers:l.slice(0, 8192),
        paintBytes:p.length, layerBytes:l.length});
      return record.call(this, paint, layers, t, a, b, c, d, e, f);
    };
    const app = ActivityThread.currentApplication();
    if (app === null) throw new Error('ActivityThread.currentApplication() returned null');
    const widget = K0.$new(app.getApplicationContext(), __HTML__,
      '{"colorScheme":"light"}', 1, 'en-US', '{}');
    widget.h.value = '{"data":{},"context":{"preview":true}}';
    widget.e.overload('boolean').call(widget, true);
    held.push(Java.retain(widget));
    emit({event:'inject-session-created'});
    widget.f.overload('int').call(widget, 1008);
    emit({event:'inject-session-start-called'});
    setTimeout(function () {
      Java.perform(function () {
        emit({event:'inject-session-handle', handle:String(widget.t.value)});
      });
    }, 2000);
  } catch (e) {
    emit({event:'inject-error', error:String(e), stack:e.stack ? String(e.stack) : ''});
  }
});
'''.replace("__LIBRARY__", json.dumps(args.library))
    agent = agent.replace("__HTML__", json.dumps(html, ensure_ascii=False))
    agent = agent.replace("__QJS_HOOK__", qjs_hook)
    source = bridge + "\nglobalThis.Java = bridge;\n" + agent

    messages: list[dict[str, Any]] = []
    session = None
    script = None
    pid = 0
    process_alive = False
    firewall_added: list[str] = []
    owner_rule = f"OUTPUT -m owner --uid-owner {package_uid} -j REJECT"
    try:
        shell(f"am force-stop {package_q}")
        if not args.allow_network:
            for tool in ("iptables", "ip6tables"):
                if root_result(f"{tool} -C {owner_rule}").returncode != 0:
                    root_shell(f"{tool} -I {owner_rule}")
                    firewall_added.append(tool)
        shell(f"am start -W -n {package_q}/.DefaultIcon")
        time.sleep(3)
        pid_text = shell(f"pidof {package_q}")
        pid = int(pid_text.split()[0])
        print(json.dumps({"event": "attach", "pid": pid}), flush=True)

        def on_message(message: dict[str, Any], data: bytes | None) -> None:
            messages.append(message)
            print(json.dumps(message, ensure_ascii=False), flush=True)

        device = frida.get_device_manager().add_remote_device("127.0.0.1:27042")
        session = device.attach(pid)
        script = session.create_script(source)
        script.on("message", on_message)
        script.load()
        process_alive = True
        for second in range(args.wait_seconds):
            time.sleep(1)
            if str(pid) not in shell(f"pidof {package_q}", check=False).split():
                process_alive = False
                print(json.dumps({"event": "process-exited", "second": second + 1}), flush=True)
                break
    finally:
        if not args.keep_app_running:
            shell(f"am force-stop {package_q}", check=False)
            time.sleep(1)
        if session is not None:
            try:
                session.detach()
            except Exception:
                pass
        for tool in firewall_added:
            root_shell(f"{tool} -D {owner_rule}", check=False)
        if not args.keep_app_running:
            shell(f"am force-stop {package_q}", check=False)

    payloads = [item.get("payload", {}) for item in messages if item.get("type") == "send"]
    create_count = sum(p.get("event") == "native-widget-create" for p in payloads)
    eval_count = sum(p.get("event") == "qjs-eval" for p in payloads)
    records = [p for p in payloads if p.get("event") == "backend-record"]
    errors = [p for p in payloads if p.get("event") == "inject-error"]
    rendered = "\n".join(str(p.get("paint", "")) for p in records)
    expected_seen = not args.expect_text or args.expect_text in rendered
    passed = bool(process_alive and create_count and records and expected_seen and not errors)
    if args.qjs_eval_rva is not None:
        passed = passed and eval_count > 0
    summary = {
        "event": "summary",
        "passed": passed,
        "process_alive_until_cleanup": process_alive,
        "native_widget_creates": create_count,
        "backend_records": len(records),
        "qjs_eval_entries": eval_count,
        "expected_text": args.expect_text,
        "expected_text_seen": expected_seen,
        "inject_errors": errors,
        "network_isolated": not args.allow_network,
        "network_rules_removed": True,
        "app_force_stopped": not args.keep_app_running,
    }
    print(json.dumps(summary, ensure_ascii=False), flush=True)
    return 0 if passed else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(json.dumps({"event": "error", "error": str(exc)}), file=sys.stderr)
        raise SystemExit(1)
