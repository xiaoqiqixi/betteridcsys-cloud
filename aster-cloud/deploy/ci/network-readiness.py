#!/usr/bin/env python3
"""Read-only CI host warm-up BEFORE the native harness takes its baseline.

No packages, fixtures, guests, links, addresses, routes or firewall rules are
created here. This is readiness observation, not retrying a failed test and not
rebasing any native proof. The existing strict harness checkpoints are unchanged.
"""
import argparse
import hashlib
import importlib.util
import json
import math
from pathlib import Path
import signal
import sys
import time


class NotReady(Exception):
    pass


def wait_for_network(observe, monotonic, sleep):
    """Observe the external OS/clock boundaries with fixed, non-CLI budgets."""
    start = monotonic()
    if not isinstance(start,(int,float)) or not math.isfinite(start):
        raise NotReady('HOST_NETWORK_READINESS_CLOCK_REJECTED')
    previous, stable_since, last_time, transitions = None, start, start, 0
    # A bounded sample count also prevents a stalled clock from looping forever.
    for sample in range(1,38):
        try:
            snapshot = observe()
            if not isinstance(snapshot,dict) or set(snapshot)!={'addresses','routes','firewall'}:
                raise ValueError('snapshot schema')
            raw=json.dumps(snapshot,sort_keys=True,separators=(',',':'),allow_nan=False).encode()
        except NotReady:
            raise
        except Exception:
            raise NotReady('HOST_NETWORK_OBSERVATION_UNAVAILABLE') from None
        current=monotonic()
        if not isinstance(current,(int,float)) or not math.isfinite(current) or current<last_time:
            raise NotReady('HOST_NETWORK_READINESS_CLOCK_REJECTED')
        last_time=current
        if current-start>=180:
            raise NotReady('HOST_NETWORK_NOT_READY')
        # Compare the complete canonical snapshot, not an allowlist of expected
        # adapters, truncated diagnostic fields, or only route/firewall hashes.
        if previous is None or raw!=previous:
            if previous is not None:
                transitions+=1
            stable_since=current
        previous=raw
        if current-start>=60 and current-stable_since>=30:
            return {'schema':1,'ready':True,'scope':'read_only_preflight_before_native_baseline',
                    'elapsed_seconds':round(current-start,3),'stable_seconds':round(current-stable_since,3),
                    'samples':sample,'transitions':transitions,'last_snapshot_sha256':hashlib.sha256(raw).hexdigest(),
                    'native_test_executed':False,'native_network_guard_relaxed':False}
        sleep(5)
    raise NotReady('HOST_NETWORK_NOT_READY')


def main():
    argparse.ArgumentParser(description=__doc__).parse_args()
    if sys.platform!='linux':
        raise NotReady('LINUX_READINESS_HOST_REQUIRED')
    spec=importlib.util.spec_from_file_location('native_readonly_observer',Path(__file__).with_name('libvirt-native.py'))
    observer=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(observer)
    def deadline(_signum,_frame):
        # Exception unwinding executes the observer's owned-subprocess cleanup.
        raise NotReady('HOST_NETWORK_READINESS_DEADLINE')
    previous=signal.signal(signal.SIGALRM,deadline)
    signal.alarm(180)
    try:
        report=wait_for_network(observer.host_network,time.monotonic,time.sleep)
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM,previous)
    print(json.dumps(report,sort_keys=True))


if __name__=='__main__':
    try:
        main()
    except NotReady as e:
        print(json.dumps({'schema':1,'ready':False,'code':str(e),'native_test_executed':False}),file=sys.stderr)
        raise SystemExit(1)
