import psutil
import time


def scan_processes():
    processes = []

    procs = []
    for proc in psutil.process_iter(attrs=["pid", "name", "username"]):
        try:
            proc.cpu_percent(interval=None)
            procs.append(proc)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    time.sleep(0.5)  # use a longer sample for smoother readings

    num_cpus = psutil.cpu_count(logical=True)

    for proc in procs:
        try:
            info = proc.as_dict(attrs=["pid", "name", "username"])
            raw_cpu = proc.cpu_percent(interval=None)
            info["cpu_percent"] = raw_cpu / num_cpus  # normalize
            info["memory_percent"] = proc.memory_percent()
            processes.append(info)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    return processes
