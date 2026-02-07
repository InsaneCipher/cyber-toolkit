import psutil


def old_scan_services():
    services = []
    for service in psutil.win_service_iter():
        try:
            svc = service.as_dict()
            services.append({
                "name": svc["name"],
                "display_name": svc["display_name"],
                "status": svc["status"],
                "start_type": svc["start_type"],
                "pid": svc.get("pid", None),
            })
        except Exception:
            continue

    # Sort: running first, then alphabetical by name
    services.sort(key=lambda x: (x["status"] != "running", x["name"].lower()))

    # Save into dictionary: {service_name: {details...}}
    services_dict = {}

    for svc in services:
        service_name = svc["name"]
        services_dict[service_name] = svc

    return services_dict
