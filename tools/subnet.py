import ipaddress
import math
import re


def allocate_subnets(base_network, host_requirements):
    # Validate base network
    try:
        network = ipaddress.ip_network(base_network, strict=False)
    except ValueError:
        raise ValueError(f"Invalid IP network: {base_network}")

    # Validate host_requirements string (only digits, commas, spaces)
    if not re.fullmatch(r"[0-9,\s]+", host_requirements):
        raise ValueError("Host requirements must be numbers separated by commas (e.g. '50,20,10')")

    # Parse requirements and sort descending (biggest first)
    requirements = sorted([int(x.strip()) for x in host_requirements.split(",") if x.strip()], reverse=True)
    if not requirements:
        raise ValueError("No valid host requirements provided.")

    allocations = []
    subnets_to_allocate = [network]  # start with the whole block

    for idx, hosts in enumerate(requirements, 1):
        if hosts <= 0:
            raise ValueError(f"Invalid host requirement: {hosts}. Must be > 0.")

        # Calculate required subnet size
        needed = hosts + 2  # include network + broadcast
        prefix = 32 - math.ceil(math.log2(needed))

        # Find a subnet big enough
        for parent in subnets_to_allocate:
            if parent.prefixlen <= prefix:
                # Pick the first candidate
                chosen = next(parent.subnets(new_prefix=prefix))
                # Remove parent and add siblings
                subnets_to_allocate.remove(parent)
                subnets_to_allocate.extend([s for s in parent.subnets(new_prefix=prefix) if s != chosen])
                break
        else:
            raise ValueError(f"Not enough space to allocate {hosts} hosts")

        usable_hosts = list(chosen.hosts())
        allocations.append({
            "Group": idx,
            "Hosts Required": hosts,
            "Network": str(chosen.network_address),
            "Broadcast": str(chosen.broadcast_address),
            "Netmask": str(chosen.netmask),
            "Prefix": f"/{chosen.prefixlen}",
            "Usable Range": f"{usable_hosts[0]} - {usable_hosts[-1]}",
            "Usable Count": len(usable_hosts)
        })

    return allocations

