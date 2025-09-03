def yaml_to_form_data(path_to_yaml):
    import yaml
    from yaml import SafeLoader

    with open(path_to_yaml, "r") as file:
        data = yaml.load(file, Loader=SafeLoader)['ctf']

    print(data)

    form_data = {
        "name": data.get("name", ""),
        "description": data.get("description", ""),
        "category": data.get("category", ""),
        "difficulty": data.get("difficulty", ""),
        "hint": data.get("hint", ""),
        "solution": data.get("solution", ""),
        "isActive": data.get("is_active", True),
        "vms": [],
        "subnets": [],
        "flags": [],
        "hints": []
    }

    for name, vm_data in data.get("vms", {}).items():
        vm_entry = {
            "name": name,
            "ova_name": vm_data.get("ova_name", ""),
            "cores": vm_data.get("cores", 1),
            "ram_gb": vm_data.get("ram_gb", 1),
            "domain_name": vm_data.get("domain_name", ""),
        }
        form_data["vms"].append(vm_entry)

    for name, subnet_data in data.get("subnets", {}).items():
        subnet_entry = {
            "name": name,
            "dmz": subnet_data.get("dmz", False),
            "accessible": subnet_data.get("accessible", False),
            "attached_vms": subnet_data.get("attached_vms", [])
        }
        form_data["subnets"].append(subnet_entry)

    for flag_data in data.get("flags", []).values():
        flag_entry = {
            "flag": flag_data.get("flag", ""),
            "description": flag_data.get("description", ""),
            "points": flag_data.get("points", 0),
            "order_index": flag_data.get("order_index", 0)
        }
        form_data["flags"].append(flag_entry)

    for hint_data in data.get("hints", []).values():
        hint_entry = {
            "hint_text": hint_data.get("hint_text", ""),
            "unlock_points": hint_data.get("unlock_points", 0),
            "order_index": hint_data.get("order_index", 0)
        }
        form_data["hints"].append(hint_entry)

    return form_data
