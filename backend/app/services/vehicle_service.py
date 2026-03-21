import json


def build_add_vehicle_body(vin: str, plate_number: str, owner_name: str) -> dict:
    return {
        "vin": vin,
        "plateNumber": plate_number,
        "ownerName": owner_name,
        "pincode": "123456"
    }


def try_extract_vehicle_ids(response_text: str) -> list:
    try:
        data = json.loads(response_text)
    except Exception:
        return []

    ids = []

    if isinstance(data, list):
        for item in data:
            if isinstance(item, dict):
                for key in ("id", "vehicleId", "vehicle_id", "uuid"):
                    if key in item:
                        ids.append(item[key])
                        break

    elif isinstance(data, dict):
        for key in ("vehicles", "data", "items", "result"):
            value = data.get(key)
            if isinstance(value, list):
                for item in value:
                    if isinstance(item, dict):
                        for id_key in ("id", "vehicleId", "vehicle_id", "uuid"):
                            if id_key in item:
                                ids.append(item[id_key])
                                break

    return ids