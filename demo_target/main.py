import os
from typing import Any

from fastapi import FastAPI, Header, HTTPException, Query
from pydantic import BaseModel


class VehicleLocation(BaseModel):
    vehicle_id: str
    owner_role: str
    latitude: float
    longitude: float
    vin: str


VEHICLE_DB: dict[str, dict[str, Any]] = {
    "veh-123": {
        "owner_role": "user_a",
        "latitude": 37.7749,
        "longitude": -122.4194,
        "vin": "CRAPI-VEH-123",
    },
    "veh-456": {
        "owner_role": "user_b",
        "latitude": 34.0522,
        "longitude": -118.2437,
        "vin": "CRAPI-VEH-456",
    },
}

TOKEN_TO_ROLE = {
    "token-a": "user_a",
    "token-b": "user_b",
}


def create_app(mode: str | None = None) -> FastAPI:
    app = FastAPI(title="Demo Target API", version="0.1.0")
    app.state.mode = (mode or os.getenv("DEMO_TARGET_MODE", "vulnerable")).strip().lower()

    @app.get("/health")
    async def health() -> dict[str, str]:
        return {"status": "ok", "mode": app.state.mode}

    @app.get("/identity/api/v2/vehicle/{vehicle_id}/location")
    async def vehicle_location(
        vehicle_id: str,
        x_debug_role: str | None = Header(default=None, alias="X-Debug-Role"),
        authorization: str | None = Header(default=None, alias="Authorization"),
        mode: str | None = Query(default=None),
    ) -> dict[str, Any]:
        effective_mode = (mode or app.state.mode or "vulnerable").strip().lower()
        role = _resolve_role(x_debug_role=x_debug_role, authorization=authorization)
        vehicle = VEHICLE_DB.get(vehicle_id)

        if vehicle is None:
            raise HTTPException(status_code=404, detail="vehicle_not_found")
        if role is None:
            raise HTTPException(status_code=401, detail="missing_role")

        if effective_mode == "secure" and role != vehicle["owner_role"]:
            raise HTTPException(status_code=403, detail="forbidden")

        return {
            "vehicle_id": vehicle_id,
            "owner_role": vehicle["owner_role"],
            "requested_by": role,
            "location": {
                "latitude": vehicle["latitude"],
                "longitude": vehicle["longitude"],
            },
            "vin": vehicle["vin"],
            "mode": effective_mode,
        }

    return app


def _resolve_role(x_debug_role: str | None, authorization: str | None) -> str | None:
    if x_debug_role:
        return x_debug_role
    if not authorization:
        return None
    parts = authorization.split(" ", 1)
    token = parts[1].strip() if len(parts) == 2 else authorization.strip()
    return TOKEN_TO_ROLE.get(token)


app = create_app()
