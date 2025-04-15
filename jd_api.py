#!/usr/bin/env python3
"""
Deere API Client Masterpiece

This module provides functions to authenticate with the John Deere API, 
retrieve or create organizations, clients, farms, fields, and boundaries based 
on KML file input.
"""

import logging
import os
import re
import secrets
import requests
import webbrowser
import xml.etree.ElementTree as ET
from urllib.parse import urlencode

# Configure logging for debug-level output
logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

# === Configuration ===
# It is best practice to load credentials from environment variables.
CLIENT_ID = os.getenv("CLIENT_ID", "")
CLIENT_SECRET = os.getenv("CLIENT_SECRET", "")
REDIRECT_URI = os.getenv("REDIRECT_URI", "http://localhost:9090/callback")
BASE_URL = os.getenv("BASE_URL", "https://api.deere.com/platform")
AUTH_URL = os.getenv(
    "AUTH_URL", "https://signin.johndeere.com/oauth2/aus78tnlaysMraFhC1t7/v1/authorize"
)
TOKEN_URL = os.getenv(
    "TOKEN_URL", "https://signin.johndeere.com/oauth2/aus78tnlaysMraFhC1t7/v1/token"
)
DEFAULT_SCOPE = "ag3"

# Default timeout for HTTP requests in seconds
REQUEST_TIMEOUT = 10


def get_authorization() -> str:
    """Initiate the OAuth2 authorization process and return the authorization code."""
    state = secrets.token_urlsafe(16)
    params = {
        "response_type": "code",
        "client_id": CLIENT_ID,
        "redirect_uri": REDIRECT_URI,
        "scope": DEFAULT_SCOPE,
        "state": state,
    }
    # Build URL safely using URL encoding.
    auth_request_url = f"{AUTH_URL}?{urlencode(params)}"
    logging.info("Visit the URL below to authorize the app:")
    logging.info(auth_request_url)
    webbrowser.open(auth_request_url)
    auth_code = input("Paste the authorization code here: ").strip()
    returned_state = input("Paste the returned state here: ").strip()
    if returned_state != state:
        raise ValueError("Returned state does not match. Possible CSRF attack.")
    return auth_code


def get_access_token(auth_code: str) -> dict:
    """Exchange the authorization code for an access token."""
    data = {
        "grant_type": "authorization_code",
        "code": auth_code,
        "redirect_uri": REDIRECT_URI,
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
    }
    try:
        response = requests.post(TOKEN_URL, data=data, timeout=REQUEST_TIMEOUT)
        response.raise_for_status()
        token_data = response.json()
        logging.info("Access token obtained successfully.")
        return token_data
    except requests.RequestException as e:
        logging.error("Error obtaining access token: %s", e)
        raise


def make_headers(
    token: str,
    accept: str = "application/vnd.deere.axiom.v3+json",
    content_type: str = None,
) -> dict:
    """Helper function to create HTTP headers for API requests."""
    headers = {"Authorization": f"Bearer {token}", "Accept": accept}
    if content_type:
        headers["Content-Type"] = content_type
    return headers


def get_organizations(token: str) -> list:
    """Retrieve all organizations associated with the access token."""
    url = f"{BASE_URL}/organizations"
    headers = make_headers(token)
    try:
        response = requests.get(url, headers=headers, timeout=REQUEST_TIMEOUT)
        response.raise_for_status()
        orgs = response.json().get("values", [])
        for org in orgs:
            org_name = org.get("name", "Unnamed")
            logging.info("Organization ID: %s, Name: %s", org["id"], org_name)
        return orgs
    except requests.RequestException as e:
        logging.error("Error retrieving organizations: %s", e)
        raise


def get_or_create_client(token: str, org_id: str, client_name: str) -> dict:
    """Retrieve an existing client or create a new one if it doesn't exist."""
    clients_url = f"{BASE_URL}/organizations/{org_id}/clients"
    headers = make_headers(token)
    try:
        response = requests.get(clients_url, headers=headers, timeout=REQUEST_TIMEOUT)
        response.raise_for_status()
        clients = response.json().get("values", [])
        for client in clients:
            if client.get("name", "").lower() == client_name.lower():
                logging.info(
                    "Client '%s' already exists. Using existing client.", client_name
                )
                return client
    except requests.RequestException as e:
        logging.error("Error retrieving clients: %s", e)
        raise

    # Create a new client if not found.
    create_client_url = f"{BASE_URL}/organizations/{org_id}/clients"
    create_client_data = {"name": client_name, "description": "New client description"}
    try:
        response = requests.post(
            create_client_url,
            json=create_client_data,
            headers=make_headers(
                token, content_type="application/vnd.deere.axiom.v3+json"
            ),
            timeout=REQUEST_TIMEOUT,
        )
        response.raise_for_status()
        new_client = response.json()
        logging.info("Created new client: %s", client_name)
        return new_client
    except requests.RequestException as e:
        logging.error("Error creating client: %s", e)
        raise


def get_farms(token: str, org_id: str) -> list:
    """Retrieve all farms for a given organization."""
    url = f"{BASE_URL}/organizations/{org_id}/farms"
    headers = make_headers(token)
    # Disable paging to retrieve all results.
    headers["X-DEERE-NO-PAGING"] = "true"
    try:
        response = requests.get(url, headers=headers, timeout=REQUEST_TIMEOUT)
        response.raise_for_status()
        farms = response.json().get("values", [])
        return farms
    except requests.RequestException as e:
        logging.error("Error retrieving farms: %s", e)
        raise


def create_farm(token: str, org_id: str, farm_name: str, client_uri: str) -> dict:
    """Create a new farm under a given organization."""
    url = f"{BASE_URL}/organizations/{org_id}/farms"
    headers = make_headers(
        token,
        accept="application/vnd.deere.axiom.v3+json",
        content_type="application/vnd.deere.axiom.v3+json",
    )
    payload = {
        "name": farm_name,
        "archived": False,
        "links": [{"@type": "Link", "rel": "client", "uri": client_uri}],
    }
    try:
        response = requests.post(
            url, json=payload, headers=headers, timeout=REQUEST_TIMEOUT
        )
        response.raise_for_status()
        return response.json()
    except requests.RequestException as e:
        logging.error("Error creating farm: %s", e)
        raise


def get_or_create_farm(
    token: str, org_id: str, farm_name: str, client_uri: str
) -> dict:
    """Retrieve an existing farm or create a new one if it doesn't exist."""
    cleaned_farm_name = re.sub(r"[^a-zA-Z0-9\s]", "", farm_name).strip()
    farms = get_farms(token, org_id)
    for farm in farms:
        if farm.get("name", "").lower().strip() == cleaned_farm_name.lower():
            logging.info(
                "Farm '%s' already exists. Using existing farm.", cleaned_farm_name
            )
            return farm
    return create_farm(token, org_id, cleaned_farm_name, client_uri)


def get_fields(token: str, org_id: str, farm_id: str) -> list:
    """Retrieve all fields for a given farm within an organization."""
    url = f"{BASE_URL}/organizations/{org_id}/farms/{farm_id}/fields?itemLimit=100"
    headers = make_headers(token)
    try:
        response = requests.get(url, headers=headers, timeout=REQUEST_TIMEOUT)
        response.raise_for_status()
        return response.json().get("values", [])
    except requests.RequestException as e:
        logging.error("Error retrieving fields: %s", e)
        raise


def create_field(
    token: str, org_id: str, farm_id: str, client_id: str, field_name: str
) -> dict:
    """Create a new field under a specific farm."""
    url = f"{BASE_URL}/organizations/{org_id}/fields"
    headers = make_headers(
        token,
        accept="application/vnd.deere.axiom.v3+json",
        content_type="application/vnd.deere.axiom.v3+json",
    )
    payload = {
        "name": field_name,
        "archived": False,
        "farms": {"farms": [{"id": farm_id}]},
        "clients": {"clients": [{"id": client_id}]},
    }
    try:
        response = requests.post(
            url, json=payload, headers=headers, timeout=REQUEST_TIMEOUT
        )
        response.raise_for_status()
        return response.json()
    except requests.RequestException as e:
        logging.error("Error creating field: %s", e)
        raise


def get_or_create_field(
    token: str, org_id: str, farm_id: str, field_name: str, client_id: str
) -> dict:
    """Retrieve an existing field or create a new one if it doesn't exist."""
    cleaned_field_name = re.sub(r"[^a-zA-Z0-9\s]", "", field_name).strip()
    fields = get_fields(token, org_id, farm_id)
    for field in fields:
        if field.get("name", "").lower() == cleaned_field_name.lower():
            logging.info(
                "Field '%s' already exists. Using existing field.", cleaned_field_name
            )
            return field
    return create_field(token, org_id, farm_id, client_id, cleaned_field_name)


def create_boundary(
    token: str, org_id: str, field_id: str, boundary_payload: dict
) -> dict:
    """Create a boundary for a specific field."""
    url = f"{BASE_URL}/organizations/{org_id}/fields/{field_id}/boundaries"
    headers = make_headers(
        token,
        accept="application/vnd.deere.axiom.v3+json",
        content_type="application/vnd.deere.axiom.v3+json",
    )
    try:
        response = requests.post(
            url, json=boundary_payload, headers=headers, timeout=REQUEST_TIMEOUT
        )
        response.raise_for_status()
        logging.info("Boundary created: %s", boundary_payload.get("name", "[no name]"))
        return response.json() if response.content else {}
    except requests.RequestException as e:
        logging.error("Error creating boundary: %s", e)
        raise


def parse_kml_fields_etree(kml_file_path: str) -> list:
    """Parse a KML file to extract field data."""
    ns = {"kml": "http://www.opengis.net/kml/2.2"}
    try:
        tree = ET.parse(kml_file_path)
    except ET.ParseError as e:
        logging.error("Error parsing KML file: %s", e)
        raise
    root = tree.getroot()
    placemarks = root.findall(".//kml:Placemark", ns)
    field_entries = []
    for placemark in placemarks:
        name_el = placemark.find("kml:name", ns)
        field_name = name_el.text.strip() if name_el is not None else "Unnamed Field"
        farm_name = "Default Farm"
        simple_datas = placemark.findall(".//kml:SimpleData", ns)
        for sd in simple_datas:
            if sd.attrib.get("name") == "layer":
                farm_name = sd.text.strip()
                break
        coord_el = placemark.find(".//kml:coordinates", ns)
        if coord_el is None:
            logging.warning(
                "Skipping field '%s' due to missing coordinates.", field_name
            )
            continue
        coord_text = coord_el.text.strip()
        coord_pairs = coord_text.split()
        try:
            coords = [
                [float(lon), float(lat)]
                for lon, lat, *_ in (pair.split(",") for pair in coord_pairs)
            ]
        except (ValueError, IndexError) as e:
            logging.error(
                "Error processing coordinates for field '%s': %s", field_name, e
            )
            continue
        # Ensure closed polygon: if not enough points or polygon is not closed, close it.
        if len(coords) < 3 or coords[0] != coords[-1]:
            coords.append(coords[0])
        field_entries.append(
            {"farm_name": farm_name, "field_name": field_name, "coordinates": [coords]}
        )
    return field_entries


def deduplicate_coords(coords: list) -> list:
    """Remove duplicate coordinates from a list."""
    deduped = []
    prev = None
    for coord in coords:
        if coord != prev:
            deduped.append(coord)
        prev = coord
    return deduped


def process_kml(
    token: str, org_id: str, client_uri: str, client_id: str, kml_path: str
):
    """Process a KML file to create farms, fields, and boundaries."""
    entries = parse_kml_fields_etree(kml_path)
    for entry in entries:
        farm_name = entry.get("farm_name", "Default Farm")
        field_name = entry.get("field_name", "Unnamed Field")
        coords = entry.get("coordinates", [[]])[0]
        try:
            logging.info(
                "Processing field '%s' under farm '%s'...", field_name, farm_name
            )
            farm = get_or_create_farm(token, org_id, farm_name, client_uri)
            farm_id = farm["id"]
            logging.info("Farm '%s' ready (ID: %s)", farm_name, farm_id)
            field = get_or_create_field(token, org_id, farm_id, field_name, client_id)
            field_id = field["id"]
            logging.info("Field '%s' ready (ID: %s)", field_name, field_id)
            deduped_coords = deduplicate_coords(coords)
            if deduped_coords and deduped_coords[0] != deduped_coords[-1]:
                deduped_coords.append(deduped_coords[0])
            points = [
                {"@type": "Point", "lat": lat, "lon": lon}
                for lon, lat in deduped_coords
            ]
            boundary_payload = {
                "@type": "Boundary",
                "name": f"Boundary_{field_name.replace(' ', '_')}",
                "sourceType": "External",
                "multipolygons": [
                    {
                        "@type": "Polygon",
                        "rings": [
                            {
                                "@type": "Ring",
                                "points": points,
                                "type": "exterior",
                                "passable": True,
                            }
                        ],
                    }
                ],
                "active": False,
                "archived": False,
                "irrigated": False,
                "signalType": "dtiSignalTypeRTK",
            }
            create_boundary(token, org_id, field_id, boundary_payload)
            logging.info("Boundary created for field '%s'.", field_name)
        except Exception as e:
            logging.error(
                "Failed to process farm '%s', field '%s'. Error: %s",
                farm_name,
                field_name,
                e,
            )


def main():
    """Main execution function."""
    try:
        auth_code = get_authorization()
        tokens = get_access_token(auth_code)
        access_token = tokens.get("access_token")
        if not access_token:
            logging.error("Access token not found in response.")
            return
        orgs = get_organizations(access_token)
        if not orgs:
            logging.error("No organizations found.")
            return
        org_id = orgs[0]["id"]  # Assuming the first organization is the target
        client_name = "G&D Wallace, Inc."
        client = get_or_create_client(access_token, org_id, client_name)
        client_uri = client.get("links", [{}])[0].get("uri", "")
        client_id = client.get("id", "")
        kml_path = "data/raw/all-fields.kml"
        process_kml(access_token, org_id, client_uri, client_id, kml_path)
    except Exception as e:
        logging.critical("An unrecoverable error occurred: %s", e)


if __name__ == "__main__":
    main()
