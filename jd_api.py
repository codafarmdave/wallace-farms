import requests
import webbrowser
import secrets

# === Configuration ===
CLIENT_ID = ''
CLIENT_SECRET = ''
REDIRECT_URI = 'http://localhost:9090/callback'
BASE_URL = 'https://api.deere.com/platform'
AUTH_URL = 'https://signin.johndeere.com/oauth2/aus78tnlaysMraFhC1t7/v1/authorize'
TOKEN_URL = 'https://signin.johndeere.com/oauth2/aus78tnlaysMraFhC1t7/v1/token'


def get_authorization():
    state = secrets.token_urlsafe(16)  # Generate a secure random state string

    # Update the scope to include the necessary permissions for reading and writing farms, fields, and boundaries
    scope = "ag3"# read:fields write:fields read:boundaries write:boundaries"

    auth_request_url = (
        f"{AUTH_URL}"
        f"?response_type=code"
        f"&client_id={CLIENT_ID}"
        f"&redirect_uri={REDIRECT_URI}"
        f"&scope={scope.replace(' ', '%20')}"  # Ensure spaces are URL-encoded
        f"&state={state}"
    )

    print(f"Go to the following URL to authorize the app:\n{auth_request_url}")
    webbrowser.open(auth_request_url)

    # When you're redirected, John Deere appends ?code=...&state=... to your redirect URI.
    # You must manually verify the state matches.
    code = input("Paste the authorization code here: ")
    returned_state = input("Paste the returned state here: ")

    if returned_state != state:
        raise Exception("Returned state does not match. Possible CSRF attack.")
    
    return code


def get_access_token(auth_code):
    data = {
        'grant_type': 'authorization_code',
        'code': auth_code,
        'redirect_uri': REDIRECT_URI,
        'client_id': CLIENT_ID,
        'client_secret': CLIENT_SECRET
    }
    response = requests.post(TOKEN_URL, data=data)
    response.raise_for_status()
    return response.json()


def get_or_create_client(token, org_id, client_name):
    # Get existing clients for the organization
    clients_url = f"{BASE_URL}/organizations/{org_id}/clients"
    headers = {
        'Authorization': f"Bearer {token}",
        'Accept': 'application/vnd.deere.axiom.v3+json'
    }
    
    response = requests.get(clients_url, headers=headers)
    response.raise_for_status()

    clients = response.json().get("values", [])
    
    # Check if client already exists
    for client in clients:
        if client["name"].lower() == client_name.lower():
            print(f"Client '{client_name}' already exists. Using existing client.")
            return client  # Return the clientUri
    
    # Client does not exist, create a new one
    create_client_url = f"{BASE_URL}/platform/organizations/{org_id}/clients"
    create_client_data = {
        "name": client_name,
        "description": "New client description"  # Add description if needed
    }
    
    create_response = requests.post(create_client_url, json=create_client_data, headers=headers)
    create_response.raise_for_status()

    new_client = create_response.json()
    print(f"Created new client: {client_name}")
    return new_client


# In this step, the user needs to copy the code and state strings from the redirect url
# For example, it will look like:
#  code=CEtrhUf6eNLlu7RL9BzCg-KtzLKFuLvJE4jwUiTQkvs&state=uS5T9mVfGxjglPJe0IhMIw
code = get_authorization()
tokens = get_access_token(code)
access_token = tokens["access_token"]


def get_oauth_well_known_info():
    # Define the well-known URL for John Deere OAuth 2.0 authorization server
    well_known_url = "https://signin.johndeere.com/oauth2/aus78tnlaysMraFhC1t7/.well-known/oauth-authorization-server"
    
    # Make a GET request to retrieve the well-known configuration
    response = requests.get(well_known_url)

    if response.status_code == 200:
        # Parse the JSON response
        oauth_info = response.json()
        
        # Print the information (you can also store it for further use)
        print("Authorization Endpoint:", oauth_info.get("authorization_endpoint"))
        print("Token Endpoint:", oauth_info.get("token_endpoint"))
        print("Scopes Supported:", oauth_info.get("scopes_supported"))
        
        return oauth_info
    else:
        print(f"Error: Unable to fetch well-known information. Status code: {response.status_code}")
        return None


# Call the function to fetch the OAuth 2.0 well-known configuration
oauth_info = get_oauth_well_known_info()

def get_organizations(token):
    url = f"{BASE_URL}/organizations"
    headers = {
        'Authorization': f'Bearer {token}',
        'Accept': 'application/vnd.deere.axiom.v3+json'
    }

    response = requests.get(url, headers=headers)
    response.raise_for_status()
    
    orgs = response.json().get('values', [])
    for org in orgs:
        print(f"Organization ID: {org['id']}, Name: {org.get('name', 'Unnamed')}")
    
    return orgs

# confirm that this worked to get associated organizations
orgs = get_organizations(access_token)

# get the selected client uri and id
client = get_or_create_client(access_token, org_id, "G&D Wallace, Inc.")
client_uri = client["links"][0]["uri"]  # Return the newly created clientUri
client_id = client['id']


import re

def get_farms(token, org_id):
    url = f"{BASE_URL}/organizations/{org_id}/farms"
    headers = {
        'Authorization': f"Bearer {token}",
        'Accept': 'application/vnd.deere.axiom.v3+json',
        'X-DEERE-NO-PAGING': "true" # This header prevents pagination!!!!! IMPORTANT!!!!
    }
    response = requests.get(url, headers=headers)
    response.raise_for_status()
    return response.json().get("values", [])


def create_farm(token, org_id, farm_name, client_uri):
    url = f"{BASE_URL}/organizations/{org_id}/farms"
    
    # Adding the Accept header as well
    headers = {
        'Authorization': f"Bearer {token}",
        'Content-Type': 'application/vnd.deere.axiom.v3+json',
        'Accept': 'application/vnd.deere.axiom.v3+json'  # Ensuring Accept header is set as well
    }
    
    # Ensure the correct payload structure
    payload = {
        "name": farm_name,
        "archived": False,
        "links": [
            {
                "@type": "Link",
                "rel": "client",
                "uri": client_uri  # Ensure it's 'href' and not 'links'
            }
        ]
    }
    
    # Send POST request to create farm
    response = requests.post(url, json=payload, headers=headers)
    
    # Debugging: Print out the response content to help identify issues
    print(f"Response Status Code: {response.status_code}")
    print(f"Response Content: {response.content}")
    
    try:
        # Try to parse the response as JSON
        response_json = response.json()
    except Exception as e:
        print(f"Error decoding JSON: {e}")
        print("Response content might not be in JSON format.")
        return None
    
    # If successful, return the JSON response
    return response_json


def get_or_create_farm(token, org_id, farm_name, client_uri):
    f_name_clean = re.sub(r'[^a-zA-Z0-9\s]', '', farm_name)
    farms = get_farms(token, org_id)
    for farm in farms:
        if farm["name"].lower().strip() == f_name_clean.lower().strip():
            print(f"Farm '{f_name_clean}' already exists. Using existing farm.")
            return farm

    # Farm doesn't exist, so create it
    create_farm(token, org_id, f_name_clean, client_uri)
    farms = get_farms(token, org_id)
    for farm in farms:
        if farm["name"].lower() == f_name_clean.lower():
            print(f"Farm '{f_name_clean}' already exists. Using existing farm.")
            return farm
            
    raise ValueError(f"Tried to match farm name to itself and failed! farm_name: {farm_name}")

farm = get_or_create_farm(access_token, org_id, farm_name="Home", client_uri=client_uri)

def get_fields(token, farm_id):
    url = f"{BASE_URL}/organizations/{org_id}/farms/{farm_id}/fields?itemLimit=100"
    headers = {
        'Authorization': f"Bearer {token}",
        'Accept': 'application/vnd.deere.axiom.v3+json'
    }
    response = requests.get(url, headers=headers)
    response.raise_for_status()
    return response.json().get("values", [])


def create_field(token, farm_id, client_id, field_name):
    url = f"{BASE_URL}/organizations/{org_id}/fields"
    headers = {
        'Authorization': f"Bearer {token}",
        'Content-Type': 'application/vnd.deere.axiom.v3+json',
        'Accept': 'application/vnd.deere.axiom.v3+json'
    }
    
    payload = {
        "name": field_name,
        "archived": False,
        "farms": {
            "farms": [
                {
                    "id": farm_id
                }
            ]
        },
        "clients": {
            "clients": [
                {
                    "id": client_id
                }
            ]
        }
    }
    
    response = requests.post(url, json=payload, headers=headers)
    return response


def get_or_create_field(token, farm_id, field_name, client_id):
    f_name_clean = re.sub(r'[^a-zA-Z0-9\s]', '', field_name)
    fields = get_fields(token, farm_id)
    for field in fields:
        if field["name"].lower() == f_name_clean.lower():
            print(f"Field '{f_name_clean}' already exists. Using existing field.")
            return field

    # Field doesn't exist, so create it
    create_field(token, farm_id, client_id, f_name_clean)
    fields = get_fields(token, farm_id)
    for field in fields:
        if field["name"].lower() == f_name_clean.lower():
            print(f"Field '{f_name_clean}' already exists. Using existing field.")
            return field

    raise ValueError(f"Tried to match field name to itself and failed! field: {f_name_clean}")

# #
# field_name = "Test311pm"
# #print(get_fields(token=access_token, farm_id=farm_id))
# #create_field(token=access_token, farm_id=farm_id, field_name="Test203pm", client_id=client_id)
# field = get_or_create_field(token=access_token, farm_id=farm_id, field_name=field_name, client_id=client_id)
# field_id = field['id']


def create_boundary(token, org_id, field_id, boundary_payload):
    url = f"https://api.deere.com/platform/organizations/{org_id}/fields/{field_id}/boundaries"
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/vnd.deere.axiom.v3+json",
        "Accept": "application/vnd.deere.axiom.v3+json"
    }

    response = requests.post(url, json=boundary_payload, headers=headers)
    
    try:
        response.raise_for_status()
    except requests.exceptions.HTTPError as e:
        print(f"❌ Failed to create boundary: {e}")
        print(f"Status Code: {response.status_code}")
        print(f"Response Content: {response.content}")
        raise
    
    print(f"✅ Boundary created: {boundary_payload.get('name', '[no name]')}")
    return response.json() if response.content else {}


import xml.etree.ElementTree as ET

def parse_kml_fields_etree(kml_file_path):
    ns = {'kml': 'http://www.opengis.net/kml/2.2'}
    
    tree = ET.parse(kml_file_path)
    root = tree.getroot()

    placemarks = root.findall(".//kml:Placemark", ns)
    field_entries = []

    for placemark in placemarks:
        name_el = placemark.find("kml:name", ns)
        field_name = name_el.text.strip() if name_el is not None else "Unnamed Field"

        farm_name = "Default Farm"
        # Look for <SimpleData name="layer">
        simple_datas = placemark.findall(".//kml:SimpleData", ns)
        for sd in simple_datas:
            if sd.attrib.get("name") == "layer":
                farm_name = sd.text.strip()
                break

        # Find coordinates inside <coordinates>
        coord_el = placemark.find(".//kml:coordinates", ns)
        if coord_el is None:
            print(f"Skipping field '{field_name}' due to missing coordinates.")
            continue

        coord_text = coord_el.text.strip()
        coord_pairs = coord_text.split()
        coords = []
        for pair in coord_pairs:
            lon, lat, *_ = map(float, pair.split(","))
            coords.append([lon, lat])

        if len(coords) < 3 or coords[0] != coords[-1]:
            coords.append(coords[0])  # Close the polygon

        field_entries.append({
            "farm_name": farm_name,
            "field_name": field_name,
            "coordinates": [coords]
        })

    return field_entries


def deduplicate_coords(coords):
    deduped = []
    prev = None
    for coord in coords:
        if coord != prev:
            deduped.append(coord)
        prev = coord
    return deduped


def process_kml(token, org_id, client_uri, client_id, kml_path):
    entries = parse_kml_fields_etree(kml_path)

    for entry in entries:
        try:
            farm_name = entry["farm_name"]
            field_name = entry["field_name"]
            coords = entry["coordinates"][0]
    
            print(f"\n📍 Processing field '{field_name}' under farm '{farm_name}'...")
    
            farm = get_or_create_farm(token, org_id, farm_name, client_uri)
            farm_id = farm["id"]
            print(f"✅ Farm '{farm_name}' ready (ID: {farm_id})")
    
            field = get_or_create_field(token, farm_id, field_name, client_id)
            field_id = field["id"]
            print(f"✅ Field '{field_name}' ready (ID: {field_id})")
    
            boundary_name = f"Boundary_{field_name.replace(' ', '_')}"
            
            # coords is a list of [lon, lat]
            deduped_coords = deduplicate_coords(coords)
            
            # Ensure polygon is closed
            if deduped_coords[0] != deduped_coords[-1]:
                deduped_coords.append(deduped_coords[0])
            
            points = [{"@type": "Point", "lat": lat, "lon": lon} for lon, lat in deduped_coords]
            
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
                                "passable": True
                            }
                        ]
                    }
                ],
                "active": False,
                "archived": False,
                "irrigated": False,
                "signalType": "dtiSignalTypeRTK"
            }
    
    
            boundary = create_boundary(token, org_id, field_id, boundary_payload)
            print(f"🟩 Boundary created for field '{field_name}' (ID: {boundary.get('id', 'unknown')})")
        except:
            print(f"failed to import farm: {farm_name}, field: {field_name}.")


kml_path = "data/raw/all-fields.kml"
fields = process_kml(token=access_token, org_id=org_id, client_uri=client_uri, client_id=client_id, kml_path=kml_path)