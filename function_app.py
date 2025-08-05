import os
import logging
import azure.functions as func
import requests
import base64
import json
from msal import ConfidentialClientApplication
from datetime import datetime
import threading

app = func.FunctionApp()

HUNTRESS_API_KEY = os.environ.get("HUNTRESS_API_KEY")
HUNTRESS_API_SECRET = os.environ.get("HUNTRESS_API_SECRET")
BASE_URL = "https://api.huntress.io/v1"


def get_auth_header():
    raw = f"{HUNTRESS_API_KEY}:{HUNTRESS_API_SECRET}"
    encoded = base64.b64encode(raw.encode()).decode()
    return {"Authorization": f"Basic {encoded}"}


def get_agents_by_org(org_id, headers):
    agents = []
    page = 1
    per_page = 250

    while True:
        params = {
            "organization_id": org_id,
            "limit": per_page,
            "page": page
        }
        resp = requests.get(f"{BASE_URL}/agents", headers=headers, params=params)
        if resp.status_code != 200:
            logging.error(f"Failed to get agents for org {org_id}: {resp.status_code} {resp.text}")
            break
        data = resp.json()
        current_agents = data.get("agents", [])
        agents.extend(current_agents)
        if not current_agents or len(current_agents) < per_page:
            break
        page += 1

    return agents


def run_sync():
    if not HUNTRESS_API_KEY or not HUNTRESS_API_SECRET:
        logging.error("Missing HUNTRESS_API_KEY or SECRET")
        return

    try:
        headers = get_auth_header()
        orgs = []
        org_url = f"{BASE_URL}/organizations"
        while org_url:
            resp = requests.get(org_url, headers=headers)
            if resp.status_code != 200:
                logging.error(f"Failed to get orgs: {resp.text}")
                return
            data = resp.json()
            orgs.extend(data.get("organizations", []))
            org_url = data.get("pagination", {}).get("next_page_url")

        if not orgs:
            logging.warning("No organizations found.")
            return

        all_agents = []
        org_summaries = []
        agent_entries = []

        for org in orgs:
            org_id = org["id"]
            agents = get_agents_by_org(org_id, headers)
            all_agents.extend(agents)

            org_summaries.append({
                "id": org_id,
                "name": org.get("name"),
                "agents_count": len(agents),
                "created_at": org.get("created_at"),
                "updated_at": org.get("updated_at")
            })

            for agent in agents:
                healthy = (
                    agent.get("defender_status") == "Protected" and
                    #agent.get("defender_substatus") == "Up to date" and
                    #agent.get("defender_policy_status") == "Compliant" and
                    agent.get("firewall_status") == "Enabled"
                )
                status = "Healthy" if healthy else "Unhealthy"

                agent_entries.append({
                    "organization": org.get("name"),
                    "agent_id": agent.get("id"),
                    "hostname": agent.get("hostname"),
                    "os": agent.get("os_family"),
                    "version": agent.get("version"),
                    "ip": agent.get("ipv4_address"),
                    "last_seen": agent.get("last_checkin"),
                    "last_callback": agent.get("last_callback_at"),
                    "last_survey": agent.get("last_survey_at"),
                    "status": status,
                    "defender_status": agent.get("defender_status", ""),
                    "defender_substatus": agent.get("defender_substatus", ""),
                    "defender_policy_status": agent.get("defender_policy_status", ""),
                    "firewall_status": agent.get("firewall_status", ""),
                    "serial_number": agent.get("serial_number", ""),
                    "mac_addresses": ", ".join(agent.get("mac_addresses", []))[:100]
                })

        TENANT_ID = os.getenv("DATAVERSE_TENANT_ID")
        CLIENT_ID = os.getenv("DATAVERSE_CLIENT_ID")
        CLIENT_SECRET = os.getenv("DATAVERSE_CLIENT_SECRET")
        ENV_URL = os.getenv("DATAVERSE_ENV_URL")
        TABLE_NAME = "cr890_huntressagentses"

        authority = f"https://login.microsoftonline.com/{TENANT_ID}"
        scope = [f"{ENV_URL}/.default"]
        app = ConfidentialClientApplication(CLIENT_ID, authority=authority, client_credential=CLIENT_SECRET)
        token_response = app.acquire_token_for_client(scopes=scope)
        if "access_token" not in token_response:
            raise Exception(f"Token error: {token_response.get('error_description')}")

        dv_headers = {
            "Authorization": f"Bearer {token_response['access_token']}",
            "Content-Type": "application/json",
            "OData-Version": "4.0",
            "Accept": "application/json"
        }

        for agent in agent_entries[:35]:
            agent_id = agent["agent_id"]
            entity = {
                "cr890_agentid": str(agent_id),
                "cr890_hostname": agent.get("hostname", ""),
                "cr890_organization": agent.get("organization", ""),
                "cr890_os": agent.get("os", ""),
                "cr890_status": agent.get("status", ""),
                "cr890_lastcallback": agent.get("last_callback", ""),
                "cr890_lastsurvey": agent.get("last_survey", ""),
                "cr890_defenderstatus": agent.get("defender_status", ""),
                "cr890_defendersubstatus": agent.get("defender_substatus", ""),
                "cr890_defenderpolicystatus": agent.get("defender_policy_status", ""),
                "cr890_firewallstatus": agent.get("firewall_status", ""),
                "cr890_ip": agent.get("ip", ""),
                "cr890_version": agent.get("version", ""),
                "cr890_serialnumber": agent.get("serial_number", ""),
                "cr890_macaddresses": agent.get("mac_addresses", "")[:100],
                "cr890_lastseenutc": datetime.utcnow().isoformat()
            }

            query_url = f"{ENV_URL}/api/data/v9.2/{TABLE_NAME}?$filter=cr890_agentid eq '{agent_id}'"
            get_test = requests.get(query_url, headers=dv_headers)
            if get_test.status_code == 200:
                records = get_test.json().get('value', [])
                if records:
                    record_id = records[0]['cr890_huntressagentsid']
                    patch_url = f"{ENV_URL}/api/data/v9.2/{TABLE_NAME}({record_id})"
                    response = requests.patch(patch_url, headers=dv_headers, json=entity)
                else:
                    response = requests.post(f"{ENV_URL}/api/data/v9.2/{TABLE_NAME}", headers=dv_headers, json=entity)
            else:
                response = requests.post(f"{ENV_URL}/api/data/v9.2/{TABLE_NAME}", headers=dv_headers, json=entity)

            if response.status_code in [200, 201, 204]:
                logging.info(f"✅ Synced Huntress agent {agent_id}")
            else:
                logging.error(f"❌ Sync failed ({agent_id}): {response.status_code} - {response.text}")

    except Exception:
        logging.exception("Unhandled error in run_sync")


@app.function_name(name="huntress_monitor")
@app.route(route="huntress/monitor", auth_level=func.AuthLevel.FUNCTION)
def monitor_huntress(req: func.HttpRequest) -> func.HttpResponse:
    logging.info("Huntress monitoring triggered.")

    thread = threading.Thread(target=run_sync)
    thread.start()

    return func.HttpResponse("Sync started.", status_code=202)