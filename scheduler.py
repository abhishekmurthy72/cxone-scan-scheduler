import os
import requests

def get_access_token(refresh_token, tenant):
    url = f"https://iam.checkmarx.net/auth/realms/{tenant}/protocol/openid-connect/token"
    data = {
        "grant_type": "refresh_token",
        "client_id": "ast-app",
        "refresh_token": refresh_token
    }
   # scheduling tasks tests 
    response = requests.post(url, data=data)
    response.raise_for_status()
    return response.json()["access_token"]

def main():
    cx_refresh_token = os.getenv('CX_REFRESH_TOKEN')
    cx_origin = os.getenv('CX_ORIGIN')
    cx_incremental_scan = os.getenv('CX_INCREMENTAL_SCAN')
    cx_project_id = os.getenv('CX_PROJECT_ID')
    cx_repo_url = os.getenv('CX_REPO_URL')
    cx_branch = os.getenv('CX_BRANCH')
    cx_username = os.getenv('CX_USERNAME')
    cx_api_key = os.getenv('CX_API_KEY')
    cx_tenant = os.getenv('CX_TENANT')

    # Log environment variables
    print("Environment variables:")
    print(f"CX_REFRESH_TOKEN: {cx_refresh_token}")
    print(f"CX_ORIGIN: {cx_origin}")
    print(f"CX_INCREMENTAL_SCAN: {cx_incremental_scan}")
    print(f"CX_PROJECT_ID: {cx_project_id}")
    print(f"CX_REPO_URL: {cx_repo_url}")
    print(f"CX_BRANCH: {cx_branch}")
    print(f"CX_USERNAME: {cx_username}")
    print(f"CX_API_KEY: {cx_api_key}")
    print(f"CX_TENANT: {cx_tenant}")

    try:
        # Get access token using refresh token
        access_token = get_access_token(cx_refresh_token, cx_tenant)
        print("Access token retrieved successfully")

        # Construct the Checkmarx API request
        headers = {
            'Authorization': f'Bearer {access_token}',
            'Content-Type': 'application/json',
            'Accept': 'application/json; version=1.0',
            'CorrelationId': ''
        }

        payload = {
            "type": "git",
            "handler": {
                "branch": cx_branch,
                "repoUrl": cx_repo_url,
                "credentials": {
                    "username": cx_username,
                    "type": "apiKey",
                    "value": cx_api_key
                },
                "skipSubModules": False
            },
            "project": {
                "id": cx_project_id,
                "tags": {
                    "test": "",
                    "priority": "high"
                }
            },
            "config": [
                {
                    "type": "sast",
                    "value": {
                        "incremental": "false"
                    }
                },
                {
                    "type": "sca"
                },
                {
                    "type": "kics"
                },
                {
                    "type": "apisec"
                }
            ],
            "tags": {
                "Scheduled Scan": "",
                "priority": "high"
            }
        }

        # Log the headers and payload
        print("Headers:")
        print(headers)
        print("Payload:")
        print(payload)

        # Send the request to the Checkmarx API
        response = requests.post('https://ast.checkmarx.net/api/scans', headers=headers, json=payload)
        
        # Log the response status code and content
        print("Response status code:", response.status_code)
        print("Response content:", response.text)

        response.raise_for_status()
        print("Checkmarx scan initiated successfully")
    except requests.exceptions.HTTPError as e:
        print(f"HTTPError: {e}")
        print("Response content:", e.response.content if e.response else 'No response content')
    except Exception as e:
        print(f"Error occurred: {e}")

if __name__ == "__main__":
    main()
