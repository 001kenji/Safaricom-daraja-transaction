from asgiref.sync import sync_to_async
from django.db import transaction
from django.conf import settings
import base64, json
from requests.auth import HTTPBasicAuth
import requests,datetime
import logging
import json
import ffmpeg
from better_ffmpeg_progress import FfmpegProcess
logger = logging.getLogger(__name__)
# Helper functions (can be in utils.py)

def get_mpesa_code():
    return settings.MPESA_BUSINESS_SHORTCODE

def get_mpesa_callack():
    return settings.MPESA_CALLBACK_URL

def get_mpesa_api_url():
    return settings.MPESA_API_URL

def get_stripe_secret_key():
    return settings.STRIPE_SECRET_KEY, settings.STRIPE_RETURN_URL , settings.FRONTEND_URL

def get_paystack_data():
    return settings.STRIPE_SECRET_KEY, settings.STRIPE_CONSUMER_KEY , settings.FRONTEND_URL

def get_mpesa_password():
    timestamp = datetime.datetime.now().strftime("%Y%m%d%H%M%S")
    passkey_val = base64.b64encode(
            f"{settings.MPESA_BUSINESS_SHORTCODE}{settings.MPESA_PASS_KEY}{timestamp}".encode()
        ).decode()
    # passkey_val = settings.MPESA_PASS_KEY
    return passkey_val, timestamp


def generate_transaction_ref():
    import uuid
    return str(uuid.uuid4())


@transaction.atomic
def _get_mpesa_auth():
    """Sync function to get M-Pesa auth token with better error handling"""
    try:
        auth_url = f'{settings.MPESA_API_URL}/oauth/v1/generate?grant_type=client_credentials'
        keyval = settings.MPESA_CONSUMER_KEY
        secretval = settings.MPESA_CONSUMER_SECRET
        # print(keyval,secretval,auth_url)
        logger.debug(f"Attempting M-Pesa auth with key: {keyval[:4]}...{keyval[-4:]}")
        
        auth = HTTPBasicAuth(keyval, secretval)
        response = requests.get(
            auth_url,
            auth=auth,
            headers={'Cache-Control': 'no-cache'},
            timeout=30
        )
        
        # Check for successful response
        response.raise_for_status()
        
        try:
            auth_data = response.json()
            access_token = auth_data.get('access_token')
            
            if not access_token:
                logger.error(f"M-Pesa auth failed: {auth_data}")
                raise ValueError("No access token in response")
                
            logger.debug("M-Pesa auth successful")
            return access_token
            
        except json.JSONDecodeError:
            logger.error(f"Invalid JSON response: {response.text}")
            raise ValueError("Invalid JSON response from M-Pesa auth endpoint")
            
    except requests.exceptions.RequestException as e:
        logger.error(f"M-Pesa auth request failed: {str(e)}")
        raise ValueError(f"Auth request failed: {str(e)}")
    except Exception as e:
        logger.error(f"Unexpected error during M-Pesa auth: {str(e)}")
        raise e
    

def register_grok(access_token=''):
    try:
        

        url = "https://sandbox.safaricom.co.ke/mpesa/c2b/v1/registerurl"

        headers = {
            "Authorization": f"Bearer {access_token}",
            "Content-Type": "application/json",
        }

        payload = {
            "ShortCode": settings.MPESA_BUSINESS_SHORTCODE,
            "ResponseType": "Completed",
            "ConfirmationURL": f"{settings.GROK_URL}/api/mpesa/confirmation/",
            "ValidationURL": f"{settings.GROK_URL}/api/mpesa/validation/"
        }

        response = requests.post(url, json=payload, headers=headers)
        print(response.json())
    except requests.exceptions.RequestException as e:
        logger.error(f"M-Pesa auth request failed: {str(e)}")
        raise ValueError(f"Auth request failed: {str(e)}")
    except Exception as e:
        logger.error(f"Unexpected error during M-Pesa auth: {str(e)}")
        raise e




def stream_ffmpeg_progress(cmd, video_length):
    """
    Run FFmpeg via better-ffmpeg-progress and yield SSE‐style JSON lines.
    
    - cmd: list of ffmpeg CLI args (from ffmpeg-python .compile())
    - video_length: float seconds, for percentage calcs
    """
    # FfmpegProgress is an iterator over progress dicts
    for stats in FfmpegProcess(cmd):
        # stats['progress'] is a string "12.34" meaning percent
        pct = int(float(stats["progress"]))
        yield json.dumps({"event": "ffmpeg_progress", "progress": pct}) + "\n\n"

    # final guarantee
    yield json.dumps({"event": "ffmpeg_progress", "progress": 100}) + "\n\n"

