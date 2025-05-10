from django.shortcuts import render,HttpResponse
import json,os,datetime,requests,ffmpeg,aiofiles,asyncio,glob,textwrap,shutil,edge_tts
import time,sys,math,re,uuid,secrets
import httpx
from django.core.files.storage import default_storage
from rest_framework.response import Response
from rest_framework.views import APIView
from paystackapi.transaction import Transaction
from paystackapi.plan import Plan
from django.http import StreamingHttpResponse
# from pesapal_v3._pesapal import Pesapal
from pesapal_v3 import Pesapal
import aiofiles.os as aios
from django.contrib.sessions.backends.db import SessionStore
from rest_framework import status
from rest_framework.permissions import IsAuthenticated,AllowAny
from google.auth.transport.requests import Request as GoogleRequest
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.throttling import UserRateThrottle
from django.views.decorators.csrf import csrf_exempt,ensure_csrf_cookie, csrf_protect
from django.utils.decorators import method_decorator
#from AuthApp.excel_py.form1s import ReadWithFullRange
from asgiref.sync import async_to_sync
import traceback,base64,stripe

from urllib.parse import urlencode
from jose import jwt
from forex_python.converter import CurrencyRates
from circuitbreaker import circuit
from djoser.compat import get_user_email
from django.db import transaction
from django.conf import settings
from django.core.files.storage import FileSystemStorage
from .models import sanitize_string,SubscriptionPlan,Payment,Account,CreationStateManager,Feeds,FolderTable,FileTable,SubscriptionPlanForm
from .models import CurrencyConverter,AccountManager
from .utilities import get_paystack_data,get_stripe_secret_key,get_mpesa_code,get_mpesa_password,generate_transaction_ref,get_mpesa_api_url,get_mpesa_callack,_get_mpesa_auth,register_grok
from .serializers import CreationStateManagerSerializer,UserSerializer,FeedsSerializer,FolderTableSerializer,FileTableSerializer
from moviepy import AudioFileClip
from .services import WhisperTranscriber
from django.middleware.csrf import get_token
from django.http import JsonResponse
from google.oauth2 import id_token
from django.db.models import QuerySet
from PIL import Image, ImageDraw, ImageFont
from django.core.exceptions import ObjectDoesNotExist
from rest_framework_simplejwt.authentication import JWTAuthentication
from asgiref.sync import sync_to_async
# YOUTUBE AND GOOGLE 
from django.http import JsonResponse
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
import random
from google_auth_oauthlib.flow import Flow
import logging
logger = logging.getLogger(__name__)
# payments/views.py
from django.shortcuts import redirect
from django.urls import reverse
from djoser.social.token.jwt import TokenStrategy
from social_django.utils import load_strategy, load_backend
##
class Datathrottler(UserRateThrottle):
    scope = 'DataThrottler'

class fileUploadthrottler(UserRateThrottle):
    scope = 'fileUpload'

class csrfTokenThrottler(UserRateThrottle):
    scope = 'csrf'

class AiTokenThrottler(UserRateThrottle):
    scope = 'ai'

class VTV_AITokenThrottler(UserRateThrottle):
    scope = 'VTV_AI'

class AsyncJWTAuthentication(JWTAuthentication):
    async def authenticate(self, request):
        header = await sync_to_async(self.get_header)(request)
        if header is None:
            return None

        raw_token = await sync_to_async(self.get_raw_token)(header)
        if raw_token is None:
            return None

        validated_token = await sync_to_async(self.get_validated_token)(raw_token)
        user = await sync_to_async(self.get_user)(validated_token)
        return (user, validated_token)  # Must return a tuple, not a coroutine

class RetryCustomError(Exception):
    def __init__(self, retry, message):
        self.retry = retry
        self.message = message
        super().__init__(retry, message)

MaximumNumberRetry = 3





def get_csrf_token(request):
    token = get_token(request)
    return JsonResponse({'Success': 'CSRF cookie set', 'encryptedToken': token})



@method_decorator(csrf_exempt, name='dispatch')
class ProcessPaymentView(APIView):
    """Handles both M-Pesa and Flutterwave payments with subscription upgrades"""
    permission_classes = [IsAuthenticated]
    throttle_classes = [csrfTokenThrottler]
    
    async def async_post(self, request):
        data = request.data
        payment_method = data.get('payment_method')
        email = sanitize_string(data.get('email'))
        plan_id = sanitize_string(data.get('plan_id'))
        billing_cycle = sanitize_string(data.get('billing_cycle', 'monthly'))

        try:
            # Validate required fields
            if not all([payment_method, plan_id, email]):
                return Response(
                    {'success': False, 'error': 'Missing required fields'},
                    status=status.HTTP_400_BAD_REQUEST
                )

            # Get account and plan
            account = await sync_to_async(Account.objects.filter)(email=email)
            account_ref = await sync_to_async(account.first)()
            new_plan = await sync_to_async(SubscriptionPlan.objects.get)(id=plan_id)
            
            if not account_ref or not account_ref.is_active :
                return Response(
                    {'success': False, 'error': 'Seams like your account is invalid or not activated.'},
                    status=status.HTTP_400_BAD_REQUEST
                )

            if not new_plan :
                return Response(
                    {'success': False, 'error': 'Seams like the subscription is invalid. Try again later'},
                    status=status.HTTP_400_BAD_REQUEST
                )

            # Process payment based on method

           
            exchange_amount = data['amount']
            amount_val =  await asyncio.to_thread(CurrencyConverter.convert_usd_to_kes, exchange_amount)
            # amount_val = CurrencyConverter.convert_usd_to_kes(100)
            print('exchanged amount: ',amount_val)
            payment_result = await self.process_mpesa(
                    phone=data['phone'],
                    amount=amount_val
                )
            
            if not payment_result['success']:
                return Response(payment_result, status=status.HTTP_402_PAYMENT_REQUIRED)

            # Update subscription if payment succeeds
            

            return Response({
                'success': True,
                'message': 'Payment processed successfully and subscription updated',
                'new_plan': new_plan.name,
                'billing_cycle': billing_cycle,
                'subscription_end': account_ref.subscription_end
            })

        except SubscriptionPlan.DoesNotExist:
            return Response(
                {'success': False, 'error': 'Subscription plan does not exist'},
                status=status.HTTP_400_BAD_REQUEST
            )
        except Exception as e:
            return Response(
                {'success': False, 'error': str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

    async def process_mpesa(self, phone, amount):
        """Process M-Pesa payment with synchronous polling"""
        try:
            async with httpx.AsyncClient() as client:
                # 1. Initiate STK Push
                auth = await sync_to_async(_get_mpesa_auth)()
                shortcode = await sync_to_async(get_mpesa_code)()
                callback_url =  await sync_to_async(get_mpesa_callack)()
                logger.debug(f"Received auth token: {auth[:20]}...")
                print('auth got:',auth)
                # Timestamp & Password
                password, timestamp = await sync_to_async(get_mpesa_password)()
                # Endpoint
                mpesa_api_url = await sync_to_async(get_mpesa_api_url)()
                
                init_payload = {
                    "BusinessShortCode": shortcode,
                    "Password": password,
                    "Timestamp": timestamp,
                    "TransactionType": "CustomerPayBillOnline",
                    "Amount": amount,
                    "PartyA": phone,
                    "PartyB": shortcode,
                    "PhoneNumber": phone,
                    "CallBackURL": callback_url,
                    "AccountReference": "MELA",
                    "TransactionDesc": "Subscription Payment"
                }
                print('making initial request')
                init_response = await client.post(
                    f"{mpesa_api_url}/mpesa/stkpush/v1/processrequest",
                    json=init_payload,
                    headers={
                        "Authorization": f"Bearer {auth}",
                        "Content-Type": "application/json"
                    },
                    timeout=30.0
                )
               
                init_data = init_response.json()
                print('initial request made:',init_data)
                if init_response.status_code != 200:
                    return {
                        'success': False,
                        'error': init_data.get('errorMessage', 'STK Push initiation failed'),
                        'response': init_data
                    }

                checkout_request_id = init_data['CheckoutRequestID']
                # merchant_request_id = init_data['MerchantRequestID']

                # 2. Poll for completion (max 3 minutes)
                print('making poll for id:',checkout_request_id)
                max_attempts = 6  # 18 attempts × 10 seconds = 3 minutes
                for attempt in range(max_attempts):
                    await asyncio.sleep(10)  # Check every 10 seconds
                    print('polling',attempt)
                    query_payload = {
                        "BusinessShortCode": shortcode,
                        "Password": password,
                        "Timestamp": timestamp,
                        "CheckoutRequestID": checkout_request_id
                    }

                    query_response = await client.post(
                        f"{mpesa_api_url}/mpesa/stkpushquery/v1/query",
                        json=query_payload,
                        headers={
                            "Authorization": f"Bearer {auth}",
                            "Content-Type": "application/json"
                        },
                        timeout=30.0
                    )

                    query_data = query_response.json()
                    result_code = str(query_data.get('ResultCode', ''))
                    print('polled request:',result_code,'\n',query_data)
                    error_mapping = {
                        '2001': 'There was a problem with authentication. Please try again later.',
                        '1032': 'It seems like the request was cancelled. Please try again.',
                        '1037': 'We didn’t receive a payment response in time. You can try again shortly.',
                        '1': 'Looks like there are not enough funds in the account. Please check and try again.',
                        '2006': 'Something went wrong while connecting to the payment service. Try again later.'
                    }
                    # 3. Check payment status
                    # Success case
                    if result_code == '0' :
                        return {
                            'success': True,
                            'transaction_id': query_data.get('MerchantRequestID'),
                            'mpesa_receipt': query_data.get('MpesaReceiptNumber'),
                            'response_data': query_data
                        }
                    # Handle specific error cases
                    if result_code in error_mapping:
                        return {
                            'success': False,
                            'error': error_mapping[result_code],
                            'result_code': result_code,
                            'response_data': query_data
                        }
                    
                    # Still processing case
                    elif result_code == '1032' or query_data.get('errorCode') == '500.001.1001':
                        continue  # Keep polling

                # 4. Timeout if max attempts reached
                return {
                    'success': False,
                    'error': 'Payment verification timeout',
                    'checkout_request_id': checkout_request_id
                }

        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }

    
    def post(self, request):
        return async_to_sync(self.async_post)(request)
    

            print('[DEBUG] Creation state updated')
        except Exception as e:
            print(f'[ERROR] Error updating creation state: {e}')
