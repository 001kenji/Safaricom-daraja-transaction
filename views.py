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

def calculate_folder_size(folder_path):
    """Sync function to calculate folder size"""
    total_size = 0
    for entry in os.scandir(folder_path):
        if entry.is_file():
            total_size += entry.stat().st_size
        elif entry.is_dir():
            total_size += calculate_folder_size(entry.path)
    return total_size

@sync_to_async
def complete_payment_transaction(account_ref, new_plan, payment_method, billing_cycle, amount, transaction_id):
    with transaction.atomic():
        old_plan = account_ref.current_plan
        account_ref.change_plan(
            new_plan=new_plan,
            old_plan=old_plan,
            payment_method=payment_method,
            billing_cycle=billing_cycle
        )
        account_ref.save()
        
        return Payment.objects.create(
            account=account_ref,
            amount=amount,
            payment_method=payment_method,
            plan=new_plan,
            transaction_id=transaction_id,
            status='completed'
        )


def get_csrf_token(request):
    token = get_token(request)
    return JsonResponse({'Success': 'CSRF cookie set', 'encryptedToken': token})


@method_decorator(csrf_exempt,name='dispatch')
class LogoutView(APIView):
     permission_classes = (IsAuthenticated,)
     throttle_classes = [csrfTokenThrottler]

     def post(self, request):
          
          try:
            refresh_token = request.data["refresh_token"]
            if refresh_token:
                    token = RefreshToken(refresh_token)
                    token.blacklist()
           
            return Response(status=status.HTTP_205_RESET_CONTENT)
          except Exception as e:
            
            return Response(status=status.HTTP_400_BAD_REQUEST)

@method_decorator(csrf_exempt,name='dispatch')
class CustomUserDeleteView(APIView):
    permission_classes = [IsAuthenticated]
    throttle_classes = [csrfTokenThrottler]
    def delete(self, request, *args, **kwargs):
        user = request.user
        
        # Step 1: Get the password and email from the request body
        password = sanitize_string(request.data.get("current_password"))
        email = sanitize_string(request.data.get('current_email'))
        
        if not password or not email:
            return Response(
                {"error": "Both password and email are required to delete your account."},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        try:
            # Step 2: Verify the user's credentials
            print('Verify the users credentials')
            user = Account.objects.get(email=email)
            if not user.check_password(password):
                raise Account.DoesNotExist
                
            # Step 3: Blacklist JWT tokens
            print(' Blacklist JWT tokens')
            try:
                refresh_token = request.data.get('refresh')
                if refresh_token:
                    token = RefreshToken(refresh_token)
                    token.blacklist()
                # Also blacklist the current access token
                token = RefreshToken.for_user(user)
                token.blacklist()
            except Exception as e:
                print(f"Error blacklisting token: {e}")
                logger.error(f"Error blacklisting token: {e}")
                
            print('Get associated Account model if it exists')
            # Step 4: Get associated Account model if it exists
            try:
                # Revoke all YouTube channel tokens
                self.revoke_oAuth_token(email=email,account=user)
            except Account.DoesNotExist:
                pass
                
            print('Perform custom cleanup')
            # Step 5: Perform custom cleanup
            self.perform_custom_actions(email)
            
            print('Delete the user')
            # Step 6: Delete the user
            user.delete()
            
            return Response(
                {"success": "Your account has been successfully deleted."},
                status=status.HTTP_200_OK
            )
            
        except Account.DoesNotExist:
            return Response(
                {"error": "Seams like your password is incorrect. Try again later"},
                status=status.HTTP_401_UNAUTHORIZED
            )
        except Exception as e:
            print(e)
            return Response(
                {"error": "Seams like there is an issue. Try again later."},
                status=status.HTTP_400_BAD_REQUEST
            )

    def revoke_oAuth_token(self, email, account):
        """
        Revoke all OAuth tokens for the user's YouTube channels
        """
        if not account.YoutubeChannels:
            return
            
        for channel in account.YoutubeChannels:
            try:
                token_path = channel.get('tokenPath')
                if not token_path:
                    continue
                    
                full_path = os.path.join(settings.MEDIA_ROOT, str(email), token_path)
                
                if os.path.exists(full_path):
                    with open(full_path, 'r') as file:
                        token_data = json.load(file)
                        access_token = token_data.get("token")
                        
                    response = requests.post(
                        "https://accounts.google.com/o/oauth2/revoke",
                        params={"token": access_token},
                        headers={"content-type": "application/x-www-form-urlencoded"},
                    )
                    
                    if response.status_code == 200:
                        print(f"✅ OAuth token for {channel['name']} revoked successfully.")
                    else:
                        print(f"⚠ Failed to revoke token for {channel['name']}:", response.json())
                        
            except Exception as e:
                print(f'\nError {e} \n occurred when trying to revoke token for channel {channel.get("name")}')

    def perform_custom_actions(self, email):
        """
        Custom cleanup actions before deleting a user.
        """
        folder_name = str(email)
        folder_path = os.path.join(settings.MEDIA_ROOT, folder_name)
        
        if os.path.exists(folder_path):
            try:
                shutil.rmtree(folder_path)
                print('User folder deleted successfully')
            except Exception as e:
                print(f'Error deleting user folder: {e}')


@method_decorator(csrf_exempt, name='dispatch')
class ModifyFeed(APIView):
    permission_classes = [IsAuthenticated]
    throttle_classes = [csrfTokenThrottler]

    def post(self, request):
        return async_to_sync(self.async_post)(request)

    async def async_post(self, request):
        try:
            data = request.data
            
            if data.get('scope') == 'DeleteFeed':
                return await self.handle_delete_feed(data)
            
            return Response(
                {'failed': 'Invalid scope'},
                status=status.HTTP_400_BAD_REQUEST
            )
            
        except Exception as e:
            print(f'Error in ModifyFeed: {str(e)}')
            return Response(
                {'failed': 'Server error'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

    async def handle_delete_feed(self, data):
        UserId = sanitize_string(data.get('UserId'))
        feedId = sanitize_string(data.get('feedId'))
        
        if not UserId or not feedId:
            return Response(
                {'failed': 'Missing UserId or feedId'},
                status=status.HTTP_400_BAD_REQUEST
            )

        try:
            account = await sync_to_async(Account.objects.get)(id=UserId)
        except ObjectDoesNotExist:
            return Response(
                {'failed': 'Account not found'},
                status=status.HTTP_404_NOT_FOUND
            )

        if not account.is_active:
            return Response(
                {'failed': 'Account is inactive'},
                status=status.HTTP_403_FORBIDDEN
            )

        deleted_count, _ = await sync_to_async(
            lambda: account.feeds.filter(id=feedId).delete()
        )()
        
        if deleted_count == 0:
            return Response(
                {'failed': 'Feed not found or already deleted'},
                status=status.HTTP_404_NOT_FOUND
            )
        
        return Response(
            {'success': 'Feed deleted'},
            status=status.HTTP_200_OK
        )

@method_decorator(csrf_exempt, name='dispatch')
class ProfileView(APIView):
    permission_classes = [AllowAny]
    throttle_classes = [csrfTokenThrottler]

    def post(self, request):
        # Convert async handler to sync for Django's URL routing
        return async_to_sync(self.async_post)(request)

    async def async_post(self, request):
        try:
            data = request.data[0]
            Scope = data['scope']
            
            if Scope == 'ReadProfile':
                return await self.handle_read_profile(data,request)
            elif Scope == 'UsernameUpdate':
                return await self.handle_username_update(data, request.data[1])
            return Response(
                {'failed': 'Invalid scope'}, 
                status=status.HTTP_400_BAD_REQUEST
            )
        except Exception as e:
            print(f"Error: {str(e)}")
            return Response(
                {'failed': 'Request processing failed'}, 
                status=status.HTTP_400_BAD_REQUEST
            )

    async def handle_read_profile(self, data,request):
        emailval = sanitize_string(data['AccountEmail'])
        IsOwner = sanitize_string(data['IsOwner'])
        
        if IsOwner == 'True' and emailval != 'gestuser@gmail.com':
            accountRef = await sync_to_async(Account.objects.filter)(email=emailval)
            accountrefGet = await sync_to_async(accountRef.first)()
            await asyncio.gather(
                sync_to_async(accountrefGet.reset_daily_creations_if_needed)(),
            )
            creation_data, profile_data, feeds_data = await asyncio.gather(
                sync_to_async(accountrefGet.state_manager.first)(),
                sync_to_async(lambda: UserSerializer(
                    accountrefGet, 
                    context={'user_email': emailval,'request': request}
                ).data)(),
                sync_to_async(lambda: list(
                    accountrefGet.feeds.filter(privacyStatus='public')[:15]
                ))()
            )
            
            creation_serialized = await sync_to_async(
                lambda: CreationStateManagerSerializer(creation_data).data
            )()
            feeds_serialized = await sync_to_async(
                lambda: FeedsSerializer(feeds_data, many=True).data
            )()
            
            return Response({
                'user': profile_data,
                'scope': 'ReadProfile',
                'IsOwner': IsOwner,
                'CreationState': creation_serialized,
                'Feeds': feeds_serialized,
                'SubscriptionPlan': ''
            })
        else:
            AccountID = sanitize_string(data['AccountID'])
            accountRef = await sync_to_async(Account.objects.filter)(id=AccountID)
            accountrefGet = await sync_to_async(accountRef.first)()

            if not accountrefGet or not accountrefGet.is_active:
                return Response({'failed': 'Account inactive'}, status.HTTP_400_BAD_REQUEST)
            
            feeds_data, profile_data = await asyncio.gather(
                sync_to_async(lambda: list(
                    accountrefGet.feeds.filter(privacyStatus='public')[:15]
                ))(),
                sync_to_async(lambda: list(
                    accountRef.values('id', 'name', 'email', 'ProfilePic')
                ))()
            )
            print(feeds_data,profile_data)
            feeds_serialized = await sync_to_async(
                lambda: FeedsSerializer(feeds_data, many=True).data
            )()
            
            return Response({
                'scope': 'ReadProfile',
                'IsOwner': IsOwner,
                'Feeds': feeds_serialized,
                'user': profile_data[0]
            })

    async def handle_username_update(self, data, emailval):
        nameval = sanitize_string(data['Username'])
        email = sanitize_string(emailval)
        @sync_to_async
        def update_username():
            with transaction.atomic():
                account = Account.objects.filter(email=email)
                accountRef = account.first()
                if not accountRef or not accountRef.is_active:
                    return {'failed': 'Account inactive'}, status.HTTP_400_BAD_REQUEST
                
                account.update(name=nameval)
                return {'success': 'Saved'}, 200
        
        response, status_code = await update_username()
        return Response(response, status=status_code)  

@method_decorator(csrf_exempt, name='dispatch')
class UploadProfileDocs(APIView):
    permission_classes = [IsAuthenticated]
    throttle_classes = [fileUploadthrottler]

    @circuit
    def post(self, request):
        return async_to_sync(self.async_post)(request)

    async def async_post(self, request):
        try:
            data = request.data
            scope = data['scope']
            
            if scope == 'ProfilePictureUpdate':
                return await self.handle_profile_picture_update(data)
            elif scope == 'GoogleAPICredentialFileUpload': # for linking new accounts
                return await self.handle_google_api_upload(data)
            elif scope == 'UploadRepositoryFile':
                return await self.handle_repository_upload(data)
            else:
                return Response(
                    {'failed': 'Invalid scope'},
                    status=status.HTTP_400_BAD_REQUEST
                )
                
        except Exception as e:
            print(f"Error in UploadProfileDocs: {str(e)}")
            return Response(
                {'failed': 'There was an issue processing your request'},
                status=status.HTTP_400_BAD_REQUEST
            )

    async def handle_profile_picture_update(self, data):
        emailval = sanitize_string(data['email'])
        x = await sync_to_async(Account.objects.filter)(email=emailval)
        account = await sync_to_async(x.first)()
        
        if not account.is_active:
            return Response(
                {'failed': 'This account is inactive. Kindly activate it using the link sent to this account email'},
                status=status.HTTP_400_BAD_REQUEST
            )

        file_name = sanitize_string(data['name'])
        splited_file_name = str(file_name).split('.')
        full_file_name = f'profile_picture.{splited_file_name[1]}'
        storage_name = f'/{emailval}/profile_picture.{splited_file_name[1]}'
        file_buffer = data['ProfilePicture']
        folder_name = str(emailval)
        folder_path = os.path.join(settings.MEDIA_ROOT, folder_name)
        profile_picture_path = os.path.join(settings.MEDIA_ROOT, folder_name, 'profile_picture')
        
        # Delete existing files
        await sync_to_async(self._delete_matching_files)(profile_picture_path)
        
        # Save new file
        
        if await sync_to_async(os.path.exists)(folder_path):
            custom_storage = FileSystemStorage(location=folder_path)
            await sync_to_async(self.save_uploaded_file)(custom_storage, full_file_name, file_buffer)
        
        await sync_to_async(x.update)(ProfilePic=storage_name)
        
        return Response({
                'success': 'Profile picture updated',
                'Scope': 'ProfilePictureUpdate',
            },status=status.HTTP_200_OK)

    async def handle_google_api_upload(self, data):
        emailval = sanitize_string(data['email'])
        x = await sync_to_async(Account.objects.filter)(email=emailval)
        account = await sync_to_async(x.first)()
        
        if not account.is_active:
            return Response(
                {'failed': 'This account is inactive. Kindly activate it using the link sent to this account email'},
                status=status.HTTP_400_BAD_REQUEST
            )

        file_name = sanitize_string(data['name'])
        file_buffer = data['file']
        folder_name = str(emailval)
        folder_path = os.path.join(settings.MEDIA_ROOT, folder_name)
        file_path = os.path.join(settings.MEDIA_ROOT, folder_name, file_name)

        # Delete existing file if it exists
        
        if await sync_to_async(os.path.exists)(file_path):
            try:
                await sync_to_async(os.remove)(file_path)
            except Exception as e:
                print(f"Error deleting file: {e}")
        
        # Save new file
        if await sync_to_async(os.path.exists)(folder_path):
            custom_storage = FileSystemStorage(location=folder_path)
            async with await sync_to_async(custom_storage.open)(file_name, 'wb') as f:
                file_data = await sync_to_async(file_buffer.read)()
                await sync_to_async(f.write)(file_data)
        
        # Update profile about
        xval = await sync_to_async(lambda: list(x.values()))()
        AboutBody = xval[0]['ProfileAbout'] if xval[0]['ProfileAbout'] else {}
        AboutBody['GoogleAPICredentialFile'] = file_name
        
        await sync_to_async(x.update)(ProfileAbout=AboutBody)
        AboutBody['Scope'] = 'GoogleAPICredentialFile'
        
        return Response(
            {
                'success': 'file uploaded successfully',
                'Scope': 'GoogleAPICredentialFileUpload',
                'AboutBody': AboutBody
            },
            status=status.HTTP_200_OK
        )

    async def handle_repository_upload(self, data):
        emailval = sanitize_string(data['email'])
        file_name = sanitize_string(data['name'])
        filesize = sanitize_string(data['size'])
        folderId = sanitize_string(data['folderId'])
        fileType = sanitize_string(data['fileType'])
        storage_name = f'/{emailval}/repository/{file_name}'
        file_buffer = data['file']
        folder_name = str(emailval)
        folder_path = os.path.join(settings.MEDIA_ROOT, folder_name)
        
        if not await sync_to_async(os.path.exists)(folder_path):
            return Response(
                {'failed': 'Seems like this account is invalid. Sign up to proceed'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        UserAccountRef = await sync_to_async(Account.objects.filter)(email=emailval)
        
        UserAccount = await sync_to_async(UserAccountRef.first)()
        
        max_space = await sync_to_async(UserAccount.get_max_storage_gb)()
        
        space_list = await sync_to_async(
            lambda: list(
                UserAccountRef.values_list('repository_space', flat=True)
            )
        )()
        
        space_consumed_value = space_list[0] if space_list else 0

        if space_consumed_value is not None and (space_consumed_value >= max_space or max_space == 0):
            return Response(
                {'type': 'error', 'result': 'Seems like your storage limit is reached. Upgrade subscription to get more'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Save file
        Post_folder_path = os.path.join(settings.MEDIA_ROOT, folder_name, 'repository')
        if not await sync_to_async(os.path.exists)(Post_folder_path):
            await sync_to_async(os.makedirs)(Post_folder_path)
        
        custom_storage = FileSystemStorage(location=Post_folder_path)
        await sync_to_async(self._save_file_to_storage)(custom_storage, file_name, file_buffer)
        
        # Create file record
        now = datetime.datetime.now()
        short_date = now.strftime("%d-%m-%Y")
        folderRef = await sync_to_async(FolderTable.objects.get)(id=folderId, account_email=UserAccount)
        
        await sync_to_async(FileTable.objects.create)(
            name=file_name,
            dateCreated=str(short_date),
            account_email=UserAccount,
            folder_id=folderRef,
            type=fileType,
            size=filesize,
            fileUrl=storage_name
        )
        
        # Calculate new storage size
        folder_path = os.path.join(settings.MEDIA_ROOT, emailval, 'repository')
        total_size = await sync_to_async(calculate_folder_size)(folder_path)
        size_gb = total_size / (1024 ** 3)
        percentage = 0 if max_space == 0 else min(100, (size_gb / max_space) * 100)
        
        await sync_to_async(UserAccountRef.update)(
            repository_space=size_gb,
            repository_space_percentage=percentage
        )
        
        fileData = await sync_to_async(lambda: folderRef.files.all().order_by('id'))()
        file_list = await sync_to_async(lambda: FileTableSerializer(fileData, many=True).data)()
        
        return Response(
            {
                'success': 'File uploaded successfully',
                'Scope': 'UploadRepositoryFile',
                'FileList': file_list,
                'storage_size': size_gb,
                'storage_size_percentage': percentage
            },
            status=status.HTTP_200_OK
        )

    def _delete_matching_files(self, base_path):
        """Helper method to delete matching files (sync version)"""
        matching_files = glob.glob(base_path + ".*")
        for file in matching_files:
            try:
                os.remove(file)
            except Exception as e:
                print(f"Error deleting {file}: {e}")

    def _save_file_to_storage(self, storage, filename, file_buffer):
        with storage.open(filename, 'wb') as f:
            f.write(file_buffer.read())

    def save_uploaded_file(self,storage, filename, file_buffer):
        with storage.open(filename, 'wb') as f:
            f.write(file_buffer.read())


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
            # Then call it:
            payment_method_val = 'M-pesa'
            payment = await complete_payment_transaction(
                account_ref,
                new_plan,
                payment_method_val,
                billing_cycle,
                amount_val,
                payment_result.get('transaction_id', '')
            )

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
    
@method_decorator(csrf_exempt, name='dispatch')
class ProcessStripePaymentView(APIView):
    """Handles both M-Pesa and Flutterwave payments with subscription upgrades"""
    permission_classes = [IsAuthenticated]
    throttle_classes = [csrfTokenThrottler]
    
    async def async_post(self, request):
        data = request.data
        email = sanitize_string(data.get('email'))
        plan_id = sanitize_string(data.get('plan_id'))
        billing_cycle = sanitize_string(data.get('billing_cycle', 'monthly'))

        try:
            # Validate required fields
            if not all([ plan_id, email]):
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

            
            amount_val = data['amount']
            payment_result = await self.process_stripe(
                payment_data=data,
                amount=amount_val,
                email=email
            )

            return Response({
                'success': True,
                'message': 'Authenticating the transaction',
                'user_data' : data,
                'data_stripe' : payment_result
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


    async def process_stripe(self, payment_data, amount, email):
        try:
            stripe.api_key, stripe_callback_url, frontend_url = await sync_to_async(get_stripe_secret_key)()
            
            intent = await sync_to_async(stripe.PaymentIntent.create)(
                amount=int(float(amount) * 100),
                currency='usd',
                payment_method=payment_data['payment_method_id'],
                # confirmation_method='manual',
                confirm=True,
                metadata={
                    'email': email,
                    'plan': 'subscription'
                },
                return_url=f"{frontend_url}/payment-complete",  # Point to frontend
                # return_url=stripe_callback_url,
                automatic_payment_methods={
                    'enabled': True,
                    'allow_redirects': 'never'  # Changed from 'never'
                }
            )
            
            # print(intent)
            # Modern status handling
            if intent.status == 'requires_action':
                return {
                    'success': True,  # Mark as success to trigger 3DS flow
                    'requires_3ds': True,
                    'client_secret': intent.client_secret,
                    'payment_intent_id': intent.id,
                    'url' : intent.next_action.redirect_to_url.url
                }
            # Handle other statuses
            return {
                'success': False,
                'error': f"Unexpected status: {intent.status}",
                'status': intent.status,
                'should_retry': intent.status in ['requires_payment_method', 'processing']
            }

        except stripe.error.StripeError as e:
            print(e)
            return {
                'success': False,
                'error': str(e.user_message) if hasattr(e, 'user_message') else "Payment processing failed",
                'stripe_error': getattr(e, 'code', type(e).__name__),
            }

    
    def post(self, request):
        return async_to_sync(self.async_post)(request)


redisConnection = settings.REDIS_CONNECTION
async def oauth_callback(request):
    state = request.GET.get('state')
    
    # Use sync_to_async for Redis KEYS
    matching_keys = await sync_to_async(redisConnection.keys)("oauth_flow:*")

    email = None
    data = None
    for key in matching_keys:
        raw_data = await sync_to_async(redisConnection.get)(key)
        data = json.loads(raw_data)
        if data["flow_state"] == state:
            email = data["email"]
            await sync_to_async(redisConnection.delete)(key)
            break

    if not email:
        return JsonResponse({'error': 'Invalid OAuth state or expired request'}, status=400)

    token_path = os.path.join(settings.MEDIA_ROOT, email, 'token.json')
    credential_file_path = data['client_secrets_file']

    # Still blocking: from_client_secrets_file — must wrap with sync_to_async
    flow = await sync_to_async(Flow.from_client_secrets_file)(
        credential_file_path,
        scopes=['https://www.googleapis.com/auth/youtube.upload'],
        redirect_uri=settings.GOOGLE_OAUTH_REDIRECT_URI
    )

    # Still blocking: fetch_token (Google API call)
    await sync_to_async(flow.fetch_token)(
        authorization_response=request.build_absolute_uri()
    )

    credentials = flow.credentials

    # ✅ Non-blocking file write using aiofiles
    import aiofiles
    async with aiofiles.open(token_path, 'w') as token_file:
        await token_file.write(credentials.to_json())

    return JsonResponse({'message': 'OAuth authentication successful!'})


@method_decorator(csrf_exempt, name='dispatch')
class MpesaCallbackView(APIView):
    """
    Handles M-Pesa STK Push callback
    URL: /api/mpesa/callback/
    """
    
    def post(self, request, *args, **kwargs):
        try:
            # Safaricom sends data as JSON in the request body
            callback_data = json.loads(request.body)
            
            logger.info(f"M-Pesa Callback Received: {callback_data}")
            print("Raw callback data:", request.body)
            # Extract key fields from callback
            result_code = callback_data.get('Body', {}).get('stkCallback', {}).get('ResultCode')
            merchant_request_id = callback_data.get('Body', {}).get('stkCallback', {}).get('MerchantRequestID')
            checkout_request_id = callback_data.get('Body', {}).get('stkCallback', {}).get('CheckoutRequestID')
            amount = callback_data.get('Body', {}).get('stkCallback', {}).get('CallbackMetadata', {}).get('Item', [{}])[0].get('Value')
            mpesa_receipt_number = callback_data.get('Body', {}).get('stkCallback', {}).get('CallbackMetadata', {}).get('Item', [{}])[1].get('Value')
            
            # Find the payment record
            try:
                payment = Payment.objects.get(transaction_id=merchant_request_id)
            except Payment.DoesNotExist:
                logger.error(f"Payment not found for MerchantRequestID: {merchant_request_id}")
                return JsonResponse({'status': 'error', 'message': 'Payment not found'}, status=404)
            
            # Update payment status based on result code
            if result_code == 0:
                payment.status = 'completed'
                payment.mpesa_receipt = mpesa_receipt_number
                payment.amount = amount  # Update with actual amount paid
                payment.save()
                
                # Trigger any post-payment actions (e.g., upgrade subscription)
                self.handle_successful_payment(payment)
                
                logger.info(f"Payment {payment.id} marked as completed")
            else:
                payment.status = 'failed'
                payment.save()
                logger.warning(f"Payment {payment.id} failed with result code: {result_code}")
            
            return JsonResponse({'status': 'success'})
            
        except json.JSONDecodeError:
            logger.error("Invalid JSON in M-Pesa callback")
            return JsonResponse({'status': 'error', 'message': 'Invalid JSON'}, status=400)
        except Exception as e:
            logger.exception("Error processing M-Pesa callback")
            return JsonResponse({'status': 'error', 'message': str(e)}, status=500)
    
    def handle_successful_payment(self, payment):
        """Handle successful payment (e.g., upgrade subscription)"""
        account = payment.account
        account.change_plan(
            new_plan=payment.plan,
            old_plan=account.current_plan,
            payment_method='mpesa',
            billing_cycle='monthly'  # Or get from payment data
        )


@method_decorator(csrf_exempt, name='dispatch')
class StripeCallbackView(APIView):
    """Handles verification of 3D Secure authentication status with timeout"""
    permission_classes = [IsAuthenticated]
    throttle_classes = [csrfTokenThrottler]
    
    async def async_post(self, request):
        data = request.data
        payment_intent_id = sanitize_string(data.get('payment_intent_id'))
        email = sanitize_string(data.get('email'))
        plan_id = sanitize_string(data.get('plan_id'))
        billing_cycle = sanitize_string(data.get('billing_cycle'))
        amount_val = sanitize_string(data.get('amount'))
        
        try:
            if not all([payment_intent_id, email, plan_id]):
                return Response(
                    {'success': False, 'error': 'Missing required fields'},
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            stripe.api_key, _, _ = await sync_to_async(get_stripe_secret_key)()
            start_time = datetime.datetime.now()
            timeout = datetime.timedelta(minutes=3)
            
            while datetime.datetime.now() - start_time < timeout:
                intent = await sync_to_async(stripe.PaymentIntent.retrieve)(payment_intent_id)
                
                if intent.status == 'succeeded':
                    account = await sync_to_async(Account.objects.filter)(email=email)
                    account_ref = await sync_to_async(account.first)()
                    new_plan = await sync_to_async(SubscriptionPlan.objects.get)(id=plan_id)
                    
                    payment_method_val = 'Card'
                    payment = await complete_payment_transaction(
                        account_ref,
                        new_plan,
                        payment_method_val,
                        billing_cycle,
                        amount_val,
                        payment_intent_id
                    )
                    return Response({
                        'success': True,
                        'completed': True,
                        'message': 'Payment successfully authenticated',
                        'payment_intent_status': intent.status
                    })
                
                elif intent.status == 'requires_payment_method':
                    # Failed state - don't continue polling
                    return Response({
                        'success': False,
                        'completed': False,
                        'error': '3D Secure authentication failed or was cancelled',
                        'payment_intent_status': intent.status
                    }, status=status.HTTP_400_BAD_REQUEST)
                
                # Wait 3 seconds before checking again
                await asyncio.sleep(3)
            
            # Timeout reached
            return Response({
                'success': False,
                'completed': False,
                'error': '3D Secure authentication timed out after 3 minutes',
                'payment_intent_status': 'timed_out'
            }, status=status.HTTP_408_REQUEST_TIMEOUT)
            
        except stripe.error.StripeError as e:
            print(e)
            return Response({
                'success': False,
                'error': str(e.user_message) if hasattr(e, 'user_message') else "Payment verification failed",
                'stripe_error': getattr(e, 'code', type(e).__name__),
            }, status=status.HTTP_400_BAD_REQUEST)
            
        except Exception as e:
            print(e)
            return Response(
                {'success': False, 'error': str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

    def post(self, request):        
        return async_to_sync(self.async_post)(request)   



class ProcessPaystackPaymentView(APIView):
    permission_classes = [IsAuthenticated]
    
    async def async_post(self, request):
        data = request.data
        try:
            print('called')
            secret_key, consumer_key, frontend_url = await sync_to_async(get_stripe_secret_key)()

            # Convert amount to smallest currency unit
            email = sanitize_string(data.get('email'))
            amount_val = sanitize_string(data.get('amount'))
            amount = int(float(amount_val) * 100)
            
            # Create Paystack transaction reference
            reference = f"PAYSTACK-{uuid.uuid4().hex}"
            print('initializing')
            # Initialize Paystack transaction
            response = Transaction.initialize(
                amount=amount,
                email=email,
                reference=reference,
                # currency='USD',  # or 'NGN'
                callback_url=f"{frontend_url}/payment-complete"
            )
            print('returning',response)
            return Response({
                'success': True,
                'data': {
                    'authorization_url': response['data']['authorization_url'],
                    'access_code': response['data']['access_code'],
                    'reference': reference,
                    'public_key': consumer_key
                }
            })
            
        except Exception as e:
            print(e)
            return Response({'success': False, 'error': 'An issue occured while initializing your transaction. Try again later'})
        
    def post(self, request):        
        return async_to_sync(self.async_post)(request) 

class VerifyPaystackPaymentView(APIView):
    permission_classes = [IsAuthenticated]
    
    async def async_post(self, request, reference):
        try:
            # Verify payment with Paystack
            response = Transaction.verify(reference)
            
            if response['data']['status'] == 'success':
                data = request.data
                payment_intent_id = sanitize_string(data.get('payment_intent_id'))
                email = sanitize_string(data.get('email'))
                plan_id = sanitize_string(data.get('plan_id'))
                billing_cycle = sanitize_string(data.get('billing_cycle'))
                amount_val = sanitize_string(data.get('amount'))
                account = await sync_to_async(Account.objects.filter)(email=email)

                account_ref = await sync_to_async(account.first)()
                new_plan = await sync_to_async(SubscriptionPlan.objects.get)(id=plan_id)
                
                payment_method_val = 'Card'
                payment = await complete_payment_transaction(
                    account_ref,
                    new_plan,
                    payment_method_val,
                    billing_cycle,
                    amount_val,
                    payment_intent_id
                )
                return Response({'success': True, 'data': response['data']})
                
            return Response({'success': False, 'error': 'Payment failed'})
            
        except Exception as e:
            return Response({'success': False, 'error': str(e)})
        
    def post(self, request):        
        return async_to_sync(self.async_post)(request) 


async def delete_file_async(file_path: str) -> None:
    """Asynchronously delete a file if it exists."""
    try:
        if await aios.path.exists(file_path):
            await aios.remove(file_path)
            print(f"File deleted: {file_path}")
    except Exception as e:
        print(f"Error deleting file {file_path}: {e}")

async def get_account(email: str) -> QuerySet:
    """Fetch account reference asynchronously"""
    return await sync_to_async(Account.objects.filter, thread_sensitive=True)(email=email)


def create_thumbnail(image_url, thumbnail_path, size=(1280, 720)):
    """Create thumbnail from a locally downloaded image file"""
    try:
        print('generating thumbnail')
        
        with Image.open(image_url) as img:
            if img.mode in ('RGBA', 'P'):
                img = img.convert('RGB')
                
            img.thumbnail(
                size,
                resample=Image.Resampling.LANCZOS  # Modern replacement for ANTIALIAS
            )
            img.save(thumbnail_path, "JPEG", quality=85)

        print('thumbnail generated')
        return True
    except Exception as e:
        print(f"Thumbnail error: {str(e)}")
        return False


@sync_to_async(thread_sensitive=False)
def resize_image(img_path, width, height):
    """Resize a single image (blocking, offloaded using sync_to_async)"""
    try:
        img = Image.open(img_path)
        img = img.resize((width, height), Image.Resampling.LANCZOS)
        img.save(img_path)
        print(f"Resized and saved: {img_path}")
    except Exception as e:
        print(f"Error resizing image {img_path}: {e}")

async def resize_images(image_paths, width, height):
    """Resize multiple images asynchronously and non-blockingly"""
    for img_path in image_paths:
        await resize_image(img_path, width, height)

async def Scriptize(script, audio_file_path,TTSVoice= "en-KE-AsiliaNeural"):
    """Asynchronously generate TTS audio."""
    tts = edge_tts.Communicate(script,TTSVoice )
    await tts.save(audio_file_path)  # Save the audio file asynchronously

@sync_to_async
def get_user_creation_track(account):
    return account.creation_track()

@sync_to_async
def increment_video_count(account):
    if account.daily_video_creations >= account.current_plan.max_creations:
        return False
    account.daily_video_creations += 1
    account.save()
    return True

@sync_to_async
def decrement_video_count(account):
    account.daily_video_creations -= 1
    account.save()

def get_audio_duration(audio_path):
    probe = ffmpeg.probe(audio_path)
    duration = float(probe['format']['duration'])
    return duration

@sync_to_async
def get_user_video_length(account):
    length = account.current_plan.video_length
    boost = account.current_plan.boost_speed
    result = int(length) * 60
    return int(result), int(boost)

@sync_to_async
def increment_image_count(account):
    if account.daily_audio_convertions >= account.current_plan.max_creations:
        return False
    account.daily_audio_convertions += 1
    account.save()
    return True

@method_decorator(csrf_exempt, name='dispatch')
class MergeView(APIView):
    permission_classes = [IsAuthenticated]
    throttle_classes = [fileUploadthrottler]

    @circuit
    def post(self, request):
        return async_to_sync(self.async_post)(request)

    async def async_post(self, request):
        async def event_stream():
            try:
                print("[DEBUG] Starting MergeView processing")
                data = request.data
                NumberOfRequestRetry = int(sanitize_string(data['NumberOfRequestRetry']))
                emailval = sanitize_string(data['email'])
                dataval = json.loads(data['data'])
                AudioScope = data['AudioScope']
                SocialMediaType = sanitize_string(data['SocialMediaType'])
                TTSVoice = sanitize_string(data['TTSVoice'])
                CreationStateval = json.loads(data['CreationState'])
                Transition = json.loads(data['Transition'])
                SelectedAnimation = json.loads(data['SelectedAnimation'])
                VideosType = sanitize_string(data['VideosType'])
                AudioModeScope = sanitize_string(data['AudioModeScope'])
                folder_path = os.path.join(settings.MEDIA_ROOT, emailval, SocialMediaType)
                feeds_path = os.path.join(settings.MEDIA_ROOT)
                
                print("[DEBUG] Checking account existence")
                accountref = await sync_to_async(Account.objects.filter)(email=emailval)
                account_exists = await sync_to_async(accountref.exists)()
                
                if not account_exists:
                    yield json.dumps({"failed": "This account does not exist. Login to proceed."}) + "\n"
                    return
                
                account = await sync_to_async(accountref.first)()
                if not account.is_active:
                    yield json.dumps({"failed": "This account is inactive. Kindly activate it using the link sent to this account email"}) + "\n"
                    return

                print("[DEBUG] Processing audio based on scope:", AudioScope)
                if AudioModeScope != 'RepositoryAudio':
                    if AudioScope == 'OneForAll':
                        audio_file = data['audio']
                        audio_name = data['audioName']

                        if not audio_file or not dataval or not SocialMediaType or SocialMediaType == '':
                            yield json.dumps({"error": "Missing required files"}) + "\n"
                            return

                        custom_storage = FileSystemStorage(location=folder_path)
                        custom_storage_audio_path = os.path.join(folder_path, audio_name)

                        await delete_file_async(custom_storage_audio_path)
                        if not await sync_to_async(custom_storage.exists)(audio_name):
                            await sync_to_async(custom_storage.save)(audio_name, audio_file)
                        
                        print("[DEBUG] Processing audio duration for OneForAll")
                        audio_clip = await sync_to_async(AudioFileClip)(custom_storage_audio_path)
                        audio_duration = await sync_to_async(lambda: audio_clip.duration)()
                        integered_audio_duration = int(audio_duration)
                        await sync_to_async(audio_clip.close)()
                        video_duration = str(datetime.timedelta(seconds=integered_audio_duration))[-5:]
                    elif AudioScope == 'AllForAll':
                        print("[DEBUG] Processing AllForAll audio files")
                        audio_files = request.data.getlist("audio")
                        if not audio_files or not SocialMediaType or SocialMediaType == '':
                            yield json.dumps({"error": "Missing required files"}) + "\n"
                            return

                        custom_storage_audio_list = []
                        audio_duration_list = []
                        video_duration_list = []
                        
                        for i, audio in enumerate(audio_files):
                            filename = os.path.join(folder_path, audio.name)
                            await delete_file_async(filename)
                            
                            print(f"[DEBUG] Saving audio file {i+1}/{len(audio_files)}")
                            async with aiofiles.open(filename, "wb") as destination:
                                for chunk in audio.chunks():
                                    await destination.write(chunk)
                            
                            custom_storage_audio_list.append(audio.name)                
                        
                            print(f"[DEBUG] Processing audio duration for file {i+1}")
                            audio_clip = await sync_to_async(AudioFileClip)(filename)
                            audio_duration = await sync_to_async(lambda: audio_clip.duration)()
                            audio_duration_list.append(audio_duration)
                            integered_audio_duration = int(audio_duration)
                            await sync_to_async(audio_clip.close)()
                            video_duration = str(datetime.timedelta(seconds=integered_audio_duration))[-5:]
                            video_duration_list.append(video_duration)
                    elif AudioScope == 'TextToSpeech':
                        print("[DEBUG] Processing TextToSpeech")
                        audio_files = request.data.getlist("audio")
                        if not audio_files or not SocialMediaType or SocialMediaType == '':
                            yield json.dumps({"error": "Your automated script seems empty. Try other options"}) + "\n"
                            return

                        audio_duration_list = []
                        custom_storage_audio_list = []
                        video_duration_list = []
                        
                        print("[DEBUG] Starting TTS processing")
                        tasks = []
                        for i, script in enumerate(audio_files):
                            splited_audio_name = f'transcripted_audio_{i}'
                            filename = f'{splited_audio_name}.mp3'
                            audio_file_path = os.path.join(folder_path, filename)
                            await delete_file_async(audio_file_path)
                            task = Scriptize(script, audio_file_path, TTSVoice)
                            tasks.append(task)
                            custom_storage_audio_list.append(filename)

                        print("[DEBUG] Running TTS tasks concurrently")
                        await asyncio.gather(*tasks)

                        print("[DEBUG] Processing TTS audio durations")
                        for i, filename in enumerate(custom_storage_audio_list):
                            full_path = os.path.join(folder_path, filename)
                            audio_clip = await sync_to_async(AudioFileClip)(full_path)
                            audio_duration = await sync_to_async(lambda: audio_clip.duration)()
                            audio_duration_list.append(audio_duration)
                            integered_audio_duration = int(audio_duration)
                            await sync_to_async(audio_clip.close)()
                            video_duration = str(datetime.timedelta(seconds=integered_audio_duration))[-5:]
                            video_duration_list.append(video_duration)
                else:
                  
                    print("[DEBUG] Processing AllForAll audio files")
                    audio_files = json.loads(data['audio'])

                    custom_storage_audio_list = []
                    audio_duration_list = []
                    video_duration_list = []
                    i_position = 0
                    for items in audio_files:
                        splitted_name = str(items['audio_path']).split('/repository/')
                        filename_name = splitted_name[1]
                        # print(filename)
                        filename = os.path.join(settings.MEDIA_ROOT,emailval,'repository',filename_name)
                        # print(audio_path)
                        custom_storage_audio_list.append(filename_name)                
                    
                        print(f"[DEBUG] Processing audio duration for file {i_position+1}")
                        audio_clip = await sync_to_async(AudioFileClip)(filename)
                        audio_duration = await sync_to_async(lambda: audio_clip.duration)()
                        audio_duration_list.append(audio_duration)
                        integered_audio_duration = int(audio_duration)
                        
                        await sync_to_async(audio_clip.close)()
                        video_duration = str(datetime.timedelta(seconds=integered_audio_duration))[-5:]
                        video_duration_list.append(video_duration)

                        i_position += 1

                position = 0
                response_url = []
                
                print("[DEBUG] Starting video processing loop")
                for items in dataval:

                    can_create = await increment_video_count(account)
                    if not can_create:
                        yield json.dumps({"LimitReached": f'Daily limit for video creations reached.({account.current_plan.max_creations}) video created today.'}) + "\n"
                        yield " " * 4096 + "\n"
                        await asyncio.sleep(0.2)
                        break

                    yield json.dumps({"progress": f"Processing {position + 1}/{len(dataval)} video"}) + "\n"
                    yield " " * 4096 + "\n"
                    await asyncio.sleep(0.1)

                    print("[DEBUG] Extracting image paths")
                    image_image_list = items.get("ImageList", "")
                    snippet_data = items.get("snippet", {})
                    feedsTitle = snippet_data.get("title",'Feed')
                    status_data = items.get("status", {})
                    
                    image_paths = [
                        os.path.normpath(os.path.join(settings.MEDIA_ROOT, emailval, 'youtube', item.get("name", "").strip())) 
                        for item in image_image_list if "name" in item
                    ]

                    if not image_paths:
                        yield json.dumps({"failed": "There were no images identified"}) + "\n"
                        return

                    print("[DEBUG] Preparing video parameters")
                    now = datetime.datetime.now()
                    short_date = now.strftime("%Y-%m-%dT%H:%M")
                    transition_duration = 1.0
                    framerate = 30
                    widthval = 1080 if VideosType == 'shorts' else 1920
                    heightval = 1920 if VideosType == 'shorts' else 1080
                    
                    if AudioScope == 'OneForAll':
                        current_audio_duration = audio_duration
                    else:
                        current_audio_duration = audio_duration_list[position]
                    
                    num_images = len(image_paths)
                    T = (current_audio_duration + (num_images - 1) * transition_duration) / num_images
                    d_val = int((T - transition_duration) * framerate)
                    
                    print("[DEBUG] Resizing images")
                    await resize_images(image_paths, widthval, heightval)
                    
                    print("[DEBUG] Creating feed record")
                    feedsData = {
                        "status": status_data,
                        "snippet": snippet_data,
                        'VideoLength': video_duration if AudioScope == 'OneForAll' else video_duration_list[position],
                        'DateCreated': str(short_date)
                    }
                    
                    feedRef = await self.process_video_creation(
                        account,
                        emailval,
                        feedsData,
                        VideosType,
                        feedsTitle,
                        image_paths,
                        folder_path,
                        feeds_path,
                        widthval,
                        heightval,
                        framerate,
                        Transition,
                        transition_duration,
                        T,
                        SelectedAnimation,
                        position,
                        response_url,
                        image_image_list,
                        AudioScope,
                        AudioModeScope,
                        custom_storage_audio_list if AudioScope in ['AllForAll', 'TextToSpeech'] else None,
                        os.path.join(folder_path, audio_name) if AudioScope == 'OneForAll' else None,
                        video_duration_list if AudioScope in ['AllForAll', 'TextToSpeech'] else None,
                        
                    )
                    
                    response_url.append(f'feeds/{feedRef.id}.mp4')
                    position += 1
                    track_data = await get_user_creation_track(account)
                    responseval_progress = {
                        "progress": f"Completed {position}/{len(dataval)} video.",
                        'percentage': math.floor(int(position) / len(dataval) * 100),
                        'video_track' : track_data
                    }
                    yield json.dumps(responseval_progress) + "\n"
                    yield " " * 4096 + "\n"

                print("[DEBUG] Updating creation state")
                await self.update_creation_state(account, CreationStateval, response_url)
                
                final_response = {
                    'success': 'Your video is successfully created',
                    "video_url": response_url
                }
                yield json.dumps(final_response) + "\n"
            
            except RetryCustomError as e:
                print("[ERROR] RetryCustomError caught:", e)
                await decrement_video_count(account)
                responseval = {
                    'type': e.retry,
                    'scope': 'MergeVideo',
                    'retry': 'retry',
                    'result': e.message,
                    'NumberOfRequestRetry': NumberOfRequestRetry
                }
                yield json.dumps(responseval) + "\n"
            except Exception as e:
                await decrement_video_count(account)

                print("[ERROR] Exception in MergeView:", str(e))
                responseval = {'failed': 'Error occurred when processing your request '}
                yield json.dumps(responseval) + "\n"

        response = StreamingHttpResponse(event_stream(), content_type="application/json")
        response['Cache-Control'] = 'no-cache'
        response["X-Accel-Buffering"] = "no"
        return response

    async def process_video_creation(self, account,emailval, feedsData, VideosType, feedsTitle, 
        image_paths, folder_path, feeds_path,
        width, height, framerate, transitions, 
        transition_duration, clip_duration, SelectedAnimation,
        position, response_url, image_list, AudioScope, AudioModeScope,
        custom_storage_audio_list=None, custom_storage_audio_path=None, video_duration_list=None):
        """Handle the video creation process"""
        print('[DEBUG] Starting video creation process')
        
        # Define the synchronous function we'll wrap
        
        def _sync_video_creation(video_length,boost_speed):
            print('[DEBUG] Inside atomic transaction (sync context)')
            with transaction.atomic():
                print('[DEBUG] Creating feed record in DB',custom_storage_audio_list)
                feedRef = Feeds.objects.create(
                    account_email=account,
                    video='',
                    Data=feedsData,
                    thumbnail='',
                    privacyStatus='public',
                    videoType=str(VideosType),
                    title=str(feedsTitle)
                )

                # Define paths
                if AudioModeScope == 'RepositoryAudio':
                    if AudioScope == 'AllForAll' :
                        audio_path_val = os.path.join(settings.MEDIA_ROOT,emailval,'repository',custom_storage_audio_list[position])
                    else:
                        audio_path_val = os.path.join(settings.MEDIA_ROOT,emailval,'repository',custom_storage_audio_list[0])
                else:
                    if AudioScope == 'AllForAll' or AudioScope == 'TextToSpeech':
                        audio_path_val = os.path.join(folder_path, custom_storage_audio_list[position])
                    else:
                        audio_path_val = custom_storage_audio_path

                custom_feeds_video_name = os.path.join('feeds', f'{feedRef.id}.mp4')
                final_video = os.path.join(feeds_path, custom_feeds_video_name)
                
                print('[DEBUG] Deleting existing files if they exist')
                
                if os.path.exists(final_video):
                    os.remove(final_video)

                print('[DEBUG] Starting FFmpeg processing')
                # Process video creation
                self._create_video_with_ffmpeg(
                    image_paths, audio_path_val, final_video, 
                    width, height, framerate, transitions,
                    transition_duration, clip_duration, SelectedAnimation, VideosType,
                    video_length,boost_speed
                )

                print('[DEBUG] Updating feed with video path')
                feedRef.video = custom_feeds_video_name
                
                print('[DEBUG] Generating thumbnail')
                if image_list and image_list[0]['name']:
                    image_url = os.path.join(folder_path, image_list[0]['name'])
                    thumbnail_name = os.path.join('feeds', f"{feedRef.id}_thumbnail.jpg")
                    thumbnail_path = os.path.join(feeds_path, thumbnail_name)
                    
                    result = create_thumbnail(image_url, thumbnail_path)
                    print('Thumbnail result is:', result)
                    if result:
                        feedRef.thumbnail = thumbnail_name
                    else:
                        fallback_thumbnail = os.path.join('feeds', "fallback_thumbnail.jpg")
                        feedRef.thumbnail = fallback_thumbnail

                print('[DEBUG] Saving feed record')
                feedRef.save()
                return feedRef

        print('[DEBUG] About to execute sync_to_async for video creation')
        try:
            video_length, boost_speed = await get_user_video_length(account)
            feedRef = await sync_to_async(_sync_video_creation)(video_length,boost_speed)
            print('[DEBUG] Successfully completed video creation')
            return feedRef
        except Exception as e:
            print(f'[ERROR] Failed to process video creation: {str(e)}')
            raise

    def _create_video_with_ffmpeg(self, image_paths, audio_path, final_video, 
            widthval, heightval, framerate, transitions, 
            transition_duration, clip_duration, SelectedAnimation, VideosType,
            video_length,boost_speed = 1):
        """Synchronous FFmpeg processing"""
        print('[DEBUG] Starting FFmpeg processing')
        streams = []
        T = clip_duration
        d_val = int((T - transition_duration) * framerate) 
        animationInitialPosition = 0
        
        print('[DEBUG] Creating image streams')
        for i, img in enumerate(image_paths):
            print(f'Processing image {i+1}/{len(image_paths)}: {img}')
            stream = ffmpeg.input(
                img.replace("\\", "/"),
                loop=1,
                t=T,
                thread_queue_size=512
            ).video
            
            stream = stream.filter('scale', widthval, heightval).filter('fps', fps=framerate)
            
            if SelectedAnimation:
                effect = SelectedAnimation[animationInitialPosition]
                
                if effect == 'zoom_in':
                    zoom_expr = f'if(lte(on,{d_val}),1.0 + (0.3*on/{d_val}),1.3)'
                    stream = stream.filter('zoompan', 
                        zoom=zoom_expr,
                        x=f'iw/2-(iw/zoom/2)',
                        y=f'ih/2-(ih/zoom/2)',
                        d=transition_duration,
                        s=f"{widthval}x{heightval}",
                        fps=framerate)
                elif effect == 'zoom_out':
                    zoom_expr = f'if(lte(on,{d_val}),1.3 - (0.3*on/{d_val}),1.0)'
                    stream = stream.filter('zoompan',
                        zoom=zoom_expr,
                        x=f'iw/2-(iw/zoom/2)',
                        y=f'ih/2-(ih/zoom/2)',
                        d=transition_duration,
                        s=f"{widthval}x{heightval}",
                        fps=framerate)
                
                if animationInitialPosition >= len(SelectedAnimation) - 1:
                    animationInitialPosition = 0
                else:
                    animationInitialPosition += 1

            streams.append(stream)
        
        print('[DEBUG] Chaining streams with transitions')
        output_stream = streams[0].filter('fps', fps=framerate)
        trans_choice_index = 0
        
        for i in range(1, len(streams)):
            offset = i * (T - transition_duration)
            Transition_value = transitions
            
            if len(Transition_value) > 1:
                if trans_choice_index >= len(Transition_value):
                    trans_choice_index = 0
                    transition_selected = Transition_value[0]
                else:
                    transition_selected = Transition_value[trans_choice_index]
                    trans_choice_index += 1
            else:
                transition_selected = Transition_value[0] if Transition_value else 'fade'

            scaled_stream = streams[i].filter('scale', widthval, heightval).filter('fps', fps=framerate)
            
            output_stream = ffmpeg.filter(
                [output_stream, scaled_stream],
                'xfade',
                transition=transition_selected,
                duration=transition_duration,
                offset=offset
            ).filter('fps', fps=framerate)
        
        print('[DEBUG] Adding audio stream')
        audio_stream = ffmpeg.input(audio_path)
    
        print('[DEBUG] Building final output')
        final_output = ffmpeg.output(
            output_stream,
            audio_stream,
            final_video,
            vcodec='libx264',
            acodec='aac',
            pix_fmt='yuv420p',
            preset='veryfast',
            threads=boost_speed,
            movflags='+faststart',
            r=framerate,
            t=video_length              # ← stop at desired seconds
        )
        
        print('[DEBUG] Running FFmpeg command')
        ffmpeg.run(final_output, overwrite_output=True)
        print('[DEBUG] FFmpeg processing completed')

    async def update_creation_state(self, account, CreationStateval, response_url):
        """Update the creation state manager"""
        print('[DEBUG] Updating creation state')
        try:
            creation_data = await sync_to_async(
                lambda: CreationStateManager.objects.filter(account_email=account).values('data').first()
            )()
            
            state_manager_dataval = creation_data.get('data', {}) if creation_data else {}
            state_manager_dataval = {} if state_manager_dataval == None else state_manager_dataval
            PostContentContainerval = CreationStateval.get('PostContentContainer',{})
            AiPageval = CreationStateval.get('AiPage','')
            RequestKindval = 'MergeView'
            
            state_manager_dataval['MergeViewData'] = response_url
            now = datetime.datetime.now()
            short_date = now.strftime("%Y-%m-%dT%H:%M")

            await sync_to_async(CreationStateManager.objects.update_or_create)(
                account_email=account,
                defaults={
                    'PostContentContainer': PostContentContainerval,
                    'dateModified': str(short_date),
                    'data': state_manager_dataval,
                    'AiPage': AiPageval,
                    'RequestKind': RequestKindval
                }
            )
            print('[DEBUG] Creation state updated successfully')
        except Exception as e:
            print(f'[ERROR] Error updating creation state: {e}')


@method_decorator(csrf_exempt, name='dispatch')
class MergeAudioToVideoView(APIView):
    permission_classes = [IsAuthenticated]
    throttle_classes = [fileUploadthrottler]

    @circuit
    def post(self, request):
        return async_to_sync(self.async_post)(request)

    async def async_post(self, request):
        async def event_stream():
            try:
                data = request.data
                NumberOfRequestRetry = int(sanitize_string(data['NumberOfRequestRetry']))
                emailval = sanitize_string(data['email'])
                dataval = json.loads(data['data'])
                CreationStateval = json.loads(data['CreationState'])
                SocialMediaType = sanitize_string(data['SocialMediaType'])
                AudioModeScope = sanitize_string(data['AudioModeScope'])
                Transition = json.loads(data['Transition'])
                SelectedAnimation = json.loads(data['SelectedAnimation'])
                folder_path = os.path.join(settings.MEDIA_ROOT, emailval, SocialMediaType)
                feeds_path = os.path.join(settings.MEDIA_ROOT)
                
                accountref = await sync_to_async(Account.objects.filter)(email=emailval)
                account_exists = await sync_to_async(accountref.exists)()
                
                if not account_exists:
                    yield json.dumps({"failed": "This account does not exist. Login to proceed."}) + "\n"
                    return
                
                account = await sync_to_async(accountref.first)()
                if not account.is_active:
                    yield json.dumps({"failed": "This account is inactive. Kindly activate it using the link sent to this account email"}) + "\n"
                    return

                position = 0
                response_url = []
               
                for items in dataval:
                    
                    can_create = await increment_video_count(account)
                    if not can_create:
                        yield json.dumps({"LimitReached": f'Daily limit for video creations reached.({account.current_plan.max_creations}) video created today.'}) + "\n"
                        yield " " * 4096 + "\n"
                        await asyncio.sleep(0.2)
                        break

                    yield json.dumps({"progress": f"Processing {position + 1}/{len(dataval)} video"}) + "\n"
                    yield " " * 4096 + "\n"
                    await asyncio.sleep(0.1)  # Async sleep instead of time.sleep

                    # Extract data
                    image_image_list = items.get("ImageList", "")
                    snippet_data = items.get("snippet", {})
                    feedsTitle = snippet_data.get("title",'Feed')
                    status_data = items.get("status", {})
                    videoType_list = items.get("videoType", 'shorts')
                    videoType = videoType_list
                    audio_name = items.get("audio", "fallback.mp3")
                    
                    image_paths = [
                        os.path.normpath(os.path.join(settings.MEDIA_ROOT, emailval, SocialMediaType, item.get("name", "").strip())) 
                        for item in image_image_list if "name" in item
                    ]

                    if not image_paths:
                        yield json.dumps({"failed": "There were no images identified"}) + "\n"
                        return

                    # Process audio
                    if AudioModeScope == 'RepositoryAudio':
                        splitted_name = str(audio_name).split('/repository/')
                        filename = splitted_name[1]
                        # print(filename)
                        custom_storage_audio_path = os.path.join(settings.MEDIA_ROOT,emailval,'repository',filename)
                    else:
                        custom_storage_audio_path = os.path.join(folder_path, audio_name)
                    audio_clip = await sync_to_async(AudioFileClip)(custom_storage_audio_path)
                    audio_duration = await sync_to_async(lambda: audio_clip.duration)()
                    integered_audio_duration = int(audio_duration)
                    await sync_to_async(audio_clip.close)()
                    video_duration = str(datetime.timedelta(seconds=integered_audio_duration))[-5:]
                    
                    now = datetime.datetime.now()
                    short_date = now.strftime("%Y-%m-%dT%H:%M")
                    transition_duration = 1.0
                    T = (audio_duration + (len(image_paths) - 1) * transition_duration) / len(image_paths)
                    
                    # Process images
                    widthval = 1080 if videoType == 'shorts' else 1920
                    heightval = 1920 if videoType == 'shorts' else 1080 
                    framerate = 30
                    
                    await resize_images(image_paths, widthval, heightval)
                    
                    # FFmpeg processing would remain synchronous as it's an external process
                    # This part would need to be offloaded to a task queue for true async
                    # For now, we'll keep it synchronous but wrapped in sync_to_async
                    
                    # Create feed record
                    feedsData = {
                        "status": status_data,
                        "snippet": snippet_data,
                        'VideoLength': video_duration,
                        'DateCreated': str(short_date)
                    }
                    
                    feedRef = await self.process_video_creation(
                        account,
                        feedsData,
                        videoType,
                        feedsTitle,
                        image_paths,
                        custom_storage_audio_path,
                        feeds_path,
                        folder_path,
                        widthval,
                        heightval,
                        framerate,
                        Transition,
                        transition_duration,
                        T,
                        SelectedAnimation,
                        position,
                        response_url,
                        image_image_list
                    )
                    
                    response_url.append(f'feeds/{feedRef.id}.mp4')
                    position += 1
                    track_data = await get_user_creation_track(account)
                    responseval_progress = {
                        "progress": f"Completed {position}/{len(dataval)} video.",
                        'percentage' : math.floor(int((position) / len(dataval) * 100)),
                        'video_track' : track_data
                    }
                    yield json.dumps(responseval_progress) + "\n"
                    yield " " * 4096 + "\n"

                # Update creation state
                await self.update_creation_state(account, CreationStateval, response_url)
                
                final_response = {
                    'success': 'Your video is successfully created',
                    "video_url": response_url
                }
                yield json.dumps(final_response) + "\n"
            
            except Exception as e:
                await decrement_video_count(account)
                print(f"Error in video processing: {str(e)}")
                responseval = {'failed': 'Error occurred when processing your request'}
                yield json.dumps(responseval) + "\n"

        response = StreamingHttpResponse(event_stream(), content_type="application/json")
        response['Cache-Control'] = 'no-cache'
        response["X-Accel-Buffering"] = "no"
        return response

    async def process_video_creation(self, account, feedsData, videoType, feedsTitle, 
        image_paths, audio_path, feeds_path, folder_path,
        width, height, framerate, transitions, 
        transition_duration, clip_duration, SelectedAnimation, 
        position, response_url, image_list):
        """Handle the video creation process"""
        print('[DEBUG] Starting video creation process')
        progress_queue = asyncio.Queue()
        # Define the synchronous function we'll wrap
        def _sync_video_creation(video_length,boost_speed):
            print('[DEBUG] Inside atomic transaction (sync context)☀️',boost_speed)
            
            with transaction.atomic():
                print('[DEBUG] Creating feed record in DB')
                feedRef = Feeds.objects.create(
                    account_email=account,
                    video='',
                    Data=feedsData,
                    thumbnail='',
                    privacyStatus='public',
                    videoType=str(videoType),
                    title=str(feedsTitle)
                )

                # Define paths
                custom_videos_name = f'merge_audio_to_video_{position}'
                video_no_audio = os.path.join(folder_path, f'{custom_videos_name}_no_audio.mp4')
                custom_feeds_video_name = os.path.join('feeds', f'{feedRef.id}.mp4')
                final_video = os.path.join(feeds_path, custom_feeds_video_name)

                print('[DEBUG] Deleting existing files if they exist')
                # Delete existing files
                if os.path.exists(video_no_audio):
                    os.remove(video_no_audio)
                if os.path.exists(final_video):
                    os.remove(final_video)

                print('[DEBUG] Starting FFmpeg processing')
                # Process video creation
                self._create_video_with_ffmpeg(
                    image_paths, audio_path, final_video, 
                    width, height, framerate, transitions,
                    transition_duration, clip_duration, SelectedAnimation, videoType,
                    video_length,boost_speed
                )

                # Update feed with video path
                print('[DEBUG] Updating feed with video path')
                feedRef.video = custom_feeds_video_name
                
                # Generate thumbnail
                if image_list and image_list[0]['name']:
                    image_url = os.path.join(folder_path, image_list[0]['name'])
                    thumbnail_name = os.path.join('feeds', f"{feedRef.id}_thumbnail.jpg")
                    thumbnail_path = os.path.join(feeds_path, thumbnail_name)
                    
                    print('[DEBUG] Generating thumbnail')
                    result =  create_thumbnail(image_url, thumbnail_path)
                    print('thumbnail result is:',result)
                    if result:
                        feedRef.thumbnail = thumbnail_name
                    else:
                        fallback_thumbnail = os.path.join('feeds', "fallback_thumbnail.jpg")
                        feedRef.thumbnail = fallback_thumbnail

                print('[DEBUG] Saving feed record')
                feedRef.save()
                return feedRef

        print('[DEBUG] About to execute sync_to_async for video creation')
        try:
            video_length, boost_speed = await get_user_video_length(account)
            
            feedRef = await sync_to_async(_sync_video_creation)(video_length,boost_speed)


            print('[DEBUG] Successfully completed video creation')
            return feedRef
        except Exception as e:
            print(f'[ERROR] Failed to process video creation: {str(e)}')
            raise
    
    def _create_video_with_ffmpeg(self, image_paths, audio_path, final_video, 
        widthval, heightval, framerate, transitions, 
        transition_duration, clip_duration, SelectedAnimation,videoType,video_length,boost_speed=1):
        
        streams = []
        T = clip_duration
        d_val = int((T - transition_duration) * framerate) 
        animationInitialPosition =  0

        for i, img in enumerate(image_paths):
            print(f'\n\n Image path {img}')
            # yield json.dumps({"progress": f"Processing image"}) + "\n"
            # yield " " * 4096  + "\n"
            stream = ffmpeg.input(
                img.replace("\\", "/"),
                loop=1,
                t=T,
                thread_queue_size=512  # Better for batch processing
                ).video
            
            stream = stream.filter('scale', widthval, heightval).filter('fps', fps=framerate)  # ✅ Resize after FPS normalization
            if SelectedAnimation:
                effect = SelectedAnimation[animationInitialPosition]
                
                if effect == 'zoom_in':
                    # Linear zoom in over d_val frames, then static
                    zoom_expr =  f'if(lte(on,{d_val}),1.0 + (0.3*on/{d_val}),1.3)'
                    stream = stream.filter('zoompan', 
                        zoom=zoom_expr,
                        x=f'iw/2-(iw/zoom/2)',  # Center x
                        y=f'ih/2-(ih/zoom/2)',  # Center y
                        d=transition_duration,
                        s=f"{widthval}x{heightval}",
                        fps=framerate)
                elif effect == 'zoom_out':
                    # Linear zoom out over d_val frames, then static
                    zoom_expr = f'if(lte(on,{d_val}),1.3 - (0.3*on/{d_val}),1.0)'
                    stream = stream.filter('zoompan',
                        zoom=zoom_expr,
                        x=f'iw/2-(iw/zoom/2)',  # Center x
                        y=f'ih/2-(ih/zoom/2)',  # Center y
                        d=transition_duration,
                        s=f"{widthval}x{heightval}",
                        fps=framerate)
                if animationInitialPosition >= len(SelectedAnimation) - 1:
                    animationInitialPosition = 0
                else:
                    animationInitialPosition += 1

            streams.append(stream)
        
        
        # Chain the streams using xfade.
        output_stream = streams[0].filter('fps', fps=framerate)
        trans_choice_index = 0
        
        for i in range(1, len(streams)):
            
            offset = i * (T - transition_duration)
            Transition_value = transitions
            
            if len(Transition_value) > 1:
                if trans_choice_index >= len(Transition_value):
                    trans_choice_index = 0
                    transition_selected = Transition_value[0]
                else:
                    transition_selected = Transition_value[trans_choice_index]
                    trans_choice_index += 1
            else:
                transition_selected = Transition_value[0] if Transition_value else 'fade'  # ✅ Fix: Use 'fade' if empty

            scaled_stream = streams[i].filter('scale', widthval, heightval).filter('fps', fps=framerate)
            
            output_stream = ffmpeg.filter(
                [output_stream, scaled_stream],
                'xfade',
                transition=transition_selected,           # change to any supported effect, e.g. 'wipeleft'
                duration=transition_duration,
                offset=offset
            ).filter('fps', fps=framerate)  # ✅ Apply FPS immediately after xfade
        
        print('\n\n Image streams generated:',videoType,video_length) 
        
        """Synchronous FFmpeg processing"""
        audio_stream = ffmpeg.input(audio_path)
        audio_length = get_audio_duration(audio_path)
        predicted_video_length = audio_length if audio_length < video_length else video_length
       

        process = (
            ffmpeg.output(
                output_stream,
                audio_stream,
                final_video,
                vcodec='libx264',
                acodec='aac',
                pix_fmt='yuv420p',
                preset='veryfast',
                threads=boost_speed,
                movflags='+faststart',
                r=framerate,
                t=video_length              # ← stop at desired seconds
            )
            .global_args('-progress', 'pipe:1')  # Enable progress output
            .run_async(
                pipe_stderr=True,  # Capture stderr for progress
                overwrite_output=True
            )
        )
         # 3. Parse progress in real-time
        while True:
            stderr_line = process.stderr.readline().decode('utf-8')
            if stderr_line == '' and process.poll() is not None:
                break  # FFmpeg finished

            # Extract progress percentage
            progress = self.parse_ffmpeg_progress(stderr_line, float(predicted_video_length))
            
            if progress :
                
                print('progress: ',progress,'  : predicted length',predicted_video_length)

        process.wait()  # Ensure FFmpeg completes

    def parse_ffmpeg_progress(self, stderr_line, total_duration):
        if total_duration <= 0:
            return 0
        
        # Extract time in HH:MM:SS.ms format
        time_match = re.search(r"time=(\d{2}:\d{2}:\d{2}\.\d{2})", stderr_line)
        if not time_match:
            return None
        
        try:
            # Parse hours, minutes, seconds
            hh_mm_ss = time_match.group(1)
            h, m, s = map(float, hh_mm_ss.split(':'))
            current_time = h * 3600 + m * 60 + s  # Convert to seconds
            
            # Calculate percentage (clamped to 0-100)
            progress = (current_time / total_duration) * 100
            return min(100, max(0, int(progress)))
        
        except (ValueError, IndexError):
            return None



    async def update_creation_state(self, account, CreationStateval, response_url):
        """Update the creation state manager"""
        try:
            creation_data = await sync_to_async(
                lambda: CreationStateManager.objects.filter(account_email=account).values('data').first()
            )()
            
            state_manager_dataval = creation_data.get('data', {}) if creation_data else {}
            state_manager_dataval = {} if state_manager_dataval == None else state_manager_dataval
            PostContentContainerval = CreationStateval.get('PostContentContainer',{})
            AiPageval = CreationStateval.get('AiPage','')
            RequestKindval = 'MergeAudioToVideo'
            
            state_manager_dataval['MergeAudioToVideoData'] = response_url
            now = datetime.datetime.now()
            short_date = now.strftime("%Y-%m-%dT%H:%M")

            await sync_to_async(CreationStateManager.objects.update_or_create)(
                account_email=account,
                defaults={
                    'PostContentContainer': PostContentContainerval,
                    'dateModified': str(short_date),
                    'data': state_manager_dataval,
                    'AiPage': AiPageval,
                    'RequestKind': RequestKindval
                }
            )
        except Exception as e:
            print(f'Error updating creation state: {e}')

    
async def transcribe_and_split_audio_api(account,audio_list, num_splits):
    print("[DEBUG] Starting transcription for", len(audio_list), "audio files")
    transcriptions = []
    full_transciptions = []
    i_position = 0
    try:
        for position, items in enumerate(audio_list, 1):

            if isinstance(num_splits, list):
                image_number = num_splits[i_position]
            else:
                image_number = num_splits


            print(f"[DEBUG] Processing audio {position}/{len(audio_list)}")
            audio_name = items.get('audio_name','fallback.mp3')
            audio_path = items.get('audio_path','fallback.mp3')
            
            # print("[DEBUG] Transcribing with Whisper:", audio_name)
            can_create = await increment_image_count(account=account)
            if not can_create:
                data={"Scope": "LimitReached", "details": f'Daily limit for audio transcription reached.({account.current_plan.max_creations}) audio transcribed today. You may proceed with the once processed.'},
                if i_position == 0:
                    raise Exception(f'Daily limit for audio transcription reached.{account.current_plan.max_creations} audio transcribed today. Try other audio creation mode.')
                
                return [transcriptions, full_transciptions,data]
                
            transcript = WhisperTranscriber.transcribe_audio(audio_path) 
            
            # print('⬇️⬇️',transcript)
            if not transcript:
                print("[WARNING] Empty transcript for", audio_name)
                continue

            full_transciptions.append(transcript)
            print("[DEBUG] Splitting transcript into", image_number, "parts")
            words = textwrap.wrap(transcript, width=len(transcript)//image_number)
            
            tranascipt_list = []
            base_name = str(audio_name).split('.mp3')[0]
            
            for i, words_parts in enumerate(words):
                tranascipt_list.append({
                    "name": f'{i}_{base_name}.jpg',
                    "description": str(words_parts),
                    'created': False
                })
            
            transcriptions.append(tranascipt_list)
            i_position += 1
            print(f"[DEBUG] Completed audio {position} processing")

        print("[DEBUG] Transcription completed successfully")
        data={"Scope": "success"}
        return [transcriptions, full_transciptions,data]
        
    except Exception as e:
        print(f"[ERROR] Transcription failed for {items}: {str(e)}")
        raise Exception(e)

@method_decorator(csrf_exempt, name='dispatch')
class UploadAudioToVideoAudiosView(APIView):
    permission_classes = [IsAuthenticated]
    throttle_classes = [AiTokenThrottler]

    @circuit
    def post(self, request):
        return async_to_sync(self.async_post)(request)

    async def async_post(self, request):
        async def event_stream():
            try:
                print("[DEBUG] Starting UploadAudioToVideoAudios processing")
                data = request.data
                emailval = sanitize_string(data['email'])
                NumberOfRequestRetry = int(sanitize_string(data['NumberOfRequestRetry']))
                SocialMediaType = sanitize_string(data['SocialMediaType'])
                audio_files = request.data.getlist("audio")
                NumberOfScripts = sanitize_string(data['NumberOfImages'])
                folder_path = os.path.join(settings.MEDIA_ROOT, emailval, SocialMediaType)
                stateData = json.loads(data['stateData'])
                NumberOfImagesList = json.loads(data['NumberOfImagesList'])
                ContentDetailsState = {
                    'NumberOfImages' : NumberOfImagesList
                }

                print("[DEBUG] Checking/creating folder")
                if not await sync_to_async(os.path.exists)(folder_path):
                    await sync_to_async(os.mkdir)(folder_path)
                else:
                    await sync_to_async(shutil.rmtree)(folder_path)
                    await sync_to_async(os.mkdir)(folder_path)
                
                print("[DEBUG] Checking account")
                accountref = await sync_to_async(Account.objects.filter)(email=emailval)
                account_exists = await sync_to_async(accountref.exists)()
                
                if not account_exists or emailval == 'gestuser@gmail.com':
                    responseval = {'failed': 'This account does not exist. Login to proceed.'}
                    yield json.dumps(responseval) + "\n"
                    return
                
                account = await sync_to_async(accountref.first)()
                if not account.is_active:
                    responseval = {'failed': 'This account is inactive. Kindly activate it using the link sent to this account email'}
                    yield json.dumps(responseval) + "\n"
                    return
                
                if not audio_files or not SocialMediaType or SocialMediaType == '':
                    yield json.dumps({'failed': 'Missing required files'}) + "\n"
                    return
                
                print("[DEBUG] Processing audio files")
                custom_storage_audio_list = []
                video_type_list = []
                
                for i, audio in enumerate(audio_files):
                    print(f"[DEBUG] Processing audio {i+1}/{len(audio_files)}")
                    filename = os.path.join(folder_path, audio.name)
                    await delete_file_async(filename)
                    
                    # Async file saving
                    async with aiofiles.open(filename, "wb") as destination:
                        for chunk in audio.chunks():
                            await destination.write(chunk)
                    
                    dataval = {
                        "audio_name": audio.name,
                        "audio_path": filename
                    }
                    custom_storage_audio_list.append(dataval)
                    
                    try:
                        print(f"[DEBUG] Analyzing audio duration for file {i+1}")
                        audio_clip = await sync_to_async(AudioFileClip)(filename)
                        audio_duration = await sync_to_async(lambda: audio_clip.duration)()
                        videoType = 'shorts' if int(audio_duration) <= 60 else 'video'
                        await sync_to_async(audio_clip.close)()
                    except Exception as e:
                        print(f"[WARNING] Error analyzing audio duration: {str(e)}")
                        videoType = 'shorts'
                    
                    video_type_list.append(videoType)
                    print(f'saved audio {i+1}/{len(audio_files)} audios. Type {videoType}')
                    
                    progress = {
                        "progress": f"saved audio {i+1}/{len(audio_files)} audios",
                        "current": i+1,
                        "total": len(audio_files)
                    }
                    yield json.dumps(progress) + "\n"
                    await asyncio.sleep(0.1)  # Prevent blocking
                
                print('\n\nBEGINNING TRANSCRIPTION 🚩🚩🚩🚩🚩🚩🚩🚩🚩🚩\n\n')
                yield json.dumps({"progress": "Transcribing your audio(s)"}) + "\n"
                
                try:
                    print("[DEBUG] Starting transcription")
                    # Call your transcription function (now properly async)
                    tranascipt_data = await transcribe_and_split_audio_api(
                        account,
                        custom_storage_audio_list, 
                        int(NumberOfScripts)
                    )
                    print("[DEBUG] Received transcription data:", 
                        len(tranascipt_data), "processed segments")
                except Exception as e:
                    print(f"[ERROR] Transcription failed: {str(e)}")
                    raise RetryCustomError("retry", str(e))

                print('\n\nTRANSCRIPTION FINISHED 🚩🚩🚩🚩🚩🚩🚩🚩\n\n', tranascipt_data[0] if tranascipt_data else None)
                
                if tranascipt_data is None or len(tranascipt_data[0]) == 0:
                    responseval = {'failed': 'Seems like we cannot transcribe your data now'}
                    yield json.dumps(responseval) + "\n"
                    return
                
                
                await self.update_creation_state(account, stateData, custom_storage_audio_list,ContentDetailsState)
                final_response = {
                    'success': 'Successfully transcribed your audio(s)',
                    "data": [] if tranascipt_data is None else tranascipt_data,
                    'video_type_list': video_type_list
                }
                yield json.dumps(final_response) + "\n"

            except RetryCustomError as e:
                print("[ERROR] RetryCustomError caught:", e)
                await self.update_creation_state(account, stateData, custom_storage_audio_list,ContentDetailsState)
                print("[ERROR] RetryCustomError caught:", e)
                # responseval = {
                #     'scope': 'UploadAudioToVideoAudios',
                #     'retry': 'failedRetry' if NumberOfRequestRetry >= 3 else 'retry',
                #     'result': e.message,
                #     'NumberOfRequestRetry': NumberOfRequestRetry + 1
                # }
                responseval = {'failed': e.message}
                yield json.dumps(responseval) + "\n"
            except Exception as e:
                await self.update_creation_state(account, stateData, custom_storage_audio_list,ContentDetailsState)

                print("[ERROR] Exception in UploadAudioToVideoAudios:", str(e))
                responseval = {'failed': 'Error occurred when processing your request '}
                yield json.dumps(responseval) + "\n"

        response = StreamingHttpResponse(event_stream(), content_type="application/json")
        response['Cache-Control'] = 'no-cache'
        response["X-Accel-Buffering"] = "no"
        return response

    async def update_creation_state(self, account, CreationStateval, response_url,content_data):
        """Update the creation state manager"""
        print('[DEBUG] Updating creation state',content_data)
        try:
            creation_data = await sync_to_async(
                lambda: CreationStateManager.objects.filter(account_email=account).values('data').first()
            )()
            state_manager_dataval = creation_data.get('data', {}) if creation_data else {}
            state_manager_dataval = {} if state_manager_dataval == None else state_manager_dataval
            PostContentContainerval = CreationStateval.get('PostContentContainer',{})
            AiPageval = CreationStateval.get('AiPage','')
            RequestKindval = 'RepositoryAudio'            
            state_manager_dataval['RepositoryAudioData'] = response_url
            state_manager_dataval['ContentDetailsState'] = content_data
            now = datetime.datetime.now()
            short_date = now.strftime("%Y-%m-%dT%H:%M")
            
            await sync_to_async(CreationStateManager.objects.update_or_create)(
                account_email=account,
                defaults={
                    'PostContentContainer': PostContentContainerval,
                    'dateModified': str(short_date),
                    'data': state_manager_dataval,
                    'AiPage': AiPageval,
                    'RequestKind': RequestKindval
                }
            )
            print('[DEBUG] Creation state updated successfully')
        except Exception as e:
            print(f'[ERROR] Error updating creation state: {e}')


@method_decorator(csrf_exempt, name='dispatch')
class UploadRepositoryAudioToVideoAudiosView(APIView):
    permission_classes = [IsAuthenticated]
    throttle_classes = [AiTokenThrottler]

    @circuit
    def post(self, request):
        return async_to_sync(self.async_post)(request)

    async def async_post(self, request):
        async def event_stream():
            try:
                print("[DEBUG] Starting UploadAudioToVideoAudios processing")
                data = request.data
                emailval = sanitize_string(data['email'])
                NumberOfRequestRetry = int(sanitize_string(data['NumberOfRequestRetry']))
                SocialMediaType = sanitize_string(data['SocialMediaType'])
                
                custom_storage_audio_list = json.loads(data['RepositoryList'])
                stateData = json.loads(data['stateData'])
                NumberOfImagesList = json.loads(data['NumberOfImagesList'])
                NumberOfScripts = sanitize_string(data['NumberOfImages'])
                
                folder_path = os.path.join(settings.MEDIA_ROOT, emailval, SocialMediaType)
                ContentDetailsState = {
                    'NumberOfImages' : NumberOfImagesList
                }
                print("[DEBUG] Checking/creating folder")
                if not await sync_to_async(os.path.exists)(folder_path):
                    await sync_to_async(os.mkdir)(folder_path)
                else:
                    await sync_to_async(shutil.rmtree)(folder_path)
                    await sync_to_async(os.mkdir)(folder_path)
                
                print("[DEBUG] Checking account")
                accountref = await sync_to_async(Account.objects.filter)(email=emailval)
                account_exists = await sync_to_async(accountref.exists)()
                
                if not account_exists or emailval == 'gestuser@gmail.com':
                    responseval = {'failed': 'This account does not exist. Login to proceed.'}
                    yield json.dumps(responseval) + "\n"
                    return
                
                account = await sync_to_async(accountref.first)()
                if not account.is_active:
                    responseval = {'failed': 'This account is inactive. Kindly activate it using the link sent to this account email'}
                    yield json.dumps(responseval) + "\n"
                    return
                
                print("[DEBUG] Processing audio files")
                
                video_type_list = []
                number_of_image_list = []
                i = 0
                for items in custom_storage_audio_list:
                    try:
                        print(f"[DEBUG] Analyzing audio duration for file {i+1}")
                        splitted_name = str(items['audio_path']).split('/repository/')
                        filename = splitted_name[1]
                        # print(filename)
                        audio_path = os.path.join(settings.MEDIA_ROOT,emailval,'repository',filename)
                        # print(audio_path)
                        audio_clip = await sync_to_async(AudioFileClip)(audio_path)
                        val_audio_duration = await sync_to_async(lambda: audio_clip.duration)()
                        audio_duration = int(val_audio_duration)
                        await sync_to_async(audio_clip.close)()
                        videoType = 'shorts' if int(audio_duration) <= 60 else 'video'
                        decision = str(NumberOfScripts).split('sync')
                        # print('decision is',decision,len(decision))
                        if len(decision) > 1:
                            numval = math.floor(audio_duration / int(decision[1])) #each image will last 5 seconds
                            numval = 1 if numval == 0 else numval
                            number_of_image_list.append(numval)
                        
                        custom_storage_audio_list[i]['audio_path'] = audio_path
                        custom_storage_audio_list[i]['audio_name'] = filename
                    except Exception as e:
                        print(f"[WARNING] Error analyzing audio duration: {str(e)}")
                        videoType = 'shorts'
                    
                    video_type_list.append(videoType)

                    i += 1
                
                print('BEGINNING TRANSCRIPTION 🚩🚩🚩🚩🚩🚩🚩🚩🚩🚩')
                yield json.dumps({"progress": "Transcribing your audio(s)"}) + "\n"
                
                try:
                    print("[DEBUG] Starting transcription")
                    # Call your transcription function (now properly async)
                    decision = str(NumberOfScripts).split('sync')
                        # print(decision,len(decision))
                    if len(decision) > 1:
                        number_parameter = number_of_image_list
                    else:
                        number_parameter = int(NumberOfScripts)
                    print(number_parameter)
                    tranascipt_data = await transcribe_and_split_audio_api(
                        account,
                        custom_storage_audio_list, 
                        number_parameter
                    )
                    print("[DEBUG] Received transcription data:", 
                        len(tranascipt_data), "processed segments")
                except Exception as e:
                    print(f"[ERROR] Transcription failed: {str(e)}")
                    raise RetryCustomError("retry", str(e))

                print('\n\nTRANSCRIPTION FINISHED 🚩🚩🚩🚩🚩🚩🚩🚩\n\n')
                # , tranascipt_data[0] if tranascipt_data else None
                if tranascipt_data is None or len(tranascipt_data[0]) == 0:
                    responseval = {'failed': 'Seems like we cannot transcribe your data now'}
                    yield json.dumps(responseval) + "\n"
                    return
                
                await self.update_creation_state(account, stateData, custom_storage_audio_list,ContentDetailsState)

                final_response = {
                    'success': 'Successfully transcribed your audio(s)',
                    "data": [] if tranascipt_data is None else tranascipt_data,
                    'video_type_list': video_type_list
                }
                yield json.dumps(final_response) + "\n"

            except RetryCustomError as e:
                await self.update_creation_state(account, stateData, custom_storage_audio_list,ContentDetailsState)
                print("[ERROR] RetryCustomError caught:", e)
                # responseval = {
                #     'scope': 'UploadAudioToVideoAudios',
                #     'retry': 'failedRetry' if NumberOfRequestRetry >= 3 else 'retry',
                #     'result': e.message,
                #     'NumberOfRequestRetry': NumberOfRequestRetry + 1
                # }
                responseval = {'failed': e.message}
                yield json.dumps(responseval) + "\n"
            except Exception as e:
                await self.update_creation_state(account, stateData, custom_storage_audio_list,ContentDetailsState)
                print("[ERROR] Exception in UploadAudioToVideoAudios:", str(e))
                responseval = {'failed': 'Seams like there is an issue when transcribing your audios. Try again later'}
                yield json.dumps(responseval) + "\n"

        response = StreamingHttpResponse(event_stream(), content_type="application/json")
        response['Cache-Control'] = 'no-cache'
        response["X-Accel-Buffering"] = "no"
        return response

    async def update_creation_state(self, account, CreationStateval, response_url,content_data):
        """Update the creation state manager"""
        print('[DEBUG] Updating creation state',content_data)
        try:
            creation_data = await sync_to_async(
                lambda: CreationStateManager.objects.filter(account_email=account).values('data').first()
            )()
            state_manager_dataval = creation_data.get('data', {}) if creation_data else {}
            state_manager_dataval = {} if state_manager_dataval == None else state_manager_dataval
            PostContentContainerval = CreationStateval.get('PostContentContainer',{})
            AiPageval = CreationStateval.get('AiPage','')
            RequestKindval = 'RepositoryAudio'            
            state_manager_dataval['RepositoryAudioData'] = response_url
            state_manager_dataval['ContentDetailsState'] = content_data
            now = datetime.datetime.now()
            short_date = now.strftime("%Y-%m-%dT%H:%M")
            
            await sync_to_async(CreationStateManager.objects.update_or_create)(
                account_email=account,
                defaults={
                    'PostContentContainer': PostContentContainerval,
                    'dateModified': str(short_date),
                    'data': state_manager_dataval,
                    'AiPage': AiPageval,
                    'RequestKind': RequestKindval
                }
            )
            print('[DEBUG] Creation state updated successfully')
        except Exception as e:
            print(f'[ERROR] Error updating creation state: {e}')


@method_decorator(csrf_exempt, name='dispatch')
class MergeMotionAudioToVideoView(APIView):
    permission_classes = [IsAuthenticated]
    throttle_classes = [fileUploadthrottler]

    @circuit
    def post(self, request):
        return async_to_sync(self.async_post)(request)

    async def async_post(self, request):
        async def event_stream():
            try:
                print("[DEBUG] Starting MergeMotionAudioToVideo processing")
                data = request.data
                NumberOfRequestRetry = int(sanitize_string(data['NumberOfRequestRetry']))
                emailval = sanitize_string(data['email'])
                dataval = json.loads(data['data'])
                CreationStateval = json.loads(data['CreationState'])
                SocialMediaType = sanitize_string(data['SocialMediaType'])
                folder_path = os.path.join(settings.MEDIA_ROOT, emailval, SocialMediaType)
                feeds_path = os.path.join(settings.MEDIA_ROOT)
                
                print("[DEBUG] Checking account")
                accountref = await sync_to_async(Account.objects.filter)(email=emailval)
                account_exists = await sync_to_async(accountref.exists)()
                
                if not account_exists:
                    yield json.dumps({"failed": "This account does not exist. Login to proceed."}) + "\n"
                    return
                
                account = await sync_to_async(accountref.first)()
                if not account.is_active:
                    yield json.dumps({"failed": "This account is inactive. Kindly activate it using the link sent to this account email"}) + "\n"
                    return

                position = 0
                response_url = []
                yield json.dumps({"progress": "start"}) + "\n"
                yield " " * 4096 + "\n"
                
                print("[DEBUG] Starting video processing loop")
                for items in dataval:
                    print(f'\nProcessing video {position + 1}/{len(dataval)}')
                    yield json.dumps({"progress": f"Processing {position + 1} video"}) + "\n"
                    yield " " * 4096 + "\n"
                    
                    # Extract data
                    image_image_list = items.get("ImageList", "")
                    snippet_data = items.get("snippet", {})
                    status_data = items.get("status", {})
                    videoType_list = items.get("videoType", 'shorts')
                    videoType = videoType_list
                    audio_name = items.get("audio", "fallback.mp3")
                    
                    print("[DEBUG] Processing image paths")
                    image_paths = [
                        os.path.normpath(os.path.join(settings.MEDIA_ROOT, emailval, SocialMediaType, item.get("name", "").strip())) 
                        for item in image_image_list if "name" in item
                    ]

                    if not image_paths:
                        yield json.dumps({"failed": "There were no images identified"}) + "\n"
                        return

                    print("[DEBUG] Processing audio duration")
                    custom_storage_audio_path = os.path.join(folder_path, audio_name)
                    audio_clip = await sync_to_async(AudioFileClip)(custom_storage_audio_path)
                    audio_duration = await sync_to_async(lambda: audio_clip.duration)()
                    integered_audio_duration = int(audio_duration)
                    await sync_to_async(audio_clip.close)()
                    video_duration = str(datetime.timedelta(seconds=integered_audio_duration))[-5:]
                    
                    now = datetime.datetime.now()
                    short_date = now.strftime("%Y-%m-%dT%H:%M")
                    transition_duration = 1.0
                    T = (audio_duration + (len(image_paths) - 1) * transition_duration) / len(image_paths)
                    
                    yield json.dumps({"progress": "Motionalizing your images to video. Please hold"}) + "\n"
                    yield " " * 4096 + "\n"
                    
                    print("[DEBUG] Creating feed data")
                    feedsData = {
                        "status": status_data,
                        "snippet": snippet_data,
                        'VideoLength': video_duration,
                        'DateCreated': str(short_date),
                        'VideoType': videoType
                    }
                    
                    feedRef = await self.process_video_creation(
                        account,
                        feedsData,
                        image_paths,
                        custom_storage_audio_path,
                        feeds_path,
                        folder_path,
                        videoType,
                        integered_audio_duration,
                        position,
                        response_url,
                        image_image_list
                    )
                    
                    response_url.append(f'feeds/{feedRef.id}.mp4')
                    position += 1
                    print('\nVideo processing completed ✅')
                    yield json.dumps({"progress": f"Completed {position} video over {len(dataval)}"}) + "\n"
                    yield " " * 4096 + "\n"

                print("[DEBUG] Updating creation state")
                await self.update_creation_state(account, CreationStateval, response_url)
                
                final_response = {
                    'success': 'Your video is successfully created',
                    "video_url": response_url
                }
                yield json.dumps(final_response) + "\n"
            
            except RetryCustomError as e:
                print("[ERROR] RetryCustomError caught:", e)
                fallbackMessage = 'Maximum number of retries reached🥺. Try again later'
                responseval = {
                    'scope': 'MergeAudioToVideo',
                    'retry': 'failedMergeAudioToVideoRetry' if NumberOfRequestRetry >= MaximumNumberRetry else 'MergeAudioToVideoRetry',
                    'result': fallbackMessage if NumberOfRequestRetry >= MaximumNumberRetry else e.message,
                    'NumberOfRequestRetry': NumberOfRequestRetry + 1
                }
                yield json.dumps(responseval) + "\n"
            except Exception as e:
                print("[ERROR] Exception in MergeMotionAudioToVideo:", str(e))
                responseval = {'failed': 'Error occurred when processing your request'}
                yield json.dumps(responseval) + "\n"

        response = StreamingHttpResponse(event_stream(), content_type="application/json")
        response['Cache-Control'] = 'no-cache'
        response["X-Accel-Buffering"] = "no"
        return response

    async def process_video_creation(self, account, feedsData, image_paths, audio_path, 
        feeds_path, folder_path, videoType, audio_duration,
        position, response_url, image_list):
        """Handle the video creation process"""
        print('[DEBUG] Starting video creation process')
        
        async def _sync_video_creation():
            print('[DEBUG] Inside atomic transaction')
            with transaction.atomic():
                print('[DEBUG] Creating feed record')
                feedRef = await sync_to_async(Feeds.objects.create)(
                    account_email=account,
                    video='',
                    Data=feedsData,
                    thumbnail='',
                    privacyStatus='public'
                )

                custom_feeds_video_name = os.path.join('feeds', f'{feedRef.id}.mp4')
                final_video = os.path.join(feeds_path, custom_feeds_video_name)
                
                print('[DEBUG] Deleting existing files')
                await delete_file_async(final_video)

                print('[DEBUG] Starting motion video generation')
                yield json.dumps({"progress": "Generating video from images"}) + "\n"
                yield " " * 4096 + "\n"
                
                try:
                    print("[DEBUG] Preparing files for API")
                    files = []
                    for i, img_path in enumerate(image_paths):
                        filename = os.path.basename(img_path)
                        files.append(('images', (filename, open(img_path, 'rb'), 'image/jpeg')))
                    
                    audio_filename = os.path.basename(audio_path)
                    files.append(('audio', (audio_filename, open(audio_path, 'rb'), 'audio/mpeg')))

                    payload = {
                        'fps': 25, 
                        'video_duration': audio_duration,
                        'videoType': videoType
                    }
                    
                    print("[DEBUG] Calling motion API")
                    url = f"{PUBLIC_API_URL}/mergemotion/"
                    response = await sync_to_async(requests.post)(url, files=files, data=payload)
                    
                    print(f"[DEBUG] API response: {response.status_code}")
                    if response.status_code != 200:
                        try:
                            error_details = response.json()
                            print("Error from API:", error_details)
                            raise Exception('Error merging your videos')
                        except:
                            print("Raw API error:", response.text)
                            raise Exception('Error merging your videos')
                    
                    print("[DEBUG] Saving video file")
                    async with aiofiles.open(final_video, 'wb') as f:
                        await f.write(response.content)
                    
                    yield json.dumps({"progress": f"Saving {position} video. Please hold"}) + "\n"
                    yield " " * 4096 + "\n"
                    
                    print("[DEBUG] Updating feed with video path")
                    await sync_to_async(setattr)(feedRef, 'video', custom_feeds_video_name)
                    
                    if image_list and image_list[0]['name']:
                        print("[DEBUG] Generating thumbnail")
                        image_url_thumbnail = os.path.join(folder_path, image_list[0]['name'])
                        thumbnail_name = os.path.join('feeds', f"{feedRef.id}_thumbnail.jpg")
                        thumbnail_path = os.path.join(feeds_path, thumbnail_name)
                        
                        await delete_file_async(thumbnail_path)
                        
                        try:
                            await sync_to_async(create_thumbnail)(image_url_thumbnail, thumbnail_path)
                            await sync_to_async(setattr)(feedRef, 'thumbnail', thumbnail_name)
                        except Exception as e:
                            print(f"[WARNING] Thumbnail creation failed: {str(e)}")
                            fallback_thumbnail = os.path.join('feeds', "fallback_thumbnail.jpg")
                            await sync_to_async(setattr)(feedRef, 'thumbnail', fallback_thumbnail)
                    
                    print("[DEBUG] Saving feed record")
                    await sync_to_async(feedRef.save)()
                    yield feedRef
                except Exception as e:
                    print(f'[ERROR] occured when processing API request: {str(e)}')
                    raise
        print('[DEBUG] Executing video creation')
        try:
            async for feedRef in _sync_video_creation():  # Now using async for
                print('[DEBUG] Video creation completed successfully')
                return feedRef
        except Exception as e:
            print(f'[ERROR] Video creation failed: {str(e)}')
            raise

    async def update_creation_state(self, account, CreationStateval, response_url):
        """Update the creation state manager"""
        print('[DEBUG] Updating creation state')
        try:
            creation_data = await sync_to_async(
                lambda: CreationStateManager.objects.filter(account_email=account).values('data').first()
            )()
            
            state_manager_dataval = creation_data.get('data', {}) if creation_data else {}
            state_manager_dataval = {} if state_manager_dataval == None else state_manager_dataval
            PostContentContainerval = CreationStateval.get('PostContentContainer',{})
            AiPageval = CreationStateval.get('AiPage','')
            RequestKindval = 'MergeAudioToVideo'
            
            state_manager_dataval['MergeAudioToVideoData'] = response_url
            now = datetime.datetime.now()
            short_date = now.strftime("%Y-%m-%dT%H:%M")

            await sync_to_async(CreationStateManager.objects.update_or_create)(
                account_email=account,
                defaults={
                    'PostContentContainer': PostContentContainerval,
                    'dateModified': str(short_date),
                    'data': state_manager_dataval,
                    'AiPage': AiPageval,
                    'RequestKind': RequestKindval
                }
            )
            print('[DEBUG] Creation state updated')
        except Exception as e:
            print(f'[ERROR] Error updating creation state: {e}')