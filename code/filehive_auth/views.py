from rest_framework.views import APIView
from rest_framework import status
from rest_framework.response import Response
from rest_framework.exceptions import AuthenticationFailed
from rest_framework_simplejwt.views import TokenObtainPairView

from rest_framework import serializers
from rest_framework.generics import GenericAPIView
from rest_framework.permissions import AllowAny, IsAuthenticated

from utils.response.base_response import BaseResponse
from .models import User

from .serializers import UserSerializer
from .serializers import MyTokenObtainPairSerializer
from drf_spectacular.utils import extend_schema, OpenApiParameter, OpenApiResponse

# for sending mails and generate token
from django.template.loader import render_to_string
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from .utils import TokenGenerator, generate_token
from django.utils.encoding import force_bytes, force_text
from django.core.mail import EmailMessage
from django.conf import settings
from django.shortcuts import render
from jwt import decode, exceptions
from file.models import File
from file.serializers import FileSerializer
from mlmodels.sqlinjection_model.sqlinjection_model import predict
from utils.tools import check_user_counts
from datetime import datetime
from attacks_logs.models import Log
from attacks_logs.serializers import LogSerializer
class MyTokenObtainPairView(TokenObtainPairView):
    serializer_class = MyTokenObtainPairSerializer


# register view *********** *********** *********** *********** *********** *********** *********** ***********
class RegisterRequestSerializer(serializers.Serializer):
    email = serializers.EmailField(max_length=254)
    first_name = serializers.CharField(max_length=100)
    last_name = serializers.CharField(max_length=100)
    password = serializers.CharField()


@extend_schema(
    description="This route is for creating accounts, the Sign-up route",
    request=RegisterRequestSerializer,
    responses={
        200: OpenApiResponse(
            response={
                "type": "object",
                "properties": {
                    "message": {"type": "string"},
                    "user": {"type": "object"},
                },
            }
        ),
        400: OpenApiResponse(description="Bad request, invalid data"),
        406: OpenApiResponse(description="Sql Injection detected"),
    },
)
class RegisterView(APIView):

    def post(self, request):
        predict_result = predict(self, request)
        if predict_result["sql_injection"] == True:
            sql_queries = predict_result["sqli_queries"]
            mal_input = ""
            for query in sql_queries:
                    if sql_queries.index(query) == len(sql_queries) - 1:
                        mal_input += query 
                    else:
                        mal_input += query + " |||| "
            log_data = {
                    "attack_type": "sqli",
                    "file" : None,
                    "user": "Anonymous user",
                    "attack_timing": datetime.now(),
                    "attack_input": mal_input
                }
            log = Log(
                    attack_type=log_data["attack_type"],
                    file=log_data["file"],
                    user=log_data["user"],
                    attack_timing=log_data["attack_timing"],
                    attack_input=log_data["attack_input"],
                                     )

            log.save()
            return BaseResponse(
                data=None,
                status_code=status.HTTP_406_NOT_ACCEPTABLE,
                message=predict_result["message"],
                error=predict_result["sql_injection"],
            )
        if User.objects.filter(email=request.data["email"]).exists():
            return BaseResponse(
                data=None,
                status_code=status.HTTP_400_BAD_REQUEST,
                message="This email is already registered",
                error=True,
            )
        serializer = UserSerializer(data=request.data)
        # verification of existsing
        
        serializer.is_valid(raise_exception=True)
        user = serializer.save()

        # generate token for sending mail
        email_subject = "Verify Your Account"
        message = render_to_string(
            "registration/verify.html",
            {
                "user": user,
                "domain": "localhost:3000",
                "uid": urlsafe_base64_encode(force_bytes(user.pk)),
                "token": generate_token.make_token(user),
            },
        )

        email_message = EmailMessage(
            email_subject, message, settings.EMAIL_HOST_USER, to=[user.email]
        )
        email_message.content_subtype = "html"
        email_message.send()
        return Response(
            {"message": "User registration successful!", "user": serializer.data},
            status=status.HTTP_201_CREATED,
        )


class VerifyEmailSerializer(serializers.Serializer):
    uidb64 = serializers.CharField(required=True)
    token = serializers.CharField(required=True)


@extend_schema(
    description="the backend will send the verification url that contains the token related to front-side (this is a special route for the front)",
    request=VerifyEmailSerializer,
)
class VerifyEmail(GenericAPIView):
    def get(self, request, uidb64, token):
        print("message sent")


# verifiy Account token view *******************************
@extend_schema(
    description="Verify user account using the provided uidb64 and token.",
    responses={
        200: OpenApiResponse(description="Account verified successfully"),
        400: OpenApiResponse(description="Invalid UID or Token."),
        403: OpenApiResponse(description="Verification failed"),
    },
)
class VerifyAccountView(APIView):
    def get(self, request, uidb64, token):
        try:
            uid = force_text(urlsafe_base64_decode(uidb64))
            user = User.objects.get(pk=uid)
        except Exception as identifier:
            user = None
        if user is not None and generate_token.check_token(user, token):
            user.is_verified = True
            user.save()
            return Response(
                {
                    "message": f"User {user.get_full_name()} with email: {user.email} is verified",
                    "status": "success",
                },
                status=status.HTTP_200_OK,
            )
        else:
            return Response(
                {
                    "message": f"User {user.get_full_name()} is not verified",
                    "status": "failed",
                },
                status=status.HTTP_403_FORBIDDEN,
            )


# Login View****************************************************************************
class LoginRequestSerializer(serializers.Serializer):
    email = serializers.EmailField(max_length=254)
    password = serializers.CharField()


@extend_schema(
    description="User enters his creds and sign-in and there is Email-Verification check",
    request=LoginRequestSerializer,
    responses={
        200: OpenApiResponse(
            response={
                "type": "object",
                "properties": {
                    "message": {"type": "string"},
                    "access_token": {"type": "string"},
                    "refresh_token": {"type": "string"},
                },
            }
        ),
        400: OpenApiResponse(description="Bad request, invalid creds"),
        403: OpenApiResponse(
            description="User not verified (verification email sent) || or User is Banned"
        ),
        404: OpenApiResponse(description="User not found"),
        406: OpenApiResponse(description="Sql Injection detected"),
    },
)
class LoginView(APIView):

    def post(self, request):
    #    can register warnings here
        predict_result = predict(self, request)
        if predict_result["sql_injection"] == True:
            sql_queries = predict_result["sqli_queries"]
            mal_input = ""
            for query in sql_queries:
                    if sql_queries.index(query) == len(sql_queries) - 1:
                        mal_input += query 
                    else:
                        mal_input += query + " |||| "
            log_data = {
                    "attack_type": "sqli",
                    "file" : None,
                    "user": "Anonymous user",
                    "attack_timing": datetime.now(),
                    "attack_input": mal_input
                }
            log = Log(
                    attack_type=log_data["attack_type"],
                    file=log_data["file"],
                    user=log_data["user"],
                    attack_timing=log_data["attack_timing"],
                    attack_input=log_data["attack_input"],
                                     )

            log.save()
            return BaseResponse(
                data=None,
                status_code=status.HTTP_406_NOT_ACCEPTABLE,
                message=predict_result["message"],
                error=predict_result["sql_injection"],
            )
        email = request.data["email"]
        password = request.data["password"]

        user = User.objects.filter(email=email).first()
        
        if user is None:
            raise AuthenticationFailed("user not found!")
        if not user.check_password(password):
            raise AuthenticationFailed("incorrect password")
        if not user.is_active:
             return Response(
                  {
                 "message": "Your Account is Banned due to Malicious Activity. Please Contact the Admins for more information.",
                 },
                 status=status.HTTP_403_FORBIDDEN,
             )
        
        if not user.is_verified:
            email_subject = "verify your account"
            message = render_to_string(
                "registration/verify.html",
                {
                    "user": user,
                    "domain": "localhost:3000",
                    "uid": urlsafe_base64_encode(force_bytes(user.pk)),
                    "token": generate_token.make_token(user),
                },
            )
            email_message = EmailMessage(
                email_subject, message, settings.EMAIL_HOST_USER, to=[user.email]
            )
            email_message.content_subtype = "html"
            email_message.send()

            return Response(
                {
                    "message": "user not verified. Verification email sent. Please Verify Your email and Login Again"
                },
                status=status.HTTP_403_FORBIDDEN,
            )

        tokens = MyTokenObtainPairSerializer.get_token(user)  # Get tokens directly
        # refresh = str(tokens)
        # access = str(tokens.access_token)
        # type = tokens.access_token.token_type
        # type = tokens.token_type for refresh type
        serializer = UserSerializer(user)
        user_data = serializer.data
        # files = File.objects.filter(owner=user)
        # file_serializer = FileSerializer(files, many=True)
        # for file_data in file_serializer.data:
        #     if "owner" in file_data:
        #         del file_data["owner"]

        return Response(
            {
                "message": "Login User Successful!",
                "user": user_data,
                # "files": file_serializer.data,
                "refresh_token": str(tokens),
                "acess_token": str(
                    tokens.access_token
                ),  # Unpack tokens into the response
            },
            status=status.HTTP_200_OK,
        )


# Reset Password Section


# send email-reset section **************************************************************
class SendResetEmailRequestSerializer(serializers.Serializer):
    email = serializers.EmailField(max_length=254)


@extend_schema(
    description="the front-client will send a reset-password request to this route",
    request=SendResetEmailRequestSerializer,
    responses={
        200: OpenApiResponse(description="Reset password email sent successfully"),
        400: OpenApiResponse(description="Bad request, invalid request data"),
        404: OpenApiResponse(description="User not found"),
        406: OpenApiResponse(description="Sql Injection detected"),
    },
)
class SendResetEmail(APIView):
    def post(self, request):
        predict_result = predict(self, request)
        if predict_result["sql_injection"] == True:
            sql_queries = predict_result["sqli_queries"]
            mal_input = ""
            for query in sql_queries:
                    if sql_queries.index(query) == len(sql_queries) - 1:
                        mal_input += query 
                    else:
                        mal_input += query + " |||| "
            log_data = {
                    "attack_type": "sqli",
                    "file" : None,
                    "user": "Anonymous user",
                    "attack_timing": datetime.now(),
                    "attack_input": mal_input
                }
            log = Log(
                    attack_type=log_data["attack_type"],
                    file=log_data["file"],
                    user=log_data["user"],
                    attack_timing=log_data["attack_timing"],
                    attack_input=log_data["attack_input"],
                                     )

            log.save()
            return BaseResponse(
                data=None,
                status_code=status.HTTP_406_NOT_ACCEPTABLE,
                message=predict_result["message"],
                error=predict_result["sql_injection"],
            )
        email = request.data["email"]
        user = User.objects.filter(email=email).first()
        if user is None:
            raise AuthenticationFailed("User not Found!")
        email_subject = "Reset Your Password"
        message = render_to_string(
            "registration/reset.html",
            {
                "user": user,
                "domain": "localhost:3000",
                "uid": urlsafe_base64_encode(force_bytes(user.pk)),
                "token": generate_token.make_token(user),
            },
        )
        email_message = EmailMessage(
            email_subject, message, settings.EMAIL_HOST_USER, to=[user.email]
        )
        email_message.content_subtype = "html"
        email_message.send()
        return Response(
            {"message": f"Reset Password email was sent to this email: {user.email}"}
        )


# Veriviy Reset View wih the token veririfcation****************************************
@extend_schema(
    description="the front will send the uset token for reset password and verify it to send a response",
    responses={
        200: OpenApiResponse(description="success: now you change password"),
        400: OpenApiResponse(description="Invalid uidb64 or token"),
        403: OpenApiResponse(description="Verification failed (e.g., user not found)"),
    },
)
class VerifyReset(APIView):
    def post(self, request, uidb64, token):

        try:
            uid = force_text(urlsafe_base64_decode(uidb64))
            user = User.objects.get(pk=uid)
        except Exception as identifier:
            user = None
        if user is not None and generate_token.check_token(user, token):

            return Response(
                {
                    "message": f"Now You can Change password",
                    "status": "success",
                    "email": f"{user.email}",
                },
                status=status.HTTP_200_OK,
            )
        else:
            return Response(
                {"message": f"there was an error", "status": "failed"},
                status=status.HTTP_400_BAD_REQUEST,
            )


class ResetEmailSerializer(serializers.Serializer):
    uidb64 = serializers.CharField(required=True)
    token = serializers.CharField(required=True)


@extend_schema(
    description="the backend will send the reset-password verification url that contains the token related to front-side (this is a special route for the front)",
    request=ResetEmailSerializer,
)
class ResetEmail(GenericAPIView):
    def get(self, request, uidb64, token):
        try:
            uid = force_text(urlsafe_base64_decode(uidb64))
            user = User.objects.get(pk=uid)
        except Exception as identifier:
            user = None
        if user is not None and generate_token.check_token(user, token):
            return Response(
                {"user_email": f"{user.email}", "status": "succes"},
                status=status.HTTP_200_OK,
            )
        else:
            return Response(
                {"message": f"Error in url or token ", "status": "failed"},
                status=status.HTTP_400_BAD_REQUEST,
            )
        # send email in this route


# ResetPassword view ****************************************************************************
class ResetPasswordRequestSerializer(serializers.Serializer):
    email = serializers.EmailField(max_length=254)
    password = serializers.CharField()


@extend_schema(
    description="the front-client will send a reset-password to this route",
    request=ResetPasswordRequestSerializer,
    responses={
        200: OpenApiResponse(
            response={
                "type": "object",
                "properties": {
                    "message": {"type": "string"},
                    "user": {"type": "object"},
                },
            }
        ),
        400: OpenApiResponse(description="Bad request, Provide new password"),
        403: OpenApiResponse(description="User not verified (verification email sent)"),
        404: OpenApiResponse(description="User not found"),
        406: OpenApiResponse(description="Sql Injection detected"),
    },
)
class ResetPasswordView(APIView):
    def post(self, request):
    
        predict_result = predict(self, request)
        if predict_result["sql_injection"] == True:
            sql_queries = predict_result["sqli_queries"]
            mal_input = ""
            for query in sql_queries:
                    if sql_queries.index(query) == len(sql_queries) - 1:
                        mal_input += query 
                    else:
                        mal_input += query + " |||| "
            log_data = {
                    "attack_type": "sqli",
                    "file" : None,
                    "user": "Anonymous user",
                    "attack_timing": datetime.now(),
                    "attack_input": mal_input
                }
            log = Log(
                    attack_type=log_data["attack_type"],
                    file=log_data["file"],
                    user=log_data["user"],
                    attack_timing=log_data["attack_timing"],
                    attack_input=log_data["attack_input"],
                                     )

            log.save()
            return BaseResponse(
                data=None,
                status_code=status.HTTP_406_NOT_ACCEPTABLE,
                message=predict_result["message"],
                error=predict_result["sql_injection"],
            )
        email = request.data["email"]
        newPassword = request.data["password"]
        user = User.objects.filter(email=email).first()
        if user is None:
            raise AuthenticationFailed("User not Found!")
        if not user.is_verified:
            email_subject = "Verify Your Account"
            message = render_to_string(
                "registration/verify.html",
                {
                    "user": user,
                    "domain": "localhost:3000",
                    "uid": urlsafe_base64_encode(force_bytes(user.pk)),
                    "token": generate_token.make_token(user),
                },
            )
            email_message = EmailMessage(
                email_subject, message, settings.EMAIL_HOST_USER, to=[user.email]
            )
            email_message.content_subtype = "html"
            email_message.send()
            return Response(
                {
                    "message": "user not verified. Verification email sent. Please Verify Your email and Try Again"
                },
                status=status.HTTP_403_FORBIDDEN,
            )

        if newPassword is not None:
            user.set_password(newPassword)
            user.save()
            serializer = UserSerializer(user)
            user_data = serializer.data
            return Response(
                {
                    "message": "Reset Password was Successful",
                    "user": user_data,
                    "status": "success",  # Unpack tokens into the response
                },
                status=status.HTTP_200_OK,
            )
        else:
            return Response(
                {"Error": "Please Provide a New Password"},
                status=status.HTTP_400_BAD_REQUEST,
            )


######Update-password view***************************************************************************************************


class UpdatePasswordRequestSerializer(serializers.Serializer):
    old_password = serializers.CharField()
    new_password = serializers.CharField()


@extend_schema(
    description="the front-side will send update-password  request with an old and a new password and the front-side must send the user's access_token in the authorisation-header",
    request=UpdatePasswordRequestSerializer,
    responses={
        202: OpenApiResponse(
            response={
                "type": "object",
                "properties": {
                    "message": {"type": "string"},
                    "status": {"type": "string"},
                },
            }
        ),
        401: OpenApiResponse(
            description="UNAUTHIRIZED | Invalide Token | token has expired | decoding_token_error"
        ),
        406: OpenApiResponse(description="Sql Injection detected + ban status"),
    },
)
class UpdatePasswordView(APIView):
    permission_classes = [IsAuthenticated]
    
    def put(self, request):
        user = User.objects.filter(id=request.user.id).first()
        predict_result = predict(self, request)
        if predict_result["sql_injection"] == True:
            sql_queries = predict_result["sqli_queries"]
            mal_input = ""
            for query in sql_queries:
                    if sql_queries.index(query) == len(sql_queries) - 1:
                        mal_input += query 
                    else:
                        mal_input += query + " |||| "
            log_data = {
                    "attack_type": "sqli",
                    "file" : None,
                    "user": f"user_{user.id}_{user.get_full_name()}",
                    "attack_timing": datetime.now(),
                    "attack_input": mal_input
                }
            log = Log(
                    attack_type=log_data["attack_type"],
                    file=log_data["file"],
                    user=log_data["user"],
                    attack_timing=log_data["attack_timing"],
                    attack_input=log_data["attack_input"],
                                     )

            log.save()
            message = f"Sql Injection detected, "
            warning_message = check_user_counts(user)
            if warning_message == "banned":
                message += "Your account has been banned due to multiple warnings."
                return BaseResponse(
                    data=None,
                    status_code=status.HTTP_403_FORBIDDEN,
                    message= message,
                    error=predict_result["sql_injection"],
                )
            else:
                message += warning_message
                return BaseResponse(
                data=None,
                status_code=status.HTTP_406_NOT_ACCEPTABLE,
                message=message,
                error=predict_result["sql_injection"],
             )

        old_password = request.data["old_password"]
        new_password = request.data["new_password"]

        auth_header = request.META.get("HTTP_AUTHORIZATION")
        # if not auth_header:
        #     raise AuthenticationFailed("the authorization header was not provided!.")
        parts = auth_header.split(" ")
        # if parts[0].lower() != "bearer":
        #     raise AuthenticationFailed("Invalid authentication header. Use Bearer.")
        token = parts[1]
        try:
            payload = decode(
                token,
                settings.SIMPLE_JWT["SIGNING_KEY"],
                algorithms=[settings.SIMPLE_JWT["ALGORITHM"]],
            )
            email = str(payload["email"])
            user = User.objects.filter(email=email).first()
            if not user.check_password(old_password):
                return Response(
                    {"error": "Invalid old password"},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            user.set_password(new_password)
            user.save()
            return Response(
                {"message": "Password updated successfully", "status": "success"},
                status=status.HTTP_202_ACCEPTED,
            )
        except exceptions.DecodeError as e:
            raise AuthenticationFailed("Invalid token format.")
        except exceptions.ExpiredSignatureError as e:
            raise AuthenticationFailed("Token has expired.")
        # except exceptions.InvalidSignatureError as e:
        #     raise AuthenticationFailed("Invalid token signature.")
        except exceptions.JWTError as e:
            raise AuthenticationFailed("An error occurred while decoding the token.")


######Update user Info view***************************************************************************************************
class UpdateUserInfoRequestSerializer(serializers.Serializer):
    first_name = serializers.CharField()
    last_name = serializers.CharField()
    profilePicture = serializers.FileField(required=False)


@extend_schema(
    description="the token-verification route and the front-side must send the user's access-token in the authorisation header",
    request=UpdateUserInfoRequestSerializer,
    responses={
        202: OpenApiResponse(
            response={
                "type": "object",
                "properties": {
                    "success": {"type": "string"},
                },
            }
        ),
        400: OpenApiResponse(description="Bad request"),
        401: OpenApiResponse(
            description="UNAUTHIRIZED | Invalide Token | token has expired | decoding_token_error"
        ),
        403: OpenApiResponse(description="User is Banned"),
        404: OpenApiResponse(description="User Not Found"),
        406: OpenApiResponse(description="Sql Injection detected + ban status"),
    },
)
class UpdateUserInfoView(APIView):
    permission_classes = [IsAuthenticated]

    def put(self, request):
        user = User.objects.filter(id=request.user.id).first()
        
        predict_result = predict(self, request)
        if predict_result["sql_injection"] == True:
            sql_queries = predict_result["sqli_queries"]
            mal_input = ""
            for query in sql_queries:
                    if sql_queries.index(query) == len(sql_queries) - 1:
                        mal_input += query 
                    else:
                        mal_input += query + " |||| "
            log_data = {
                    "attack_type": "sqli",
                    "file" : None,
                    "user": f"user_{user.id}_{user.get_full_name()}",
                    "attack_timing": datetime.now(),
                    "attack_input": mal_input
                }
            log = Log(
                    attack_type=log_data["attack_type"],
                    file=log_data["file"],
                    user=log_data["user"],
                    attack_timing=log_data["attack_timing"],
                    attack_input=log_data["attack_input"],
                                     )

            log.save()
            message = "Sql Injection detected, "
            warning_message = check_user_counts(user)
            if warning_message == "banned":
                message += "Your account has been banned due to multiple warnings."
                return BaseResponse(
                    data=None,
                    status_code=status.HTTP_403_FORBIDDEN,
                    message= message,
                    error=predict_result["sql_injection"],
                )
            else:
                message += warning_message
                return BaseResponse(
                data=None,
                status_code=status.HTTP_406_NOT_ACCEPTABLE,
                message=message,
                error=predict_result["sql_injection"],
             )
        auth_header = request.META.get("HTTP_AUTHORIZATION")
        parts = auth_header.split(" ")
        access_token = parts[1]

        try:
            payload = decode(
                access_token,
                settings.SIMPLE_JWT["SIGNING_KEY"],
                algorithms=[settings.SIMPLE_JWT["ALGORITHM"]],
            )
            email = str(payload["email"])

            user = User.objects.filter(email=email).first()
            if user is None:
                return Response(
                    {"error": "User not found"}, status=status.HTTP_404_NOT_FOUND
                )

        except exceptions.DecodeError as e:
            raise AuthenticationFailed("Invalid token format.")
        except exceptions.ExpiredSignatureError as e:
            raise AuthenticationFailed("Token has expired.")
        # except exceptions.InvalidSignatureError as e:
        #     raise AuthenticationFailed("Invalid token signature.")
        except exceptions.JWTError as e:
            raise AuthenticationFailed("An error occurred while decoding the token.")

        serializer = UserSerializer(instance=user, data=request.data, partial=True)
        if serializer.is_valid():

            serializer.save()
            return Response({"success": "User data updated"}, status=status.HTTP_200_OK)

        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


# verify Token View*****************************************************************************


@extend_schema(
    description="Update the user information route and the front-side must send the user's access-token in the authorisation header",
    responses={
        200: OpenApiResponse(
            response={
                "type": "object",
                "properties": {
                    "message": {"type": "string"},
                },
            }
        ),
        401: OpenApiResponse(
            description="UNAUTHIRIZED | Invalide Token | token has expired | decoding_token_error"
        ),
    },
)
class VerifyTokenView(APIView):
    authentication_classes = []

    def get(self, request):
        auth_header = request.META.get("HTTP_AUTHORIZATION")
        if not auth_header:
            raise AuthenticationFailed("No AUTHORIZATION header provided!.")
        parts = auth_header.split(" ")
        if parts[0].lower() != "bearer":
            raise AuthenticationFailed("Invalid authentication header. User Bearer")

        token = parts[1]
        try:
            payload = decode(
                token,
                settings.SIMPLE_JWT["SIGNING_KEY"],
                algorithms=[settings.SIMPLE_JWT["ALGORITHM"]],
            )
        # except exceptions.InvalidTokenError as e:
        #      return Response({'error': 'Invalid token'},status=status.HTTP_401_UNAUTHORIZED)
        except exceptions.DecodeError as e:
            return Response(
                {"error": "Invalid Token"}, status=status.HTTP_401_UNAUTHORIZED
            )
        except exceptions.ExpiredSignatureError as e:
            return Response(
                {"error": "Token has expired"}, status=status.HTTP_401_UNAUTHORIZED
            )
        except exceptions.JWTError as e:
            # raise AuthenticationFailed("An error occurred while decoding the token.")
            return Response(
                {"error": "An error occurred while decoding the token."},
                status=status.HTTP_401_UNAUTHORIZED,
            )

        return Response({"message": "Token is Valid!"}, status=status.HTTP_200_OK)


class GetUserView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        auth_header = request.META.get("HTTP_AUTHORIZATION")
        parts = auth_header.split(" ")
        access_token = parts[1]

        try:
            payload = decode(
                access_token,
                settings.SIMPLE_JWT["SIGNING_KEY"],
                algorithms=[settings.SIMPLE_JWT["ALGORITHM"]],
            )

        except exceptions.DecodeError as e:
            raise AuthenticationFailed("Invalid token format.")
        except exceptions.ExpiredSignatureError as e:
            raise AuthenticationFailed("Token has expired.")
        # except exceptions.InvalidSignatureError as e:
        #     raise AuthenticationFailed("Invalid token signature.")
        except exceptions.JWTError as e:
            raise AuthenticationFailed("An error occurred while decoding the token.")
        email = str(payload["email"])
        user = User.objects.filter(email=email).first()
        serializer = UserSerializer(user)
        user_data = serializer.data
        return Response(
            {"user": user_data},
            status=status.HTTP_200_OK,
        )

        # user_id = None
        # if "HTTP_AUTHORIZATION" in request.META:
        #     auth_header = request.META["HTTP_AUTHORIZATION"]
        #     user_id = extract_owner_id_from_token(auth_header)
        # if not user_id:
        #     return None

        # try:
        #     user = User.objects.get(id=user_id)
        #     serializer = UserSerializer(user)

        #     files = File.objects.filter(owner=user)
        #     file_serializer = FileSerializer(files, many=True)
        #     for file_data in file_serializer.data:
        #         if "owner" in file_data:
        #             del file_data["owner"]
        #     return BaseResponse(
        #         status_code=status.HTTP_200_OK,
        #         error=False,
        #         message="User informations retreived successfully",
        #         data={
        #             "user": serializer.data,
        #             "files": file_serializer.data,
        #         },
        #     )
        # except Exception as e:
        #     return BaseResponse(
        #         status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        #         error=True,
        #         message=str(e),
        #         data=str(e),
        #     )


def extract_owner_id_from_token(auth_header):

    try:
        token = auth_header.split()[1]
        payload = decode(
            token,
            settings.SIMPLE_JWT["SIGNING_KEY"],
            algorithms=[settings.SIMPLE_JWT["ALGORITHM"]],
        )
        return payload.get("user_id", None)
    except Exception as e:
        return None


#  404 not found error view Handler************************************************************


def error_404_view(request, exception):
    return render(request, "custom_404.html", status=404)
