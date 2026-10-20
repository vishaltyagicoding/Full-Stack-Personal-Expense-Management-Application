from rest_framework import status, generics, permissions
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth import authenticate, get_user_model
from django.core.mail import send_mail
from django.conf import settings
from .serializers import RegisterSerializer, UserSerializer, ChangePasswordSerializer, UserProfileSerializer
from .models import OTPVerification

User = get_user_model()

class LoginView(APIView):
    permission_classes = [permissions.AllowAny]
    
    def post(self, request):
        email = request.data.get('email')
        password = request.data.get('password')
        
        if not email or not password:
            return Response(
                {'detail': 'Email and password are required'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        user = authenticate(username=email, password=password)
        
        if user is None:
            return Response(
                {'detail': 'Invalid email or password. Please check your credentials and try again.'},
                status=status.HTTP_401_UNAUTHORIZED
            )
        
        if not user.is_active:
            return Response(
                {'detail': 'Your account has been disabled. Please contact support.'},
                status=status.HTTP_403_FORBIDDEN
            )
        
        refresh = RefreshToken.for_user(user)
        
        return Response({
            'user': UserSerializer(user).data,
            'refresh': str(refresh),
            'access': str(refresh.access_token),
        }, status=status.HTTP_200_OK)

class RegisterView(generics.CreateAPIView):
    queryset = User.objects.all()
    permission_classes = [permissions.AllowAny]
    serializer_class = RegisterSerializer

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()

        # Deactivate until email verified
        user.is_active = False
        user.save()

        # Generate and send OTP
        otp_obj = OTPVerification.generate_otp(user)
        
        try:
            send_mail(
                subject='Your Email Verification OTP',
                message=f'Your OTP is: {otp_obj.otp}\nIt expires in 10 minutes.',
                from_email=settings.DEFAULT_FROM_EMAIL,
                recipient_list=[user.email],
                fail_silently=False,
            )
            print(f"✓ OTP email sent successfully to {user.email}")
            print(f"✓ OTP: {otp_obj.otp}")
        except Exception as e:
            print(f"✗ Failed to send email: {str(e)}")
            # Still return success but log the error
            import logging
            logger = logging.getLogger(__name__)
            logger.error(f"Failed to send OTP email to {user.email}: {str(e)}")

        return Response(
            {'detail': 'Registration successful. Please check your email for the OTP to verify your account.'},
            status=status.HTTP_201_CREATED
        )


class VerifyOTPView(APIView):
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        email = request.data.get('email')
        otp = request.data.get('otp')

        if not email or not otp:
            return Response({'detail': 'Email and OTP are required.'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            return Response({'detail': 'User not found.'}, status=status.HTTP_404_NOT_FOUND)

        otp_obj = OTPVerification.objects.filter(user=user, otp=otp, is_used=False).last()

        if not otp_obj:
            return Response({'detail': 'Invalid OTP.'}, status=status.HTTP_400_BAD_REQUEST)

        if otp_obj.is_expired():
            return Response({'detail': 'OTP has expired. Please request a new one.'}, status=status.HTTP_400_BAD_REQUEST)

        # Activate user
        otp_obj.is_used = True
        otp_obj.save()
        user.is_active = True
        user.save()

        refresh = RefreshToken.for_user(user)
        return Response({
            'detail': 'Email verified successfully.',
            'user': UserSerializer(user).data,
            'refresh': str(refresh),
            'access': str(refresh.access_token),
        }, status=status.HTTP_200_OK)


class ResendOTPView(APIView):
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        email = request.data.get('email')
        if not email:
            return Response({'detail': 'Email is required.'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            user = User.objects.get(email=email, is_active=False)
        except User.DoesNotExist:
            return Response({'detail': 'No pending verification found for this email.'}, status=status.HTTP_404_NOT_FOUND)

        otp_obj = OTPVerification.generate_otp(user)
        
        try:
            send_mail(
                subject='Your Email Verification OTP',
                message=f'Your new OTP is: {otp_obj.otp}\nIt expires in 10 minutes.',
                from_email=settings.DEFAULT_FROM_EMAIL,
                recipient_list=[user.email],
                fail_silently=False,
            )
            print(f"✓ OTP resent successfully to {user.email}")
            print(f"✓ New OTP: {otp_obj.otp}")
        except Exception as e:
            print(f"✗ Failed to resend email: {str(e)}")
            import logging
            logger = logging.getLogger(__name__)
            logger.error(f"Failed to resend OTP email to {user.email}: {str(e)}")

        return Response({'detail': 'OTP resent successfully.'}, status=status.HTTP_200_OK)

class LogoutView(APIView):
    permission_classes = [permissions.IsAuthenticated]
    
    def post(self, request):
        try:
            refresh_token = request.data.get("refresh")
            if refresh_token:
                token = RefreshToken(refresh_token)
                token.blacklist()
                return Response({"message": "Logout successful"}, status=status.HTTP_200_OK)
            # If no refresh token provided, just return success (user already logged out from frontend)
            return Response({"message": "Logout successful"}, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)

class UserProfileView(generics.RetrieveUpdateAPIView):
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = UserProfileSerializer
    
    def get_object(self):
        return self.request.user

class ChangePasswordView(APIView):
    permission_classes = [permissions.IsAuthenticated]
    
    def post(self, request):
        serializer = ChangePasswordSerializer(data=request.data)
        if serializer.is_valid():
            user = request.user
            if not user.check_password(serializer.data.get('old_password')):
                return Response({"old_password": "Wrong password"}, status=status.HTTP_400_BAD_REQUEST)
            
            user.set_password(serializer.data.get('new_password'))
            user.save()
            return Response({"message": "Password changed successfully"}, status=status.HTTP_200_OK)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    