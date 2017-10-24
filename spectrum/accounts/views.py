from __future__ import absolute_import, division, print_function, unicode_literals

from django.contrib.auth.models import User
from django.shortcuts import get_object_or_404

from django.contrib.auth import authenticate, login
from django.conf import settings
from django.utils import timezone

from rest_framework import viewsets
from rest_framework.views import APIView
from rest_framework.permissions import AllowAny
from rest_framework import authentication
from rest_framework.response import Response
from rest_framework import status

from oauth2_provider.models import AccessToken, Application
from oauthlib.common import generate_token

from datetime import datetime, timedelta

from .serializer import UserSerializer, UserActivateSerializer, UserPasswordResetSerializer
from .permissions import IsStaffOrAuthenticatedUser


class UserAuthenticationView(APIView):

    permission_classes = (AllowAny, )

    def post(self, request, pk=None):
        authentication_status = None
        bearer_token = None
        expired_token = False
        username = request.data.get('username', None)
        password = request.data.get('password', None)

        if None in [username, password]:
            return Response('Username/Password is required.', status.HTTP_401_UNAUTHORIZED)

        try:
            user = authenticate(username=username, password=password)
            if user is not None:
                if not user.is_active:
                    authentication_status = "Your account is not active, please access activation link."
            else:
                authentication_status = "Your email and/or password were incorrect."

            if authentication_status is not None:
                return Response(authentication_status, status=status.HTTP_401_UNAUTHORIZED)

            # get registered app to retrived client_id and client_secret key
            registered_app = Application.objects.get(name=settings.OAUTH2_APPLICATION_NAME)
            authorization = AccessToken.objects.filter(
                user=user, application=registered_app).values('token', 'expires')

            if authorization:
                # check if token is already expired.
                if authorization[0]['expires'] < datetime.now(timezone.utc):
                    expired_token = True
                else:
                    bearer_token = authorization[0]['token']
            
            if expired_token:
                bearer_token, _ = AccessToken.objects.get_or_create(
                    user=user, application=registered_app,
                    expires=datetime.now() + timedelta(days=5), token=generate_token(request)
                )

            return Response({'Authorization': 'Bearer {}'.format(bearer_token)})

        except Exception as e:
            return Response(e.message, status=status.HTTP_400_BAD_REQUEST)


class UserAccountViewSet(viewsets.ModelViewSet):
    """
    A simple ModelViewSet for display and manage accounts of the DRF.
    Implement oauth2 authentication for authentication/authorization.
    """
    serializer_class = UserSerializer
    permission_classes = (IsStaffOrAuthenticatedUser,)

    def get_object(self, queryset=None):
        obj = self.request.user
        return obj

    def get_queryset(self, pk=None):
        queryset = User.objects.all()
        if pk is not None:
            queryset = queryset.filter(pk=pk)
        return queryset.order_by('date_joined')

    def list(self, request):
        queryset = self.get_queryset()
        if not authentication.get_authorization_header(request):
            return Response(queryset.values(
                'username', 'last_name', 'first_name', 'is_active'),
                status=status.HTTP_200_OK
            )

        serializer = UserSerializer(queryset, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

    def post(self, request, *args, **kwargs):
        serializer = UserSerializer(request.data, many=True)
        if serializer.is_valid():
            return self.create(request, *args, **kwargs)

        return Response(serializer.errors, status.HTTP_400_BAD_REQUEST)

    def retrieve(self, request, pk=None):
        user = get_object_or_404(self.get_queryset(), pk=pk)
        serializer = UserSerializer(user)
        return Response(serializer.data)

    def partial_update(self, request, pk=None):
        user = get_object_or_404(self.get_queryset(pk))
        if request.data.get('newpassword'):
            serializer = UserPasswordResetSerializer(data=request.data)
            if serializer.is_valid():
                if user.check_password(serializer.data.get("password")):
                    user.set_password(serializer.data.get("newpassword"))
                    user.save()
                    return Response("Password reset successfully.", status=status.HTTP_200_OK)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        elif request.data.get('is_active'):
            if user.is_active:
                return Response('User account({}) status is active.'.format(
                    user.username), status=status.HTTP_200_OK
                )

            serializer = UserActivateSerializer(data=request.data)
            if serializer.is_valid():
                if serializer.data['is_active'] and serializer.data['is_active'] == 1:
                    user.is_active = True
                    user.save()
                    return Response('User account now have an active status', status=status.HTTP_205_RESET_CONTENT)

            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        return Response('Unknown action request', status=status.HTTP_400_BAD_REQUEST)
