from __future__ import absolute_import, division, print_function, unicode_literals

from django.shortcuts import get_object_or_404
from django.contrib.auth.models import User
from rest_framework import viewsets
from rest_framework.views import APIView
from rest_framework.permissions import AllowAny

from rest_framework import authentication
from rest_framework import exceptions

# from .permissions import IsStaffOrTargetUser
# from .serializer import UserSerializer

# from rest_framework.authentication import get_authorization_header
from rest_framework.response import Response
from rest_framework import status

from .serializer import UserSerializer


class UserAccountViewSet(viewsets.ModelViewSet):
    """
    A simple ModelViewSet for display and manage accounts of the DRF.
    Implement oauth2 authentication for authentication/authorization.
    """
    queryset = User.objects.all()
    serializer_class = UserSerializer
    # permission_classes = [IsAccountAdminOrReadOnly]

    def list(self, request):
        auth = authentication.get_authorization_header(request)
        if not auth:
            return Response(User.objects.values('username', 'first_name', 'is_active'))
        
        queryset = User.objects.all()    
        serializer = UserSerializer(queryset, many=True)
        return Response(serializer.data)

    def retrieve(self, request, pk=None):
        queryset = self.queryset
        userinfo = get_object_or_404(queryset, pk=pk)
        serializer = UserSerializer(userinfo)
        return Response(serializer.data)

    def update(self, request, pk=None):
        queryset = self.queryset
        userinfo = get_object_or_404(queryset, pk=pk)
        userinfo.is_active = True
        userinfo.save()
        serializer = UserSerializer(userinfo)
        return Response(serializer.data)
