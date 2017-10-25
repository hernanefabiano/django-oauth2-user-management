from __future__ import absolute_import

from rest_framework import permissions


class IsStaffOrAuthenticatedUser(permissions.BasePermission):

    def has_permission(self, request, view):
        # Only authenticated users or admin account will be able to retrieve
        # user details and make adjustment to user object
        if view.action in ['list', 'create']:
            return True
        elif view.action in ['retrieve', 'update', 'partial_update', 'destroy', 'activate']:
            return request.user.is_authenticated()
        else:
            return False

    def has_object_permission(self, request, view, obj):
        # Only authenticated users or admin account will be able to retrieve.
        # login users will be able to change their own password.
        if view.action == 'retrieve':
            return request.user.is_authenticated() and obj == request.user
        elif view.action in ['update', 'partial_update', 'activate']:
            return request.user.is_authenticated() and obj == request.user
        elif view.action == 'destroy':
            return request.user.is_authenticated() and request.user.is_superuser
        else:
            return False
