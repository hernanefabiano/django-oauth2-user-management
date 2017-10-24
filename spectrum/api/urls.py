from __future__ import absolute_import, division, print_function, unicode_literals

from django.conf.urls import url

from rest_framework.routers import DefaultRouter

from accounts.views import UserAccountViewSet, UserAuthenticationView

router = DefaultRouter()
router.register(r"users", UserAccountViewSet, base_name="users")

urlpatterns = [
    url(r'^login/', UserAuthenticationView.as_view()),
]

urlpatterns += router.urls
