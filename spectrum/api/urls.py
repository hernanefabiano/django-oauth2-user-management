from __future__ import absolute_import, division, print_function, unicode_literals

from django.conf.urls import include, url
from rest_framework.routers import SimpleRouter

from accounts.views import UserAccountViewSet


router = SimpleRouter()
router.register("users", UserAccountViewSet)
urlpatterns = router.urls
