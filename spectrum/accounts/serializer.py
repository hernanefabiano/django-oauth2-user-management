from rest_framework import serializers, viewsets
from rest_framework.response import Response
from rest_framework.permissions import AllowAny

from django.http import Http404, HttpResponseForbidden
from django.contrib.auth.models import User

from django.core.mail import send_mail


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ('id', 'password', 'email', 'first_name', 'last_name', 'is_active')
        extra_kwargs = {
            'email': {'required': True}, 
            # 'password': {'required': False}
        }

    def create(self, validated_data):
        password = validated_data.pop('password', None)
        instance = self.Meta.model(**validated_data)
        instance.is_active = False
        instance.username = validated_data.pop('email', None)
        if password is not None:
            instance.set_password(password)
        if instance.save():
            self.send_registration_mail(validated_data)
        return instance

    # def put(self, request, *args, **kwargs):
    #     return self.update(request, *args, **kwargs)

    def send_registration_mail(self, validated_data):
        message_body = '''
            Hi {},
            Please access the link below to activate your account.
            Activation url: {}.
        '''.format(validated_data.get('first_name', 'New User'), 'http://spectrum.co')

        send_mail(
            'Account Registration', message_body,
            'admin@spectrum.co', [validated_data.get('email')],
            fail_silently=False
        )
