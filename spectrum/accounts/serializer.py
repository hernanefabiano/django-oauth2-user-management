from __future__ import absolute_import, division, print_function, unicode_literals

from django.contrib.auth.models import User

from django.core.mail import send_mail

from rest_framework import serializers


class UserActivateSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ('is_active',)
        extra_kwargs = {
            'is_active': {'required': True},
        }


class UserPasswordResetSerializer(serializers.Serializer):
    password = serializers.CharField(max_length=128)
    newpassword = serializers.CharField(max_length=128)

    class Meta:
        extra_kwargs = {
            'password': {'required': True, 'write_only': True},
            'newpassword': {'required': True, },
        }


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ('id', 'email', 'password', 'username', 'first_name', 'last_name')
        extra_kwargs = {
            'email': {'required': True},
            'password': {'required': True, 'write_only': True},
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

    def send_registration_mail(self, validated_data):
        first_name = validated_data.get('first_name', 'New User')
        token_url = 'http://localhost:8000/api/get-token?username={}'.format(validated_data.get('email'))
        message_body = '''
            Hi {},
            Please access the link below to activate your account.
            Activation url: {}.'''.format(first_name, token_url)

        send_mail(
            'Account Registration', message_body,
            'admin@test.com', [validated_data.get('email')],
            fail_silently=False
        )
