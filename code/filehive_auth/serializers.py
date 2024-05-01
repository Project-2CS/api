from rest_framework import serializers
from .models import User
from django.contrib.auth.password_validation import validate_password
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from rest_framework.validators import UniqueValidator
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from django.contrib.sites.shortcuts import get_current_site
from django.urls import reverse
from django.core.mail import send_mail
from django.core.files.base import ContentFile
from django.conf import settings
import uuid
import os


class UserSerializer(serializers.ModelSerializer):

    class Meta:
        model = User
        fields = [
            "id",
            "email",
            "password",
            "profilePicture",
            "first_name",
            "last_name",
            "is_active",
            "is_verified",
            "is_superuser",
        ]
        extra_kwargs = {
            'password': {'write_only': True}
            }

    def create(self, validated_data):
        password = validated_data.pop("password", None)
        instance = self.Meta.model(**validated_data)

        instance.is_verified = False
        if password is not None:
            instance.set_password(password)
            instance.save()

        return instance

    def update(self, instance, validated_data):
        if 'profilePicture' in validated_data:
            newProfilePicture = validated_data.pop('profilePicture')
        
            try:
                oldProfilePicture = instance.profilePicture.path
                
            except ValueError:
                oldProfilePicture = None
            if oldProfilePicture and os.path.exists(oldProfilePicture):
                os.remove(oldProfilePicture)
            instance.profilePicture.save(newProfilePicture.name, ContentFile(newProfilePicture.read()), save=False)
            
        # print(f"the validated_data:  {dir(validated_data)}")
        print(f"the validated data {validated_data.items} {validated_data.keys} {validated_data.keys}")
        # instance.first_name = validated_data.get("first_name")
        # instance.last_name = validated_data.get("last_name") 
        print(f"Before update: {instance.__dict__}")
        for attr, value in validated_data.items():
         
            setattr(instance, attr, value)
       

        instance.save()
      
        return instance


class MyTokenObtainPairSerializer(TokenObtainPairSerializer):

    @classmethod
    def get_token(cls, user):
        token = super().get_token(user)

        token["email"] = user.email
        token["first_name"] = user.first_name
        token["last_name"] = user.last_name
        token["profilePicture"] = str(user.profilePicture)
        token["is_verified"] = user.is_verified
        token["is_active"] = user.is_active

        return token
