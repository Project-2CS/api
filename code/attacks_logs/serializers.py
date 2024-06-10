from rest_framework import serializers
from .models import Log



class LogSerializer(serializers.ModelSerializer):
    class Meta:
        model = Log
        fields = [  "attack_type", "file",  "user", "attack_timing", "attack_input"]
        def create(self, validated_data):
            
            return super().create(validated_data)
        
            


            

        
       
   


