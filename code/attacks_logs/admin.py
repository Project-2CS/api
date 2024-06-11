from django.contrib import admin

# Register your models here.

from .models import Log

class LogAdmin(admin.ModelAdmin):
  
    list_editable = []
  
    list_display = ('attack_type', 'user', 'file', 'attack_input', 'attack_timing')
 





admin.site.register(Log, LogAdmin)
