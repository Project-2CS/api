from django.db import models
from django.contrib.auth.models import AbstractUser, BaseUserManager
from filehive_auth.models import User
# Create your models here.
class Log(models.Model):
    id = models.AutoField(primary_key=True)
    attack_type = models.CharField(max_length=254)
    file = models.FileField(upload_to=f"attack-files/%y/%m/%d/")
    attack_timing = models.DateTimeField(auto_now_add=True)
    user = models.CharField(max_length=254)
    attack_input = models.CharField(max_length=700)

    class Meta:
        db_table = 'logs'
        managed = True
        verbose_name = 'Log'
        verbose_name_plural = 'Logs'
    def __str__(self):
        return self.attack_type

    

    def save(self, *args, **kwargs):
        super().save(*args, **kwargs)

