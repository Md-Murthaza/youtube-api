from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone


class Youtubetoken(models.Model):
    user = models.OneToOneField(User,on_delete=models.CASCADE)
    access_token = models.TextField()
    refresh_token = models.TextField(null=True , blank=True)
    expires_at = models.DateTimeField()


    def is_expired(self):
        return timezone.now() >= self.expires_at

    def __str__(self):
        return f"Token for {self.user.username}"