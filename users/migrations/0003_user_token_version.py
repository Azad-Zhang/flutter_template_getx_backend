# Generated by Django 5.2.1 on 2025-05-14 20:10

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('users', '0002_user_encrypted_private_key_user_public_key_and_more'),
    ]

    operations = [
        migrations.AddField(
            model_name='user',
            name='token_version',
            field=models.IntegerField(default=0, verbose_name='Token版本号'),
        ),
    ]
