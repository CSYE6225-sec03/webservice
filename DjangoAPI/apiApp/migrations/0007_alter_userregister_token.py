# Generated by Django 3.2.5 on 2022-02-12 20:54

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('apiApp', '0006_alter_userregister_username'),
    ]

    operations = [
        migrations.AlterField(
            model_name='userregister',
            name='token',
            field=models.CharField(blank=True, max_length=200, null=True),
        ),
    ]
