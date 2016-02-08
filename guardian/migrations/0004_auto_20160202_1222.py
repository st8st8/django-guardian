# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations


class Migration(migrations.Migration):

    dependencies = [
        ('guardian', '0003_auto_20150922_1356'),
    ]

    operations = [
        migrations.AddField(
            model_name='groupobjectpermission',
            name='permission_expiry_0day_email_sent',
            field=models.BooleanField(default=False),
        ),
        migrations.AddField(
            model_name='organizationobjectpermission',
            name='permission_expiry_0day_email_sent',
            field=models.BooleanField(default=False),
        ),
        migrations.AddField(
            model_name='userobjectpermission',
            name='permission_expiry_0day_email_sent',
            field=models.BooleanField(default=False),
        ),
    ]
