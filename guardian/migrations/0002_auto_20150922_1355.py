# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations


class Migration(migrations.Migration):

    dependencies = [
        ('contenttypes', '0002_remove_content_type_name'),
        ('auth', '0006_require_contenttypes_0002'),
        ('organizations', '0005_organizationuser_date_created'),
        ('guardian', '0001_initial'),
    ]

    operations = [
        migrations.CreateModel(
            name='OrganizationObjectPermission',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('object_pk', models.CharField(max_length=255, verbose_name='object ID')),
                ('permission_expiry', models.DateTimeField(null=True, blank=True)),
                ('content_type', models.ForeignKey(to='contenttypes.ContentType')),
                ('organization', models.ForeignKey(to='organizations.Organization')),
                ('permission', models.ForeignKey(to='auth.Permission')),
            ],
        ),
        migrations.AddField(
            model_name='groupobjectpermission',
            name='permission_expiry',
            field=models.DateTimeField(null=True, blank=True),
        ),
        migrations.AddField(
            model_name='userobjectpermission',
            name='permission_expiry',
            field=models.DateTimeField(null=True, blank=True),
        ),
        migrations.AlterUniqueTogether(
            name='organizationobjectpermission',
            unique_together=set([('organization', 'permission', 'object_pk')]),
        ),
    ]
