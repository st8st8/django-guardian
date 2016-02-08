#!/usr/bin/python
# -*- coding: utf-8 -*-

from __future__ import unicode_literals
from builtins import str
from builtins import object

from django.db import models
from django.core.exceptions import ValidationError
from django.contrib.auth.models import Group
from django.contrib.auth.models import Permission
from django.contrib.contenttypes.models import ContentType

try:
    from django.contrib.contenttypes.fields import GenericForeignKey
except ImportError:
    from django.contrib.contenttypes.generic import GenericForeignKey

from django.utils.translation import ugettext_lazy as _

from organizations.models import Organization
from guardian.compat import user_model_label
from guardian.compat import str
from guardian.managers import GroupObjectPermissionManager, OrganizationObjectPermissionManager
from guardian.managers import UserObjectPermissionManager
from django.conf import settings


class BaseObjectPermission(models.Model):
    """
    Abstract ObjectPermission class. Actual class should additionally define
    a ``content_object`` field and either ``user`` or ``group`` field.
    """
    permission = models.ForeignKey(Permission)

    class Meta(object):
        abstract = True

    def __unicode__(self):
        return u'%s | %s | %s' % (
            str(self.content_object),
            str(getattr(self, 'user', False) or getattr(self, 'user', False) or self.organization),
            str(self.permission.codename))

    def save(self, *args, **kwargs):
        content_type = ContentType.objects.get_for_model(self.content_object)
        if content_type != self.permission.content_type:
            raise ValidationError("Cannot persist permission not designed for "
                                  "this class (permission's type is %r and object's type is %r)"
                                  % (self.permission.content_type, content_type))
        return super(BaseObjectPermission, self).save(*args, **kwargs)


class BaseGenericObjectPermission(models.Model):
    content_type = models.ForeignKey(ContentType)
    object_pk = models.CharField(_('object ID'), max_length=255)
    content_object = GenericForeignKey(fk_field='object_pk')
    permission_expiry = models.DateTimeField(null=True, blank=True)
    permission_expiry_30day_email_sent = models.BooleanField(null=False, default=False, blank=True)
    permission_expiry_0day_email_sent = models.BooleanField(null=False, default=False, blank=True)

    class Meta(object):
        abstract = True


class UserObjectPermissionBase(BaseObjectPermission):
    """
    **Manager**: :manager:`UserObjectPermissionManager`
    """
    user = models.ForeignKey(user_model_label)

    objects = UserObjectPermissionManager()

    class Meta(object):
        abstract = True
        unique_together = ['user', 'permission', 'content_object']


class UserObjectPermission(UserObjectPermissionBase, BaseGenericObjectPermission):
    class Meta(object):
        unique_together = ['user', 'permission', 'object_pk']


class GroupObjectPermissionBase(BaseObjectPermission):
    """
    **Manager**: :manager:`GroupObjectPermissionManager`
    """
    group = models.ForeignKey(Group)

    objects = GroupObjectPermissionManager()

    class Meta(object):
        abstract = True
        unique_together = ['group', 'permission', 'content_object']


class GroupObjectPermission(GroupObjectPermissionBase, BaseGenericObjectPermission):
    class Meta(object):
        unique_together = ['group', 'permission', 'object_pk']


class OrganizationObjectPermissionBase(BaseObjectPermission):
    """
    **Manager**: :manager:`GroupObjectPermissionManager`
    """
    organization = models.ForeignKey(Organization)

    objects = OrganizationObjectPermissionManager()

    class Meta(object):
        abstract = True
        unique_together = ['organization', 'permission', 'content_object']


class OrganizationObjectPermission(OrganizationObjectPermissionBase, BaseGenericObjectPermission):
    class Meta(object):
        unique_together = ['organization', 'permission', 'object_pk']


# As with Django 1.7, you can't use the get_user_model at this point
# because the app registry isn't ready yet (we're inside a model file).
import django

if django.VERSION < (1, 7) and settings.MONKEY_PATCH:
    from . import monkey_patch_user

    monkey_patch_user()

setattr(Group, 'add_obj_perm',
        lambda self, perm, obj: GroupObjectPermission.objects.assign_perm(perm, self, obj))
setattr(Group, 'del_obj_perm',
        lambda self, perm, obj: GroupObjectPermission.objects.remove_perm(perm, self, obj))

setattr(Organization, 'add_obj_perm',
        lambda self, perm, obj: OrganizationObjectPermission.objects.assign_perm(perm, self, obj))
setattr(Organization, 'del_obj_perm',
        lambda self, perm, obj: OrganizationObjectPermission.objects.remove_perm(perm, self, obj))
