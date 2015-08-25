#!/usr/bin/python
# -*- coding: utf-8 -*-

from __future__ import unicode_literals

import warnings

from django.db import models
from django.contrib.contenttypes.models import ContentType

from guardian.exceptions import ObjectNotPersisted
from guardian.models import Permission


# TODO: consolidate UserObjectPermissionManager and GroupObjectPermissionManager
from guardian.utils import calculate_permission_expiry


class BaseObjectPermissionManager(models.Manager):
    def is_generic(self):
        try:
            self.model._meta.get_field('object_pk')
            return True
        except models.fields.FieldDoesNotExist:
            return False


class UserObjectPermissionManager(BaseObjectPermissionManager):
    def assign_perm(self, perm, user, obj, renewal_period=None):
        """
        Assigns permission with given ``perm`` for an instance ``obj`` and
        ``user``.
        """
        if getattr(obj, 'pk', None) is None:
            raise ObjectNotPersisted("Object %s needs to be persisted first"
                                     % obj)
        ctype = ContentType.objects.get_for_model(obj)
        permission = Permission.objects.get(content_type=ctype, codename=perm)

        kwargs = {'permission': permission, 'user': user}
        if self.is_generic():
            kwargs['content_type'] = ctype
            kwargs['object_pk'] = obj.pk
        else:
            kwargs['content_object'] = obj
        obj_perm, created = self.get_or_create(**kwargs)

        obj_perm.permission_expiry = calculate_permission_expiry(obj_perm, renewal_period)
        obj_perm.save()
        return obj_perm

    def assign(self, perm, user, obj):
        """ Depreciated function name left in for compatibility"""
        warnings.warn(
            "UserObjectPermissionManager method 'assign' is being renamed to 'assign_perm'. Update your code accordingly as old name will be depreciated in 2.0 version.",
            DeprecationWarning)
        return self.assign_perm(perm, user, obj)

    def remove_perm(self, perm, user, obj):
        """
        Removes permission ``perm`` for an instance ``obj`` and given ``user``.

        Please note that we do NOT fetch object permission from database - we
        use ``Queryset.delete`` method for removing it. Main implication of this
        is that ``post_delete`` signals would NOT be fired.
        """
        if getattr(obj, 'pk', None) is None:
            raise ObjectNotPersisted("Object %s needs to be persisted first"
                                     % obj)
        filters = {
            'permission__codename': perm,
            'permission__content_type': ContentType.objects.get_for_model(obj),
            'user': user,
        }
        if self.is_generic():
            filters['object_pk'] = obj.pk
        else:
            filters['content_object__pk'] = obj.pk
        self.filter(**filters).delete()


class GroupObjectPermissionManager(BaseObjectPermissionManager):
    def assign_perm(self, perm, group, obj, renewal_period=None):
        """
        Assigns permission with given ``perm`` for an instance ``obj`` and
        ``group``.
        """
        if getattr(obj, 'pk', None) is None:
            raise ObjectNotPersisted("Object %s needs to be persisted first"
                                     % obj)
        ctype = ContentType.objects.get_for_model(obj)
        permission = Permission.objects.get(content_type=ctype, codename=perm)

        kwargs = {'permission': permission, 'group': group}
        if self.is_generic():
            kwargs['content_type'] = ctype
            kwargs['object_pk'] = obj.pk
        else:
            kwargs['content_object'] = obj
        obj_perm, created = self.get_or_create(**kwargs)
        obj_perm.permission_expiry = calculate_permission_expiry(obj_perm, renewal_period)
        obj_perm.save()
        return obj_perm

    def assign(self, perm, user, obj):
        """ Depreciated function name left in for compatibility"""
        warnings.warn(
            "UserObjectPermissionManager method 'assign' is being renamed to 'assign_perm'. Update your code accordingly as old name will be depreciated in 2.0 version.",
            DeprecationWarning)
        return self.assign_perm(perm, user, obj)

    def remove_perm(self, perm, group, obj):
        """
        Removes permission ``perm`` for an instance ``obj`` and given ``group``.
        """
        if getattr(obj, 'pk', None) is None:
            raise ObjectNotPersisted("Object %s needs to be persisted first"
                                     % obj)
        filters = {
            'permission__codename': perm,
            'permission__content_type': ContentType.objects.get_for_model(obj),
            'group': group,
        }
        if self.is_generic():
            filters['object_pk'] = obj.pk
        else:
            filters['content_object__pk'] = obj.pk

        self.filter(**filters).delete()


class OrganizationObjectPermissionManager(BaseObjectPermissionManager):
    def assign_perm(self, perm, organization, obj, renewal_period=None):
        """
        Assigns permission with given ``perm`` for an instance ``obj`` and
        ``organization``.
        """
        if getattr(obj, 'pk', None) is None:
            raise ObjectNotPersisted("Object %s needs to be persisted first"
                                     % obj)
        ctype = ContentType.objects.get_for_model(obj)
        permission = Permission.objects.get(content_type=ctype, codename=perm)

        kwargs = {'permission': permission, 'organization': organization}
        if self.is_generic():
            kwargs['content_type'] = ctype
            kwargs['object_pk'] = obj.pk
        else:
            kwargs['content_object'] = obj
        obj_perm, created = self.get_or_create(**kwargs)
        obj_perm.permission_expiry = calculate_permission_expiry(obj_perm, renewal_period)
        obj_perm.save()
        return obj_perm

    def assign(self, perm, user, obj):
        """ Depreciated function name left in for compatibility"""
        warnings.warn(
            "UserObjectPermissionManager method 'assign' is being renamed to 'assign_perm'. Update your code accordingly as old name will be depreciated in 1.0.5 version.",
            DeprecationWarning)
        return self.assign_perm(perm, user, obj)

    def remove_perm(self, perm, organization, obj):
        """
        Removes permission ``perm`` for an instance ``obj`` and given ``organization``.
        """
        if getattr(obj, 'pk', None) is None:
            raise ObjectNotPersisted("Object %s needs to be persisted first"
                                     % obj)
        filters = {
            'permission__codename': perm,
            'permission__content_type': ContentType.objects.get_for_model(obj),
            'organization': organization,
        }
        if self.is_generic():
            filters['object_pk'] = obj.pk
        else:
            filters['content_object__pk'] = obj.pk

        self.filter(**filters).delete()

    def get_for_object(self, organization, obj):
        if getattr(obj, 'pk', None) is None:
            raise ObjectNotPersisted("Object %s needs to be persisted first"
                                     % obj)
        ctype = ContentType.objects.get_for_model(obj)
        perms = self.filter(
            content_type=ctype,
            organization=organization,
        )
        return perms

