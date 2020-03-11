from datetime import datetime
from itertools import chain

from django.contrib.auth import get_user_model
from django.contrib.auth.models import Permission
from django.db.models import Q
from django.db.models.query import QuerySet
from django.utils.encoding import force_str
from pytz import utc

from guardian.conf import settings as guardian_settings
from guardian.ctypes import get_content_type
from guardian.utils import get_group_obj_perms_model, get_identity, get_user_obj_perms_model, \
    get_organization_obj_perms_model


def _get_pks_model_and_ctype(objects):
    """
    Returns the primary keys, model and content type of an iterable of Django model objects.
    Assumes that all objects are of the same content type.
    """

    if isinstance(objects, QuerySet):
        model = objects.model
        pks = [force_str(pk) for pk in objects.values_list('pk', flat=True)]
        ctype = get_content_type(model)
    else:
        pks = []
        for idx, obj in enumerate(objects):
            if not idx:
                model = type(obj)
                ctype = get_content_type(model)
            pks.append(force_str(obj.pk))

    return pks, model, ctype


class ObjectPermissionChecker:
    """
    Generic object permissions checker class being the heart of
    ``django-guardian``.

    .. note::
       Once checked for single object, permissions are stored and we don't hit
       database again if another check is called for this object. This is great
       for templates, views or other request based checks (assuming we don't
       have hundreds of permissions on a single object as we fetch all
       permissions for checked object).

       On the other hand, if we call ``has_perm`` for perm1/object1, then we
       change permission state and call ``has_perm`` again for same
       perm1/object1 on same instance of ObjectPermissionChecker we won't see a
       difference as permissions are already fetched and stored within cache
       dictionary.
    """

    def __init__(self, user_or_group=None):
        """
        Constructor for ObjectPermissionChecker.

        :param user_or_group: should be an ``User``, ``AnonymousUser`` or
          ``Group`` instance
        """
        self.user, self.group, self.organization = get_identity(user_or_group)
        self._obj_perms_cache = {}

    def has_perm(self, perm, obj, permission_expiry=True):
        """
        Checks if user/group has given permission for object.

        :param perm: permission as string, may or may not contain app_label
          prefix (if not prefixed, we grab app_label from ``obj``)
        :param obj: Django model instance for which permission should be checked

        """
        if self.user and not self.user.is_active:
            return False
        elif self.user and self.user.is_superuser:
            return True
        if '.' in perm:
            _, perm = perm.split('.', maxsplit=1)
        return perm in self.get_perms(obj, permission_expiry)

    def get_organization_filters(self, obj, permission_expiry=False):
        User = get_user_model()
        ctype = get_content_type(obj)

        # Django organizations
        organization_model = get_organization_obj_perms_model(obj)
        organization_rel_name = organization_model.permission.field.related_query_name()
        if self.user:
            fieldname = '%s__organization__%s' % (
                organization_rel_name,
                "users",
            )
            organization_filters = {fieldname: self.user}
        else:
            organization_filters = {'%s__organization' % organization_rel_name: self.organization}
        if organization_model.objects.is_generic():
            organization_filters.update({
                '%s__content_type' % organization_rel_name: ctype,
                '%s__object_pk' % organization_rel_name: obj.pk,
            })
        else:
            organization_filters['%s__content_object' % organization_rel_name] = obj

        org_q = tuple()
        if permission_expiry:
            kwargs1 = {"%s__permission_expiry" % organization_rel_name: None}
            kwargs2 = {"%s__permission_expiry__gte" % organization_rel_name: datetime.utcnow().replace(tzinfo=utc)}
            org_q = (Q(**kwargs1) | Q(**kwargs2),)

        return organization_filters, org_q

    def get_group_filters(self, obj, permission_expiry=False):
        User = get_user_model()
        ctype = get_content_type(obj)

        group_model = get_group_obj_perms_model(obj)
        group_rel_name = group_model.permission.field.related_query_name()
        if self.user:
            fieldname = '%s__group__%s' % (
                group_rel_name,
                User.groups.field.related_query_name(),
            )
            group_filters = {fieldname: self.user}
        else:
            group_filters = {'%s__group' % group_rel_name: self.group}
        if group_model.objects.is_generic():
            group_filters.update({
                '%s__content_type' % group_rel_name: ctype,
                '%s__object_pk' % group_rel_name: obj.pk,
            })
        else:
            group_filters['%s__content_object' % group_rel_name] = obj

        return group_filters, tuple()

    def get_user_filters(self, obj, permission_expiry=False):
        ctype = get_content_type(obj)
        model = get_user_obj_perms_model(obj)
        related_name = model.permission.field.related_query_name()

        user_filters = {'%s__user' % related_name: self.user}
        if model.objects.is_generic():
            user_filters.update({
                '%s__content_type' % related_name: ctype,
                '%s__object_pk' % related_name: obj.pk,
            })
        else:
            user_filters['%s__content_object' % related_name] = obj

        user_q = tuple()
        if permission_expiry:
            kwargs1 = {"%s__permission_expiry" % related_name: None}
            kwargs2 = {"%s__permission_expiry__gte" % related_name: datetime.utcnow().replace(tzinfo=utc)}
            user_q = (Q(**kwargs1) | Q(**kwargs2),)

        return user_filters, user_q

    def get_user_perms(self, obj, permission_expiry=False):
        ctype = get_content_type(obj)

        perms_qs = Permission.objects.filter(content_type=ctype)
        user_filters, user_q = self.get_user_filters(obj, permission_expiry)
        user_perms_qs = perms_qs.filter(*user_q, **user_filters)
        user_perms = user_perms_qs.values_list("codename", flat=True)

        return user_perms

    def get_group_perms(self, obj, permission_expiry=False):
        ctype = get_content_type(obj)

        perms_qs = Permission.objects.filter(content_type=ctype)
        group_filters, group_q = self.get_group_filters(obj, permission_expiry)
        group_perms_qs = perms_qs.filter(**group_filters)
        group_perms = group_perms_qs.values_list("codename", flat=True)

        return group_perms

    def get_organization_perms(self, obj, permission_expiry=False):
        ctype = get_content_type(obj)

        perms_qs = Permission.objects.filter(content_type=ctype)
        organization_filters, org_q = self.get_organization_filters(obj, permission_expiry)
        organization_perms_qs = perms_qs.filter(*org_q, **organization_filters)
        organization_perms = organization_perms_qs.values_list("codename", flat=True)

        return organization_perms

    def get_perms(self, obj, permission_expiry=False, include_group_perms=True):
        """
        Returns list of ``codename``'s of all permissions for given ``obj``.

        :param obj: Django model instance for which permission should be checked

        """
        if self.user and not self.user.is_active:
            return []

        if guardian_settings.AUTO_PREFETCH:
            self._prefetch_cache()

        ctype = get_content_type(obj)
        key = self.get_local_cache_key(obj, include_group_perms, permission_expiry)
        if key not in self._obj_perms_cache:
            # If auto-prefetching enabled, do not hit database
            if guardian_settings.AUTO_PREFETCH:
                return []
            if self.user and self.user.is_superuser:
                perms = list(chain(*Permission.objects
                                   .filter(content_type=ctype)
                                   .values_list("codename")))
            elif self.user:
                # Query user and group permissions separately and then combine
                # the results to avoid a slow query
                user_perms = self.get_user_perms(obj, permission_expiry)
                if include_group_perms:
                    org_perms = self.get_organization_perms(obj, permission_expiry)
                    perms = list(set(chain(user_perms, org_perms)))
                else:
                    perms = user_perms
            elif self.group:
                group_filters, group_q = self.get_group_filters(obj, permission_expiry)
                perms = list(set(chain(*Permission.objects
                                       .filter(content_type=ctype)
                                       .filter(**group_filters)
                                       .values_list("codename"))))
            elif self.organization:
                organization_filters, org_q = self.get_organization_filters(obj, permission_expiry)
                perms = list(set(chain(*Permission.objects
                                       .filter(content_type=ctype)
                                        .filter(*org_q)
                                       .filter(**organization_filters)
                                       .values_list("codename"))))
            self._obj_perms_cache[key] = perms
        return self._obj_perms_cache[key]

    def get_local_cache_key(self, obj, include_group_perms=True, permission_expiry=False):
        """
        Returns cache key for ``_obj_perms_cache`` dict.
        """
        ctype = get_content_type(obj)
        return (ctype.id, force_str(obj.pk), include_group_perms, permission_expiry)

    def prefetch_perms(self, objects):
        """
        Prefetches the permissions for objects in ``objects`` and puts them in the cache.

        :param objects: Iterable of Django model objects

        """
        if self.user and not self.user.is_active:
            return []

        User = get_user_model()
        pks, model, ctype = _get_pks_model_and_ctype(objects)

        if self.user and self.user.is_superuser:
            perms = list(chain(
                *Permission.objects
                .filter(content_type=ctype)
                .values_list("codename")))

            for pk in pks:
                key = (ctype.id, force_str(pk))
                self._obj_perms_cache[key] = perms

            return True

        group_model = get_group_obj_perms_model(model)

        group_filters = {
            'object_pk__in': pks
        }

        if self.user:
            fieldname = 'group__{}'.format(
                User.groups.field.related_query_name(),
            )
            group_filters.update({fieldname: self.user})
        else:
            group_filters = {'group': self.group}

        if group_model.objects.is_generic():
            group_filters.update({
                'content_type': ctype,
                'object_pk__in': pks,
            })
        else:
            group_filters.update({
                'content_object_id__in': pks
            })

        if self.user:
            model = get_user_obj_perms_model(model)
            user_filters = {
                'user': self.user,
            }

            if model.objects.is_generic():
                user_filters.update({
                    'content_type': ctype,
                    'object_pk__in': pks
                })
            else:
                user_filters.update({
                    'content_object_id__in': pks
                })

            # Query user and group permissions separately and then combine
            # the results to avoid a slow query
            user_perms_qs = model.objects.filter(**user_filters).select_related('permission')
            group_perms_qs = group_model.objects.filter(**group_filters).select_related('permission')
            perms = chain(user_perms_qs, group_perms_qs)
        else:
            perms = chain(
                *(group_model.objects.filter(**group_filters).select_related('permission'),)
            )

        # initialize entry in '_obj_perms_cache' for all prefetched objects
        for obj in objects:
            key = self.get_local_cache_key(obj)
            if key not in self._obj_perms_cache:
                self._obj_perms_cache[key] = []

        for perm in perms:
            if type(perm).objects.is_generic():
                key = (ctype.id, perm.object_pk)
            else:
                key = (ctype.id, force_str(perm.content_object_id))

            self._obj_perms_cache[key].append(perm.permission.codename)

        return True
