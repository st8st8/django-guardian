"""
django-guardian helper functions.

Functions defined within this module should be considered as django-guardian's
internal functionality. They are **not** guaranteed to be stable - which means
they actual input parameters/output type may change in future releases.
"""
from __future__ import unicode_literals

import logging
import os
from datetime import datetime
from itertools import chain

import django
from django.conf import settings
from django.contrib.auth import REDIRECT_FIELD_NAME
from django.contrib.auth.models import AnonymousUser, Group
from django.core.exceptions import ObjectDoesNotExist, PermissionDenied
from django.db.models import Model
from django.http import HttpResponseForbidden, HttpResponseNotFound
from django.shortcuts import render_to_response, render
from django.template import RequestContext
from pytz import utc

from guardian.compat import get_user_model
from guardian.conf import settings as guardian_settings
from guardian.ctypes import get_content_type
from guardian.exceptions import NotUserNorGroup
from organizations.models import Organization

logger = logging.getLogger(__name__)
abspath = lambda *p: os.path.abspath(os.path.join(*p))


def get_anonymous_user():
    """
    Returns ``User`` instance (not ``AnonymousUser``) depending on
    ``ANONYMOUS_USER_NAME`` configuration.
    """
    User = get_user_model()
    lookup = {User.USERNAME_FIELD: guardian_settings.ANONYMOUS_USER_NAME}
    return User.objects.get(**lookup)


def get_identity(identity):
    """
    Returns (user_obj, None) or (None, group_obj) tuple depending on what is
    given. Also accepts AnonymousUser instance but would return ``User``
    instead - it is convenient and needed for authorization backend to support
    anonymous users.

    :param identity: either ``User`` or ``Group`` instance

    :raises ``NotUserNorGroup``: if cannot return proper identity instance

    **Examples**::

       >>> from django.contrib.auth.models import User
       >>> user = User.objects.create(username='joe')
       >>> get_identity(user)
       (<User: joe>, None)

       >>> group = Group.objects.create(name='users')
       >>> get_identity(group)
       (None, <Group: users>)

       >>> anon = AnonymousUser()
       >>> get_identity(anon)
       (<User: AnonymousUser>, None)

       >>> get_identity("not instance")
       ...
       NotUserNorGroup: User/AnonymousUser or Group instance is required (got )

    """
    if isinstance(identity, AnonymousUser):
        identity = get_anonymous_user()

    if isinstance(identity, get_user_model()):
        return identity, None, None
    elif isinstance(identity, Group):
        return None, identity, None
    elif isinstance(identity, Organization):
        return None, None, identity

    raise NotUserNorGroup("User/AnonymousUser or Group/Organization instance is required "
        "(got %s)" % identity)


def get_40x_or_None(request, perms, obj=None, login_url=None,
                    redirect_field_name=None, return_403=False,
                    return_404=False, accept_global_perms=False):
    login_url = login_url or settings.LOGIN_URL
    redirect_field_name = redirect_field_name or REDIRECT_FIELD_NAME

    # Handles both original and with object provided permission check
    # as ``obj`` defaults to None

    has_permissions = False
    # global perms check first (if accept_global_perms)
    if accept_global_perms:
        has_permissions = all(request.user.has_perm(perm) for perm in perms)
    # if still no permission granted, try obj perms
    if not has_permissions:
        has_permissions = all(request.user.has_perm(perm, obj)
                              for perm in perms)

    if not has_permissions:
        if return_403:
            if guardian_settings.RENDER_403:
                if django.VERSION >= (1, 10):
                    response = render(request, guardian_settings.TEMPLATE_403)
                else:
                    response = render_to_response(
                        guardian_settings.TEMPLATE_403, {},
                        RequestContext(request))
                response.status_code = 403
                return response
            elif guardian_settings.RAISE_403:
                raise PermissionDenied
            return HttpResponseForbidden()
        if return_404:
            if guardian_settings.RENDER_404:
                if django.VERSION >= (1, 10):
                    response = render(request, guardian_settings.TEMPLATE_404)
                else:
                    response = render_to_response(
                        guardian_settings.TEMPLATE_404, {},
                        RequestContext(request))
                response.status_code = 404
                return response
            elif guardian_settings.RAISE_404:
                raise ObjectDoesNotExist
            return HttpResponseNotFound()
        else:
            from django.contrib.auth.views import redirect_to_login
            return redirect_to_login(request.get_full_path(),
                                     login_url,
                                     redirect_field_name)


def clean_orphan_obj_perms():
    """
    Seeks and removes all object permissions entries pointing at non-existing
    targets.

    Returns number of removed objects.
    """
    from guardian.models import UserObjectPermission
    from guardian.models import GroupObjectPermission
    from guardian.models import OrganizationObjectPermission


    deleted = 0
    # TODO: optimise
    for perm in chain(UserObjectPermission.objects.all().iterator(),
                      GroupObjectPermission.objects.all().iterator(),
                      OrganizationObjectPermission.objects.all().iterator()):
        if perm.content_object is None:
            logger.debug("Removing %s (pk=%d)" % (perm, perm.pk))
            perm.delete()
            deleted += 1
    logger.info("Total removed orphan object permissions instances: %d" %
                deleted)
    return deleted


# TODO: should raise error when multiple UserObjectPermission direct relations
# are defined

def get_obj_perms_model(obj, base_cls, generic_cls):
    if isinstance(obj, Model):
        obj = obj.__class__
    ctype = get_content_type(obj)

    if django.VERSION >= (1, 8):
        fields = (f for f in obj._meta.get_fields()
                  if (f.one_to_many or f.one_to_one) and f.auto_created)
    else:
        fields = obj._meta.get_all_related_objects()

    for attr in fields:
        if django.VERSION < (1, 8):
            model = getattr(attr, 'model', None)
        else:
            model = getattr(attr, 'related_model', None)
        if (model and issubclass(model, base_cls) and
                model is not generic_cls):
            # if model is generic one it would be returned anyway
            if not model.objects.is_generic():
                # make sure that content_object's content_type is same as
                # the one of given obj
                fk = model._meta.get_field('content_object')
                if ctype == get_content_type(fk.remote_field.model):
                    return model
    return generic_cls


def get_user_obj_perms_model(obj):
    """
    Returns model class that connects given ``obj`` and User class.
    """
    from guardian.models import UserObjectPermissionBase
    from guardian.models import UserObjectPermission
    return get_obj_perms_model(obj, UserObjectPermissionBase, UserObjectPermission)


def get_group_obj_perms_model(obj):
    """
    Returns model class that connects given ``obj`` and Group class.
    """
    from guardian.models import GroupObjectPermissionBase
    from guardian.models import GroupObjectPermission
    return get_obj_perms_model(obj, GroupObjectPermissionBase, GroupObjectPermission)


def get_organization_obj_perms_model(obj):
    """
    Returns model class that connects given ``obj`` and Group class.
    """
    from guardian.models import OrganizationObjectPermissionBase
    from guardian.models import OrganizationObjectPermission
    return get_obj_perms_model(obj, OrganizationObjectPermissionBase, OrganizationObjectPermission)


def calculate_permission_expiry(perm, renewal_period):
    if not perm or not renewal_period:
        return None

    expiry = perm.permission_expiry
    if expiry is None:
        return (datetime.utcnow() + renewal_period).replace(tzinfo=utc)
    elif expiry < datetime.utcnow().replace(tzinfo=utc):
        return datetime.utcnow().replace(tzinfo=utc) + renewal_period
    else:
        return expiry.replace(tzinfo=utc) + renewal_period
