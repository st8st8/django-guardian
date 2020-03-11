"""
Convenient shortcuts to manage or check object permissions.
"""
import warnings
from collections import defaultdict
from itertools import groupby

from django.apps import apps
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group, Permission
from django.contrib.contenttypes.models import ContentType
from django.db.models import Count, Q, QuerySet
from django.shortcuts import _get_queryset
from django.db.models.functions import Cast
from django.db.models import (
    IntegerField,
    AutoField,
    BigIntegerField,
    PositiveIntegerField,
    PositiveSmallIntegerField,
    SmallIntegerField,
    ForeignKey
)
from guardian.core import ObjectPermissionChecker
from guardian.ctypes import get_content_type
from guardian.exceptions import MixedContentTypeError, WrongAppError, MultipleIdentityAndObjectError
from guardian.models import GroupObjectPermission
from guardian.utils import get_anonymous_user, get_group_obj_perms_model, get_identity, get_user_obj_perms_model
OrganizationObjectPermission = get_group_obj_perms_model()
GroupObjectPermission = get_group_obj_perms_model()
UserObjectPermission = get_user_obj_perms_model()


def assign_perm(perm, user_or_group, obj=None):
    """
    Assigns permission to user/group and object pair.

    :param perm: proper permission for given ``obj``, as string (in format:
      ``app_label.codename`` or ``codename``) or ``Permission`` instance.
      If ``obj`` is not given, must be in format ``app_label.codename`` or
      ``Permission`` instance.

    :param user_or_group: instance of ``User``, ``AnonymousUser``, ``Group``,
      list of ``User`` or ``Group``, or queryset of ``User`` or ``Group``;
      passing any other object would raise
      ``guardian.exceptions.NotUserNorGroup`` exception

    :param obj: persisted Django's ``Model`` instance or QuerySet of Django
      ``Model`` instances or ``None`` if assigning global permission.
      Default is ``None``.

    We can assign permission for ``Model`` instance for specific user:

    >>> from django.contrib.sites.models import Site
    >>> from guardian.models import User
    >>> from guardian.shortcuts import assign_perm
    >>> site = Site.objects.get_current()
    >>> user = User.objects.create(username='joe')
    >>> assign_perm("change_site", user, site)
    <UserObjectPermission: example.com | joe | change_site>
    >>> user.has_perm("change_site", site)
    True

    ... or we can assign permission for group:

    >>> group = Group.objects.create(name='joe-group')
    >>> user.groups.add(group)
    >>> assign_perm("delete_site", group, site)
    <GroupObjectPermission: example.com | joe-group | delete_site>
    >>> user.has_perm("delete_site", site)
    True

    **Global permissions**

    This function may also be used to assign standard, *global* permissions if
    ``obj`` parameter is omitted. Added Permission would be returned in that
    case:

    >>> assign_perm("sites.change_site", user)
    <Permission: sites | site | Can change site>

    """
    user, group, organization = get_identity(user_or_group)
    # If obj is None we try to operate on global permissions
    if obj is None:
        if not isinstance(perm, Permission):
            try:
                app_label, codename = perm.split('.', 1)
            except ValueError:
                raise ValueError("For global permissions, first argument must be in"
                                 " format: 'app_label.codename' (is %r)" % perm)
            perm = Permission.objects.get(content_type__app_label=app_label,
                                          codename=codename)

        if user:
            user.user_permissions.add(perm)
            return perm
        if group:
            group.permissions.add(perm)
            return perm
        if organization:
            organization.permissions.add(perm)
            return perm

    if not isinstance(perm, Permission):
        if '.' in perm:
            app_label, perm = perm.split(".", 1)

    if isinstance(obj, QuerySet):
        if isinstance(user_or_group, (QuerySet, list)):
            raise MultipleIdentityAndObjectError("Only bulk operations on either users/groups OR objects supported")
        if user:
            model = get_user_obj_perms_model(obj.model)
            return model.objects.bulk_assign_perm(perm, user, obj, renewal_period, subscribe_to_emails)
        if group:
            model = get_group_obj_perms_model(obj.model)
            return model.objects.bulk_assign_perm(perm, group, obj, renewal_period, subscribe_to_emails)
        if organization:
            model = get_organization_obj_perms_model(obj.model)
            return model.objects.bulk_assign_perm(perm, organization, obj, renewal_period, subscribe_to_emails)

    if isinstance(user_or_group, (QuerySet, list)):
        if user:
            model = get_user_obj_perms_model(obj)
            return model.objects.assign_perm_to_many(perm, user, renewal_period, subscribe_to_emails)
        if group:
            model = get_group_obj_perms_model(obj)
            return model.objects.assign_perm_to_many(perm, group, obj, renewal_period, subscribe_to_emails)
        if organization:
            model = get_organization_obj_perms_model(obj)
            return model.objects.assign_perm_to_many(perm, organization, obj, renewal_period, subscribe_to_emails)

    if user:
        model = get_user_obj_perms_model(obj)
        return model.objects.assign_perm(perm, user, obj)

    if group:
        model = get_group_obj_perms_model(obj)
        return model.objects.assign_perm(perm, group, obj)


def assign(perm, user_or_group, obj=None):
    """ Depreciated function name left in for compatibility"""
    warnings.warn(
        "Shortcut function 'assign' is being renamed to 'assign_perm'. Update your code accordingly as old name will be depreciated in 2.0 version.",
        DeprecationWarning)
    return assign_perm(perm, user_or_group, obj)


def remove_perm(perm, user_or_group=None, obj=None):
    """
    Removes permission from user/group and object pair.

    :param perm: proper permission for given ``obj``, as string (in format:
      ``app_label.codename`` or ``codename``). If ``obj`` is not given, must
      be in format ``app_label.codename``.

    :param user_or_group: instance of ``User``, ``AnonymousUser`` or ``Group``;
      passing any other object would raise
      ``guardian.exceptions.NotUserNorGroup`` exception

    :param obj: persisted Django's ``Model`` instance or QuerySet of Django
      ``Model`` instances or ``None`` if assigning global permission.
      Default is ``None``.

    """
    user, group, organization = get_identity(user_or_group)
    if obj is None:
        try:
            app_label, codename = perm.split('.', 1)
        except ValueError:
            raise ValueError("For global permissions, first argument must be in"
                             " format: 'app_label.codename' (is %r)" % perm)
        perm = Permission.objects.get(content_type__app_label=app_label,
                                      codename=codename)
        if user:
            user.user_permissions.remove(perm)
            return
        elif group:
            group.permissions.remove(perm)
            return

    if not isinstance(perm, Permission):
        perm = perm.split('.')[-1]

    if isinstance(obj, QuerySet):
        if user:
            model = get_user_obj_perms_model(obj.model)
            return model.objects.bulk_remove_perm(perm, user, obj)
        if group:
            model = get_group_obj_perms_model(obj.model)
            return model.objects.bulk_remove_perm(perm, group, obj)

    if user:
        model = get_user_obj_perms_model(obj)
        return model.objects.remove_perm(perm, user, obj)

    if group:
        model = get_group_obj_perms_model(obj)
        return model.objects.remove_perm(perm, group, obj)

    if organization:
        model = get_organization_obj_perms_model(obj)
        return model.objects.remove_perm(perm, organization, obj)


def get_perms(user_or_group, obj):
    """
    Returns permissions for given user/group and object pair, as list of
    strings.
    """
    check = ObjectPermissionChecker(user_or_group)
    return check.get_perms(obj)


def get_user_perms(user, obj):
    """
    Returns permissions for given user and object pair, as list of
    strings, only those assigned directly for the user.
    """
    check = ObjectPermissionChecker(user)
    return check.get_user_perms(obj)


def get_group_perms(user_or_group, obj):
    """
    Returns permissions for given user/group and object pair, as list of
    strings. It returns only those which are inferred through groups.
    """
    check = ObjectPermissionChecker(user_or_group)
    return check.get_group_perms(obj)


def get_organization_perms(user_or_group, obj):
    """
    Returns permissions for given user/group and object pair, as list of
    strings. It returns only those which are inferred through groups.
    """
    check = ObjectPermissionChecker(user_or_group)
    return check.get_organization_perms(obj)


def get_perms_for_model(cls):
    """
    Returns queryset of all Permission objects for the given class. It is
    possible to pass Model as class or instance.
    """
    if isinstance(cls, str):
        app_label, model_name = cls.split('.')
        model = apps.get_model(app_label, model_name)
    else:
        model = cls
    ctype = get_content_type(model)
    return Permission.objects.filter(content_type=ctype)


def get_unattached_users_with_perms_qset(obj, perm,
                                         permission_expiry=False, with_group_users=True, with_superusers=False, only_with_perms_in=None):
    # It's much easier without attached perms so we do it first if that is
    # the case

    # JOINing into the perms table is a no-go - would have to be done three times, for users, groups and orgs.
    # Getting perm id first allows us to forgo this JOIN
    perm_id = None
    if perm:
        perm_id = cache.get("permission_id_{0}".format(perm))
        if not perm_id:
            perm_id = Permission.objects.get(codename=perm).id
            cache.set("permission_id_{0}".format(perm), perm_id, 86400)
    ctype = get_content_type(obj)
    user_model = get_user_obj_perms_model(obj)
    related_name = user_model.user.field.related_query_name()
    if user_model.objects.is_generic():
        user_filters = {
            '%s__content_type' % related_name: ctype,
            '%s__object_pk' % related_name: obj.pk,
        }
        if perm_id:
            user_filters.update({
                '%s__permission_id' % related_name: perm_id,
            })
    else:
        user_filters = {'%s__content_object' % related_name: obj}
    qset = Q(**user_filters)
    if only_with_perms_in is not None:
        permission_ids = Permission.objects.filter(content_type=ctype, codename__in=only_with_perms_in).values_list('id', flat=True)
        qset &= Q(**{
             '%s__permission_id__in' % related_name: permission_ids,
            })

    if permission_expiry:
        kwargs1 = {"%s__permission_expiry" % related_name: None}
        kwargs2 = {"%s__permission_expiry__gte" % related_name: datetime.utcnow().replace(tzinfo=utc)}
        qset &= (Q(**kwargs1) | Q(**kwargs2))

    if with_group_users:
        group_model = get_group_obj_perms_model(obj)
        group_rel_name = group_model.group.field.related_query_name()
        if group_model.objects.is_generic():
            group_filters = {
                'groups__%s__content_type' % group_rel_name: ctype,
                'groups__%s__object_pk' % group_rel_name: obj.pk,
            }
            if perm_id:
                group_filters.update({
                    'groups__%s__permission_id' % group_rel_name: perm_id,
                })
        else:
            group_filters = {
                'groups__%s__content_object' % group_rel_name: obj,
            }
        if only_with_perms_in is not None:
            permission_ids = Permission.objects.filter(content_type=ctype, codename__in=only_with_perms_in).values_list('id', flat=True)
            group_filters.update({
                'groups__%s__permission_id__in' % group_rel_name: permission_ids,
                })
        qset = qset | Q(**group_filters)

        org_model = get_organization_obj_perms_model(obj)
        organization_rel_name = org_model.organization.field.related_query_name()
        if org_model.objects.is_generic():
            organization_filters = {
                'organizations_organization__%s__content_type' % organization_rel_name: ctype,
                'organizations_organization__%s__object_pk' % organization_rel_name: obj.pk,
            }
            if perm_id:
                organization_filters.update({
                    'organizations_organization__%s__permission_id' % organization_rel_name: perm_id,
                })
        else:
            organization_filters = {
                'organizations_organization__%s__content_object' % organization_rel_name: obj
            }

        if permission_expiry:
            kwargs1 = {"organizations_organization__%s__permission_expiry" % organization_rel_name: None}
            kwargs2 = {"organizations_organization__%s__permission_expiry__gte" % organization_rel_name: datetime.utcnow().replace(tzinfo=utc)}
            qset &= (Q(**kwargs1) | Q(**kwargs2))

        qset = qset | Q(**organization_filters)
    if with_superusers:
        qset = qset | Q(is_superuser=True)
    return qset


def get_users_with_perms(obj, attach_perms=False, with_superusers=False,
                         with_group_users=True, permission_expiry=False, only_with_perms_in=None):
        """
        Returns queryset of all ``User`` objects with *any* object permissions for
        the given ``obj``.

    :param obj: persisted Django's ``Model`` instance

    :param attach_perms: Default: ``False``. If set to ``True`` result would be
      dictionary of ``User`` instances with permissions' codenames list as
      values. This would fetch users eagerly!

    :param with_superusers: Default: ``False``. If set to ``True`` result would
      contain all superusers.

    :param with_group_users: Default: ``True``. If set to ``False`` result would
      **not** contain those users who have only group permissions for given
      ``obj``.

    :param only_with_perms_in: Default: ``None``. If set to an iterable of
      permission strings then only users with those permissions would be
      returned.

    Example::

        >>> from django.contrib.flatpages.models import FlatPage
        >>> from django.contrib.auth.models import User
        >>> from guardian.shortcuts import assign_perm, get_users_with_perms
        >>>
        >>> page = FlatPage.objects.create(title='Some page', path='/some/page/')
        >>> joe = User.objects.create_user('joe', 'joe@example.com', 'joesecret')
        >>> dan = User.objects.create_user('dan', 'dan@example.com', 'dansecret')
        >>> assign_perm('change_flatpage', joe, page)
        >>> assign_perm('delete_flatpage', dan, page)
        >>>
        >>> get_users_with_perms(page)
        [<User: joe>, <User: dan>]
        >>>
        >>> get_users_with_perms(page, attach_perms=True)
        {<User: joe>: [u'change_flatpage'], <User: dan>: [u'delete_flatpage']}
        >>> get_users_with_perms(page, only_with_perms_in=['change_flatpage'])
        [<User: joe>]

        """
        if not attach_perms:
            qset = get_unattached_users_with_perms_qset(obj, None,
                                                        with_group_users=with_group_users,
                                                        with_superusers=with_superusers,
                                                        permission_expiry=permission_expiry
                                                        )
            return get_user_model().objects.filter(qset).distinct()
        else:
            # TODO: Do not hit db for each user!
            users = {}
            for user in get_users_with_perms(obj,
                                             with_group_users=with_group_users,
                                             with_superusers=with_superusers,
                                             permission_expiry=permission_expiry):
                # TODO: Support the case of set with_group_users but not with_superusers.
                if with_group_users or with_superusers:
                    users[user] = sorted(get_perms(user, obj))
                else:
                    users[user] = sorted(get_user_perms(user, obj))
            return users


def get_users_with_permission(obj, perm, attach_perms=False, with_superusers=False,
                         with_group_users=True, permission_expiry=False, only_with_perms_in=None):
    qset = get_unattached_users_with_perms_qset(obj, perm,
         with_group_users=with_group_users,
         with_superusers=with_superusers,
         permission_expiry=permission_expiry
    )
    if not attach_perms:
        # It's much easier without attached perms so we do it first if that is
        # the case
        user_model = get_user_obj_perms_model(obj)
        related_name = user_model.user.field.related_query_name()
        ret = get_user_model().objects.filter(qset).distinct()
        return ret
    else:
        # TODO: Do not hit db for each user!
        users = {}
        for user in get_users_with_perms(obj,
                                         with_group_users=with_group_users,
                                         only_with_perms_in=only_with_perms_in,
                                         with_superusers=with_superusers):
            # TODO: Support the case of set with_group_users but not with_superusers.
            if with_group_users or with_superusers:
                users[user] = sorted(get_perms(user, obj))
            else:
                users[user] = sorted(get_user_perms(user, obj))
        return users


def get_groups_with_perms(obj, attach_perms=False):
    """
    Returns queryset of all ``Group`` objects with *any* object permissions for
    the given ``obj``.

    :param obj: persisted Django's ``Model`` instance

    :param attach_perms: Default: ``False``. If set to ``True`` result would be
      dictionary of ``Group`` instances with permissions' codenames list as
      values. This would fetch groups eagerly!

    Example::

        >>> from django.contrib.flatpages.models import FlatPage
        >>> from guardian.shortcuts import assign_perm, get_groups_with_perms
        >>> from guardian.models import Group
        >>>
        >>> page = FlatPage.objects.create(title='Some page', path='/some/page/')
        >>> admins = Group.objects.create(name='Admins')
        >>> assign_perm('change_flatpage', admins, page)
        >>>
        >>> get_groups_with_perms(page)
        [<Group: admins>]
        >>>
        >>> get_groups_with_perms(page, attach_perms=True)
        {<Group: admins>: [u'change_flatpage']}

    """
    ctype = get_content_type(obj)
    group_model = get_group_obj_perms_model(obj)

    if not attach_perms:
        # It's much easier without attached perms so we do it first if that is the case
        group_rel_name = group_model.group.field.related_query_name()
        if group_model.objects.is_generic():
            group_filters = {
                '%s__content_type' % group_rel_name: ctype,
                '%s__object_pk' % group_rel_name: obj.pk,
            }
        else:
            group_filters = {'%s__content_object' % group_rel_name: obj}
        return Group.objects.filter(**group_filters).distinct()
    else:
        group_perms_mapping = defaultdict(list)
        groups_with_perms = get_groups_with_perms(obj)
        qs = group_model.objects.filter(group__in=groups_with_perms).prefetch_related('group', 'permission')
        if group_model is GroupObjectPermission:
            qs = qs.filter(object_pk=obj.pk, content_type=ctype)
        else:
            qs = qs.filter(content_object_id=obj.pk)

        for group_perm in qs:
            group_perms_mapping[group_perm.group].append(group_perm.permission.codename)
        return dict(group_perms_mapping)


def get_organizations_with_perms(obj, attach_perms=False):
    ctype = ContentType.objects.get_for_model(obj)
    if not attach_perms:
        # It's much easier without attached perms so we do it first if that is
        # the case
        org_model = get_organization_obj_perms_model(obj)
        organization_rel_name = org_model.organization.field.related_query_name()
        if org_model.objects.is_generic():
            organization_filters = {
                '%s__content_type' % organization_rel_name: ctype,
                '%s__object_pk' % organization_rel_name: obj.pk,
            }
        else:
            organization_filters = {'%s__content_object' % organization_rel_name: obj}
        organizations = organization_models.Organization.objects.filter(**organization_filters).distinct()
        return organizations
    else:
        # TODO: Do not hit db for each organization!
        organizations = {}
        for organization in get_organizations_with_perms(obj):
            if not organization in organizations:
                organizations[organization] = sorted(get_perms(organization, obj))
        return organizations


def get_objects_for_user(user, perms, klass=None, use_groups=True, any_perm=False,
                         with_superuser=True, accept_global_perms=True):
    """
    Returns queryset of objects for which a given ``user`` has *all*
    permissions present at ``perms``.

    :param user: ``User`` or ``AnonymousUser`` instance for which objects would
      be returned.
    :param perms: single permission string, or sequence of permission strings
      which should be checked.
      If ``klass`` parameter is not given, those should be full permission
      names rather than only codenames (i.e. ``auth.change_user``). If more than
      one permission is present within sequence, their content type **must** be
      the same or ``MixedContentTypeError`` exception would be raised.
    :param klass: may be a Model, Manager or QuerySet object. If not given
      this parameter would be computed based on given ``params``.
    :param use_groups: if ``False``, wouldn't check user's groups object
      permissions. Default is ``True``.
    :param any_perm: if True, any of permission in sequence is accepted. Default is ``False``.
    :param with_superuser: if ``True`` and if ``user.is_superuser`` is set,
      returns the entire queryset. Otherwise will only return objects the user
      has explicit permissions. This must be ``True`` for the accept_global_perms
      parameter to have any affect. Default is ``True``.
    :param accept_global_perms: if ``True`` takes global permissions into account.
      Object based permissions are taken into account if more than one permission is handed in in perms and at least
      one of these perms is not globally set. If any_perm is set to false then the intersection of matching object
      is returned. Note, that if with_superuser is False, accept_global_perms will be ignored, which means that only
      object permissions will be checked! Default is ``True``.

    :raises MixedContentTypeError: when computed content type for ``perms``
      and/or ``klass`` clashes.
    :raises WrongAppError: if cannot compute app label for given ``perms``/
      ``klass``.

    Example::

        >>> from django.contrib.auth.models import User
        >>> from guardian.shortcuts import get_objects_for_user
        >>> joe = User.objects.get(username='joe')
        >>> get_objects_for_user(joe, 'auth.change_group')
        []
        >>> from guardian.shortcuts import assign_perm
        >>> group = Group.objects.create('some group')
        >>> assign_perm('auth.change_group', joe, group)
        >>> get_objects_for_user(joe, 'auth.change_group')
        [<Group some group>]


    The permission string can also be an iterable. Continuing with the previous example:

        >>> get_objects_for_user(joe, ['auth.change_group', 'auth.delete_group'])
        []
        >>> get_objects_for_user(joe, ['auth.change_group', 'auth.delete_group'], any_perm=True)
        [<Group some group>]
        >>> assign_perm('auth.delete_group', joe, group)
        >>> get_objects_for_user(joe, ['auth.change_group', 'auth.delete_group'])
        [<Group some group>]

    Take global permissions into account:

        >>> jack = User.objects.get(username='jack')
        >>> assign_perm('auth.change_group', jack) # this will set a global permission
        >>> get_objects_for_user(jack, 'auth.change_group')
        [<Group some group>]
        >>> group2 = Group.objects.create('other group')
        >>> assign_perm('auth.delete_group', jack, group2)
        >>> get_objects_for_user(jack, ['auth.change_group', 'auth.delete_group']) # this retrieves intersection
        [<Group other group>]
        >>> get_objects_for_user(jack, ['auth.change_group', 'auth.delete_group'], any_perm) # this retrieves union
        [<Group some group>, <Group other group>]

    If accept_global_perms is set to ``True``, then all assigned global
    permissions will also be taken into account.

    - Scenario 1: a user has view permissions generally defined on the model
      'books' but no object based permission on a single book instance:

        - If accept_global_perms is ``True``: List of all books will be
          returned.
        - If accept_global_perms is ``False``: list will be empty.

    - Scenario 2: a user has view permissions generally defined on the model
      'books' and also has an object based permission to view book 'Whatever':

        - If accept_global_perms is ``True``: List of all books will be
          returned.
        - If accept_global_perms is ``False``: list will only contain book
          'Whatever'.

    - Scenario 3: a user only has object based permission on book 'Whatever':

        - If accept_global_perms is ``True``: List will only contain book
          'Whatever'.
        - If accept_global_perms is ``False``: List will only contain book
          'Whatever'.

    - Scenario 4: a user does not have any permission:

        - If accept_global_perms is ``True``: Empty list.
        - If accept_global_perms is ``False``: Empty list.
    """
    if isinstance(perms, str):
        perms = [perms]
    ctype = None
    app_label = None
    codenames = set()

    # Compute codenames set and ctype if possible
    for perm in perms:
        if '.' in perm:
            new_app_label, codename = perm.split('.', 1)
            if app_label is not None and app_label != new_app_label:
                raise MixedContentTypeError("Given perms must have same app "
                                            "label (%s != %s)" % (app_label, new_app_label))
            else:
                app_label = new_app_label
        else:
            codename = perm
        codenames.add(codename)
        if app_label is not None:
            new_ctype = ContentType.objects.get(app_label=app_label,
                                                permission__codename=codename)
            if ctype is not None and ctype != new_ctype:
                raise MixedContentTypeError("ContentType was once computed "
                                            "to be %s and another one %s" % (ctype, new_ctype))
            else:
                ctype = new_ctype

    # Compute queryset and ctype if still missing
    if ctype is None and klass is not None:
        queryset = _get_queryset(klass)
        ctype = get_content_type(queryset.model)
    elif ctype is not None and klass is None:
        queryset = _get_queryset(ctype.model_class())
    elif klass is None:
        raise WrongAppError("Cannot determine content type")
    else:
        queryset = _get_queryset(klass)
        if ctype.model_class() != queryset.model:
            raise MixedContentTypeError("Content type for given perms and "
                                        "klass differs")

    # At this point, we should have both ctype and queryset and they should
    # match which means: ctype.model_class() == queryset.model
    # we should also have ``codenames`` list

    # First check if user is superuser and if so, return queryset immediately
    if with_superuser and user.is_superuser:
        return queryset

    # Check if the user is anonymous. The
    # django.contrib.auth.models.AnonymousUser object doesn't work for queries
    # and it's nice to be able to pass in request.user blindly.
    if user.is_anonymous:
        user = get_anonymous_user()

    global_perms = set()
    has_global_perms = False
    # a superuser has by default assigned global perms for any
    if accept_global_perms and with_superuser:
        for code in codenames:
            if user.has_perm(ctype.app_label + '.' + code):
                global_perms.add(code)
        for code in global_perms:
            codenames.remove(code)
        # prerequisite: there must be elements in global_perms otherwise just follow the procedure for
        # object based permissions only AND
        # 1. codenames is empty, which means that permissions are ONLY set globally, therefore return the full queryset.
        # OR
        # 2. any_perm is True, then the global permission beats the object based permission anyway,
        # therefore return full queryset
        if len(global_perms) > 0 and (len(codenames) == 0 or any_perm):
            return queryset
        # if we have global perms and still some object based perms differing from global perms and any_perm is set
        # to false, then we have to flag that global perms exist in order to merge object based permissions by user
        # and by group correctly. Scenario: global perm change_xx and object based perm delete_xx on object A for user,
        # and object based permission delete_xx  on object B for group, to which user is assigned.
        # get_objects_for_user(user, [change_xx, delete_xx], use_groups=True, any_perm=False, accept_global_perms=True)
        # must retrieve object A and B.
        elif len(global_perms) > 0 and (len(codenames) > 0):
            has_global_perms = True

    # Now we should extract list of pk values for which we would filter
    # queryset
    user_model = get_user_obj_perms_model(queryset.model)
    user_obj_perms_queryset = (user_model.objects
                               .filter(user=user)
                               .filter(permission__content_type=ctype))
    groups_obj_perms_queryset = None
    organizations_obj_perms_queryset = None
    group_fields = None
    organization_fields = None
    organization_model = None
    group_model = None

    if len(codenames):
        user_obj_perms_queryset = user_obj_perms_queryset.filter(
            permission__codename__in=codenames)
    direct_fields = ['content_object__pk', 'permission__codename']
    generic_fields = ['object_pk', 'permission__codename']
    if user_model.objects.is_generic():
        user_fields = generic_fields
    else:
        user_fields = direct_fields

    if use_groups:
        group_model = get_group_obj_perms_model(queryset.model)
        group_filters = {
            'permission__content_type': ctype,
            'group__%s' % get_user_model().groups.field.related_query_name(): user,
        }
        if len(codenames):
            group_filters.update({
                'permission__codename__in': codenames,
            })
        groups_obj_perms_queryset = group_model.objects.filter(**group_filters)
        if group_model.objects.is_generic():
            group_fields = generic_fields
        else:
            group_fields = direct_fields

        # Orgs
        organization_model = get_organization_obj_perms_model(queryset.model)
        organization_filters = {
            'permission__content_type': ctype,
            'permission__codename__in': codenames,
            'organization__users': user,
        }
        organizations_obj_perms_queryset = organization_model.objects.filter(**organization_filters)
        if organization_model.objects.is_generic():
            organization_fields = generic_fields
        else:
            organization_fields = direct_fields

        if not any_perm and len(codenames) and not has_global_perms:
            user_obj_perms = user_obj_perms_queryset.values_list(*user_fields)
            groups_obj_perms = groups_obj_perms_queryset.values_list(*group_fields)
            organizations_obj_perms = organizations_obj_perms_queryset.values_list(*organization_fields)
            data = list(user_obj_perms) + list(groups_obj_perms) + list(organizations_obj_perms)
            # sorting/grouping by pk (first in result tuple)
            keyfunc = lambda t: t[0]
            data = sorted(data, key=keyfunc)
            pk_list = []
            for pk, group in groupby(data, keyfunc):
                obj_codenames = {e[1] for e in group}
                if codenames.issubset(obj_codenames):
                    pk_list.append(pk)
            objects = queryset.filter(pk__in=pk_list)
            return objects

    if not any_perm and len(codenames) > 1:
        counts = user_obj_perms_queryset.values(
            user_fields[0]).annotate(object_pk_count=Count(user_fields[0]))
        user_obj_perms_queryset = counts.filter(
            object_pk_count__gte=len(codenames))

    is_cast_integer = _is_cast_integer_pk(queryset)

    field_pk = user_fields[0]
    values = user_obj_perms_queryset
    if is_cast_integer:
        values = values.annotate(
            obj_pk=Cast(field_pk, BigIntegerField())
        )
        field_pk = 'obj_pk'

    values = values.values_list(field_pk, flat=True)
    q = Q(pk__in=values)
    if use_groups:
        field_pk = group_fields[0]
        values = groups_obj_perms_queryset
        if is_cast_integer:
            values = values.annotate(
                obj_pk=Cast(field_pk, BigIntegerField())
            )
            field_pk = 'obj_pk'
        values = values.values_list(field_pk, flat=True)
        q |= Q(pk__in=values)

        field_pk = organization_fields[0]
        values = organizations_obj_perms_queryset
        if is_cast_integer:
            values = values.annotate(
                obj_pk=Cast(field_pk, BigIntegerField())
            )
            field_pk = 'obj_pk'
        values = values.values_list(field_pk, flat=True)
        q |= Q(pk__in=values)

    return queryset.filter(q)


def get_objects_for_group(group, perms, klass=None, any_perm=False, accept_global_perms=True):
    """
    Returns queryset of objects for which a given ``group`` has *all*
    permissions present at ``perms``.

    :param group: ``Group`` instance for which objects would be returned.
    :param perms: single permission string, or sequence of permission strings
      which should be checked.
      If ``klass`` parameter is not given, those should be full permission
      names rather than only codenames (i.e. ``auth.change_user``). If more than
      one permission is present within sequence, their content type **must** be
      the same or ``MixedContentTypeError`` exception would be raised.
    :param klass: may be a Model, Manager or QuerySet object. If not given
      this parameter would be computed based on given ``params``.
    :param any_perm: if True, any of permission in sequence is accepted
    :param accept_global_perms: if ``True`` takes global permissions into account.
      If any_perm is set to false then the intersection of matching objects based on global and object based permissions
      is returned. Default is ``True``.

    :raises MixedContentTypeError: when computed content type for ``perms``
      and/or ``klass`` clashes.
    :raises WrongAppError: if cannot compute app label for given ``perms``/
      ``klass``.

    Example:

    Let's assume we have a ``Task`` model belonging to the ``tasker`` app with
    the default add_task, change_task and delete_task permissions provided
    by Django::

        >>> from guardian.shortcuts import get_objects_for_group
        >>> from tasker import Task
        >>> group = Group.objects.create('some group')
        >>> task = Task.objects.create('some task')
        >>> get_objects_for_group(group, 'tasker.add_task')
        []
        >>> from guardian.shortcuts import assign_perm
        >>> assign_perm('tasker.add_task', group, task)
        >>> get_objects_for_group(group, 'tasker.add_task')
        [<Task some task>]

    The permission string can also be an iterable. Continuing with the previous example:
        >>> get_objects_for_group(group, ['tasker.add_task', 'tasker.delete_task'])
        []
        >>> assign_perm('tasker.delete_task', group, task)
        >>> get_objects_for_group(group, ['tasker.add_task', 'tasker.delete_task'])
        [<Task some task>]

    Global permissions assigned to the group are also taken into account. Continuing with previous example:
        >>> task_other = Task.objects.create('other task')
        >>> assign_perm('tasker.change_task', group)
        >>> get_objects_for_group(group, ['tasker.change_task'])
        [<Task some task>, <Task other task>]
        >>> get_objects_for_group(group, ['tasker.change_task'], accept_global_perms=False)
        [<Task some task>]

    """
    if isinstance(perms, str):
        perms = [perms]
    ctype = None
    app_label = None
    codenames = set()

    # Compute codenames set and ctype if possible
    for perm in perms:
        if '.' in perm:
            new_app_label, codename = perm.split('.', 1)
            if app_label is not None and app_label != new_app_label:
                raise MixedContentTypeError("Given perms must have same app "
                                            "label (%s != %s)" % (app_label, new_app_label))
            else:
                app_label = new_app_label
        else:
            codename = perm
        codenames.add(codename)
        if app_label is not None:
            new_ctype = ContentType.objects.get(app_label=app_label,
                                                permission__codename=codename)
            if ctype is not None and ctype != new_ctype:
                raise MixedContentTypeError("ContentType was once computed "
                                            "to be %s and another one %s" % (ctype, new_ctype))
            else:
                ctype = new_ctype

    # Compute queryset and ctype if still missing
    if ctype is None and klass is not None:
        queryset = _get_queryset(klass)
        ctype = get_content_type(queryset.model)
    elif ctype is not None and klass is None:
        queryset = _get_queryset(ctype.model_class())
    elif klass is None:
        raise WrongAppError("Cannot determine content type")
    else:
        queryset = _get_queryset(klass)
        if ctype.model_class() != queryset.model:
            raise MixedContentTypeError("Content type for given perms and "
                                        "klass differs")

    # At this point, we should have both ctype and queryset and they should
    # match which means: ctype.model_class() == queryset.model
    # we should also have ``codenames`` list

    global_perms = set()
    if accept_global_perms:
        global_perm_set = group.permissions.values_list('codename', flat=True)
        for code in codenames:
            if code in global_perm_set:
                global_perms.add(code)
        for code in global_perms:
            codenames.remove(code)
        if len(global_perms) > 0 and (len(codenames) == 0 or any_perm):
            return queryset

    # Now we should extract list of pk values for which we would filter
    # queryset
    group_model = get_group_obj_perms_model(queryset.model)
    groups_obj_perms_queryset = (group_model.objects
                                 .filter(group=group)
                                 .filter(permission__content_type=ctype))
    if len(codenames):
        groups_obj_perms_queryset = groups_obj_perms_queryset.filter(
            permission__codename__in=codenames)
    if group_model.objects.is_generic():
        fields = ['object_pk', 'permission__codename']
    else:
        fields = ['content_object__pk', 'permission__codename']
    if not any_perm and len(codenames):
        groups_obj_perms = groups_obj_perms_queryset.values_list(*fields)
        data = list(groups_obj_perms)

        keyfunc = lambda t: t[0]  # sorting/grouping by pk (first in result tuple)
        data = sorted(data, key=keyfunc)
        pk_list = []
        for pk, group in groupby(data, keyfunc):
            obj_codenames = {e[1] for e in group}
            if any_perm or codenames.issubset(obj_codenames):
                pk_list.append(pk)
        objects = queryset.filter(pk__in=pk_list)
        return objects

    is_cast_integer = _is_cast_integer_pk(queryset)

    field_pk = fields[0]
    values = groups_obj_perms_queryset

    if is_cast_integer:
        values = values.annotate(
            obj_pk=Cast(field_pk, BigIntegerField())
        )
        field_pk = 'obj_pk'

    values = values.values_list(field_pk, flat=True)
    return queryset.filter(pk__in=values)


def get_objects_for_organization(organization, perms, klass=None, any_perm=False, accept_global_perms=True):
    """
    Returns queryset of objects for which a given ``organization`` has *all*
    permissions present at ``perms``.

    :param organization: ``organization`` instance for which objects would be returned.
    :param perms: single permission string, or sequence of permission strings
      which should be checked.
      If ``klass`` parameter is not given, those should be full permission
      names rather than only codenames (i.e. ``auth.change_user``). If more than
      one permission is present within sequence, their content type **must** be
      the same or ``MixedContentTypeError`` exception would be raised.
    :param klass: may be a Model, Manager or QuerySet object. If not given
      this parameter would be computed based on given ``params``.
    :param any_perm: if True, any of permission in sequence is accepted

    :raises MixedContentTypeError: when computed content type for ``perms``
      and/or ``klass`` clashes.
    :raises WrongAppError: if cannot compute app label for given ``perms``/
      ``klass``.

    Example:

    Let's assume we have a ``Task`` model belonging to the ``tasker`` app with
    the default add_task, change_task and delete_task permissions provided
    by Django::

        >>> from guardian.shortcuts import get_objects_for_organization
        >>> from tasker import Task
        >>> organization = organization.objects.create('some organization')
        >>> task = Task.objects.create('some task')
        >>> get_objects_for_organization(organization, 'tasker.add_task')
        []
        >>> from guardian.shortcuts import assign_perm
        >>> assign_perm('tasker.add_task', organization, task)
        >>> get_objects_for_organization(organization, 'tasker.add_task')
        [<Task some task>]

    The permission string can also be an iterable. Continuing with the previous example:
        >>> get_objects_for_organization(organization, ['tasker.add_task', 'tasker.delete_task'])
        []
        >>> assign_perm('tasker.delete_task', organization, task)
        >>> get_objects_for_organization(organization, ['tasker.add_task', 'tasker.delete_task'])
        [<Task some task>]

    """
    if isinstance(perms, basestring):
        perms = [perms]
    ctype = None
    app_label = None
    codenames = set()

    # Compute codenames set and ctype if possible
    for perm in perms:
        if '.' in perm:
            new_app_label, codename = perm.split('.', 1)
            if app_label is not None and app_label != new_app_label:
                raise MixedContentTypeError("Given perms must have same app "
                                            "label (%s != %s)" % (app_label, new_app_label))
            else:
                app_label = new_app_label
        else:
            codename = perm
        codenames.add(codename)
        if app_label is not None:
            new_ctype = ContentType.objects.get(app_label=app_label,
                                                permission__codename=codename)
            if ctype is not None and ctype != new_ctype:
                raise MixedContentTypeError("ContentType was once computed "
                                            "to be %s and another one %s" % (ctype, new_ctype))
            else:
                ctype = new_ctype

    # Compute queryset and ctype if still missing
    if ctype is None and klass is not None:
        queryset = _get_queryset(klass)
        ctype = ContentType.objects.get_for_model(queryset.model)
    elif ctype is not None and klass is None:
        queryset = _get_queryset(ctype.model_class())
    elif klass is None:
        raise WrongAppError("Cannot determine content type")
    else:
        queryset = _get_queryset(klass)
        if ctype.model_class() != queryset.model:
            raise MixedContentTypeError("Content type for given perms and "
                                        "klass differs")

    # At this point, we should have both ctype and queryset and they should
    # match which means: ctype.model_class() == queryset.model
    # we should also have ``codenames`` list

    # Now we should extract list of pk values for which we would filter queryset
    organization_model = get_organization_obj_perms_model(queryset.model)
    organizations_obj_perms_queryset = (organization_model.objects
                                        .filter(organization=organization)
                                        .filter(permission__content_type=ctype))
    if len(codenames):
        organizations_obj_perms_queryset = organizations_obj_perms_queryset.filter(
            permission__codename__in=codenames)
    if organization_model.objects.is_generic():
        fields = ['object_pk', 'permission__codename']
    else:
        fields = ['content_object__pk', 'permission__codename']

    if not any_perm and len(codenames):
        organizations_obj_perms = organizations_obj_perms_queryset.values_list(*fields)
        data = list(organizations_obj_perms)

        keyfunc = lambda t: t[0]  # sorting/organizationing by pk (first in result tuple)
        data = sorted(data, key=keyfunc)
        pk_list = []
        for pk, organization in groupby(data, keyfunc):
            obj_codenames = {(e[1] for e in organization)}
            if any_perm or codenames.issubset(obj_codenames):
                pk_list.append(pk)
        objects = queryset.filter(pk__in=pk_list)
        return objects

    values = organizations_obj_perms_queryset.values_list(fields[0], flat=True)
    if organization_model.objects.is_generic():
        values = list(values)
    return queryset.filter(pk__in=values)


def _is_cast_integer_pk(queryset):
    pk = queryset.model._meta.pk

    if isinstance(pk, ForeignKey):
        return _is_cast_integer_pk(pk.target_field)

    return isinstance(pk, (
        IntegerField, AutoField, BigIntegerField,
        PositiveIntegerField, PositiveSmallIntegerField,
        SmallIntegerField))
