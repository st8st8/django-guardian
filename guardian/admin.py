from __future__ import unicode_literals

from django import forms
from django.conf import settings
from django.contrib.admin import ModelAdmin
from django.db.models import Q
from organizations.models import Organization
from guardian.compat import url, patterns
from django.contrib import admin
from django.contrib import messages
from django.contrib.admin.widgets import FilteredSelectMultiple
from django.core.urlresolvers import reverse
from django.shortcuts import render_to_response, get_object_or_404, redirect
from django.template import RequestContext
from django.utils.datastructures import SortedDict
from django.utils.translation import ugettext, ugettext_lazy as _

from guardian.compat import get_user_model
from guardian.forms import UserObjectPermissionsForm, OrganizationObjectPermissionsForm
from guardian.forms import GroupObjectPermissionsForm
from guardian.shortcuts import get_perms, get_organizations_with_perms
from guardian.shortcuts import get_users_with_perms
from guardian.shortcuts import get_groups_with_perms
from guardian.shortcuts import get_perms_for_model
from guardian.models import Group, UserObjectPermission
from organizations.managers import OrgManager


class AdminUserObjectPermissionsForm(UserObjectPermissionsForm):
    """
    Extends :form:`UserObjectPermissionsForm`. It only overrides
    ``get_obj_perms_field_widget`` method so it return
    ``django.contrib.admin.widgets.FilteredSelectMultiple`` widget.
    """
    def get_obj_perms_field_widget(self):
        return FilteredSelectMultiple(_("Permissions"), False)


class AdminGroupObjectPermissionsForm(GroupObjectPermissionsForm):
    """
    Extends :form:`GroupObjectPermissionsForm`. It only overrides
    ``get_obj_perms_field_widget`` method so it return
    ``django.contrib.admin.widgets.FilteredSelectMultiple`` widget.
    """
    def get_obj_perms_field_widget(self):
        return FilteredSelectMultiple(_("Permissions"), False)

class AdminOrganizationObjectPermissionsForm(OrganizationObjectPermissionsForm):
    """
    Extends :form:`GroupObjectPermissionsForm`. It only overrides
    ``get_obj_perms_field_widget`` method so it return
    ``django.contrib.admin.widgets.FilteredSelectMultiple`` widget.
    """
    def get_obj_perms_field_widget(self):
        return FilteredSelectMultiple(_("Permissions"), False)

class GuardedModelAdminMixin(object):
    """
    Serves as a helper for custom subclassing ``admin.ModelAdmin``.
    """

    change_form_template = \
        'admin/guardian/model/change_form.html'
    obj_perms_manage_template = \
        'admin/guardian/model/obj_perms_manage.html'
    obj_perms_manage_user_template = \
        'admin/guardian/model/obj_perms_manage_user.html'
    obj_perms_manage_group_template = \
        'admin/guardian/model/obj_perms_manage_group.html'
    obj_perms_manage_organization_template = \
        'admin/guardian/model/obj_perms_manage_organization.html'
    user_can_access_owned_objects_only = False
    user_owned_objects_field = 'user'
    user_can_access_owned_by_group_objects_only = False
    group_owned_objects_field = 'group'
    user_can_access_owned_by_organization_objects_only = False
    organization_owned_objects_field = 'organization'
    include_object_permissions_urls = True

    def get_queryset(self, request):
        # Prefer the Django >= 1.6 interface but maintain
        # backward compatibility
        method = getattr(
            super(GuardedModelAdminMixin, self), 'get_queryset',
            super(GuardedModelAdminMixin, self).queryset)
        qs = method(request)

        if request.user.is_superuser:
            return qs

        if self.user_can_access_owned_objects_only:
            filters = {self.user_owned_objects_field: request.user}
            qs = qs.filter(**filters)
        if self.user_can_access_owned_by_group_objects_only:
            User = get_user_model()
            user_rel_name = User.groups.field.related_query_name()
            qs_key = '%s__%s' % (self.group_owned_objects_field, user_rel_name)
            filters = {qs_key: request.user}
            qs = qs.filter(**filters)
        if self.user_can_access_owned_by_organization_objects_only:
            User = get_user_model()
            m = OrgManager()
            qs = m.get_for_user(request.user)
        return qs

    # Allow queryset method as fallback for Django versions < 1.6
    # for versions >= 1.6 this is taken care of by Django itself
    # and triggers a warning message automatically.
    import django
    if django.VERSION < (1, 6):
        queryset = get_queryset

    def get_urls(self):
        """
        Extends standard admin model urls with the following:

        - ``.../permissions/`` under ``app_mdodel_permissions`` url name (params: object_pk)
        - ``.../permissions/user-manage/<user_id>/`` under ``app_model_permissions_manage_user`` url name (params: object_pk, user_pk)
        - ``.../permissions/group-manage/<group_id>/`` under ``app_model_permissions_manage_group`` url name (params: object_pk, group_pk)
        - ``.../permissions/organization-manage/<org_id>/`` under ``app_model_permissions_manage_organization`` url name (params: object_pk, org_pk)

        .. note::
           ``...`` above are standard, instance detail url (i.e.
           ``/admin/flatpages/1/``)

        """
        urls = super(GuardedModelAdminMixin, self).get_urls()
        if self.include_object_permissions_urls:
            info = self.model._meta.app_label, self.model._meta.module_name
            myurls = patterns('',
                url(r'^(?P<object_pk>.+)/permissions/$',
                    view=self.admin_site.admin_view(self.obj_perms_manage_view),
                    name='%s_%s_permissions' % info),
                url(r'^(?P<object_pk>.+)/permissions/user-manage/(?P<user_id>\-?\d+)/$',
                    view=self.admin_site.admin_view(
                        self.obj_perms_manage_user_view),
                    name='%s_%s_permissions_manage_user' % info),
                url(r'^(?P<object_pk>.+)/permissions/group-manage/(?P<group_id>\-?\d+)/$',
                    view=self.admin_site.admin_view(
                        self.obj_perms_manage_group_view),
                    name='%s_%s_permissions_manage_group' % info),
		        url(r'^(?P<object_pk>.+)/permissions/organization-manage/(?P<organization_id>\-?\d+)/$',
		            view=self.admin_site.admin_view(
		                self.obj_perms_manage_organization_view),
		            name='%s_%s_permissions_manage_organization' % info),
            )
            urls = myurls + urls
        return urls

    def get_obj_perms_base_context(self, request, obj):
        """
        Returns context dictionary with common admin and object permissions
        related content.
        """
        context = {
            'adminform': {'model_admin': self},
            'media': self.media,
            'object': obj,
            'app_label': self.model._meta.app_label,
            'opts': self.model._meta,
            'original': hasattr(obj, '__unicode__') and obj.__unicode__() or\
                str(obj),
            'has_change_permission': self.has_change_permission(request, obj),
            'model_perms': get_perms_for_model(obj),
            'title': _("Object permissions"),
        }
        return context

    def obj_perms_manage_view(self, request, object_pk):
        """
        Main object permissions view. Presents all users and groups with any
        object permissions for the current model *instance*. Users or groups
        without object permissions for related *instance* would **not** be
        shown. In order to add or manage user or group one should use links or
        forms presented within the page.
        """
        obj = get_object_or_404(self.queryset(request), pk=object_pk)
        #users_perms = SortedDict(
        #    get_users_with_perms(obj, attach_perms=True,
        #        with_group_users=False))

        #users_perms.keyOrder.sort(key=lambda user:
        #                          getattr(user, get_user_model().USERNAME_FIELD))
        users_perms = None
        groups_perms = SortedDict(
            get_groups_with_perms(obj, attach_perms=True))
        groups_perms.keyOrder.sort(key=lambda group: group.name)
        organization_perms = SortedDict(
            get_organizations_with_perms(obj, attach_perms=True))
        organization_perms.keyOrder.sort(key=lambda group: group.name)

        if request.method == 'POST' and 'submit_manage_user' in request.POST:
            user_form = UserManage(request.POST)
            group_form = GroupManage()
            organization_form = OrganizationManage()
            info = (
                self.admin_site.name,
                self.model._meta.app_label,
                self.model._meta.module_name
            )
            if user_form.is_valid():
                users = user_form.cleaned_data['user']
                users_perms = SortedDict()
                for user in users:
                    users_perms[user] = sorted(get_perms(user, obj))
                users_perms.keyOrder.sort(key=lambda user: user.get_full_name())
        elif request.method == 'POST' and 'submit_manage_group' in request.POST:
            user_form = UserManage()
            group_form = GroupManage(request.POST)
            organization_form = OrganizationManage()
            info = (
                self.admin_site.name,
                self.model._meta.app_label,
                self.model._meta.module_name
            )
            if group_form.is_valid():
                group_id = group_form.cleaned_data['group'].id
                url = reverse(
                    '%s:%s_%s_permissions_manage_group' % info,
                    args=[obj.pk, group_id]
                )
                return redirect(url)
        elif request.method == 'POST' and 'submit_manage_organization' in request.POST:
            user_form = UserManage()
            group_form = GroupManage()
            organization_form = OrganizationManage(request.POST)
            info = (
                self.admin_site.name,
                self.model._meta.app_label,
                self.model._meta.module_name
            )
            if organization_form.is_valid():
                org_id = organization_form.cleaned_data['organization'].id
                url = reverse(
                    '%s:%s_%s_permissions_manage_organization' % info,
                    args=[obj.pk, org_id]
                )
                return redirect(url)
        else:
            user_form = UserManage()
            group_form = GroupManage()
            organization_form = OrganizationManage()

        context = self.get_obj_perms_base_context(request, obj)
        context['users_perms'] = users_perms
        context['groups_perms'] = groups_perms
        context['organization_perms'] = organization_perms
        context['user_form'] = user_form
        context['group_form'] = group_form
        context['organization_form'] = organization_form

        return render_to_response(self.get_obj_perms_manage_template(),
            context, RequestContext(request, current_app=self.admin_site.name))

    def get_obj_perms_manage_template(self):
        """
        Returns main object permissions admin template.  May be overridden if
        need to change it dynamically.

        .. note::
           If ``INSTALLED_APPS`` contains ``grappelli`` this function would
           return ``"admin/guardian/grappelli/obj_perms_manage.html"``.

        """
        if 'grappelli' in settings.INSTALLED_APPS:
            return 'admin/guardian/contrib/grappelli/obj_perms_manage.html'
        return self.obj_perms_manage_template

    def obj_perms_manage_user_view(self, request, object_pk, user_id):
        """
        Manages selected users' permissions for current object.
        """
        user = get_object_or_404(get_user_model(), pk=user_id)
        obj = get_object_or_404(self.queryset(request), pk=object_pk)
        form_class = self.get_obj_perms_manage_user_form()
        form = form_class(user, obj, request.POST or None)

        if request.method == 'POST' and form.is_valid():
            form.save_obj_perms()
            msg = ugettext("Permissions saved.")
            messages.success(request, msg)
            info = (
                self.admin_site.name,
                self.model._meta.app_label,
                self.model._meta.module_name
            )
            url = reverse(
                '%s:%s_%s_permissions_manage_user' % info,
                args=[obj.pk, user.pk]
            )
            return redirect(url)

        context = self.get_obj_perms_base_context(request, obj)
        context['user_obj'] = user
        context['user_perms'] = get_perms(user, obj)
        context['form'] = form

        return render_to_response(self.get_obj_perms_manage_user_template(),
            context, RequestContext(request, current_app=self.admin_site.name))

    def get_obj_perms_manage_user_template(self):
        """
        Returns object permissions for user admin template.  May be overridden
        if need to change it dynamically.

        .. note::
           If ``INSTALLED_APPS`` contains ``grappelli`` this function would
           return ``"admin/guardian/grappelli/obj_perms_manage_user.html"``.

        """
        if 'grappelli' in settings.INSTALLED_APPS:
            return 'admin/guardian/contrib/grappelli/obj_perms_manage_user.html'
        return self.obj_perms_manage_user_template

    def get_obj_perms_manage_user_form(self):
        """
        Returns form class for user object permissions management.  By default
        :form:`AdminUserObjectPermissionsForm` is returned.
        """
        return AdminUserObjectPermissionsForm

    def obj_perms_manage_group_view(self, request, object_pk, group_id):
        """
        Manages selected groups' permissions for current object.
        """
        group = get_object_or_404(Group, id=group_id)
        obj = get_object_or_404(self.queryset(request), pk=object_pk)
        form_class = self.get_obj_perms_manage_group_form()
        form = form_class(group, obj, request.POST or None)

        if request.method == 'POST' and form.is_valid():
            form.save_obj_perms()
            msg = ugettext("Permissions saved.")
            messages.success(request, msg)
            info = (
                self.admin_site.name,
                self.model._meta.app_label,
                self.model._meta.module_name
            )
            url = reverse(
                '%s:%s_%s_permissions_manage_group' % info,
                args=[obj.pk, group.id]
            )
            return redirect(url)

        context = self.get_obj_perms_base_context(request, obj)
        context['group_obj'] = group
        context['group_perms'] = get_perms(group, obj)
        context['form'] = form

        return render_to_response(self.get_obj_perms_manage_group_template(),
            context, RequestContext(request, current_app=self.admin_site.name))

    def get_obj_perms_manage_group_template(self):
        """
        Returns object permissions for group admin template.  May be overridden
        if need to change it dynamically.

        .. note::
           If ``INSTALLED_APPS`` contains ``grappelli`` this function would
           return ``"admin/guardian/grappelli/obj_perms_manage_group.html"``.

        """
        if 'grappelli' in settings.INSTALLED_APPS:
            return 'admin/guardian/contrib/grappelli/obj_perms_manage_group.html'
        return self.obj_perms_manage_group_template

    def get_obj_perms_manage_group_form(self):
        """
        Returns form class for group object permissions management.  By default
        :form:`AdminGroupObjectPermissionsForm` is returned.
        """
        return AdminGroupObjectPermissionsForm


class GuardedModelAdmin(GuardedModelAdminMixin, admin.ModelAdmin):
    """
    Extends ``django.contrib.admin.ModelAdmin`` class. Provides some extra
    views for object permissions management at admin panel. It also changes
    default ``change_form_template`` option to
    ``'admin/guardian/model/change_form.html'`` which is required for proper
    url (object permissions related) being shown at the model pages.

    **Extra options**

    ``GuardedModelAdmin.obj_perms_manage_template``

        *Default*: ``admin/guardian/model/obj_perms_manage.html``

    ``GuardedModelAdmin.obj_perms_manage_user_template``

        *Default*: ``admin/guardian/model/obj_perms_manage_user.html``

    ``GuardedModelAdmin.obj_perms_manage_group_template``

        *Default*: ``admin/guardian/model/obj_perms_manage_group.html``

    ``GuardedModelAdmin.user_can_access_owned_objects_only``

        *Default*: ``False``

        If this would be set to ``True``, ``request.user`` would be used to
        filter out objects he or she doesn't own (checking ``user`` field
        of used model - field name may be overridden by
        ``user_owned_objects_field`` option).

        .. note::
           Please remember that this will **NOT** affect superusers!
           Admins would still see all items.

    ``GuardedModelAdmin.user_can_access_owned_by_group_objects_only``

        *Default*: ``False``

        If this would be set to ``True``, ``request.user`` would be used to
        filter out objects her or his group doesn't own (checking if any group
        user belongs to is set as ``group`` field of the object; name of the
        field can be changed by overriding ``group_owned_objects_field``).

        .. note::
           Please remember that this will **NOT** affect superusers!
           Admins would still see all items.

    ``GuardedModelAdmin.group_owned_objects_field``

        *Default*: ``group``

    ``GuardedModelAdmin.include_object_permissions_urls``

        *Default*: ``True``

        .. versionadded:: 1.2

        Might be set to ``False`` in order **NOT** to include guardian-specific
        urls.

    **Usage example**

    Just use :admin:`GuardedModelAdmin` instead of
    ``django.contrib.admin.ModelAdmin``.

    .. code-block:: python

        from django.contrib import admin
        from guardian.admin import GuardedModelAdmin
        from myapp.models import Author

        class AuthorAdmin(GuardedModelAdmin):
            pass

        admin.site.register(Author, AuthorAdmin)

    """

    def obj_perms_manage_organization_view(self, request, object_pk, organization_id):
        """
        Manages selected organization' permissions for current object.
        """
        organization = get_object_or_404(Organization, id=organization_id)
        obj = get_object_or_404(self.queryset(request), pk=object_pk)
        form_class = self.get_obj_perms_manage_organization_form()
        form = form_class(organization, obj, request.POST or None)

        if request.method == 'POST' and form.is_valid():
            form.save_obj_perms()
            msg = ugettext("Permissions saved.")
            messages.success(request, msg)
            info = (
                self.admin_site.name,
                self.model._meta.app_label,
                self.model._meta.module_name
            )
            url = reverse(
                '%s:%s_%s_permissions_manage_organization' % info,
                args=[obj.pk, organization.id]
            )
            return redirect(url)

        context = self.get_obj_perms_base_context(request, obj)
        context['organization_obj'] = organization
        context['organization_perms'] = get_perms(organization, obj)
        context['form'] = form

        return render_to_response(self.get_obj_perms_manage_organization_template(),
            context, RequestContext(request, current_app=self.admin_site.name))


    def get_obj_perms_manage_organization_template(self):
        return self.obj_perms_manage_organization_template

    def get_obj_perms_manage_organization_form(self):
        return AdminOrganizationObjectPermissionsForm


class UserManage(forms.Form):
    user = forms.CharField(label=_("User identification"),
                        max_length=200,
                        error_messages = {'does_not_exist': _("This user does not exist")},
                        help_text=_('Enter a value compatible with User.USERNAME_FIELD')
                     )
    
    def clean_user(self):
        """
        Returns ``User`` instance based on the given identification.
        """
        s = self.cleaned_data['user']
        user_model = get_user_model()
        try:
            username_field = user_model.USERNAME_FIELD
        except AttributeError:
            username_field = 'username'
        try:
            users = get_user_model().objects.filter(Q(username__icontains=s)| Q(first_name__icontains=s)|Q(last_name__icontains=s))[:20]
            return users

        except user_model.DoesNotExist:
            raise forms.ValidationError(
                self.fields['user'].error_messages['does_not_exist'])


class GroupManage(forms.Form):
    group = forms.CharField(max_length=80, error_messages={'does_not_exist':
        _("This group does not exist")})

    def clean_group(self):
        """
        Returns ``Group`` instance based on the given group name.
        """
        name = self.cleaned_data['group']
        try:
            group = Group.objects.get(name=name)
            return group
        except Group.DoesNotExist:
            raise forms.ValidationError(
                self.fields['group'].error_messages['does_not_exist'])


class OrganizationManage(forms.Form):
    organization = forms.CharField(max_length=80, error_messages={'does_not_exist':
        _("This organization does not exist")})

    def clean_organization(self):
        """
        Returns ``Group`` instance based on the given group name.
        """
        name = self.cleaned_data['organization']
        try:
            org = Organization.objects.get(name=name)
            return org
        except Organization.DoesNotExist:
            raise forms.ValidationError(
                self.fields['organization'].error_messages['does_not_exist'])

