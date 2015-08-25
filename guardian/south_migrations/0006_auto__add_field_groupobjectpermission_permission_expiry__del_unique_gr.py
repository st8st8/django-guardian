#!/usr/bin/python
# -*- coding: utf-8 -*-

# -*- coding: utf-8 -*-
from __future__ import unicode_literals
from south.db import db
from south.v2 import SchemaMigration


class Migration(SchemaMigration):
    def forwards(self, orm):
        # Removing unique constraint on 'UserObjectPermission', fields ['object_pk', 'user', 'content_type', 'permission']
        db.delete_unique('guardian_userobjectpermission', ['object_pk', 'user_id', 'content_type_id', 'permission_id'])

        # Removing unique constraint on 'GroupObjectPermission', fields ['object_pk', 'group', 'content_type', 'permission']
        db.delete_unique('guardian_groupobjectpermission',
                         ['object_pk', 'group_id', 'content_type_id', 'permission_id'])

        # Adding field 'GroupObjectPermission.permission_expiry'
        db.add_column('guardian_groupobjectpermission', 'permission_expiry',
                      self.gf('django.db.models.fields.DateTimeField')(null=True, blank=True),
                      keep_default=False)

        # Adding unique constraint on 'GroupObjectPermission', fields ['object_pk', 'group', 'permission']
        db.create_unique('guardian_groupobjectpermission', ['object_pk', 'group_id', 'permission_id'])

        # Adding field 'UserObjectPermission.permission_expiry'
        db.add_column('guardian_userobjectpermission', 'permission_expiry',
                      self.gf('django.db.models.fields.DateTimeField')(null=True, blank=True),
                      keep_default=False)

        # Adding unique constraint on 'UserObjectPermission', fields ['object_pk', 'user', 'permission']
        db.create_unique('guardian_userobjectpermission', ['object_pk', 'user_id', 'permission_id'])


    def backwards(self, orm):
        # Removing unique constraint on 'UserObjectPermission', fields ['object_pk', 'user', 'permission']
        db.delete_unique('guardian_userobjectpermission', ['object_pk', 'user_id', 'permission_id'])

        # Removing unique constraint on 'GroupObjectPermission', fields ['object_pk', 'group', 'permission']
        db.delete_unique('guardian_groupobjectpermission', ['object_pk', 'group_id', 'permission_id'])

        # Deleting field 'GroupObjectPermission.permission_expiry'
        db.delete_column('guardian_groupobjectpermission', 'permission_expiry')

        # Adding unique constraint on 'GroupObjectPermission', fields ['object_pk', 'group', 'content_type', 'permission']
        db.create_unique('guardian_groupobjectpermission',
                         ['object_pk', 'group_id', 'content_type_id', 'permission_id'])

        # Deleting field 'UserObjectPermission.permission_expiry'
        db.delete_column('guardian_userobjectpermission', 'permission_expiry')

        # Adding unique constraint on 'UserObjectPermission', fields ['object_pk', 'user', 'content_type', 'permission']
        db.create_unique('guardian_userobjectpermission', ['object_pk', 'user_id', 'content_type_id', 'permission_id'])


    models = {
        'auth.group': {
            'Meta': {'object_name': 'Group'},
            'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'name': ('django.db.models.fields.CharField', [], {'unique': 'True', 'max_length': '80'}),
            'permissions': ('django.db.models.fields.related.ManyToManyField', [],
                            {'to': "orm['auth.Permission']", 'symmetrical': 'False', 'blank': 'True'})
        },
        'auth.permission': {
            'Meta': {'ordering': "('content_type__app_label', 'content_type__model', 'codename')",
                     'unique_together': "(('content_type', 'codename'),)", 'object_name': 'Permission'},
            'codename': ('django.db.models.fields.CharField', [], {'max_length': '100'}),
            'content_type': (
                'django.db.models.fields.related.ForeignKey', [], {'to': "orm['contenttypes.ContentType']"}),
            'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'name': ('django.db.models.fields.CharField', [], {'max_length': '50'})
        },
        'auth.user': {
            'Meta': {'object_name': 'User'},
            'date_joined': ('django.db.models.fields.DateTimeField', [], {'default': 'datetime.datetime.utcnow'}),
            'email': ('django.db.models.fields.EmailField', [], {'max_length': '75', 'blank': 'True'}),
            'first_name': ('django.db.models.fields.CharField', [], {'max_length': '30', 'blank': 'True'}),
            'groups': ('django.db.models.fields.related.ManyToManyField', [],
                       {'to': "orm['auth.Group']", 'symmetrical': 'False', 'blank': 'True'}),
            'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'is_active': ('django.db.models.fields.BooleanField', [], {'default': 'True'}),
            'is_staff': ('django.db.models.fields.BooleanField', [], {'default': 'False'}),
            'is_superuser': ('django.db.models.fields.BooleanField', [], {'default': 'False'}),
            'last_login': ('django.db.models.fields.DateTimeField', [], {'default': 'datetime.datetime.utcnow'}),
            'last_name': ('django.db.models.fields.CharField', [], {'max_length': '30', 'blank': 'True'}),
            'password': ('django.db.models.fields.CharField', [], {'max_length': '128'}),
            'user_permissions': ('django.db.models.fields.related.ManyToManyField', [],
                                 {'to': "orm['auth.Permission']", 'symmetrical': 'False', 'blank': 'True'}),
            'username': ('django.db.models.fields.CharField', [], {'unique': 'True', 'max_length': '30'})
        },
        'contenttypes.contenttype': {
            'Meta': {'ordering': "('name',)", 'unique_together': "(('app_label', 'model'),)",
                     'object_name': 'ContentType', 'db_table': "'django_content_type'"},
            'app_label': ('django.db.models.fields.CharField', [], {'max_length': '100'}),
            'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'model': ('django.db.models.fields.CharField', [], {'max_length': '100'}),
            'name': ('django.db.models.fields.CharField', [], {'max_length': '100'})
        },
        'guardian.groupobjectpermission': {
            'Meta': {'unique_together': "([u'group', u'permission', u'object_pk'],)",
                     'object_name': 'GroupObjectPermission'},
            'content_type': (
                'django.db.models.fields.related.ForeignKey', [], {'to': "orm['contenttypes.ContentType']"}),
            'group': ('django.db.models.fields.related.ForeignKey', [], {'to': "orm['auth.Group']"}),
            'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'object_pk': ('django.db.models.fields.CharField', [], {'max_length': '255'}),
            'permission': ('django.db.models.fields.related.ForeignKey', [], {'to': "orm['auth.Permission']"}),
            'permission_expiry': ('django.db.models.fields.DateTimeField', [], {'null': 'True', 'blank': 'True'})
        },
        'guardian.userobjectpermission': {
            'Meta': {'unique_together': "([u'user', u'permission', u'object_pk'],)",
                     'object_name': 'UserObjectPermission'},
            'content_type': (
                'django.db.models.fields.related.ForeignKey', [], {'to': "orm['contenttypes.ContentType']"}),
            'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'object_pk': ('django.db.models.fields.CharField', [], {'max_length': '255'}),
            'permission': ('django.db.models.fields.related.ForeignKey', [], {'to': "orm['auth.Permission']"}),
            'permission_expiry': ('django.db.models.fields.DateTimeField', [], {'null': 'True', 'blank': 'True'}),
            'user': ('django.db.models.fields.related.ForeignKey', [], {'to': "orm['auth.User']"})
        }
    }

    complete_apps = ['guardian']