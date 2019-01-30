#!/usr/bin/python
# -*- coding: utf-8 -*-

from __future__ import unicode_literals
from django.apps import AppConfig
from . import monkey_patch_user
from guardian.conf import settings


class GuardianConfig(AppConfig):
    name = 'guardian'

    def ready(self):
        if settings.MONKEY_PATCH:
            monkey_patch_user()
