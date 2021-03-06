# -*- coding: utf-8 -*-
# vim: sw=4 ts=4 fenc=utf-8 et
# ==============================================================================
# Copyright © 2009 UfSoft.org - Pedro Algarvio <ufs@ufsoft.org>
#
# License: BSD - Please view the LICENSE file for additional information.
# ==============================================================================
"""
Audio Failures Monitor
======================

"""

__version__     = '0.1'
__package__     = 'AFM'
__summary__     = "Audio Failure Monitor"
__author__      = 'Pedro Algarvio'
__email__       = 'ufs@ufsoft.org'
__license__     = 'BSD'
__url__         = 'http://gst.ufsoft.org/hg/AFM/'
__description__ = __doc__

import sys
from types import ModuleType

sys.modules['afm.application'] = application = ModuleType('application')
sys.modules['afm.config'] = config = ModuleType('config')
sys.modules['afm.config.db'] = config.db = ModuleType('db')
sys.modules['afm.config.client'] = config.client = ModuleType('client')
sys.modules['afm.config.server'] = config.server = ModuleType('server')
sys.modules['afm.eventmanager'] = eventmanager = ModuleType('eventmanager')
