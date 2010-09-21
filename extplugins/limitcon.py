# LimitCon - A plugin to prevent changing guid at every start
#
# Copyright (C) 2010 BlackMamba
#
# This program is free software; you can redistribute it and/or modify it 
# under the terms of the GNU General Public License as published by the Free 
# Software Foundation; either version 3 of the License, or (at your option) 
# any later version.
#
# This program is distributed in the hope that it will be useful, but WITHOUT 
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS 
# FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along with 
# this program; if not, see <http://www.gnu.org/licenses/>.
#
# Requirements B3 v1.2+
#
# Changelog:
# 
# 05/17/2010 - 0.1.0 - BlackMamba
#  Initial version
#

__version__ = '0.1.0'
__author__ = 'BlackMamba'

import string
import b3, os
import b3.events
import b3.plugin

user_agent = "B3 limitcon plugin/%s" % __version__

class LimitconPlugin(b3.plugin.Plugin):

	_modLevel = 20

	def onStartup(self):
		self.registerEvent(b3.events.EVT_CLIENT_AUTH)
		self.registerEvent(b3.events.EVT_CLIENT_NAME_CHANGE)

	def onLoadConfig(self):
		try:
			self._excludedNames =  self.config.get('settings','exclude_names').split(',')
		except:
			self._excludedNames = []
		try:
			self._excludeAdmins = self.config.getint('settings','exclude_admins')
		except:
			self._excludeAdmins = 1
		try:
			self._tempBanDuration = self.config.getint('settings','duration')
		except:
			self._tempBanDuration = 1440
		try:
			self._maxConnections = self.config.getint('settings','max_connections')
		except:
			self._maxConnections = 20
	def onEvent(self, event):
		self.checkClient(event)
	
	def checkClient(self, event):
		client = event.client
		self.debug('checking client: %s, %s, %s, %s' % (client.cid, client.name, client.ip, client.guid))
		if (self._excludeAdmins == 1 and client.maxLevel >= self._modLevel):
			self.debug('client %s is admin, no check' % (client.name))
			return None
		if (self._excludedNames.count(client.name)>0):
			self.debug('name %s is in the list for exclusion, no check' % (client.name))
			return None
		if (client.connections>1):
			self.debug('client %s connected more than 1 time, no check' % (client.name))
			return None
		q = "SELECT name, count(*) as nr_cons FROM clients where name = \"%s\" and connections = 1 group by name" % client.name
		self.debug("query: %s" % q)
		cursor = self.console.storage.query(q)
		if (cursor and (cursor.rowcount > 0) ):
			self.debug("rowcount: %s, id:%s" % (cursor.rowcount, cursor.lastrowid))
			r = cursor.getRow();
			self.debug("Name: %s, No. of single connections: %i" % (r['name'],r['nr_cons']))
			if r['nr_cons'] > self._maxConnections:
				client.tempban('tempbanned by LimitCon', keyword="limitcon", duration=self._tempBanDuration)
				self.info('tempbanning @%s %s, ip:%s, guid:%s. Number of single connections : %s' % (client.id, client.name, client.ip, client.guid, r['nr_cons']))
