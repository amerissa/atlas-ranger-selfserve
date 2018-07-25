#!/usr/bin/env python
import os
import sys
import json
import requests
import optparse
import logging
import time
import math
from urlparse import urlparse
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


class rangercon(object):
    def __init__(self, url, username, password, kerberos=False):
        parsed = urlparse(url)
        self.protocol = parsed.scheme
        self.host = parsed.netloc.split(':')[0]
        self.port = parsed.netloc.split(':')[1]
        self.username = username
        self.password = password
        self.kerberos = kerberos

    def rest(self, endpoint, data=None, method='get', formatjson=True, params=None):
        url = self.protocol + "://" + self.host + ":" + str(self.port) + "/" + endpoint
        header = {"Accept": "application/json", "Content-Type": "application/json"}
        if kerberos == True:
            auth = HTTPKerberosAuth()
        else:
            auth = (self.username, self.password)
        try:
            r = requests.request(method, url, headers=header, auth=auth, verify=False, data=data, params=params)
        except:
            logger.error('Cannot connect to Ranger')
            return(False)
        if formatjson:
            return(json.loads(r.text))
        else:
            return(r.text)

    def listgroups(self):
        listofgroups = []
        initial = self.rest('service/xusers/groups')
        pages = int(math.ceil(initial['totalCount']/200.))
        for i in range(pages):
            groups = [v['name'] for v in self.rest('service/xusers/groups?startIndex=%s' % (i*200))['vXGroups']]
            listofgroups.extend(groups)
        return(listofgroups)

    def repoexists(self):
        try:
            self.repoid = [v for v in self.rest('service/plugins/services')['services'] if v['type'] == 'tag'][0]['id']
        except:
            logger.error("Ranger Atlas integration is not enabled")
            return(False)
        self.reponame = [v for v in self.rest('service/plugins/services')['services'] if v['type'] == 'tag'][0]['name']

    def policyexits(self, tag):
        try:
            policyid = [ v['id'] for v in self.rest('service/plugins/policies/service/' + str(self.repoid))['policies'] if v['name'] == tag ][0]
        except:
            return(False)
        return(policyid)

    def access(self, readonly):
        if readonly is True:
            accesses = [{"type":"hdfs:read","isAllowed":True},
            {"type":"hdfs:execute","isAllowed":True},{"type":"hbase:read","isAllowed":True},
            {"type":"hive:select","isAllowed":True},{"type":"hive:read","isAllowed":True},
            {"type":"kafka:consume","isAllowed":True},{"type":"kafka:describe","isAllowed":True}]
        else:
            accesses = [{"type":"hdfs:read","isAllowed":True},{"type":"hdfs:write","isAllowed":True},{"type":"hdfs:execute","isAllowed":True},
            {"type":"hbase:read","isAllowed":True},{"type":"hbase:write","isAllowed":True},{"type":"hive:select","isAllowed":True},
            {"type":"hive:update","isAllowed":True},{"type":"hive:create","isAllowed":True},{"type":"hive:drop","isAllowed":True},
            {"type":"hive:alter","isAllowed":True},{"type":"hive:index","isAllowed":True},{"type":"hive:lock","isAllowed":True},{
            "type":"hive:all","isAllowed":True},{"type":"kafka:publish","isAllowed":True},{"type":"kafka:consume","isAllowed":True},
            {"type":"kafka:describe","isAllowed":True}]
        return(accesses)

    def policyitems(self, tag, groups):
        policyitems = []
        for group in groups:
            policyitems.append({'groups':[group['group']], "conditions": [], "users": [], "delegateAdmin": False, 'accesses': self.access(group['readonly'])})
        return(policyitems)

    def createpolicy(self, tag, groups):
        if not groups:
            return(True)
        policies = self.policyitems(tag, groups)
        data = {"policyType":"0","name":tag,"isEnabled":True,"isAuditEnabled":True,"description":"","resources":
        {"tag":{"values":[tag],"isRecursive":False,"isExcludes":False}},"policyItems": policies,
        "denyPolicyItems":[],"allowExceptions":[],"denyExceptions":[],"service":self.reponame}
        self.rest('service/plugins/policies', method='post', data=json.dumps(data))
        logger.info('Creating policy for tag %s' % (tag))

    def updatepolicy(self, policyid, groups, tag):
        if not groups:
            self.rest('service/plugins/policies/' + str(policyid), method='delete', formatjson=False)
            logger.info('Deleted policy for tag %s since it has no groups' % (tag))
        else:
            policyinfo = self.rest('service/plugins/policies/' + str(policyid))
            newitems = self.policyitems(tag, groups)
            if cmp(newitems, policyinfo['policyItems']):
                policyinfo['policyItems'] = newitems
                self.rest('service/plugins/policies/' + str(policyid), method='put', data=json.dumps(policyinfo))
                logger.info('Updating policy for tag %s' % (tag))

    def policies(self, tag, groups):
        tagid = self.policyexits(tag)
        if tagid != False:
            self.updatepolicy(tagid, groups, tag)
        else:
            self.createpolicy(tag, groups)

class atlascon(object):
    def __init__(self, url, username, password, kerberos=False):
        parsed = urlparse(url)
        self.protocol = parsed.scheme
        self.host = parsed.netloc.split(':')[0]
        self.port = parsed.netloc.split(':')[1]
        self.username = username
        self.password = password
        self.kerberos = kerberos
        self.createentity()

    def rest(self, endpoint, data=None, method='get', formatjson=True, params=None):
        url = self.protocol + "://" + self.host + ":" + str(self.port) + "/api/atlas/" + endpoint
        header = {"Accept": "application/json", "Content-Type": "application/json"}
        if kerberos == True:
            auth = HTTPKerberosAuth()
        else:
            auth = (self.username, self.password)
        try:
            r = requests.request(method, url, headers=header, auth=auth, verify=False, data=data, params=params)
        except:
            logger.error("Cannot connect to Atlas")
            return(False)
        if formatjson:
            return(json.loads(r.text))
        else:
            return(r.text)

    def createentity(self):
        if 'UserGroups' not in self.rest('types')['results']:
            data = { "enumTypes": [], "structTypes": [], "traitTypes": [], "classTypes": [{
             "superTypes": ["DataSet"], "hierarchicalMetaTypeName": "org.apache.atlas.typesystem.types.ClassType",
             "typeName": "UserGroups", "typeDescription": None, "attributeDefinitions": [ {
             "name": "Name", "dataTypeName": "string", "multiplicity": "required", "isComposite": False,
             "isUnique": True, "isIndexable": True, "reverseAttributeName": None }] }] }
            self.rest('types', method='post', data=json.dumps(data))
            logger.info('Created UserGroups type in Atlas')

    def syncgroups(self, groups):
        data = {"excludeDeletedEntities":True,"includeSubClassifications":True,"includeSubTypes":True,"entityFilters":None,"tagFilters":None,
               "attributes":["qualifiedName"], "limit": 100, "offset":0,"typeName":"UserGroups","classification":None}
        count = self.rest('entities?type=UserGroups')['count']
        listofgroups = []
        if count != 0:
            pages = int(math.ceil(float(count/100.)))
            for i in range(pages):
                data['offset'] = i*100
                listofgroups.extend([v['attributes']['Name'] for v in self.rest('v2/search/basic', method='post', data= json.dumps(data))['entities']])
        for group in groups:
            if group not in listofgroups:
                data = { "jsonClass": "org.apache.atlas.typesystem.json.InstanceSerialization$_Reference", "id": {
                 "jsonClass": "org.apache.atlas.typesystem.json.InstanceSerialization$_Id", "version": 0,
                 "typeName": "UserGroups" }, "typeName": "UserGroups", "values": { "Name": group, "name": group, "qualifiedName": group },"traitNames": [], "traits": {} }
                self.rest('entities', method='post', data=json.dumps(data))
                logger.info('Group %s has been created' % (group))
        deletedgroups = list(set(listofgroups) - set(groups))
        if deletedgroups:
            for group in deletedgroups:
                guid = self.rest('entities?type=UserGroups&property=qualifiedName&value=' + group)['definition']['id']['id']
                self.rest('entities?guid=' + guid, method='delete')
                logger.info('Group %s has been deleted' % (group))

    def readonly(self, response, tag, group):
        classification = [v['classifications'][0] for v in response if v['displayText'] == group ]
        try:
            attributes = [v['attributes'] for v in classification if v['typeName'] == tag ]
        except:
            return(True)
        try:
            readonly = attributes[0]['readonly']
        except:
            readonly = True
        return(readonly)

    def listoftags(self):
        tags = [v for v in self.rest('types?type=TRAIT')['results'] if v != 'TaxonomyTerm']
        return(tags)

    def groupsfortag(self, tag):
        data = {"excludeDeletedEntities":True,"includeSubClassifications":True,"includeSubTypes":True,"entityFilters":None,
        "tagFilters":None,'includeClassificationAttributes': True, "attributes":[],"limit":100,"offset":0,
        "typeName":"UserGroups","classification":tag}
        response = self.rest('v2/search/basic', method='post', data= json.dumps(data))
        if 'entities' in response:
            groups = [v['attributes']['Name'] for v in response['entities']]
        else:
            groups = []
        list = []
        for group in groups:
            list.append({"group": group, "readonly": self.readonly(response['entities'], tag, group)})
        return(list)

def sync():
    ranger = rangercon(rangerurl, username, password, kerberos)
    if ranger.repoexists() is False:
        return(False)
    atlas = atlascon(atlasurl, username, password, kerberos)
    if atlas.rest('admin/status') is False:
        return(False)
    rangergroups = ranger.listgroups()
    atlas.syncgroups(rangergroups)
    for tag in atlas.listoftags():
        groups = atlas.groupsfortag(tag)
        ranger.policies(tag, groups)


def main():
    parser = optparse.OptionParser(usage="usage: %prog [options]")
    parser.add_option("-r", "--rangerurl", dest="rangerurl", default="http://localhost:6080", help="Ranger URL")
    parser.add_option("-a", "--atlasurl", dest="atlasurl", default="http://localhost:21000", help="Atlas URL")
    parser.add_option("-u", "--username", dest="username", default="admin", help="Username to connect to Ranger and Atlas")
    parser.add_option("-p", "--password", dest="password", default="admin", help="Password to connect to Ranger and Atlas")
    parser.add_option("-i", "--interval", dest="interval", default=60, help="Sync Interval")
    parser.add_option("-l", "--log-file", dest="logfile", default="./atlasync.log", help="Log file location")
    parser.add_option("-k", "--kerberos", action="store_true", dest="kerberos", default=False, help="Use kerberos auth" )
    (options, args) = parser.parse_args()
    global password
    global username
    global atlasurl
    global rangerurl
    global kerberos
    username = options.username
    password = options.password
    rangerurl = options.rangerurl
    atlasurl = options.atlasurl
    logfile = options.logfile
    kerberos = options.kerberos
    if kerberos == True:
        from requests_kerberos import HTTPKerberosAuth
    global logger
    logger = logging.getLogger('usersync')
    hdlr = logging.FileHandler(logfile)
    formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
    hdlr.setFormatter(formatter)
    logger.addHandler(hdlr)
    logger.setLevel(logging.INFO)
    logger.info('Starting Sync Daemon')
    while 1 == 1:
        logger.info('Starting sync session')
        sync()
        time.sleep(int(options.interval))
        logger.info('Finished sync session')

if __name__ == "__main__":
    try:
        sys.exit(main())
    except (KeyboardInterrupt, EOFError):
        print("\nAborting ... Keyboard Interrupt.")
        sys.exit(1)
