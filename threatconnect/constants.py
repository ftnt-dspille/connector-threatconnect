""" Copyright start
  Copyright (C) 2008 - 2022 Fortinet Inc.
  All rights reserved.
  FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
  Copyright end """

error_msg = {
    400: 'Bad Request: Request was not properly formatted.',
    401: 'Unauthorized: User does not have access to the specified resource or the method attempted on a resource.',
    403: 'Bad Request: This Indicator is included in a system.',
    404: 'Not Found: The service or resource specified in the path does not exist.',
    500: 'Internal Server Error: An unknown internal error.',
    503: 'Service Unavailable: The Instance of ThreatConnect is not licensed to enable the API.'
}

PARAM_MAPPING = {'Tags': 'tags', 'Threat Assess': 'threatAssess', 'Associated Groups': 'associatedGroups'}

# The v3 body field that carries each indicator type's value (File is chosen by hash length).
INDICATOR_VALUE_FIELDS = {
    'Address': 'ip',
    'EmailAddress': 'address',
    'File': 'sha256',
    'Host': 'hostName',
    'URL': 'text',
    'ASN': 'AS Number',
    'CIDR': 'Block',
    'Email Subject': 'Subject',
    'Hashtag': 'Hashtag',
    'Mutex': 'Mutex',
    'User Agent': 'User Agent String',
}

# How a tag or security label list is applied on update: the v3 `mode` values.
MODES = {'Add': 'append', 'Replace': 'replace', 'Remove': 'delete'}
