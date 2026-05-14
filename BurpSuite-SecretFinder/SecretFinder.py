#!/usr/bin/env python3
# -*- coding:utf-8 -*-

# SecretFinder: Burp Suite Extension to find and search apikeys/tokens from a webpage
# by m4ll0k
# https://github.com/m4ll0k

# Code Credits:
# OpenSecurityResearch CustomPassiveScanner: https://github.com/OpenSecurityResearch/CustomPassiveScanner
# PortSwigger example-scanner-checks: https://github.com/PortSwigger/example-scanner-checks
# https://github.com/redhuntlabs/BurpSuite-Asset_Discover/blob/master/Asset_Discover.py

from burp import IBurpExtender
from burp import IScannerCheck
from burp import IScanIssue
from array import array
import re
import binascii
import base64
import xml.sax.saxutils as saxutils


class BurpExtender(IBurpExtender, IScannerCheck):
    def	registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._callbacks.setExtensionName("SecretFinder")
        self._callbacks.registerScannerCheck(self)
        return

    def consolidateDuplicateIssues(self, existingIssue, newIssue):
        if (existingIssue.getIssueDetail() == newIssue.getIssueDetail()):
            return -1
        else:
            return 0

    # add your regex here
    # Expanded patterns from Advanced Edition
    regexs = {
        'google_api_key': 'AIza[0-9A-Za-z\-_]{35}',
        'google_oauth2': 'ya29\.[0-9A-Za-z\-_]+',
        'docs_file_extension': '(?i)\\.(xlsx|xlsm|xlsb|xls|csv|xml|mht|mhtml|html|htm|xltx|xltm|xlt|txt|prn|dif|slk|xlam|xla|pdf|xps|ods|docx|docm|doc|dotx|dotm|dot|rtf|odt)',
        'bitcoin_address': '\\b[13][a-km-zA-HJ-NP-Z0-9]{26,33}\\b',
        'google_cloud_platform_auth': '\\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\\b',
        'google_cloud_platform_api': '\\b[A-Za-z0-9_]{21}--[A-Za-z0-9_]{8}\\b',
        'instagram_token': '\\b[0-9a-fA-F]{7}\\.[0-9a-fA-F]{32}\\b',
        'gmail_auth_token': '[0-9]{12}-[0-9A-Za-z_]{32}\\.apps\\.googleusercontent\\.com',
        'global_postal_code': '\\b\\d{5}(?:[-\\s]\\d{4})?\\b|\\b[A-Z]\\d[A-Z]\\s?\\d[A-Z]\\d\\b|\\b[A-Z]{1,2}\\d[A-Z\\d]?\\s?\\d[A-Z]{2}\\b|\\b\\d{3}-\\d{4}\\b|\\b\\d{4,6}\\b',
        'slack_api_key': 'xox.-[0-9]{12}-[0-9]{12}-[0-9a-zA-Z]{24}',
        'amazon_secret_key': '(?i)aws_secret_access_key\\s*=\\s*[A-Za-z0-9/+=]{40}',
        'github_auth_token': '[0-9a-fA-F]{40}',
        'twitter_access_token': '[1-9][ 0-9]+-(0-9a-zA-Z]{40}',
        'firebase': 'AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}',
        'google_captcha': '6L[0-9A-Za-z-_]{38}|^6[0-9a-zA-Z_-]{39}$',
        'google_oauth': 'ya29\\.[0-9A-Za-z\\-_]+',
        'aws_access_key_id': 'A[SK]IA[0-9A-Z]{16}',
        'aws_secret_access_key_v2': '(?i)aws_secret_access_key\\s*=\\s*[A-Za-z0-9/+=]{40}',
        'aws_mws_token': 'amzn\\.mws\\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',
        'amazon_s3_url': '[a-zA-Z0-9\\-\\.\\_]+\\.s3\\.amazonaws\\.com|s3://[a-zA-Z0-9\\-\\.\\_]+|s3\\.amazonaws\\.com/[a-zA-Z0-9\\-\\.\\_]+',
        'azure_storage_key': 'DefaultEndpointsProtocol=https?;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{88}',
        'azure_sas_token': 'sv=\\d{4}-\\d{2}-\\d{2}&s[a-z]=&sig=[A-Za-z0-9%+/=]+',
        'facebook_access_token': 'EAACEdEose0cBA[0-9A-Za-z]+',
        'facebook_app_secret': '(?i)(facebook|fb)(.{0,20})([0-9a-f]{32})',
        'github_pat_classic': 'ghp_[A-Za-z0-9]{36}',
        'github_pat_fine': 'github_pat_[A-Za-z0-9_]{82}',
        'github_oauth': 'gho_[A-Za-z0-9]{36}',
        'github_cred_url': '[a-zA-Z0-9_\\-]*:[a-zA-Z0-9_\\-]+@github\\.com',
        'gitlab_token': 'glpat-[A-Za-z0-9\\-_]{20}',
        'stripe_live_key': 'sk_live_[0-9a-zA-Z]{24}',
        'stripe_restricted_key': 'rk_live_[0-9a-zA-Z]{24}',
        'slack_bot_token': 'xoxb-[0-9]{11}-[0-9]{11}-[a-zA-Z0-9]{24}',
        'slack_user_token': 'xoxp-[0-9]+-[0-9]+-[0-9]+-[a-f0-9]+',
        'slack_webhook': 'https://hooks\\.slack\\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+',
        'twilio_api_key': 'SK[0-9a-fA-F]{32}',
        'twilio_account_sid': 'AC[a-zA-Z0-9_\\-]{32}',
        'paypal_braintree_token': 'access_token\\$production\\$[0-9a-z]{16}\\$[0-9a-f]{32}',
        'mailgun_api_key': 'key-[0-9a-zA-Z]{32}',
        'sendgrid_api_key': 'SG\\.[a-zA-Z0-9\\-_]{22}\\.[a-zA-Z0-9\\-_]{43}',
        'mailchimp_api_key': '[0-9a-f]{32}-us[0-9]{1,2}',
        'jwt_token': 'ey[A-Za-z0-9_\\-]{10,}\\.[A-Za-z0-9_\\-]{10,}\\.[A-Za-z0-9_\\-\\.+/=]{10,}',
        'basic_auth_header': '(?i)basic\\s+[a-zA-Z0-9=:_+/\\-]{10,200}',
        'bearer_token': '(?i)bearer\\s+[a-zA-Z0-9_\\-\\..=:+/]{10,500}',
        'db_connection_string': '(?i)(mongodb|mysql|postgres|postgresql|redis|mssql|oracle)\\://[^\\s\'"<>]+',
        'hardcoded_password': '(?i)(password|passwd|pwd|secret|credentials?)\\s*[`=:"\\[]+\\s*[^\\s,;\\]]{4,}',
        'discord_bot_token': '[MN][A-Za-z\\d]{23}\\.[\\w\\-]{6}\\.[\\w\\-]{27}',
        'telegram_bot_token': '[0-9]{9}:[a-zA-Z0-9_\\-]{35}',
        'shopify_token': 'shpat_[a-fA-F0-9]{32}|shpca_[a-fA-F0-9]{32}|shppa_[a-fA-F0-9]{32}',
        'openai_api_key': 'sk-[A-Za-z0-9]{48}|sk-proj-[A-Za-z0-9\\-_]{90,}',
        'anthropic_api_key': 'sk-ant-api\\d{2}-[A-Za-z0-9\\-_]{93}AA',
        'huggingface_token': 'hf_[A-Za-z0-9]{37}',
        'kubernetes_token': '(?i)(kube[_\\-\\s]?token|k8s[_\\-\\s]?token|KUBERNETES_TOKEN)\\s*[=:]\\s*["\']?ey[A-Za-z0-9_\\-]{50,}["\']?',
        'cloudflare_api_token': '(?i)(cloudflare[_\\-\\s]?(api[_\\-\\s]?)?token)\\s*[=:]\\s*["\']?[A-Za-z0-9_\\-]{40}["\']?',
        'ethereum_private_key': '(?i)(eth[_\\-\\s]?private[_\\-\\s]?key|PRIVATE_KEY)\\s*[=:]\\s*["\']?0x[a-fA-F0-9]{64}["\']?',
        'rsa_private_key': '-----BEGIN RSA PRIVATE KEY-----',
        'dsa_private_key': '-----BEGIN DSA PRIVATE KEY-----',
        'generic_private_key': '-----BEGIN [^\\s]+ PRIVATE KEY-----',
    }
    regex = r"[:|=|\'|\"|\s*|`|´| |,|?=|\]|\|//|/\*}](%%regex%%)[:|=|\'|\"|\s*|`|´| |,|?=|\]|\}|&|//|\*/]"
    issuename = "SecretFinder: %s"
    issuelevel = "Information"
    issuedetail = r"""Potential Secret Find: <b>%%regex%%</b>
    <br><br><b>Note:</b> Please note that some of these issues could be false positives, a manual review is recommended."""

    def doActiveScan(self, baseRequestResponse,pa):
        scan_issues = []
        tmp_issues = []

        self._CustomScans = CustomScans(baseRequestResponse, self._callbacks)


        for reg in self.regexs.items():
            tmp_issues = self._CustomScans.findRegEx(
                BurpExtender.regex.replace(r'%%regex%%',reg[1]),
                BurpExtender.issuename%(' '.join([x.title() for x in reg[0].split('_')])),
                BurpExtender.issuelevel,
                BurpExtender.issuedetail
                )
            scan_issues = scan_issues + tmp_issues

        if len(scan_issues) > 0:
            return scan_issues
        else:
            return None

    def doPassiveScan(self, baseRequestResponse):
        scan_issues = []
        tmp_issues = []

        self._CustomScans = CustomScans(baseRequestResponse, self._callbacks)


        for reg in self.regexs.items():
            tmp_issues = self._CustomScans.findRegEx(
                BurpExtender.regex.replace(r'%%regex%%',reg[1]),
                BurpExtender.issuename%(' '.join([x.title() for x in reg[0].split('_')])),
                BurpExtender.issuelevel,
                BurpExtender.issuedetail
                )
            scan_issues = scan_issues + tmp_issues

        if len(scan_issues) > 0:
            return scan_issues
        else:
            return None

class CustomScans:
    def __init__(self, requestResponse, callbacks):
        self._requestResponse = requestResponse
        self._callbacks = callbacks
        self._helpers = self._callbacks.getHelpers()
        self._mime_type = self._helpers.analyzeResponse(self._requestResponse.getResponse()).getStatedMimeType()
        return

    def findRegEx(self, regex, issuename, issuelevel, issuedetail):
        print(self._mime_type)
        if '.js' in str(self._requestResponse.getUrl()):
            print(self._mime_type)
            print(self._requestResponse.getUrl())
        scan_issues = []
        offset = array('i', [0, 0])
        response = self._requestResponse.getResponse()
        responseLength = len(response)

        if self._callbacks.isInScope(self._helpers.analyzeRequest(self._requestResponse).getUrl()):
            myre = re.compile(regex, re.VERBOSE)
            encoded_resp=binascii.b2a_base64(self._helpers.bytesToString(response))
            decoded_resp=base64.b64decode(encoded_resp)
            decoded_resp = saxutils.unescape(decoded_resp)

            match_vals = myre.findall(decoded_resp)

            for ref in match_vals:
                url = self._helpers.analyzeRequest(self._requestResponse).getUrl()
                offsets = []
                start = self._helpers.indexOf(response,
                                    ref, True, 0, responseLength)
                offset[0] = start
                offset[1] = start + len(ref)
                offsets.append(offset)

                try:
                    print("%s : %s"%(issuename.split(':')[1],ref))
                    scan_issues.append(ScanIssue(self._requestResponse.getHttpService(),
                        self._helpers.analyzeRequest(self._requestResponse).getUrl(),
                        [self._callbacks.applyMarkers(self._requestResponse, None, offsets)],
                        issuename, issuelevel, issuedetail.replace(r"%%regex%%", ref)))
                except:
                    continue
        return (scan_issues)

class ScanIssue(IScanIssue):
    def __init__(self, httpservice, url, requestresponsearray, name, severity, detailmsg):
        self._url = url
        self._httpservice = httpservice
        self._requestresponsearray = requestresponsearray
        self._name = name
        self._severity = severity
        self._detailmsg = detailmsg

    def getUrl(self):
        return self._url

    def getHttpMessages(self):
        return self._requestresponsearray

    def getHttpService(self):
        return self._httpservice

    def getRemediationDetail(self):
        return None

    def getIssueDetail(self):
        return self._detailmsg

    def getIssueBackground(self):
        return None

    def getRemediationBackground(self):
        return None

    def getIssueType(self):
        return 0

    def getIssueName(self):
        return self._name

    def getSeverity(self):
        return self._severity

    def getConfidence(self):
        return "Tentative"
