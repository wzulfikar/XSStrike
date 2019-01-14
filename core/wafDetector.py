import json
import re
import os
import sys

from core.requester import requester

class WafSignaturesFile:
    file = ''
    @staticmethod
    def get():
        if len(WafSignaturesFile.file) > 0:
            return WafSignaturesFile.file

        if "WAF_SIGNATURES_FILE" in os.environ and len(os.environ['WAF_SIGNATURES_FILE'].strip()) > 0:
            WafSignaturesFile.file = os.environ['WAF_SIGNATURES_FILE']
        else:
            # use default waf signatures file
            WafSignaturesFile.file = './db/wafSignatures.json'

        if not os.path.isfile(WafSignaturesFile.file):
            print("Error: couldn't find waf signatures file at '"+ WafSignaturesFile.file + "'.")
            print("verify that the file exists or provide your own waf signatures file")
            print("by specifying `WAF_SIGNATURES_FILE` environment variable.")
            sys.exit()

        return WafSignaturesFile.file

def wafDetector(url, params, headers, GET, delay, timeout):
    with open(WafSignaturesFile.get(), 'r') as file:
        wafSignatures = json.load(file)
    # a payload which is noisy enough to provoke the WAF
    noise = '<script>alert("XSS")</script>'
    params['xss'] = noise
    # Opens the noise injected payload
    response = requester(url, params, headers, GET, delay, timeout)
    page = response.text
    code = str(response.status_code)
    headers = str(response.headers)
    if int(code) >= 400:
        bestMatch = [0, None]
        for wafName, wafSignature in wafSignatures.items():
            score = 0
            pageSign = wafSignature['page']
            codeSign = wafSignature['code']
            headersSign = wafSignature['headers']
            if pageSign:
                if re.search(pageSign, page, re.I):
                    score += 1
            if codeSign:
                if re.search(codeSign, code, re.I):
                    score += 0.5  # increase the overall score by a smaller amount because http codes aren't strong indicators
            if headersSign:
                if re.search(headersSign, headers, re.I):
                    score += 1
            # if the overall score of the waf is higher than the previous one
            if score > bestMatch[0]:
                del bestMatch[:]  # delete the previous one
                bestMatch.extend([score, wafName])  # and add this one
        if bestMatch[0] != 0:
            return bestMatch[1]
        else:
            return None
    else:
        return None
