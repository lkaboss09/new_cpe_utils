#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
CPE UTILS

TODO: Add a good description of this module
"""
from collections import deque
import json
import re
import fnmatch
import types


class CPEException(Exception): pass


class CPE(object):
    """A container class for parsed cpe strings.
    """

    attrs = ["part", "vendor", "product", "version", "update", "edition", "language", "sw_edition", "target_hw", "target_sw", "other"]

    def __init__(self, cpe_str, extended_wildcards=False):
        """Create a new CPE object that represents the cpe_str

        :param str cpe_str: The cpe string
        :param str extended_wildcards: True or False
        """
        if cpe_str.startswith("cpe:/"):
            self.part     = ""
            self.vendor   = ""
            self.product  = ""
            self.version  = ""
            self.update   = ""
            self.edition  = ""
            self.language = ""
            cpe_str = cpe_str.replace("cpe:/", "")
            parts = deque(cpe_str.split(":"))
            to_set = deque(self.attrs[:7])
            if not len(parts) <= 7:
                raise CPEException("Invalid cpe string: must have less than 7 attributes {}".format(to_set))
            while len(parts) > 0 and len(to_set) > 0:
                next_attr = to_set.popleft()
                setattr(self, next_attr, parts.popleft())

        elif cpe_str.startswith("cpe:2.3"):
            self.part       = ""
            self.vendor     = ""
            self.product    = ""
            self.version    = ""
            self.update     = ""
            self.edition    = ""
            self.language   = ""
            self.sw_edition = ""
            self.target_sw  = ""
            self.target_hw  = ""
            self.other      = ""
            cpe_str = cpe_str.replace("cpe:2.3:", "")
            parts = deque(cpe_str.split(":"))
            to_set = deque(self.attrs)
            if not len(parts) <= 11:
                raise CPEException("Invalid cpe string: must have less than 11 attributes {}".format(to_set))
            while len(parts) > 0 and len(to_set) > 0:
                next_attr = to_set.popleft()
                setattr(self, next_attr, parts.popleft())

        #if type(cpe_str) == dict:
        #    self.part       = cpe_str["part"] if "part" in cpe_str else ""
        #    self.vendor     = cpe_str["vendor"] if "vendor" in cpe_str else ""
        #    self.product    = cpe_str["product"] if "product" in cpe_str else ""
        #   self.version    = cpe_str["version"] if "version" in cpe_str else ""
        #    self.update     = cpe_str["update"] if "update" in cpe_str else ""
        #    self.edition    = cpe_str["edition"] if "edition" in cpe_str else ""
        #    self.language   = cpe_str["language"] if "language" in cpe_str else ""
        #   self.sw_edition = cpe_str["sw_edition"] if "sw_edition" in cpe_str else ""
        #    self.target_sw  = cpe_str["target_sw"] if "target_sw" in cpe_str else ""
        #    self.target_hw  = cpe_str["target_hw"] if "target_hw" in cpe_str else ""
        #    self.other      = cpe_str["other"] if "other" in cpe_str else ""
        #else:
        #    raise CPEException("Invalid cpe string: cpe must be an string or dictionary {!r}".format(cpe_str))

        if not re.match("^[a|o|h\*\?\-\part]*$", self.part):
            raise CPEException("Invalid cpe self.part: valid character only {!r}".format(self.part))
        if not re.match("^[A-Za-z0-9\*\?\-\$\!\@\#\%\^\&\+\=\(\)\:\;\{\}\[\]\~\`\|\+\_\.]*$", self.vendor):
            raise CPEException("Invalid cpe self.vendor: valid character only {!r}".format(self.vendor))
        if not re.match("^[A-Za-z0-9\*\?\-\$\!\@\#\%\^\&\+\=\(\)\:\;\{\}\[\]\~\`\|\+\_\.]*$", self.product):
            raise CPEException("Invalid cpe self.product: valid character only {!r}".format(self.match))
        if not re.match("^[A-Za-z0-9\*\?\-\$\!\@\#\%\^\&\+\=\(\)\:\;\{\}\[\]\~\`\|\+\_\.]*$", self.version):
            raise CPEException("Invalid cpe self.version: valid character only {!r}".format(self.version))
        if not re.match("^[A-Za-z0-9\*\?\-\$\!\@\#\%\^\&\+\=\(\)\:\;\{\}\[\]\~\`\|\+\_\.]*$", self.update):
            raise CPEException("Invalid cpe self.update: valid character only {!r}".format(self.update))
        if not re.match("^[A-Za-z0-9\*\?\-\$\!\@\#\%\^\&\+\=\(\)\:\;\{\}\[\]\~\`\|\+\_\.]*$", self.edition):
            raise CPEException("Invalid cpe self.edition: valid character only {!r}".format(self.edition))
        #if not re.match("^[A-Za-z0-9\*\?\-\$\!\@\#\%\^\&\+\=\(\)\:\;\{\}\[\]\~\`\|\+\_\.]*$", self.language):
        #    raise CPEException("Invalid cpe self.language: valid character only {!r}".format(self.language))
        #if not re.match("^[A-Za-z0-9\*\?\-\$\!\@\#\%\^\&\+\=\(\)\:\;\{\}\[\]\~\`\|\+\_\.]*$", self.sw_edition):
        #    raise CPEException("Invalid cpe self.sw_edition: valid character only {!r}".format(self.sw_edition))
        #if not re.match("^[A-Za-z0-9\*\?\-\$\!\@\#\%\^\&\+\=\(\)\:\;\{\}\[\]\~\`\|\+\_\.]*$", self.target_sw):
        #    raise CPEException("Invalid cpe self.target_sw: valid character only {!r}".format(self.target_sw))
        #if not re.match("^[A-Za-z0-9\*\?\-\$\!\@\#\%\^\&\+\=\(\)\:\;\{\}\[\]\~\`\|\+\_\.]*$", self.target_hw):
        #    raise CPEException("Invalid cpe self.target_hw: valid character only {!r}".format(self.target_hw))
        #if not re.match("^[A-Za-z0-9\*\?\-\$\!\@\#\%\^\&\+\=\(\)\:\;\{\}\[\]\~\`\|\+\_\.]*$", self.other):
        #    raise CPEException("Invalid cpe self.other: valid character only {!r}".format(self.other))
        #else:
        #    pass

        if (extended_wildcards == False):
            for part in parts:
                if re.search(r'((\w|\d)(\*|\?)(\w|\d|\.))', part) is not None:
                    raise CPEException(
                        "Wildcards * and ? may be used at the beginning and/or the end of an attribute-value string")
                else:
                    pass

    def has_wildcards(self):
        """Return true or false if any of this cpe's fields contain
        wildcards
        """

        if re.search('([\*|\?])', self.part):
            return True
        if re.search('([\*|\?])', self.vendor):
            return True
        if re.search('([\*|\?])', self.product):
            return True
        if re.search('([\*|\?])', self.version):
            return True
        if re.search('([\*|\?])', self.update):
            return True
        if re.search('([\*|\?])', self.edition):
            return True
        if re.search('([\*|\?])', self.language):
            return True
        if re.search('([\*|\?])', self.sw_edition):
            return True
        if re.search('([\*|\?])', self.target_sw):
            return True
        if re.search('([\*|\?])', self.target_hw):
            return True
        if re.search('([\*|\?])', self.other):
            return True
        else:
            return False


    def __str__(self):
        version = hasattr(object, "sw_edition")
        if version == True:
            return "cpe:/{}:{}:{}:{}:{}:{}:{}".format(
            self.part,
            self.vendor,
            self.product,
            self.version,
            self.update,
            self.edition,
            self.language,
        )
        else:
            return "cpe:2.3:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}".format(
                self.part,
                self.vendor,
                self.product,
                self.version,
                self.update,
                self.edition,
                self.language,
                self.sw_edition,
                self.target_sw,
                self.target_hw,
                self.other
            )
