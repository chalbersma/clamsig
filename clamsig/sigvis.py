#!/usr/bin/env python2

import logging
import subprocess
import os.path
import shlex
import importlib.resources
import clamsig
import csv


class ClamSigVis:

    '''
    Use the tooling
    '''

    # Use the default directory
    _freshclam_dir = None

    # Use the default path by default
    _bin_path = None

    #
    _clamftypes = {0: "any file",
                   1: "Portable Executable, both 32 - and 64 - bit ",
                   2: "OLE2 containers, including specific macros.Primarily used by MS Office and MSI installation files",
                   3: "HTML(normalized)",
                   4: "Mail file",
                   5: "Graphics",
                   6: "ELF",
                   7: "ASCII text file(normalized)",
                   8: "Unused",
                   9: "Mach-O files",
                   10: "PDF files",
                   11: "Flash files",
                   12: "Java class files"}


    def __init__(self, signature_name=None, **kwargs):

        self.logger = logging.getLogger("ClamSigVis")

        self.freshclam_dir = kwargs.get("freshclam_dir", self._freshclam_dir)
        self.bin_path = kwargs.get("bin_path", self._bin_path)

        self.clamftypes = kwargs.get("clamftypes", self._clamftypes)
        self.clamflevels = kwargs.get("clamflevels", self.read_flevels())

        self.signature_search_name = signature_name


        self.sig_text_raw = self.get_sig_data()
        self.sig_decoded = self.get_decoded_sig()

    def read_flevels(self):

        flevels = dict()

        with importlib.resources.path(clamsig, "flevel.csv") as flevel_csv:
            with open(flevel_csv, "r") as flevel_csv_fobj:
                reader = csv.DictReader(flevel_csv_fobj)

                for row in reader:
                    flevels[int(row["FLEVEL"])] = row

        return flevels

    def get_sig_data(self):

        '''
        Use sigtool to get the signature string
        :return:
        '''

        get_sig_cmd = list()

        if self.bin_path is not None:
            sigtool_bin = os.path.join(self.bin_path, "sigtool")

        get_sig_cmd.append("sigtool")

        if self.freshclam_dir is not None:

            defs_path = os.path.join(self.freshclam_dir, "defs")

            get_sig_cmd.append("-d {}".format(defs_path.abspath))

        get_sig_cmd.append("--find-sigs {}".format(self.signature_search_name))

        try:
            read_sig_result = subprocess.run(" ".join(get_sig_cmd),
                                             executable="/bin/bash",
                                             shell=True,
                                             timeout=120,
                                             capture_output=True)
        except Exception as sig_read_error:
            self.logger.error("Unable to Read Signature")
            self.logger.info(sig_read_error)
            signature_raw_text = None
        else:
            # Let's Parse the Results

            signature_raw_text = read_sig_result.stdout.decode("utf-8")

            self.logger.debug("Signature Raw Text:\n{}".format(signature_raw_text))

            total_signatures = len(signature_raw_text.splitlines())


            self.logger.debug("Found {} Signature for search term: {}".format(total_signatures, self.signature_search_name))

            if total_signatures == 0:
                raise FileNotFoundError("I was unable to find a signature.")
            elif total_signatures > 1:
                raise ValueError("I found too many signatures!")

        return signature_raw_text

    def get_decoded_sig(self):

        '''
        Decode the Signature and Return the Data Back
        :return:
        '''

        decode_sig_cmd = ['''echo -e "{}" |'''.format(self.sig_text_raw)]

        if self.bin_path is not None:
            sigtool_bin = os.path.join(self.bin_path, "sigtool")

        decode_sig_cmd.append("sigtool --decode-sigs")

        try:
            decode_sig_result = subprocess.run(" ".join(decode_sig_cmd),
                                               executable="/bin/bash",
                                               shell=True,
                                               timeout=120,
                                               capture_output=True)
        except Exception as sig_read_error:
            self.logger.error("Unable to Read Signature")
            # Change back to info later
            self.logger.error(sig_read_error)
            signature_decode = None
        else:
            # Let's Parse the Results

            signature_decode = decode_sig_result.stdout.decode("utf-8")

            self.logger.debug("Signature Decoded Text:\n{}".format(signature_decode))

        return signature_decode
