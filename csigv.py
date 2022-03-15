#!/usr/bin/env python3

import logging
import argparse
import clamsig

if __name__ == "__main__":

    # Let's grab my runtime options
    parser = argparse.ArgumentParser()

    parser.add_argument("-v", "--verbose", action="append_const", help="Verbosity Controls",
                        const=1, default=[])
    parser.add_argument("term", help="Name of Signature to Visualize")

    args = parser.parse_args()

    VERBOSE = len(args.verbose)

    EXTRA_MODULES = ["boto3", "urllib3", "botocore",
                     "botocore.hooks", "botocore.retryhandler"]

    extra_level = logging.ERROR

    extra_log_args = dict(handlers=[logging.StreamHandler()],
                          format="%(asctime)s [%(levelname)s] %(message)s")

    if VERBOSE == 0:
        logging.basicConfig(level=logging.ERROR,
                            **extra_log_args)
    elif VERBOSE == 1:
        logging.basicConfig(level=logging.WARNING,
                            **extra_log_args)
        extra_level = logging.ERROR
    elif VERBOSE == 2:
        logging.basicConfig(level=logging.INFO,
                            **extra_log_args)
        extra_level = logging.WARNING
    elif VERBOSE == 3:
        logging.basicConfig(level=logging.DEBUG,
                            **extra_log_args)
        extra_level = logging.INFO
    elif VERBOSE == 4:
        logging.basicConfig(level=logging.DEBUG,
                            **extra_log_args)
        extra_level = logging.DEBUG

    for mod in EXTRA_MODULES:
        logging.getLogger(mod).setLevel(extra_level)

    logger = logging.getLogger("csigv.py")

    logger.info("Searching for Term : {}".format(args.term))

    signature = clamsig.ClamSigVis(signature_name=args.term)
